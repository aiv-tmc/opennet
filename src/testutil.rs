//! Shared test helpers: scratch directories and prebuilt daemon contexts
//! wired to a real loopback transport, used by the unit tests of every
//! module.
//!
//! Scratch directories are unique per test run (a process-wide random
//! suffix generated once) and per calling thread, so test artifacts
//! never leak between `cargo test` invocations or between parallel
//! tests, while repeated calls from one test still hit the same
//! directory.
//!
//! The execution sandbox is disabled in test contexts: namespace
//! creation depends on host privileges and outer container runtimes,
//! which may reap nested-namespace children and make task outcomes
//! nondeterministic. The real sandbox is exercised explicitly by the
//! gated test in `compute::executor::tests` (set `OPENNET_SANDBOX_TEST=1`).

use crate::compute::provider::Cmd;
use crate::compute::ComputeEvent;
use crate::config::Config;
use crate::daemon::Ctx;
use crate::dht::Dht;
use crate::node::identity::Identity;
use crate::node::state::NodeState;
use crate::reputation::RepTable;
use crate::swarm::{Consent, PlanState, ShardProc};
use crate::transport::Transport;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Mutex};

/// Random suffix shared by every scratch directory of the current test
/// process run; generated once so one run never reads another run's
/// persisted state left behind in the temporary directory.
fn run_suffix() -> &'static str {
    static SUFFIX: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SUFFIX.get_or_init(|| format!("{:016x}", rand::random::<u64>()))
}

/// Path of a scratch directory for one test tag. The calling thread is
/// part of the path so two tests never share a directory even with the
/// same tag, while repeated calls from one test hit the same directory.
pub fn scratch_dir(tag: &str) -> PathBuf {
    let thread = format!("{:?}", std::thread::current().id())
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    std::env::temp_dir().join(format!("opennet-test-{tag}-{thread}-{}", run_suffix()))
}

/// Whether the gated sandbox-isolation test was requested for this run.
/// When set, test contexts keep the real sandbox defaults and the
/// isolation assertions execute; otherwise every unit test runs with
/// the sandbox disabled for determinism.
pub fn sandbox_test_requested() -> bool {
    std::env::var_os("OPENNET_SANDBOX_TEST").is_some()
}

/// Build a daemon context backed by a loopback transport and a scratch
/// state directory; the returned receiver is the compute scheduler's
/// command channel, which tests may drain or ignore.
pub async fn make_ctx(tag: &str) -> (Arc<Ctx>, mpsc::Receiver<Cmd>) {
    let dir = scratch_dir(tag);
    std::fs::create_dir_all(&dir).expect("cannot create scratch dir");
    let mut config = Config::default();
    config.paths.state_dir = dir.clone();
    config.paths.socket_path = dir.join("control.sock");
    if !sandbox_test_requested() {
        // Unit tests must be deterministic on any host: real namespace
        // and cgroup isolation depends on privileges the test machine
        // may or may not grant, and on outer runtimes that may reap
        // nested-namespace children. The sandbox is verified explicitly
        // by the gated isolation test instead.
        config.sandbox.namespaces = false;
        config.sandbox.cgroup = false;
    }
    let transport = Arc::new(
        Transport::new(0, Duration::from_secs(60))
            .await
            .expect("cannot bind loopback transport"),
    );
    let identity = Identity::load_or_create(&dir).expect("cannot create identity");
    let state = Arc::new(Mutex::new(
        NodeState::load(&dir, config.mode, config.limits.clone(), &config.trust)
            .expect("cannot load state"),
    ));
    let (compute_tx, compute_rx) = mpsc::channel::<Cmd>(256);
    let (shutdown, _shutdown_rx) = watch::channel(false);
    let waiters: HashMap<String, tokio::sync::oneshot::Sender<ComputeEvent>> = HashMap::new();
    let ctx = Arc::new(Ctx {
        config: config.clone(),
        identity,
        state,
        dht: Arc::new(Mutex::new(Dht::new())),
        transport,
        reputation: Arc::new(Mutex::new(
            RepTable::load(&dir).expect("cannot load reputation"),
        )),
        compute: compute_tx,
        result_waiters: Arc::new(Mutex::new(waiters)),
        swarm: Arc::new(Mutex::new(Consent::load(&dir, &config.swarm))),
        swarm_plans: Arc::new(Mutex::new(HashMap::<String, PlanState>::new())),
        swarm_procs: Arc::new(Mutex::new(HashMap::<String, ShardProc>::new())),
        shutdown,
    });
    (ctx, compute_rx)
}
