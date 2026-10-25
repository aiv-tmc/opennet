//! Shared helpers for the unit tests of this crate: unique scratch
//! directories and fully wired daemon contexts backed by a real loopback
//! transport, so subsystem tests exercise the same code paths as production.

use crate::compute::provider::Cmd;
use crate::compute::ComputeEvent;
use crate::config::Config;
use crate::daemon::Ctx;
use crate::dht::Dht;
use crate::node::identity::Identity;
use crate::node::state::NodeState;
use crate::reputation::RepTable;
use crate::transport::Transport;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

/// Global counter keeping scratch directory names unique across tests in
/// one process run.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Create a unique scratch directory under the system temp dir; tests leave
/// removal to the operating system because parallel tests share the temp
/// store and exact lifetime tracking adds no value for test data.
pub fn scratch_dir(tag: &str) -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("opennet-test-{}-{}-{id}", tag, std::process::id()))
}

/// Build a daemon context with a fresh identity, genesis trust, empty
/// routing tables and a real loopback transport. Returns the context
/// together with the compute command receiver so tests can attach a real
/// scheduler when they need one.
pub async fn make_ctx(tag: &str) -> (Arc<Ctx>, mpsc::Receiver<Cmd>) {
    let mut config = Config::default();
    config.paths.state_dir = scratch_dir(tag);
    // The identity store expects the state directory to exist; create it
    // before writing the node key.
    std::fs::create_dir_all(&config.paths.state_dir).expect("test state dir");
    let identity = Identity::load_or_create(&config.paths.state_dir).expect("test identity");
    let state = Arc::new(Mutex::new(
        NodeState::load(
            &config.paths.state_dir,
            config.mode,
            config.limits.clone(),
            &config.trust,
        )
        .expect("test state"),
    ));
    let transport = Arc::new(Transport::new(0).await.expect("test transport"));
    let (compute_tx, compute_rx) = mpsc::channel::<Cmd>(64);
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let ctx = Arc::new(Ctx {
        config: config.clone(),
        identity,
        state,
        dht: Arc::new(Mutex::new(Dht::new())),
        transport,
        reputation: Arc::new(Mutex::new(
            RepTable::load(&config.paths.state_dir).expect("test reputation"),
        )),
        compute: compute_tx,
        running_tasks: Arc::new(AtomicU32::new(0)),
        reservations: Arc::new(Mutex::new(HashMap::new())),
        result_waiters: Arc::new(Mutex::new(
            HashMap::<String, oneshot::Sender<ComputeEvent>>::new(),
        )),
        shutdown: shutdown_tx,
    });
    (ctx, compute_rx)
}
