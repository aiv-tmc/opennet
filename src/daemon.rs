//! Daemon wiring: shared context construction, subsystem startup, the
//! inbound frame loop and the ordered graceful-shutdown sequence.

use crate::compute::provider::{self, Cmd};
use crate::compute::ComputeEvent;
use crate::config::Config;
use crate::control;
use crate::dht::Dht;
use crate::discovery;
use crate::dispatch;
use crate::heartbeat;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::node::state::NodeState;
use crate::reputation::RepTable;
use crate::swarm::{self, Consent, PlanState, ShardProc};
use crate::transport::Transport;
use crate::wan;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

/// Consumer waiters keyed by task id, each bound to the provider node
/// id the request was booked with. Signed TaskAccept, TaskReject and
/// TaskResult frames complete a waiter only when the signature verifies
/// against that exact node id, so a frame injected from an unrelated
/// connection cannot satisfy an in-flight request.
pub type ResultWaiters = Arc<Mutex<HashMap<String, (String, oneshot::Sender<ComputeEvent>)>>>;

/// Audit waiters keyed by the hex request id of a ReceiptRequest.
pub type ReceiptWindows = Arc<Mutex<HashMap<String, oneshot::Sender<Message>>>>;

/// Successful chain audits, keyed by node id with the verified head:
/// an entry means "this head already verified, skip re-auditing".
pub type AuditedHeads = Arc<Mutex<HashMap<String, [u8; 32]>>>;

/// Process-wide operation counters surfaced in `opennetctl status`:
/// plain atomics so producers increment without touching the state
/// mutex or each other.
#[derive(Default)]
pub struct Counters {
    /// Tasks that entered execution on this provider.
    pub tasks_started: std::sync::atomic::AtomicU64,
    /// Billing receipts settled into journals on this node (both sides
    /// of the market count their own settlements).
    pub receipts_settled: std::sync::atomic::AtomicU64,
    /// Receipt-chain audits that ended in refusal or forgery.
    pub audits_failed: std::sync::atomic::AtomicU64,
}

/// Shared daemon context: every subsystem holds one of these and all
/// cross-subsystem state hangs off it behind its own lock. Fields are
/// `Arc`-shared so subsystems can be spawned as independent tasks; the
/// mutexes are never held across `.await` points that take other locks
/// in a different order.
pub struct Ctx {
    pub identity: Identity,
    pub config: Config,
    pub state: Arc<Mutex<NodeState>>,
    pub dht: Arc<Mutex<Dht>>,
    pub reputation: Arc<Mutex<RepTable>>,
    pub swarm: Arc<Mutex<Consent>>,
    pub swarm_plans: Arc<Mutex<HashMap<String, PlanState>>>,
    pub swarm_procs: Arc<Mutex<HashMap<String, ShardProc>>>,
    pub result_waiters: ResultWaiters,
    /// Provider-signed billing receipts that arrived one frame ahead
    /// of their task results, keyed by task id.
    pub pending_receipts: Arc<Mutex<HashMap<String, Message>>>,
    /// Pending receipt-window audits, keyed by request id.
    pub receipt_windows: ReceiptWindows,
    /// Verified chain heads per node id.
    pub audited_heads: AuditedHeads,
    /// Process-wide operation counters for `opennetctl status`.
    pub counters: Arc<Counters>,
    pub shutdown: watch::Sender<bool>,
    pub compute: mpsc::Sender<Cmd>,
    pub transport: Arc<Transport>,
}

/// Send one message to one address and account it as sent; errors are
/// logged by the caller and never panic the sender.
pub async fn send_msg(ctx: &Arc<Ctx>, addr: &str, msg: &Message) -> Result<()> {
    ctx.transport.send(addr, msg.encode().into()).await?;
    ctx.state.lock().await.msgs_sent += 1;
    Ok(())
}

/// Run the daemon until the shutdown flag fires; builds the tokio
/// runtime internally so the binary entry point stays a plain
/// synchronous `main`.
pub fn run(config: Config, shutdown: watch::Sender<bool>) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("cannot start tokio runtime")?;
    runtime.block_on(run_async(config, shutdown))
}

/// Async daemon body: load state, start subsystems, dispatch frames
/// until shutdown, then tear everything down in dependency order.
async fn run_async(config: Config, shutdown: watch::Sender<bool>) -> Result<()> {
    let identity =
        Identity::load_or_create(&config.paths.state_dir).context("cannot load node identity")?;
    let state = NodeState::load(
        &config.paths.state_dir,
        config.mode,
        config.limits.clone(),
        &config.trust,
    )
    .context("cannot load node state")?;
    let consent = Consent::load(&config.paths.state_dir, &config.swarm);
    let transport = Arc::new(
        Transport::new(
            identity.clone(),
            config.network.port,
            Duration::from_secs(60),
        )
        .await
        .context("cannot bind transport")?,
    );
    let (compute_tx, compute_rx) = mpsc::channel::<Cmd>(256);
    // Static WAN seeds are seeded as unverified routing entries; the
    // first gossip round trip fills in their verified fields.
    let mut dht = Dht::new();
    for seed in &config.network.seeds {
        dht.insert(&format!("tcp:{seed}"));
    }
    let ctx = Arc::new(Ctx {
        identity,
        config: config.clone(),
        state: Arc::new(Mutex::new(state)),
        dht: Arc::new(Mutex::new(dht)),
        reputation: Arc::new(Mutex::new(
            RepTable::load(&config.paths.state_dir).context("cannot load reputation")?,
        )),
        swarm: Arc::new(Mutex::new(consent)),
        swarm_plans: Arc::new(Mutex::new(HashMap::new())),
        swarm_procs: Arc::new(Mutex::new(HashMap::new())),
        result_waiters: Arc::new(Mutex::new(HashMap::new())),
        pending_receipts: Arc::new(Mutex::new(HashMap::new())),
        receipt_windows: Arc::new(Mutex::new(HashMap::new())),
        audited_heads: Arc::new(Mutex::new(HashMap::new())),
        counters: Arc::new(Counters::default()),
        shutdown: shutdown.clone(),
        compute: compute_tx,
        transport,
    });
    discovery::spawn(
        ctx.dht.clone(),
        config.network.clone(),
        ctx.transport.advertise_id(),
    );
    heartbeat::spawn(ctx.clone());
    control::spawn(ctx.clone());
    provider::run(ctx.clone(), compute_rx);
    wan::spawn(ctx.clone());
    crate::init::systemd::notify_ready();
    // POSIX platforms stop on SIGTERM as well as on the console
    // interrupt; other platforms only offer the console interrupt.
    #[cfg(unix)]
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("cannot install SIGTERM handler");
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            let _ = shutdown.send(true);
        }
    });
    #[cfg(not(unix))]
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown.send(true);
        }
    });
    let mut shutdown_rx = shutdown.subscribe();
    loop {
        tokio::select! {
            frame = ctx.transport.recv() => {
                let Some((src, data)) = frame else { break };
                dispatch::handle_frame(&ctx, &src, &data).await;
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow_and_update() {
                    break;
                }
            }
        }
    }
    swarm::leave::broadcast_leave(&ctx).await;
    swarm::leave::shutdown_plans(&ctx).await;
    ctx.reputation.lock().await.flush();
    let _ = ctx.state.lock().await.save();
    let _ = std::fs::remove_file(&config.paths.socket_path);
    Ok(())
}
