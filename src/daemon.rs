//! Daemon context and event loop wiring every subsystem together.
//!
//! `Ctx` carries every shared component behind `Arc`: configuration,
//! identity, the persisted node state, the peer routing table, the TCP
//! transport, the reputation table, the compute scheduler channel, the
//! consumer result waiters, the swarm consent and the live plan and shard
//! registries. Subsystems communicate either through these fields or
//! through the compute command channel fed by the frame dispatcher.
//!
//! Startup is fully self-contained: the configuration file, the state
//! directory, the swarm artifacts directory and the control socket parent
//! are all created on first run when privileges allow; every missing
//! piece degrades to in-memory defaults instead of aborting.

use crate::compute::provider::Cmd;
use crate::compute::ComputeEvent;
use crate::config::Config;
use crate::control;
use crate::dht::Dht;
use crate::discovery;
use crate::dispatch::handle_frame;
use crate::heartbeat;
use crate::init::systemd;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::node::state::NodeState;
use crate::reputation::RepTable;
use crate::swarm::{Consent, PlanState, ShardProc};
use crate::transport::Transport;
use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Mutex};

/// Shared daemon context handed to every subsystem.
pub struct Ctx {
    /// Static configuration loaded at startup.
    pub config: Config,
    /// Persistent node identity used to sign wire messages.
    pub identity: Identity,
    /// Mutable runtime state: trust coefficient, consumption counter and
    /// in-flight reservations.
    pub state: Arc<Mutex<NodeState>>,
    /// Peer routing table with freshness and verified announcement fields.
    pub dht: Arc<Mutex<Dht>>,
    /// TCP transport with persistent per-peer connections.
    pub transport: Arc<Transport>,
    /// Peer reputation counters.
    pub reputation: Arc<Mutex<RepTable>>,
    /// Command channel of the compute scheduler.
    pub compute: mpsc::Sender<Cmd>,
    /// One-shot channels of consumer sessions waiting for task events.
    pub result_waiters: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<ComputeEvent>>>>,
    /// Swarm consent: hosting a shared program requires it to be enabled
    /// for the exact program name, and it is persisted across restarts.
    pub swarm: Arc<Mutex<Consent>>,
    /// Live placement plans driven by this node as coordinator.
    pub swarm_plans: Arc<Mutex<HashMap<String, PlanState>>>,
    /// Locally running shard processes, keyed by `<plan_id>:<shard_index>`.
    pub swarm_procs: Arc<Mutex<HashMap<String, ShardProc>>>,
    /// Broadcast shutdown signal requested by the control interface.
    pub shutdown: watch::Sender<bool>,
}

/// Encode a message and send it to a peer through the shared transport,
/// counting the frame in node statistics.
pub async fn send_msg(ctx: &Arc<Ctx>, dest: &str, msg: &Message) -> Result<()> {
    let data = Bytes::from(msg.encode());
    ctx.transport.send(dest, data).await?;
    ctx.state.lock().await.msgs_sent += 1;
    Ok(())
}

/// Run the daemon synchronously on a fresh multi-threaded runtime.
pub fn run(config: Config, shutdown: watch::Sender<bool>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_async(config, shutdown))
}

/// Build every subsystem and run the inbound frame loop until the shutdown
/// signal fires; state is persisted incrementally, so exiting anywhere is
/// safe.
async fn run_async(config: Config, shutdown: watch::Sender<bool>) -> Result<()> {
    let state_dir = config.paths.state_dir.clone();
    let identity = Identity::load_or_create(&state_dir)?;
    // First-run preparation: the swarm artifacts directory must exist so
    // an operator can drop manifests into it right after installing.
    if let Some(parent) = config.paths.socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::create_dir_all(&config.swarm.artifacts_dir);
    // Persistent connections may sit silent between heartbeat rounds;
    // drop them after three heartbeat intervals so dead peers are
    // re-established on the next send.
    let idle = Duration::from_secs(
        config
            .network
            .heartbeat_interval_secs
            .saturating_mul(3)
            .max(30),
    );
    let transport = Arc::new(Transport::new(config.network.port, idle).await?);
    eprintln!(
        "[opennetd] node {} listening on {}, state dir {}",
        identity.node_id(),
        transport.local_id(),
        state_dir.display()
    );
    systemd::notify_ready();
    let state = Arc::new(Mutex::new(NodeState::load(
        &state_dir,
        config.mode,
        config.limits.clone(),
        &config.trust,
    )?));
    let dht = Arc::new(Mutex::new(Dht::new()));
    let reputation = Arc::new(Mutex::new(RepTable::load(&state_dir)?));
    let (compute_tx, compute_rx) = mpsc::channel::<Cmd>(256);
    let ctx = Arc::new(Ctx {
        config: config.clone(),
        identity,
        state,
        dht: dht.clone(),
        transport: transport.clone(),
        reputation,
        compute: compute_tx,
        result_waiters: Arc::new(Mutex::new(HashMap::new())),
        swarm: Arc::new(Mutex::new(Consent::load(&state_dir, &config.swarm))),
        swarm_plans: Arc::new(Mutex::new(HashMap::new())),
        swarm_procs: Arc::new(Mutex::new(HashMap::new())),
        shutdown: shutdown.clone(),
    });

    crate::compute::provider::run(ctx.clone(), compute_rx);
    discovery::spawn(dht, config.network.clone(), transport.local_id());
    heartbeat::spawn(ctx.clone());
    control::spawn(ctx.clone());

    // Inbound frame loop: every decoded frame goes through the same
    // dispatcher the tests drive; the shutdown signal ends the loop.
    let mut shutdown_rx = shutdown.subscribe();
    loop {
        tokio::select! {
            frame = transport.recv() => {
                let Some((src, data)) = frame else { break };
                handle_frame(&ctx, &src, &data).await;
            }
            result = shutdown_rx.wait_for(|flag| *flag) => {
                if result.is_ok() {
                    eprintln!("[opennetd] shutdown requested");
                }
                break;
            }
        }
    }
    Ok(())
}
