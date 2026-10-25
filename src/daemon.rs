//! Daemon event loop: wires discovery, heartbeat, control socket, the frame
//! dispatcher and OS signals into one shutdown-aware loop.

pub use crate::dispatch::send_msg;

use crate::compute::provider::{self as provider, Cmd};
use crate::compute::ComputeEvent;
use crate::config::Config;
use crate::control;
use crate::dht::Dht;
use crate::discovery;
use crate::dispatch;
use crate::heartbeat;
use crate::init::systemd;
use crate::node::identity::Identity;
use crate::node::state::NodeState;
use crate::reputation::RepTable;
use crate::transport::Transport;
use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

/// Shared context handed to every daemon subsystem.
pub struct Ctx {
    pub config: Config,
    pub identity: Identity,
    pub state: Arc<Mutex<NodeState>>,
    pub dht: Arc<Mutex<Dht>>,
    pub transport: Arc<Transport>,
    pub reputation: Arc<Mutex<RepTable>>,
    /// Command stream feeding the compute scheduler task.
    pub compute: mpsc::Sender<Cmd>,
    /// Live count of reserved or executing task slots (scheduler-owned).
    pub running_tasks: Arc<AtomicU32>,
    /// Trust units reserved by outgoing tasks, keyed by task id; a
    /// reservation is released on failure and settled on task completion.
    pub reservations: Arc<Mutex<HashMap<String, i64>>>,
    /// Consumer sessions waiting for provider replies, keyed by task id.
    pub result_waiters: Arc<Mutex<HashMap<String, oneshot::Sender<ComputeEvent>>>>,
    /// Broadcast channel signalling shutdown to all subsystems.
    pub shutdown: watch::Sender<bool>,
}

/// Run the daemon until SIGINT, SIGTERM or a `shutdown` control command.
pub async fn run(config: Config) -> Result<()> {
    let identity = Identity::load_or_create(&config.paths.state_dir)?;
    let state = Arc::new(Mutex::new(NodeState::load(
        &config.paths.state_dir,
        config.mode,
        config.limits.clone(),
        &config.trust,
    )?));
    let reputation = Arc::new(Mutex::new(RepTable::load(&config.paths.state_dir)?));

    let transport = Arc::new(Transport::new(config.network.port).await?);
    let local_id = transport.local_id();
    println!(
        "[opennetd] node {} listening on {}",
        identity.node_id(),
        local_id
    );

    let dht = Arc::new(Mutex::new(Dht::new()));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (compute_tx, compute_rx) = mpsc::channel(64);

    let ctx = Arc::new(Ctx {
        config: config.clone(),
        identity,
        state: state.clone(),
        dht: dht.clone(),
        transport: transport.clone(),
        reputation,
        compute: compute_tx.clone(),
        running_tasks: Arc::new(AtomicU32::new(0)),
        reservations: Arc::new(Mutex::new(HashMap::new())),
        result_waiters: Arc::new(Mutex::new(HashMap::new())),
        shutdown: shutdown_tx.clone(),
    });

    // Dedicated receive task: forwarding inbound frames over a channel keeps
    // the transport from being polled directly in the main loop, so reply
    // paths can send freely while the loop is idle.
    let (frame_tx, mut frame_rx) = mpsc::channel::<(String, Bytes)>(256);
    let recv_transport = transport.clone();
    let recv_handle = tokio::spawn(async move {
        // The transport channel only closes with the process.
        while let Some(frame) = recv_transport.recv().await {
            if frame_tx.send(frame).await.is_err() {
                break;
            }
        }
    });

    provider::run(ctx.clone(), compute_rx);
    let discovery_handle = discovery::spawn(dht.clone(), config.network.clone(), local_id);
    let heartbeat_handle = heartbeat::spawn(ctx.clone());
    let control_handle = control::spawn(ctx.clone());

    // Signal readiness to systemd when the NOTIFY_SOCKET protocol is in use.
    systemd::notify_ready();

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            frame = frame_rx.recv() => match frame {
                Some((src, data)) => dispatch::handle_frame(&ctx, &src, &data).await,
                None => break,
            },
            _ = shutdown_rx.changed() => break,
            _ = sigterm.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    println!("[opennetd] shutting down");
    let _ = shutdown_tx.send(true);
    recv_handle.abort();
    discovery_handle.abort();
    heartbeat_handle.abort();
    control_handle.abort();
    systemd::notify_stopping();
    state.lock().await.save()?;
    println!("[opennetd] state saved");
    Ok(())
}
