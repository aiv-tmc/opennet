//! Daemon event loop wiring discovery, heartbeat, control socket and signals.

use crate::compute::provider::Cmd;
use crate::compute::{self, ComputeEvent};
use crate::config::Config;
use crate::control;
use crate::credits::handlers;
use crate::credits::ledger::Ledger;
use crate::credits::reputation::RepTable;
use crate::credits::transfer::PendingTransfer;
use crate::dht::Dht;
use crate::discovery;
use crate::heartbeat;
use crate::init::systemd;
use crate::message::Message;
use crate::network::Manager;
use crate::node::identity::Identity;
use crate::node::state::NodeState;
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
    pub manager: Arc<Mutex<Manager>>,
    pub ledger: Arc<Mutex<Ledger>>,
    pub reputation: Arc<Mutex<RepTable>>,
    /// Command stream feeding the compute scheduler task.
    pub compute: mpsc::Sender<Cmd>,
    /// Live count of reserved or executing task slots (scheduler-owned).
    pub running_tasks: Arc<AtomicU32>,
    /// Outgoing transfers reserved on the balance until settlement.
    pub pending: Arc<Mutex<HashMap<String, PendingTransfer>>>,
    /// Consumer sessions waiting for provider replies, keyed by task id.
    pub result_waiters: Arc<Mutex<HashMap<String, oneshot::Sender<ComputeEvent>>>>,
    /// Sessions waiting for a `CreditAck`, keyed by transfer id.
    pub ack_waiters: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
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
    )?));
    let ledger = Arc::new(Mutex::new(Ledger::load(&config.paths.state_dir)?));
    let reputation = Arc::new(Mutex::new(RepTable::load(&config.paths.state_dir)?));

    let manager = Arc::new(Mutex::new(Manager::new(config.network.port).await?));
    let local_id = manager.lock().await.local_id();
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
        manager: manager.clone(),
        ledger,
        reputation,
        compute: compute_tx.clone(),
        running_tasks: Arc::new(AtomicU32::new(0)),
        pending: Arc::new(Mutex::new(HashMap::new())),
        result_waiters: Arc::new(Mutex::new(HashMap::new())),
        ack_waiters: Arc::new(Mutex::new(HashMap::new())),
        shutdown: shutdown_tx.clone(),
    });

    // Dedicated receive task: forwarding inbound frames over a channel keeps
    // the manager lock from being held across the main loop's awaits, so
    // reply paths can acquire it freely.
    let (frame_tx, mut frame_rx) = mpsc::channel::<(String, Bytes)>(256);
    let recv_manager = manager.clone();
    let recv_handle = tokio::spawn(async move {
        loop {
            match recv_manager.lock().await.recv().await {
                Ok(frame) => {
                    if frame_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                Err(err) => eprintln!("[opennetd] receive error: {err:#}"),
            }
        }
    });

    compute::provider::run(ctx.clone(), compute_rx);
    let discovery_handle = discovery::spawn(dht.clone(), config.network.clone(), local_id);
    let heartbeat_handle = heartbeat::spawn(ctx.clone());
    let control_handle = control::spawn(ctx.clone());

    // Signal readiness to systemd when the NOTIFY_SOCKET protocol is in use.
    systemd::notify_ready();

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            frame = frame_rx.recv() => match frame {
                Some((src, data)) => handle_frame(&ctx, &src, &data).await,
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

/// Handle one inbound wire frame by dispatching it to its subsystem.
async fn handle_frame(ctx: &Arc<Ctx>, src: &str, data: &[u8]) {
    ctx.state.lock().await.msgs_received += 1;
    match Message::decode(data) {
        Some(Message::Ping) => {
            if let Err(err) = send_msg(ctx, src, &Message::Pong).await {
                eprintln!("[opennetd] pong to {src} failed: {err:#}");
            }
        }
        Some(Message::Pong) => {
            ctx.dht.lock().await.touch(src);
        }
        Some(Message::Ann {
            node_id,
            mode,
            credits,
            pubkey,
            signature,
        }) => {
            handlers::handle_ann(ctx, src, &node_id, &mode, credits, &pubkey, &signature).await
        }
        Some(Message::Credit {
            task_id,
            from_node,
            to_node,
            amount,
            pubkey,
            signature,
        }) => {
            handlers::handle_credit(
                ctx, src, &task_id, &from_node, &to_node, amount, &pubkey, &signature,
            )
            .await
        }
        Some(Message::CreditAck { task_id, accepted }) => {
            handlers::handle_credit_ack(ctx, &task_id, accepted).await;
        }
        Some(Message::TaskBid {
            task_id,
            offer,
            expires_unix,
        }) => {
            let _ = ctx
                .compute
                .send(Cmd::Bid {
                    task_id,
                    from_addr: src.to_string(),
                    offer,
                    expires_unix,
                })
                .await;
        }
        Some(Message::TaskAssign {
            task_id,
            command,
            timeout_secs,
        }) => {
            let _ = ctx
                .compute
                .send(Cmd::Assign {
                    task_id,
                    command,
                    timeout_secs,
                })
                .await;
        }
        Some(Message::TaskAccept { task_id }) => {
            compute::deliver_event(ctx, &task_id, ComputeEvent::Accepted).await;
        }
        Some(Message::TaskReject { task_id, reason }) => {
            compute::deliver_event(ctx, &task_id, ComputeEvent::Rejected(reason)).await;
        }
        Some(Message::TaskResult { task_id, outcome }) => {
            compute::deliver_event(ctx, &task_id, ComputeEvent::Outcome(outcome)).await;
        }
        None => eprintln!("[opennetd] undecodable frame from {src}"),
    }
}

/// Encode a message and send it to a peer, counting it in node statistics.
pub async fn send_msg(ctx: &Arc<Ctx>, dest: &str, msg: &Message) -> Result<()> {
    let data = Bytes::from(msg.encode());
    ctx.manager.lock().await.send(dest, data).await?;
    ctx.state.lock().await.msgs_sent += 1;
    Ok(())
}
