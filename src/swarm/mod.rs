//! Swarm mode: hosting shards of one shared program (for example a large
//! LLM split by layer ranges) across consenting LAN nodes.
//!
//! Consent is the entry gate: a node joins a placement plan only when its
//! user explicitly enabled hosting for that exact program, and shard
//! processes read only hash-verified artifacts from the local artifacts
//! directory. Without consent a node neither announces capacity, nor
//! enters a plan, nor spawns anything — incoming launches are refused
//! before any process exists.
//!
//! Execution model: the coordinator splits the program's layer space
//! across consenting peers proportionally to their offered RAM, signs one
//! `ShardLaunch` per shard, then the shards form a pipeline. Payloads flow
//! shard to shard as `ShardFwd` frames; the last shard streams `ShardOut`
//! results to the coordinator; `SwarmDone` tears the plan down everywhere.

pub mod consent;
pub mod coordinator;
pub mod runner;
pub mod shard;

pub use consent::Consent;

use crate::daemon::Ctx;
use crate::dht::PeerInfo;
use crate::node::identity::Identity;
use crate::trust::handlers::verify_swarm_join;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Re-export of the shard entry point used by the frame dispatcher.
pub use shard::handle_launch;

/// One shard slot inside a placement plan.
#[derive(Debug, Clone)]
pub struct ShardSlot {
    /// Network address of the shard node.
    pub addr: String,
    /// Verified node id of the shard node.
    pub node_id: String,
}

/// Events fed into the coordinator's event channel by the dispatcher.
#[derive(Debug)]
pub enum PlanEvent {
    /// One shard reported its runner as ready.
    Ready(u32),
    /// One shard asks the pipeline to deliver a payload to shard `dst`.
    Fwd {
        /// Monotonic sequence number within the plan.
        seq: u64,
        /// Destination shard index.
        dst: u32,
        /// Opaque payload for the destination runner.
        payload: Vec<u8>,
    },
    /// The last shard produced output for the coordinator.
    Out {
        /// Monotonic sequence number within the plan.
        seq: u64,
        /// Opaque result payload.
        payload: Vec<u8>,
    },
    /// The plan terminated with a reason.
    Done(String),
}

/// Coordinator-side state of one live placement plan.
pub struct PlanState {
    /// Ordered shard slots; index equals the shard index.
    pub shards: Vec<ShardSlot>,
    /// Shard indices that reported ready so far.
    pub ready: HashSet<u32>,
    /// Channel consumed by the coordinator driving the plan.
    pub events: mpsc::UnboundedSender<PlanEvent>,
}

/// Locally running shard process registered for one plan.
pub struct ShardProc {
    /// Index of this shard inside the plan.
    pub shard_index: u32,
    /// Pipeline payloads destined for this shard, consumed by the runner
    /// bridge.
    pub inbound: mpsc::UnboundedSender<Vec<u8>>,
    /// Shut the shard down (plan end, consent revocation or failure);
    /// consumed by the runner bridge, which reaps the child process.
    pub shutdown: oneshot::Sender<()>,
}

/// Apply a verified signed swarm offer to the routing table.
pub async fn handle_join(ctx: &Arc<Ctx>, src: &str, join: crate::message::Message) {
    let crate::message::Message::SwarmJoin {
        program,
        max_shard_ram_mb,
        cpu_cores,
        unix_ts,
        pubkey,
        signature,
    } = join
    else {
        return; // the dispatcher only routes swarm offers here
    };
    let fresh = timestamp_fresh(ctx, unix_ts);
    match verify_swarm_join(
        &program,
        max_shard_ram_mb,
        cpu_cores,
        unix_ts,
        &pubkey,
        &signature,
    ) {
        Some(node_id) if fresh => {
            ctx.reputation.lock().await.record_valid(&node_id);
            // The verified offer carries the authenticated node id, so the
            // peer becomes placeable even before its first announcement.
            ctx.dht
                .lock()
                .await
                .apply_swarm(src, &node_id, &program, max_shard_ram_mb, cpu_cores);
        }
        _ => {
            ctx.reputation.lock().await.record_invalid(src);
            eprintln!("[swarm] invalid swarm offer from {src}");
        }
    }
}

/// Verify and apply a signed retraction of a swarm offer.
pub fn handle_leave(ctx: &Arc<Ctx>, unix_ts: u64, pubkey: &[u8; 32], signature: &[u8]) {
    use crate::message::Message;
    let payload = Message::leave_signing_payload(unix_ts);
    let Ok(sig) = <&[u8; 64]>::try_from(signature) else {
        return;
    };
    if !Identity::verify(pubkey, &payload, sig) {
        return;
    }
    let node_id = Identity::node_id_from_pubkey(pubkey);
    ctx.dht.blocking_lock().clear_swarm_by_node(&node_id);
}

/// Whether a timestamp falls inside the configured freshness windows.
fn timestamp_fresh(ctx: &Arc<Ctx>, unix_ts: u64) -> bool {
    let now = crate::trust::now_unix();
    let cfg = &ctx.config.network;
    unix_ts <= now + cfg.ann_future_skew_secs && now.saturating_sub(unix_ts) <= cfg.ann_max_age_secs
}

/// Route one pipeline payload to its destination shard.
///
/// The payload reaches the destination two ways depending on where it
/// lands: directly into a locally registered shard process (this node hosts
/// that shard) or over the wire as a `ShardFwd` frame (the plan's shard
/// list, known on the coordinator, provides the address). Both paths may
/// fire when the coordinator hosts the destination shard itself.
pub async fn route_fwd(
    ctx: &Arc<Ctx>,
    plan_id: &str,
    seq: u64,
    from_shard: u32,
    dst: u32,
    payload: Vec<u8>,
) {
    use crate::message::Message;
    let key = format!("{plan_id}:{dst}");
    let local = ctx
        .swarm_procs
        .lock()
        .await
        .get(&key)
        .map(|proc_| proc_.inbound.clone());
    // The local sender is only borrowed here so the ownership stays
    // queryable for the wire decision below; `send` takes `&self`.
    let delivered_locally = match &local {
        Some(tx) => {
            let _ = tx.send(payload.clone());
            true
        }
        None => false,
    };
    let target = ctx
        .swarm_plans
        .lock()
        .await
        .get(plan_id)
        .and_then(|plan| plan.shards.get(dst as usize).map(|slot| slot.addr.clone()));
    if let Some(addr) = target {
        if !delivered_locally || addr != ctx.transport.local_id() {
            let _ = crate::daemon::send_msg(
                ctx,
                &addr,
                &Message::ShardFwd {
                    plan_id: plan_id.to_string(),
                    seq,
                    src: from_shard,
                    dst,
                    payload,
                },
            )
            .await;
        }
    }
}

/// Feed one event into the coordinator's channel for the plan.
pub async fn deliver_plan_event(ctx: &Arc<Ctx>, plan_id: &str, event: PlanEvent) {
    let sender = ctx
        .swarm_plans
        .lock()
        .await
        .get(plan_id)
        .map(|plan| plan.events.clone());
    if let Some(tx) = sender {
        let _ = tx.send(event); // a closed channel means the coordinator left
    }
}

/// Tear one plan down: notify the coordinator channel, signal every local
/// shard process of this plan and drop the plan state. The runner bridges
/// owning the children consume the shutdown signals, kill the process
/// groups and deregister themselves.
pub async fn finish_plan(ctx: &Arc<Ctx>, plan_id: &str, reason: &str) {
    let sender = ctx
        .swarm_plans
        .lock()
        .await
        .get(plan_id)
        .map(|plan| plan.events.clone());
    if let Some(tx) = sender {
        let _ = tx.send(PlanEvent::Done(reason.to_string()));
    }
    ctx.swarm_plans.lock().await.remove(plan_id);
    let mut procs = ctx.swarm_procs.lock().await;
    let keys: Vec<String> = procs
        .keys()
        .filter(|key| {
            key.rsplit_once(':')
                .map(|(p, _)| p == plan_id)
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    for key in keys {
        // Removing the entry hands ownership of the shutdown sender to this
        // loop so the signal can actually be delivered.
        if let Some(proc_) = procs.remove(&key) {
            let _ = proc_.shutdown.send(());
        }
    }
}

/// Whether a peer entry carries a live swarm offer for `program`.
pub fn peer_offers(peer: &PeerInfo, program: &str) -> bool {
    peer.swarm_program == program && !peer.node_id.is_empty()
}
