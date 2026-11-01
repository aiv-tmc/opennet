//! Swarm mode: consent-gated hosting of one shared program across the
//! LAN, a pipeline protocol between shard runners, and signed
//! placement plans coordinated by the node that starts a run.
//!
//! Consent is explicit and per-program (`opennetctl swarm enable
//! <program>`), artifacts must match their manifest hash before any
//! spawn, and every placement frame is signed by the coordinator's
//! identity key. This module holds the shared state types, the offer
//! handling, the pipeline routing with per-source sequence guards and
//! the plan lifecycle; the coordinator, consent, shard launch and
//! runner bridge live in the sibling modules.

use crate::dht::PeerInfo;
use crate::message::Message;
use crate::trust::handlers::verify_swarm_join;
use crate::trust::now_unix;
use anyhow::{bail, Result};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

mod consent;
pub mod coordinator;
pub mod leave;
mod runner;
mod shard;

pub use consent::Consent;
pub use leave::{broadcast_leave, handle_leave};
pub use shard::handle_launch;

#[cfg(test)]
mod tests;

/// Cap on queued pipeline frames per local shard worker; a stalled
/// runner can only buffer this many frames before senders drop with a
/// log line instead of exhausting memory.
pub const SHARD_INBOUND_CAP: usize = 64;

/// Cap on queued coordination events per plan; a coordinator that
/// falls behind (or a flooding peer) can only buffer this many events
/// before senders drop with a log line. Both bounded queues together
/// guarantee no unbounded memory growth anywhere in the pipeline.
pub const PLAN_EVENT_CAP: usize = 256;

/// One coordination event of a plan, consumed by the coordinator's event
/// loop and produced by inbound network frames.
#[derive(Clone, Debug)]
pub enum PlanEvent {
    /// One shard reported readiness.
    Ready(u32),
    /// A pipeline frame must be relayed to shard `dst`; carries the
    /// original source shard and frame number so the relay preserves
    /// both on the wire and the sequence guard keeps working.
    Fwd {
        /// Monotonic frame number assigned by the source shard.
        seq: u64,
        /// Index of the shard that produced the payload.
        src: u32,
        /// Index of the shard that must receive the payload.
        dst: u32,
        /// Opaque payload interpreted by the shard runner.
        payload: Vec<u8>,
    },
    /// A shard delivered output bytes to the coordinator.
    Out {
        /// Monotonic frame number within the output stream.
        seq: u64,
        /// Opaque result payload produced by the last shard.
        payload: Vec<u8>,
    },
    /// The plan ended, carrying the human-readable reason.
    Done(String),
}

/// Live coordination state for one plan, owned by the coordinator.
pub struct PlanState {
    /// Placement slots in shard order: where each shard runs. During
    /// failover the failed slot is rewritten in place to the spare's
    /// address, so relays follow the replacement transparently.
    pub shards: Vec<ShardSlot>,
    /// Shards that have reported readiness so far.
    pub ready: HashSet<u32>,
    /// Highest accepted pipeline frame number per source shard; a
    /// frame whose number does not strictly increase the stored value
    /// for its source is dropped as a replay or reordering.
    pub seqs: HashMap<u32, u64>,
    /// Highest accepted output frame number; the output stream of the
    /// last shard restarts its numbering, so it is validated against
    /// its own counter instead of the pipeline counters.
    pub out_seq: u64,
    /// Bounded event queue feeding the coordinator's select loop;
    /// producers drop with a log line when it is full.
    pub events: mpsc::Sender<PlanEvent>,
}

/// One placement slot: which shard runs on which verified peer.
#[derive(Clone, Debug)]
pub struct ShardSlot {
    /// Address of the shard's host.
    pub addr: String,
    /// Node id of the shard's host.
    pub node_id: String,
}

/// One local shard bridge registration: the bounded queue feeding the
/// runner and the handle that ends it when the plan dies.
pub struct ShardProc {
    /// Index of this shard inside the plan.
    pub shard_index: u32,
    /// Bounded queue of pipeline frames destined for the runner; the
    /// bridge task drains it and writes frames on the runner socket.
    pub inbound: mpsc::Sender<Vec<u8>>,
    /// Fired when the plan ends so the bridge tears the runner down even
    /// mid-pipeline.
    pub shutdown: oneshot::Sender<()>,
}

/// Registry key for one bridge inside `Ctx::swarm_procs`.
pub fn proc_key(plan_id: &str, shard_index: u32) -> String {
    format!("{plan_id}:{shard_index}")
}

/// Freshness check against the configured announcement windows: the
/// timestamp must not be older than `ann_max_age_secs` nor further in
/// the future than `ann_future_skew_secs`.
pub(crate) fn timestamp_fresh(ctx: &crate::daemon::Ctx, unix_ts: u64) -> bool {
    let now = now_unix();
    now.saturating_sub(unix_ts) <= ctx.config.network.ann_max_age_secs
        && unix_ts.saturating_sub(now) <= ctx.config.network.ann_future_skew_secs
}

/// Admit one pipeline frame number: numbers must strictly increase per
/// source shard, so a replayed or reordered frame is rejected. Each
/// shard emits its frames over one ordered stream, which makes
/// per-source monotonicity the exact correctness condition.
fn accept_seq(seqs: &mut HashMap<u32, u64>, src: u32, seq: u64) -> bool {
    let last = seqs.entry(src).or_insert(0);
    if seq > *last {
        *last = seq;
        true
    } else {
        false
    }
}

/// Handle a signed swarm offer carried by a heartbeat. Verification
/// failures are logged, not propagated: the dispatcher drives this from
/// a match arm expecting no result, and one bad offer must not disturb
/// the connection loop.
pub async fn handle_join(ctx: &Arc<crate::daemon::Ctx>, src: &str, join: Message) {
    if let Err(err) = try_handle_join(ctx, src, join).await {
        eprintln!("[swarm] join handling failed: {err:#}");
    }
}

/// The verified path of `handle_join`: only after signature checks does
/// the offer enter the routing table, keyed by the signer's
/// authenticated node id, so a borrowed announcement cannot smuggle a
/// node into somebody else's plan. The GPU offer travels with the offer
/// and feeds capability-aware placement.
async fn try_handle_join(ctx: &Arc<crate::daemon::Ctx>, src: &str, join: Message) -> Result<()> {
    let Message::SwarmJoin {
        program,
        max_shard_ram_mb,
        cpu_cores,
        gpus,
        unix_ts,
        pubkey,
        signature,
    } = join
    else {
        bail!("not a swarm join");
    };
    let Some(node_id) = verify_swarm_join(
        &program,
        max_shard_ram_mb,
        cpu_cores,
        gpus,
        unix_ts,
        &pubkey,
        &signature,
    ) else {
        ctx.reputation.lock().await.record_invalid(src);
        bail!("bad swarm offer signature");
    };
    if !timestamp_fresh(ctx, unix_ts) {
        bail!("stale swarm offer");
    }
    ctx.dht
        .lock()
        .await
        .apply_swarm(src, &node_id, &program, max_shard_ram_mb, cpu_cores, gpus);
    ctx.reputation.lock().await.record_valid(&node_id);
    Ok(())
}

/// Whether the routing-table entry for `addr` currently carries any
/// swarm offer; used to decide which peers need a leave retraction
/// when consent is revoked. Consent for a specific program is the
/// local gate; retraction delivery only needs "this peer saw an offer
/// from us".
pub async fn peer_offers(ctx: &Arc<crate::daemon::Ctx>, addr: &str) -> bool {
    ctx.dht
        .lock()
        .await
        .all_peers()
        .into_iter()
        .any(|peer| peer.addr == addr && !peer.swarm_program.is_empty())
}

/// Route one pipeline frame. When this node hosts the destination shard
/// the frame goes straight into its bounded runner queue; when this node
/// coordinates the plan but does not host the shard, the frame becomes a
/// coordination event for relay. The per-source sequence guard runs
/// first whenever plan state exists on this node, so a replayed or
/// reordered frame never reaches either delivery path; a frame is
/// delivered through exactly one of the two paths, never both.
pub async fn route_fwd(
    ctx: &Arc<crate::daemon::Ctx>,
    plan_id: &str,
    seq: u64,
    src: u32,
    dst: u32,
    payload: Vec<u8>,
) {
    {
        let mut plans = ctx.swarm_plans.lock().await;
        if let Some(plan) = plans.get_mut(plan_id) {
            if !accept_seq(&mut plan.seqs, src, seq) {
                eprintln!(
                    "[swarm] dropping pipeline frame seq {seq} from shard {src} \
                     for plan {plan_id}: not increasing"
                );
                return;
            }
        }
    }
    let key = proc_key(plan_id, dst);
    let local = ctx
        .swarm_procs
        .lock()
        .await
        .get(&key)
        .map(|proc_| proc_.inbound.clone());
    if let Some(inbound) = local {
        if inbound.try_send(payload).is_err() {
            eprintln!("[swarm] dropping pipeline frame for {key}: runner busy");
        }
        return;
    }
    let plans = ctx.swarm_plans.lock().await;
    if let Some(plan) = plans.get(plan_id) {
        if plan
            .events
            .try_send(PlanEvent::Fwd {
                seq,
                src,
                dst,
                payload,
            })
            .is_err()
        {
            eprintln!("[swarm] dropping pipeline frame for plan {plan_id}: coordinator busy");
        }
    }
}

/// Deliver one coordination event to the coordinator-side queue of
/// `plan_id`. Output events are validated against the plan's own output
/// counter because the output stream restarts its numbering at the last
/// shard, independent of the pipeline streams.
pub async fn deliver_plan_event(ctx: &Arc<crate::daemon::Ctx>, plan_id: &str, event: PlanEvent) {
    let mut plans = ctx.swarm_plans.lock().await;
    if let Some(plan) = plans.get_mut(plan_id) {
        if let PlanEvent::Out { seq, .. } = &event {
            if *seq > plan.out_seq {
                plan.out_seq = *seq;
            } else {
                eprintln!(
                    "[swarm] dropping output frame seq {seq} for plan {plan_id}: not increasing"
                );
                return;
            }
        }
        if plan.events.try_send(event).is_err() {
            eprintln!("[swarm] dropping plan event for {plan_id}: coordinator busy");
        }
    }
}

/// End one plan everywhere it lives locally: drop the coordination
/// state and shut every local shard bridge down so runners never
/// outlive their plan.
pub async fn finish_plan(ctx: &Arc<crate::daemon::Ctx>, plan_id: &str, reason: &str) {
    if ctx.swarm_plans.lock().await.remove(plan_id).is_some() {
        eprintln!("[swarm] plan {plan_id} finished: {reason}");
    }
    let mut procs = ctx.swarm_procs.lock().await;
    let keys: Vec<String> = procs
        .keys()
        .filter(|key| key.starts_with(&format!("{plan_id}:")))
        .cloned()
        .collect();
    for key in keys {
        if let Some(proc_) = procs.remove(&key) {
            let _ = proc_.shutdown.send(());
        }
    }
}

/// Verified swarm candidates for one program with the required GPU
/// capability; the coordinator uses this for capability-aware
/// placement.
pub(crate) async fn gpu_capable_candidates(
    ctx: &Arc<crate::daemon::Ctx>,
    program: &str,
    gpus_needed: u32,
) -> Vec<PeerInfo> {
    ctx.dht
        .lock()
        .await
        .swarm_candidates(program)
        .into_iter()
        .filter(|candidate| candidate.swarm_gpus >= gpus_needed)
        .collect()
}
