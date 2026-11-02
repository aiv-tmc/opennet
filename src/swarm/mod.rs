//! Swarm mode: consent-gated hosting of shared programs across the
//! LAN, a pipeline protocol between shard runners, and signed
//! placement plans coordinated by the node that starts a run.
//!
//! Consent is explicit and per-program (`opennetctl swarm enable
//! <program>`), artifacts must match their manifest hash before any
//! spawn, and every placement frame is signed by the coordinator's
//! identity key. This module owns the pipeline routing with per-source
//! sequence guards, the plan event admission with sender
//! authorization, checkpoint storage and the plan lifecycle; offers
//! live in `offers`, the shared state types in `state`, and the
//! coordinator, consent, shard launch and runner bridge in the sibling
//! modules.
//!
//! Sender authorization: the unsigned pipeline frames (ShardFwd,
//! ShardReady, ShardOut, ShardCheckpoint, SwarmDone) travel inside
//! authenticated transports, but the connection's validated address is
//! additionally checked against plan membership before any state
//! changes. At the coordinator, a pipeline frame is admitted only from
//! the shard host of its source index or from this node itself (local
//! prompt injection and local relays); readiness, output and
//! checkpoints are admitted only from the shard host the plan placed
//! them on; a done signal is admitted from any member shard host or
//! this node and enters the coordinator loop, which alone decides
//! between failover, completion and abort. At a shard host, pipeline
//! frames and done signals are admitted only from the coordinator that
//! launched the shard, recorded on the bridge registration at launch
//! time. A foreign peer cannot inject frames into, complete, or tear
//! down a plan it does not belong to.

use crate::daemon::Ctx;
use std::sync::Arc;

mod consent;
pub mod coordinator;
pub mod leave;
mod offers;
mod runner;
mod shard;
mod state;

#[cfg(test)]
mod tests;

pub use consent::Consent;
pub use leave::{broadcast_leave, handle_leave};
pub use offers::{announce_offers, handle_join, peer_offers};
pub use shard::handle_launch;
pub use state::{proc_key, PlanEvent, PlanState, ShardProc, ShardSlot};

pub(crate) use offers::gpu_capable_candidates;

use state::accept_seq;

/// Cap on queued pipeline frames per local shard worker; a stalled
/// runner can only buffer this many frames before senders drop with a
/// log line instead of exhausting memory.
pub const SHARD_INBOUND_CAP: usize = 64;

/// Cap on queued coordination events per plan; a coordinator that
/// falls behind (or a flooding peer) can only buffer this many events
/// before senders drop with a log line. Both bounded queues together
/// guarantee no unbounded memory growth anywhere in the pipeline.
pub const PLAN_EVENT_CAP: usize = 256;

/// Runner-bridge frame tag for checkpoint delivery: same `[u32 len]
/// [u8 tag][payload]` codec the pipeline uses, tag 5. Runners restore
/// state from this frame when they receive it and must tolerate it
/// arriving interleaved with the first input frames.
const CHECKPOINT_FRAME_TAG: u8 = 5;

/// Freshness check against the configured announcement windows: the
/// timestamp must not be older than `ann_max_age_secs` nor further in
/// the future than `ann_future_skew_secs`.
pub(crate) fn timestamp_fresh(ctx: &Ctx, unix_ts: u64) -> bool {
    let now = crate::trust::now_unix();
    now.saturating_sub(unix_ts) <= ctx.config.network.ann_max_age_secs
        && unix_ts.saturating_sub(now) <= ctx.config.network.ann_future_skew_secs
}

/// The connection address of the plan's shard `index`, when the index
/// names a live slot.
fn member_addr(plan: &PlanState, index: u32) -> Option<&str> {
    plan.shards
        .get(index as usize)
        .map(|slot| slot.addr.as_str())
}

/// Route one pipeline frame. Two receiving roles exist:
///
/// * Coordinator: local plan state exists; the frame is admitted only
///   when the sender is the shard host of the frame's source index or
///   this node itself. The per-source sequence guard runs before any
///   delivery, so a replayed or reordered frame never reaches the
///   runner queue or the relay events. Delivery is then exactly one
///   of: the local runner queue of the destination shard, or the
///   plan's relay events for a destination hosted elsewhere.
/// * Shard host: no plan state; the frame must come from the
///   coordinator this shard was launched by, and it goes straight into
///   the runner's bounded queue. Ordering on this path is guaranteed
///   by the single coordinator connection, so no sequence state is
///   needed.
///
/// Unknown plans on both roles are dropped with a log line.
pub async fn route_fwd(
    ctx: &Arc<Ctx>,
    sender: &str,
    plan_id: &str,
    seq: u64,
    src_shard: u32,
    dst: u32,
    payload: Vec<u8>,
) {
    let local = ctx.transport.local_id();
    {
        let mut plans = ctx.swarm_plans.lock().await;
        match plans.get_mut(plan_id) {
            Some(plan) => {
                let authorized = sender == local || member_addr(plan, src_shard) == Some(sender);
                if !authorized {
                    crate::log::warn(
                        module_path!(),
                        &format!(
                            "dropping pipeline frame for plan {plan_id}: \
                             {sender} is not the source shard host"
                        ),
                    );
                    return;
                }
                if !accept_seq(&mut plan.seqs, src_shard, seq) {
                    crate::log::warn(
                        module_path!(),
                        &format!(
                            "dropping pipeline frame seq {seq} from shard {src_shard} \
                             for plan {plan_id}: not increasing"
                        ),
                    );
                    return;
                }
            }
            None => {
                drop(plans);
                let key = proc_key(plan_id, dst);
                // The bounded send is a non-blocking try_send, so the
                // registry lock may be held across it; nothing here
                // awaits another swarm lock.
                let procs = ctx.swarm_procs.lock().await;
                let Some(proc) = procs.get(&key) else {
                    crate::log::warn(
                        module_path!(),
                        &format!("dropping pipeline frame for {key}: unknown plan"),
                    );
                    return;
                };
                if proc.coordinator != sender {
                    crate::log::warn(
                        module_path!(),
                        &format!(
                            "dropping pipeline frame for {key}: \
                             {sender} is not the coordinator"
                        ),
                    );
                    return;
                }
                if proc.inbound.try_send(payload).is_err() {
                    crate::log::warn(
                        module_path!(),
                        &format!("dropping pipeline frame for {key}: runner busy"),
                    );
                }
                return;
            }
        }
    }
    let key = proc_key(plan_id, dst);
    let local_proc = ctx
        .swarm_procs
        .lock()
        .await
        .get(&key)
        .map(|proc| proc.inbound.clone());
    if let Some(inbound) = local_proc {
        if inbound.try_send(payload).is_err() {
            crate::log::warn(
                module_path!(),
                &format!("dropping pipeline frame for {key}: runner busy"),
            );
        }
        return;
    }
    let plans = ctx.swarm_plans.lock().await;
    if let Some(plan) = plans.get(plan_id) {
        if plan
            .events
            .try_send(PlanEvent::Fwd {
                seq,
                src: src_shard,
                dst,
                payload,
            })
            .is_err()
        {
            crate::log::warn(
                module_path!(),
                &format!("dropping pipeline frame for plan {plan_id}: coordinator busy"),
            );
        }
    }
}

/// Admit one readiness report: the sender must be the host the plan
/// placed this shard on. Ready shards are recorded in the plan's
/// readiness set — the coordinator's readiness phase counts exactly
/// this set — and the event enters the coordinator queue. A readiness
/// event additionally hands the shard's stored checkpoint to the local
/// runner queue as a bridge frame, so a stateful replacement resumes
/// before new input flows.
pub async fn handle_ready(ctx: &Arc<Ctx>, sender: &str, plan_id: &str, shard_index: u32) {
    let mut plans = ctx.swarm_plans.lock().await;
    let Some(plan) = plans.get_mut(plan_id) else {
        crate::log::warn(
            module_path!(),
            &format!("dropping readiness for plan {plan_id}: unknown plan"),
        );
        return;
    };
    if member_addr(plan, shard_index) != Some(sender) {
        crate::log::warn(
            module_path!(),
            &format!(
                "dropping readiness for plan {plan_id} shard {shard_index}: \
                 {sender} is not the shard host"
            ),
        );
        return;
    }
    plan.ready.insert(shard_index);
    let checkpoint = plan
        .checkpoints
        .get(&shard_index)
        .map(|blob| (shard_index, blob.clone()));
    if plan.events.try_send(PlanEvent::Ready(shard_index)).is_err() {
        crate::log::warn(
            module_path!(),
            &format!("dropping plan event for {plan_id}: coordinator busy"),
        );
        return;
    }
    drop(plans);
    if let Some((index, blob)) = checkpoint {
        deliver_checkpoint_frame(ctx, plan_id, index, blob).await;
    }
}

/// Admit one output frame: only the plan's last shard emits output, so
/// the sender must be that shard's host. The output stream restarts
/// its numbering at the last shard, independent of the pipeline
/// streams, and is validated against the plan's own output counter.
pub async fn handle_out(ctx: &Arc<Ctx>, sender: &str, plan_id: &str, seq: u64, payload: Vec<u8>) {
    let mut plans = ctx.swarm_plans.lock().await;
    let Some(plan) = plans.get_mut(plan_id) else {
        crate::log::warn(
            module_path!(),
            &format!("dropping output for plan {plan_id}: unknown plan"),
        );
        return;
    };
    let last_shard = plan.shards.len().saturating_sub(1) as u32;
    if member_addr(plan, last_shard) != Some(sender) {
        crate::log::warn(
            module_path!(),
            &format!(
                "dropping output for plan {plan_id}: \
                 {sender} is not the last shard host"
            ),
        );
        return;
    }
    if seq <= plan.out_seq {
        crate::log::warn(
            module_path!(),
            &format!("dropping output frame seq {seq} for plan {plan_id}: not increasing"),
        );
        return;
    }
    plan.out_seq = seq;
    if plan
        .events
        .try_send(PlanEvent::Out { seq, payload })
        .is_err()
    {
        crate::log::warn(
            module_path!(),
            &format!("dropping plan event for {plan_id}: coordinator busy"),
        );
    }
}

/// Store one runner checkpoint for one shard of a plan. The sender
/// must be the shard's host; the latest blob per shard wins, and the
/// payload arrived inside the 1 MiB frame cap, so the table stays
/// bounded by the shard count.
pub async fn handle_checkpoint(
    ctx: &Arc<Ctx>,
    sender: &str,
    plan_id: &str,
    shard_index: u32,
    payload: Vec<u8>,
) {
    let mut plans = ctx.swarm_plans.lock().await;
    let Some(plan) = plans.get_mut(plan_id) else {
        return;
    };
    if member_addr(plan, shard_index) != Some(sender) {
        crate::log::warn(
            module_path!(),
            &format!(
                "dropping checkpoint for plan {plan_id} shard {shard_index}: \
                 {sender} is not the shard host"
            ),
        );
        return;
    }
    plan.checkpoints.insert(shard_index, payload);
}

/// Handle one inbound `SwarmDone`, routing by this node's role:
///
/// * Coordinator (local plan state): the sender must be a member shard
///   host or this node; the reason enters the plan's event queue so
///   the coordinator loop sees it — a host-side launch failure
///   (`shard <i> launch failed: ...`) triggers failover onto the
///   spare, the last shard's `"completed"` ends the plan with its
///   output, anything else aborts. The coordinator loop is the only
///   place a coordinated plan is torn down on this node.
/// * Shard host (no plan state, local runner bridges): the sender
///   must be the coordinator that launched the shard; the plan is
///   finished locally, shutting every local runner bridge down.
/// * Neither role: nothing local belongs to the plan, so the frame is
///   ignored.
pub async fn handle_done(ctx: &Arc<Ctx>, sender: &str, plan_id: &str, reason: &str) {
    {
        let plans = ctx.swarm_plans.lock().await;
        if let Some(plan) = plans.get(plan_id) {
            let local = ctx.transport.local_id();
            let member = sender == local || plan.shards.iter().any(|slot| slot.addr == sender);
            if !member {
                crate::log::warn(
                    module_path!(),
                    &format!(
                        "dropping done signal for plan {plan_id}: \
                         {sender} is not a member of the plan"
                    ),
                );
                return;
            }
            if plan
                .events
                .try_send(PlanEvent::Done(reason.to_string()))
                .is_err()
            {
                crate::log::warn(
                    module_path!(),
                    &format!("dropping plan event for {plan_id}: coordinator busy"),
                );
            }
            return;
        }
    }
    let coordinator = {
        let procs = ctx.swarm_procs.lock().await;
        let prefix = format!("{plan_id}:");
        procs
            .iter()
            .find(|(key, _)| key.starts_with(&prefix))
            .map(|(_, proc)| proc.coordinator.clone())
    };
    match coordinator {
        Some(coordinator) if coordinator == sender => {
            finish_plan(ctx, plan_id, reason).await;
        }
        Some(_) => {
            crate::log::warn(
                module_path!(),
                &format!(
                    "dropping done signal for plan {plan_id}: \
                     {sender} is not the coordinator"
                ),
            );
        }
        None => {}
    }
}

/// Deliver one checkpoint blob to the local runner bridge of one
/// shard, framed with the runner-bridge codec (`[u32 len][u8 tag]
/// [payload]`, checkpoint tag).
async fn deliver_checkpoint_frame(ctx: &Arc<Ctx>, plan_id: &str, shard_index: u32, blob: Vec<u8>) {
    let mut frame = Vec::with_capacity(blob.len() + 5);
    frame.extend_from_slice(&((blob.len() as u32 + 1).to_be_bytes()));
    frame.push(CHECKPOINT_FRAME_TAG);
    frame.extend_from_slice(&blob);
    let key = proc_key(plan_id, shard_index);
    let inbound = ctx
        .swarm_procs
        .lock()
        .await
        .get(&key)
        .map(|proc| proc.inbound.clone());
    if let Some(inbound) = inbound {
        if inbound.try_send(frame).is_err() {
            crate::log::warn(
                module_path!(),
                &format!("dropping checkpoint for {key}: runner busy"),
            );
        }
    }
}

/// End one plan everywhere it lives locally: drop the coordination
/// state and shut every local shard bridge down so runners never
/// outlive their plan.
pub async fn finish_plan(ctx: &Arc<Ctx>, plan_id: &str, reason: &str) {
    if ctx.swarm_plans.lock().await.remove(plan_id).is_some() {
        crate::log::warn(
            module_path!(),
            &format!("plan {plan_id} finished: {reason}"),
        );
    }
    let mut procs = ctx.swarm_procs.lock().await;
    let keys: Vec<String> = procs
        .keys()
        .filter(|key| key.starts_with(&format!("{plan_id}:")))
        .cloned()
        .collect();
    for key in keys {
        if let Some(proc) = procs.remove(&key) {
            let _ = proc.shutdown.send(());
        }
    }
}
