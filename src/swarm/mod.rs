//! Swarm mode: consent-gated hosting of one shared program across the
//! LAN, a pipeline protocol between shard runners, and signed
//! placement plans coordinated by the node that starts a run.
//!
//! Consent is explicit and per-program (`opennetctl swarm enable
//! <program>`), artifacts must match their manifest hash before any
//! spawn, and every placement frame is signed by the coordinator's
//! identity key. This module owns offer handling, pipeline routing
//! with per-source sequence guards, checkpoint storage and the plan
//! lifecycle; the shared state types live in `state.rs`, and the
//! coordinator, consent, shard launch and runner bridge live in the
//! sibling modules.

use crate::dht::PeerInfo;
use crate::message::Message;
use crate::trust::handlers::verify_swarm_join;
use crate::trust::now_unix;
use anyhow::{bail, Result};
use std::sync::Arc;

mod consent;
pub mod coordinator;
pub mod leave;
mod runner;
mod shard;
mod state;

#[cfg(test)]
mod tests;

pub use consent::Consent;
pub use leave::{broadcast_leave, handle_leave};
pub use shard::handle_launch;
pub use state::{proc_key, PlanEvent, PlanState, ShardProc, ShardSlot};

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
pub(crate) fn timestamp_fresh(ctx: &crate::daemon::Ctx, unix_ts: u64) -> bool {
    let now = now_unix();
    now.saturating_sub(unix_ts) <= ctx.config.network.ann_max_age_secs
        && unix_ts.saturating_sub(now) <= ctx.config.network.ann_future_skew_secs
}

/// Handle a signed swarm offer carried by a heartbeat. Verification
/// failures are logged, not propagated: the dispatcher drives this from
/// a match arm expecting no result, and one bad offer must not disturb
/// the connection loop.
pub async fn handle_join(ctx: &Arc<crate::daemon::Ctx>, src: &str, join: Message) {
    if let Err(err) = try_handle_join(ctx, src, join).await {
        crate::log::warn(module_path!(), &format!("join handling failed: {err:#}"));
    }
}

/// The verified path of `handle_join`: only after signature checks does
/// the offer enter the routing table, keyed by the signer's
/// authenticated node id, so a borrowed announcement cannot smuggle a
/// node into somebody else's plan. The GPU offer travels with the
/// offer and feeds capability-aware placement.
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

/// Publish every consented program's offer: record each one in the
/// local routing table so local placement sees the node, and
/// broadcast one signed `SwarmJoin` per program to every known peer so
/// remote coordinators learn the offer too. Called right after a
/// grant; a full revocation retracts everything via
/// `leave::broadcast_leave` instead, which is the wire-level
/// all-or-nothing signal.
pub async fn announce_offers(ctx: &Arc<crate::daemon::Ctx>) {
    let gpus_offered = ctx.config.gpu.count;
    let offers: Vec<(String, consent::ProgramConsent)> = {
        let consent = ctx.swarm.lock().await;
        consent
            .programs
            .iter()
            .map(|(name, limits)| (name.clone(), *limits))
            .collect()
    };
    let peers: Vec<String> = ctx.dht.lock().await.all_addrs();
    let local = ctx.transport.local_id();
    for (program, limits) in offers {
        let unix_ts = now_unix();
        let join = Message::SwarmJoin {
            program: program.clone(),
            max_shard_ram_mb: limits.max_shard_ram_mb,
            cpu_cores: limits.max_shard_cpu_percent,
            gpus: gpus_offered,
            unix_ts,
            pubkey: ctx.identity.pubkey(),
            signature: ctx
                .identity
                .sign(&Message::swarm_signing_payload(
                    &program,
                    limits.max_shard_ram_mb,
                    limits.max_shard_cpu_percent,
                    gpus_offered,
                    unix_ts,
                ))
                .to_vec(),
        };
        ctx.dht.lock().await.apply_swarm(
            &local,
            &ctx.identity.node_id(),
            &program,
            limits.max_shard_ram_mb,
            limits.max_shard_cpu_percent,
            gpus_offered,
        );
        for addr in &peers {
            if *addr != local {
                let _ = crate::daemon::send_msg(ctx, addr, &join).await;
            }
        }
    }
}

/// Whether the routing-table entry for `addr` currently carries any
/// swarm offer; used to decide which peers need a leave retraction
/// when consent is revoked.
pub async fn peer_offers(ctx: &Arc<crate::daemon::Ctx>, addr: &str) -> bool {
    ctx.dht
        .lock()
        .await
        .all_peers()
        .into_iter()
        .any(|peer| peer.addr == addr && !peer.swarm.is_empty())
}

/// Store one runner checkpoint for one shard of a plan. The latest
/// blob per shard wins; the payload arrived inside the 1 MiB frame
/// cap, so the table stays bounded by the shard count.
pub async fn handle_checkpoint(
    ctx: &Arc<crate::daemon::Ctx>,
    plan_id: &str,
    shard_index: u32,
    payload: Vec<u8>,
) {
    let mut plans = ctx.swarm_plans.lock().await;
    if let Some(plan) = plans.get_mut(plan_id) {
        plan.checkpoints.insert(shard_index, payload);
    }
}

/// Route one pipeline frame. When this node hosts the destination
/// shard the frame goes straight into its bounded runner queue; when
/// this node coordinates the plan but does not host the shard, the
/// frame becomes a coordination event for relay. The per-source
/// sequence guard runs first whenever plan state exists on this node,
/// so a replayed or reordered frame never reaches either delivery
/// path; a frame is delivered through exactly one of the two paths,
/// never both.
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
                crate::log::warn(
                    module_path!(),
                    &format!(
                        "dropping pipeline frame seq {seq} from shard {src} \
                         for plan {plan_id}: not increasing"
                    ),
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
                src,
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

/// Deliver one coordination event to the coordinator-side queue of
/// `plan_id`. Output events are validated against the plan's own
/// output counter because the output stream restarts its numbering at
/// the last shard, independent of the pipeline streams. A readiness
/// event additionally hands the shard's stored checkpoint — after a
/// spare relaunch — to the local runner queue as a bridge frame, so a
/// stateful replacement resumes before new input flows.
pub async fn deliver_plan_event(ctx: &Arc<crate::daemon::Ctx>, plan_id: &str, event: PlanEvent) {
    let mut plans = ctx.swarm_plans.lock().await;
    let Some(plan) = plans.get_mut(plan_id) else {
        return;
    };
    if let PlanEvent::Out { seq, .. } = &event {
        if *seq > plan.out_seq {
            plan.out_seq = *seq;
        } else {
            crate::log::warn(
                module_path!(),
                &format!("dropping output frame seq {seq} for plan {plan_id}: not increasing"),
            );
            return;
        }
    }
    let checkpoint = match &event {
        PlanEvent::Ready(shard_index) => plan
            .checkpoints
            .get(shard_index)
            .map(|blob| (*shard_index, blob.clone())),
        _ => None,
    };
    if plan.events.try_send(event).is_err() {
        crate::log::warn(
            module_path!(),
            &format!("dropping plan event for {plan_id}: coordinator busy"),
        );
        return;
    }
    drop(plans);
    if let Some((shard_index, blob)) = checkpoint {
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
            .map(|proc_| proc_.inbound.clone());
        if let Some(inbound) = inbound {
            if inbound.try_send(frame).is_err() {
                crate::log::warn(
                    module_path!(),
                    &format!("dropping checkpoint for {key}: runner busy"),
                );
            }
        }
    }
}

/// End one plan everywhere it lives locally: drop the coordination
/// state and shut every local shard bridge down so runners never
/// outlive their plan.
pub async fn finish_plan(ctx: &Arc<crate::daemon::Ctx>, plan_id: &str, reason: &str) {
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
        .filter(|candidate| {
            candidate
                .swarm
                .get(program)
                .is_some_and(|offer| offer.gpus >= gpus_needed)
        })
        .collect()
}
