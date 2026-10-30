//! Swarm mode: consent-gated hosting of one shared program (for example a
//! sharded LLM) across the network.
//!
//! Participation is strictly opt-in per program. A node grants consent
//! with `opennetctl swarm enable <program>`; consenting nodes announce
//! their offer inside the signed heartbeat (`Message::SwarmJoin`); a
//! coordinator collects offers from the routing table, splits the
//! manifest layer space across hosts proportional to offered RAM, and
//! signs one `Message::ShardLaunch` per shard. Receivers re-verify every
//! constraint — signature, freshness, known peer, explicit consent,
//! manifest digest, RAM caps, layer ranges — before any process spawns.
//!
//! Pipeline frames travel as `Message::ShardFwd` between neighbouring
//! shard hosts; the last shard reports completion with
//! `Message::SwarmDone`, which terminates the plan everywhere it runs.
//!
//! Local shard runners talk to their worker over loopback inside the
//! daemon's network namespace; the runner sandbox profile deliberately
//! keeps the host network namespace so that loopback stays reachable.

use crate::dht::PeerInfo;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::trust::handlers::verify_swarm_join;
use crate::trust::now_unix;
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Consent record shared by control, shard and coordinator paths.
pub use crate::swarm::consent::Consent;
/// Launch handler re-exported at the module boundary the dispatcher
/// uses (`swarm::handle_launch`).
pub use crate::swarm::shard::handle_launch;

pub mod consent;
pub mod coordinator;
mod runner;
pub mod shard;

/// Cap on queued pipeline frames per local shard worker; a stalled
/// runner can only buffer this many frames before senders drop with a
/// log line instead of exhausting memory.
pub const SHARD_INBOUND_CAP: usize = 64;

/// One coordination event of a plan, consumed by the coordinator's event
/// loop and produced by inbound network frames.
#[derive(Clone, Debug)]
pub enum PlanEvent {
    /// One shard reported readiness.
    Ready(u32),
    /// A pipeline frame must be relayed to shard `dst`.
    Fwd {
        seq: u64,
        dst: u32,
        payload: Vec<u8>,
    },
    /// A shard delivered output bytes to the coordinator.
    Out { seq: u64, payload: Vec<u8> },
    /// The plan ended, carrying the human-readable reason.
    Done(String),
}

/// Live coordination state for one plan, owned by the coordinator.
pub struct PlanState {
    /// Placement slots in shard order: where each shard runs.
    pub shards: Vec<ShardSlot>,
    /// Shards that have reported readiness so far.
    pub ready: HashSet<u32>,
    /// Event queue feeding the coordinator's select loop.
    pub events: mpsc::UnboundedSender<PlanEvent>,
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
/// node into somebody else's plan.
async fn try_handle_join(ctx: &Arc<crate::daemon::Ctx>, src: &str, join: Message) -> Result<()> {
    let Message::SwarmJoin {
        program,
        max_shard_ram_mb,
        cpu_cores,
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
        .apply_swarm(src, &node_id, &program, max_shard_ram_mb, cpu_cores);
    ctx.reputation.lock().await.record_valid(&node_id);
    Ok(())
}

/// Handle a swarm retraction. Kept synchronous and total: the
/// dispatcher calls it from a match arm without awaiting and expects no
/// result. The routing table is a tokio mutex, which must never be
/// `blocking_lock`-ed from an async context (that panics), so the
/// actual table work runs on a spawned task; failures are logged.
pub fn handle_leave(
    ctx: &Arc<crate::daemon::Ctx>,
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) {
    let Ok(sig) = signature.try_into() as Result<[u8; 64], _> else {
        eprintln!("[swarm] malformed swarm leave signature");
        return;
    };
    if !Identity::verify(pubkey, &Message::leave_signing_payload(unix_ts), &sig) {
        eprintln!("[swarm] bad swarm leave signature");
        return;
    }
    if !timestamp_fresh(ctx, unix_ts) {
        eprintln!("[swarm] stale swarm leave");
        return;
    }
    let node_id = Identity::node_id_from_pubkey(pubkey);
    let dht = ctx.dht.clone();
    tokio::spawn(async move {
        dht.lock().await.clear_swarm_by_node(&node_id);
    });
}

/// Broadcast a signed retraction of this node's offer to every known
/// peer; control calls this when consent is revoked so placement stops
/// immediately instead of waiting for offers to age out.
pub async fn broadcast_leave(ctx: &Arc<crate::daemon::Ctx>) {
    let unix_ts = now_unix();
    let leave = Message::SwarmLeave {
        unix_ts,
        pubkey: ctx.identity.pubkey(),
        signature: ctx
            .identity
            .sign(&Message::leave_signing_payload(unix_ts))
            .to_vec(),
    };
    for peer in ctx.dht.lock().await.all_peers() {
        let _ = crate::daemon::send_msg(ctx, &peer.addr, &leave).await;
    }
}

/// Route one pipeline frame. When this node hosts the destination shard
/// the frame goes straight into its bounded runner queue; when this node
/// coordinates the plan but does not host the shard, the frame becomes a
/// coordination event for relay. A frame is delivered through exactly
/// one of the two paths, never both.
pub async fn route_fwd(
    ctx: &Arc<crate::daemon::Ctx>,
    plan_id: &str,
    seq: u64,
    src: u32,
    dst: u32,
    payload: Vec<u8>,
) {
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
        // The source shard index travels with the event for logging and
        // future protocol extensions; relay re-stamps it on the wire.
        let _ = (src, plan.events.send(PlanEvent::Fwd { seq, dst, payload }));
    }
}

/// Deliver one coordination event to the coordinator-side queue of
/// `plan_id`.
pub async fn deliver_plan_event(ctx: &Arc<crate::daemon::Ctx>, plan_id: &str, event: PlanEvent) {
    let plans = ctx.swarm_plans.lock().await;
    if let Some(plan) = plans.get(plan_id) {
        let _ = plan.events.send(event);
    }
}

/// End one plan on this node: notify the coordinator-side event loop,
/// signal every local runner bridge of the plan (registry keys share
/// the `plan_id:` prefix) and drop the plan state, so a `SwarmDone`
/// arriving anywhere terminates the plan everywhere it runs.
pub async fn finish_plan(ctx: &Arc<crate::daemon::Ctx>, plan_id: &str, reason: &str) {
    let plan = ctx.swarm_plans.lock().await.remove(plan_id);
    if let Some(plan) = plan {
        let _ = plan.events.send(PlanEvent::Done(reason.to_string()));
    }
    let prefix = format!("{plan_id}:");
    let keys: Vec<String> = {
        let procs = ctx.swarm_procs.lock().await;
        procs
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect()
    };
    let mut procs = ctx.swarm_procs.lock().await;
    for key in keys {
        if let Some(proc_) = procs.remove(&key) {
            let _ = proc_.shutdown.send(());
        }
    }
}

/// Whether a peer's routing entry currently offers `program`.
pub fn peer_offers(peer: &PeerInfo, program: &str) -> bool {
    peer.swarm_program == program
}
