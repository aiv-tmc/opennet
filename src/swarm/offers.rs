//! Swarm offer handling: consent-gated hosting offers carried by
//! signed `SwarmJoin` frames — verification, routing-table
//! registration, (re)announcement after a grant, and the routing-table
//! queries placement and revocation rely on.
//!
//! An offer enters the routing table only after its signature
//! verifies, keyed by the signer's authenticated node id, so a borrowed
//! announcement cannot smuggle a node into somebody else's plan. The
//! GPU offer travels with the offer and feeds capability-aware
//! placement.

use crate::dht::PeerInfo;
use crate::message::Message;
use crate::trust::handlers::verify_swarm_join;
use crate::trust::now_unix;
use anyhow::{bail, Result};
use std::sync::Arc;

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
/// authenticated node id. Stale offers are dropped.
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
    if !crate::swarm::timestamp_fresh(ctx, unix_ts) {
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
    let offers: Vec<(String, crate::swarm::consent::ProgramConsent)> = {
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
