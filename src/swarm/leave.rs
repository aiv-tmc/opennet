//! Swarm leave handling: announcing a signed retraction when consent is
//! revoked and processing retractions from peers.
//!
//! A leave is signed by the revoking node and timestamped; peers that
//! accept it immediately clear the retracted offer from their routing
//! tables, so placement stops at once instead of waiting for the offer
//! to age out of the candidate list. Retractions also run at daemon
//! shutdown, so a stopping node never leaves a stale offer behind.

use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::identity::Identity;
use crate::swarm::{self, timestamp_fresh};
use crate::trust::now_unix;
use std::sync::Arc;

/// Announce a signed leave to every peer that currently carries our
/// offer. Best effort: peers that miss the retraction drop the offer
/// when it ages out of their routing tables anyway.
pub async fn broadcast_leave(ctx: &Arc<Ctx>) {
    let (enabled, program) = {
        let consent = ctx.swarm.lock().await;
        (consent.enabled, consent.program.clone())
    };
    if !enabled || program.is_empty() {
        return;
    }
    let unix_ts = now_unix();
    let leave = Message::SwarmLeave {
        unix_ts,
        pubkey: ctx.identity.pubkey(),
        signature: ctx
            .identity
            .sign(&Message::leave_signing_payload(unix_ts))
            .to_vec(),
    };
    let addrs: Vec<String> = ctx
        .dht
        .lock()
        .await
        .all_peers()
        .into_iter()
        .map(|peer| peer.addr)
        .collect();
    for addr in addrs {
        if swarm::peer_offers(ctx, &addr).await {
            let _ = send_msg(ctx, &addr, &leave).await;
        }
    }
}

/// Process one inbound signed leave: verify the signature, check
/// freshness and clear the retracted offer from the routing table.
pub async fn handle_leave(ctx: &Arc<Ctx>, unix_ts: u64, pubkey: &[u8; 32], signature: &[u8]) {
    let payload = Message::leave_signing_payload(unix_ts);
    let Ok(sig) = <&[u8; 64]>::try_from(signature) else {
        return;
    };
    if !Identity::verify(pubkey, &payload, sig) {
        return;
    }
    if !timestamp_fresh(ctx, unix_ts) {
        return;
    }
    let node = Identity::node_id_from_pubkey(pubkey);
    ctx.dht.lock().await.clear_swarm_by_node(&node);
}

/// Tear every live plan down at daemon shutdown: finish local state and
/// tell every shard host to drop its runners.
pub async fn shutdown_plans(ctx: &Arc<Ctx>) {
    let plans: Vec<(String, Vec<swarm::ShardSlot>)> = ctx
        .swarm_plans
        .lock()
        .await
        .iter()
        .map(|(plan_id, plan)| (plan_id.clone(), plan.shards.clone()))
        .collect();
    for (plan_id, slots) in plans {
        swarm::finish_plan(ctx, &plan_id, "daemon shutting down").await;
        let local = ctx.transport.local_id();
        for slot in slots {
            if slot.addr != local {
                let _ = send_msg(
                    ctx,
                    &slot.addr,
                    &Message::SwarmDone {
                        plan_id: plan_id.clone(),
                        reason: "daemon shutting down".to_string(),
                    },
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swarm::{handle_join, peer_offers};
    use crate::testutil::make_ctx;

    #[tokio::test]
    async fn a_valid_leave_retracts_the_offer() {
        let (ctx, _rx) = make_ctx("leave-ok").await;
        ctx.dht.lock().await.insert(&ctx.transport.local_id());
        let unix_ts = now_unix();
        let payload = Message::swarm_signing_payload("demo", 1024, 1, 1, unix_ts);
        let join = Message::SwarmJoin {
            program: "demo".into(),
            max_shard_ram_mb: 1024,
            cpu_cores: 1,
            gpus: 1,
            unix_ts,
            pubkey: ctx.identity.pubkey(),
            signature: ctx.identity.sign(&payload).to_vec(),
        };
        handle_join(&ctx, &ctx.transport.local_id(), join).await;
        assert_eq!(ctx.dht.lock().await.swarm_candidates("demo").len(), 1);
        assert!(peer_offers(&ctx, &ctx.transport.local_id()).await);
        let leave_sig = ctx.identity.sign(&Message::leave_signing_payload(unix_ts));
        handle_leave(&ctx, unix_ts, &ctx.identity.pubkey(), leave_sig.as_slice()).await;
        assert!(ctx.dht.lock().await.swarm_candidates("demo").is_empty());
    }

    #[tokio::test]
    async fn a_forged_leave_is_ignored() {
        let (ctx, _rx) = make_ctx("leave-forged").await;
        ctx.dht.lock().await.insert(&ctx.transport.local_id());
        let unix_ts = now_unix();
        let payload = Message::swarm_signing_payload("demo", 1024, 1, 0, unix_ts);
        let join = Message::SwarmJoin {
            program: "demo".into(),
            max_shard_ram_mb: 1024,
            cpu_cores: 1,
            gpus: 0,
            unix_ts,
            pubkey: ctx.identity.pubkey(),
            signature: ctx.identity.sign(&payload).to_vec(),
        };
        handle_join(&ctx, &ctx.transport.local_id(), join).await;
        let foreign = Identity::generate();
        let foreign_leave = foreign.sign(&Message::leave_signing_payload(unix_ts));
        handle_leave(&ctx, unix_ts, &foreign.pubkey(), foreign_leave.as_slice()).await;
        assert_eq!(ctx.dht.lock().await.swarm_candidates("demo").len(), 1);
    }
}
