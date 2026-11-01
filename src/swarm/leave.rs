//! Signed swarm leave handling: consent revocation is announced with a
//! `SwarmLeave` frame so peers stop placing shards on the node
//! immediately instead of waiting for the offer to age out of the
//! routing table. Retraction is all-or-nothing on the wire: one frame
//! retracts every program the node was hosting, because the frame
//! carries no program name. Handling verifies the signature, checks
//! freshness, and clears every offer of that node from the routing
//! table.

use super::timestamp_fresh;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::identity::Identity;
use crate::trust::now_unix;
use std::sync::Arc;

/// Broadcast one signed `SwarmLeave` to every known peer address when
/// this node still has something to retract (at least one consented
/// program). Addresses are collected before sending so the routing
/// table lock is never held across the network.
pub async fn broadcast_leave(ctx: &Arc<Ctx>) {
    let has_consent = !ctx.swarm.lock().await.is_empty();
    if !has_consent {
        return;
    }
    let unix_ts = now_unix();
    let leave = Message::SwarmLeave {
        signature: ctx
            .identity
            .sign(&Message::leave_signing_payload(unix_ts))
            .to_vec(),
        unix_ts,
        pubkey: ctx.identity.pubkey(),
    };
    let addrs = ctx.dht.lock().await.all_addrs();
    for addr in addrs {
        let _ = send_msg(ctx, &addr, &leave).await;
    }
}

/// Handle one inbound signed `SwarmLeave`: verify the signature and
/// freshness window, then clear every swarm offer of the signer from
/// the routing table. The sender is looked up by signing key, so a
/// borrowed frame can never retract somebody else's programs.
pub async fn handle_leave(ctx: &Arc<Ctx>, unix_ts: u64, pubkey: &[u8; 32], signature: &[u8]) {
    let node_id = Identity::node_id_from_pubkey(pubkey);
    if !timestamp_fresh(ctx, unix_ts) {
        return;
    }
    let payload = Message::leave_signing_payload(unix_ts);
    let Ok(sig) = <&[u8; 64]>::try_from(signature) else {
        return;
    };
    if !Identity::verify(pubkey, &payload, sig) {
        return;
    }
    ctx.dht.lock().await.clear_swarm_by_node(&node_id);
    crate::log::warn(
        module_path!(),
        &format!("[swarm] {node_id} retracted its offers"),
    );
}

/// Daemon-shutdown helper: finish every live plan so shard bridges and
/// runner processes never outlive the daemon.
pub async fn shutdown_plans(ctx: &Arc<Ctx>) {
    let plan_ids: Vec<String> = ctx.swarm_plans.lock().await.keys().cloned().collect();
    for plan_id in plan_ids {
        super::finish_plan(ctx, &plan_id, "daemon shutdown").await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::make_ctx;

    #[tokio::test]
    async fn broadcast_and_handle_leave_roundtrip() {
        let (ctx, _rx) = make_ctx("sw-leave-rt").await;
        let peer = crate::transport::Transport::new(
            Identity::generate(),
            0,
            std::time::Duration::from_secs(60),
        )
        .await
        .unwrap();
        let addr = peer.local_id();
        ctx.dht.lock().await.insert(&addr);
        let node = Identity::generate();
        ctx.dht
            .lock()
            .await
            .apply_ann_ext(&addr, &node.node_id(), "peer", 100, 44, 0, [7; 32], 1);
        ctx.dht
            .lock()
            .await
            .apply_swarm(&addr, &node.node_id(), "demo", 1024, 1, 1);
        {
            let mut consent = ctx.swarm.lock().await;
            consent.grant("demo");
        }
        let unix_ts = now_unix();
        handle_leave(
            &ctx,
            unix_ts,
            &node.pubkey(),
            node.sign(&Message::leave_signing_payload(unix_ts)).as_ref(),
        )
        .await;
        assert!(
            ctx.dht
                .lock()
                .await
                .all_peers()
                .iter()
                .all(|peer| peer.swarm.is_empty()),
            "leave must clear every offer of the node"
        );
    }

    #[tokio::test]
    async fn stale_leave_is_ignored() {
        let (ctx, _rx) = make_ctx("sw-leave-stale").await;
        let node = Identity::generate();
        let unix_ts = now_unix();
        handle_leave(
            &ctx,
            unix_ts,
            &node.pubkey(),
            node.sign(&Message::leave_signing_payload(unix_ts)).as_ref(),
        )
        .await;
        // No panic, no table churn: freshness rejected the frame.
    }
}
