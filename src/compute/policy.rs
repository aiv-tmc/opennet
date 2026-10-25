//! Trust consumption policy enforced by providers before a bid is accepted.
//!
//! The policy compares the consumer's signed trust claim against the last
//! verified announcement, keeping the market fair: consuming compute drains
//! the trust coefficient and only donating compute refills it. The claimed
//! trust is already net of the consumer's own reservation, so no further
//! arithmetic is applied to it here.

use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use std::sync::Arc;

/// Enforce the trust consumption policy for one bid.
///
/// The claimed trust must not exceed the last announced value (a higher
/// claim proves forged arithmetic and costs reputation), and it must stay
/// at or above the configured floor. Violations are rejected with an
/// explanation sent to the consumer's connection address.
pub async fn policy_allows(ctx: &Arc<Ctx>, from_node: &str, from_addr: &str, trust: i64) -> bool {
    let announced = ctx
        .dht
        .lock()
        .await
        .find_by_node_id(from_node)
        .map(|peer| peer.trust);
    let Some(announced) = announced else {
        reject(ctx, from_addr, "", "identity not announced yet").await;
        return false;
    };
    if trust > announced {
        // The bid is authentically signed, so the node itself overstated
        // its trust: deliberate fraud, penalized in the reputation table.
        ctx.reputation.lock().await.record_invalid(from_node);
        reject(ctx, from_addr, "", "claimed trust exceeds announced trust").await;
        return false;
    }
    if trust < ctx.config.trust.min_trust {
        reject(ctx, from_addr, "", "insufficient trust coefficient").await;
        return false;
    }
    true
}

/// Refuse one bid with a human-readable reason.
pub async fn reject(ctx: &Arc<Ctx>, addr: &str, task_id: &str, reason: &str) {
    let _ = send_msg(
        ctx,
        addr,
        &Message::TaskReject {
            task_id: task_id.to_string(),
            reason: reason.to_string(),
        },
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::identity::Identity;
    use crate::testutil::make_ctx;
    use crate::trust::now_unix;

    /// Register a fake verified peer with the given trust and return its
    /// node id.
    async fn seed_peer(ctx: &Arc<Ctx>, trust: i64) -> String {
        let node = Identity::node_id_from_pubkey(&[9u8; 32]);
        let addr = format!("tcp:10.9.9.9:{}", rand::random::<u16>());
        ctx.dht.lock().await.insert(&addr);
        ctx.dht
            .lock()
            .await
            .apply_ann(&addr, &node, "peer", trust, 2, now_unix());
        node
    }

    #[tokio::test]
    async fn unknown_identity_is_rejected() {
        let (ctx, _rx) = make_ctx("pol-unknown").await;
        let allowed = policy_allows(&ctx, "stranger", "tcp:127.0.0.1:9", 50).await;
        assert!(!allowed);
    }

    #[tokio::test]
    async fn inflated_claim_costs_reputation() {
        let (ctx, _rx) = make_ctx("pol-fraud").await;
        let node = seed_peer(&ctx, 50).await;
        let allowed = policy_allows(&ctx, &node, "tcp:127.0.0.1:9", 60).await;
        assert!(!allowed);
        let reputation = ctx.reputation.lock().await;
        let entry = reputation.all().into_iter().find(|(k, _)| k == &node);
        assert_eq!(entry.expect("fraud not recorded").1.invalid_msgs, 1);
    }

    #[tokio::test]
    async fn claim_below_floor_is_rejected() {
        let (ctx, _rx) = make_ctx("pol-floor").await;
        let node = seed_peer(&ctx, 100).await;
        // A consumer that spent itself into the negative must serve the
        // network before it can consume again.
        let allowed = policy_allows(&ctx, &node, "tcp:127.0.0.1:9", -5).await;
        assert!(!allowed);
    }

    #[tokio::test]
    async fn honest_bid_within_floor_is_accepted() {
        let (ctx, _rx) = make_ctx("pol-honest").await;
        let node = seed_peer(&ctx, 100).await;
        // Claimed trust is already net of the reservation (90 after
        // reserving a 10-unit task out of 100).
        let allowed = policy_allows(&ctx, &node, "tcp:127.0.0.1:9", 90).await;
        assert!(allowed);
    }
}
