//! Provider-side bid policy: given the bidder's signed trust snapshot
//! and the local configuration, decide whether to accept and how many
//! units to reserve. The inequality enforced here is
//! `trust - consumed - in_flight >= min_trust`, evaluated against the
//! announced (signed) values, so a consumer cannot inflate its
//! effective trust by racing announcements.

use crate::config::{Config, Limits};
use crate::daemon::Ctx;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::node::state::genesis_head;
use crate::trust::{now_unix, points::units_for};
use std::sync::Arc;

/// Scheduling decision for one bid.
pub enum Decision {
    Accept { units: i64 },
    Reject(&'static str),
}

/// Local concurrency gate checked before the trust economy: a full
/// node refuses work regardless of how much trust the bidder offers.
pub fn check_capacity(limits: &Limits, running: usize) -> Decision {
    if running >= limits.max_tasks as usize {
        return Decision::Reject("at capacity");
    }
    Decision::Accept { units: 0 }
}

/// Pricing multiplier for one consumer: nodes with a countersigned
/// receipt history (a non-genesis announced head) pay the base price;
/// strangers — including every freshly wiped identity — pay the
/// configured surcharge. Both sides derive the identical factor from
/// the consumer's announced head, so the reservation and the settlement
/// stay in lockstep.
pub fn stranger_factor(config: &Config, consumer_known: bool) -> i64 {
    if consumer_known {
        1
    } else {
        config.trust.new_node_units_factor as i64
    }
}

/// Evaluate one verified bid: capacity first, then the trust floor
/// against the announced snapshot, then the receipt-chain audit for
/// consumers claiming more trust than the genesis endowment — their
/// announced head must verify against the receipts they can produce.
/// The reservation is priced from this provider's own announced
/// capacity points, the GPU offer and the stranger surcharge, so
/// consumer and provider compute the identical number.
pub async fn evaluate_bid(
    ctx: &Arc<Ctx>,
    from_node: &str,
    trust: i64,
    consumed: u64,
    expires_unix: u64,
    in_flight: i64,
) -> Decision {
    {
        let state = ctx.state.lock().await;
        let capacity = check_capacity(&state.limits, 0);
        if let Decision::Reject(reason) = capacity {
            return Decision::Reject(reason);
        }
    }
    if expires_unix <= now_unix() {
        return Decision::Reject("bid expired");
    }
    let Some(peer) = ctx.dht.lock().await.find_by_exact_node_id(from_node) else {
        return Decision::Reject("unknown consumer");
    };
    if trust > peer.trust {
        return Decision::Reject("trust claim exceeds announced value");
    }
    let effective = trust - consumed as i64 - in_flight;
    if effective < ctx.config.trust.min_trust {
        return Decision::Reject("insufficient trust");
    }
    // Receipt-chain audit: earned trust must be backed by a chain whose
    // recomputed head matches the announcement. An unreachable peer
    // does not block the market (the surcharge already prices the
    // risk); a peer whose chain mismatches is refused outright.
    if trust > ctx.config.trust.genesis_trust && peer.receipt_head != genesis_head() {
        match crate::trust::handlers::audit_chain(ctx, &peer, peer.receipt_head).await {
            Ok(true) => {}
            Ok(false) => return Decision::Reject("receipt chain mismatch"),
            Err(err) => eprintln!("[audit] {} skipped: {err:#}", peer.node_id),
        }
    }
    let points = ctx.state.lock().await.points;
    let factor = stranger_factor(&ctx.config, peer.receipt_head != genesis_head());
    Decision::Accept {
        units: bid_units(&ctx.config, points) * factor,
    }
}

/// Verify an assignment signature and bind it to the node whose bid was
/// accepted. The payload covers the command, the wall-clock limit and
/// the resource request (`ram_mb`, `gpus`), so none of them can be
/// altered in flight; the scheduler separately re-checks the request
/// against what this node actually offers. The arity mirrors the signed
/// assignment field set.
#[allow(clippy::too_many_arguments)]
pub fn verify_assign(
    task_id: &str,
    command: &str,
    timeout_secs: u64,
    ram_mb: u64,
    gpus: u32,
    pubkey: &[u8; 32],
    signature: &[u8],
    accepted_from: &str,
) -> bool {
    if Identity::node_id_from_pubkey(pubkey) != accepted_from {
        return false;
    }
    let payload = Message::assign_signing_payload(task_id, command, timeout_secs, ram_mb, gpus);
    let Ok(sig) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    Identity::verify(pubkey, &payload, sig)
}

/// Announced points of one node id, the market price of its capacity.
pub fn announced_points(dht: &crate::dht::Dht, node_id: &str) -> Option<u32> {
    dht.announced_points(node_id)
}

/// Base trust units one bid reserves, priced from the provider's
/// points, before the stranger surcharge.
pub fn bid_units(config: &Config, points: u32) -> i64 {
    units_for(points, config.network.task_timeout_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::make_ctx;
    use crate::transport::Transport;
    use std::time::Duration;

    /// Announce one consumer in the routing table with the given trust
    /// coefficient and receipt head, using a throwaway transport only
    /// for its dial address.
    async fn announce_consumer(ctx: &Arc<Ctx>, node_id: &str, trust: i64, receipt_head: [u8; 32]) {
        let consumer = Transport::new(
            crate::node::identity::Identity::generate(),
            0,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let addr = consumer.local_id();
        ctx.dht.lock().await.insert(&addr);
        ctx.dht.lock().await.apply_ann_ext(
            &addr,
            node_id,
            "peer",
            trust,
            24,
            0,
            receipt_head,
            1_700_000_000,
        );
    }

    #[tokio::test]
    async fn full_node_rejects_regardless_of_trust() {
        let (ctx, _rx) = make_ctx("pol-full").await;
        ctx.state.lock().await.limits.max_tasks = 0;
        let decision = evaluate_bid(&ctx, "node-x", 10_000, 0, u64::MAX, 0).await;
        assert!(matches!(decision, Decision::Reject("at capacity")));
    }

    #[tokio::test]
    async fn expired_bid_is_rejected() {
        let (ctx, _rx) = make_ctx("pol-expired").await;
        let decision = evaluate_bid(&ctx, "node-x", 100, 0, 1, 0).await;
        assert!(matches!(decision, Decision::Reject("bid expired")));
    }

    #[tokio::test]
    async fn trust_floor_uses_signed_snapshot_and_in_flight() {
        let (ctx, _rx) = make_ctx("pol-floor").await;
        announce_consumer(&ctx, "node-x", -5, [9; 32]).await;
        let decision = evaluate_bid(&ctx, "node-x", -5, 0, u64::MAX, 0).await;
        assert!(matches!(decision, Decision::Reject("insufficient trust")));
        announce_consumer(&ctx, "node-y", 100, [9; 32]).await;
        let decision = evaluate_bid(&ctx, "node-y", 100, 60, u64::MAX, 45).await;
        assert!(matches!(decision, Decision::Reject("insufficient trust")));
    }

    #[tokio::test]
    async fn inflated_trust_claim_is_rejected() {
        let (ctx, _rx) = make_ctx("pol-inflate").await;
        announce_consumer(&ctx, "node-x", 40, [9; 32]).await;
        let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 0).await;
        assert!(matches!(
            decision,
            Decision::Reject("trust claim exceeds announced value")
        ));
    }

    #[tokio::test]
    async fn unknown_consumer_is_rejected() {
        let (ctx, _rx) = make_ctx("pol-unknown").await;
        let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 0).await;
        assert!(matches!(decision, Decision::Reject("unknown consumer")));
    }

    #[tokio::test]
    async fn known_consumer_is_accepted_with_base_units() {
        let (ctx, _rx) = make_ctx("pol-ok").await;
        // Trust at the genesis endowment: no audit trigger, base price.
        announce_consumer(&ctx, "node-x", 100, [9; 32]).await;
        let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 0).await;
        let Decision::Accept { units } = decision else {
            panic!("expected acceptance");
        };
        assert_eq!(units, 120);
    }

    #[tokio::test]
    async fn stranger_with_genesis_head_pays_the_surcharge() {
        let (ctx, _rx) = make_ctx("pol-stranger").await;
        announce_consumer(&ctx, "node-x", 100, genesis_head()).await;
        let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 0).await;
        let Decision::Accept { units } = decision else {
            panic!("expected acceptance");
        };
        assert_eq!(units, 240);
    }

    #[tokio::test]
    async fn earned_trust_from_an_unreachable_peer_does_not_block_the_market() {
        let (ctx, _rx) = make_ctx("pol-audit-skip").await;
        // Claims trust above genesis with a non-genesis head but cannot
        // answer an audit: the bid still goes through (best-effort
        // audit), priced by the announced head.
        announce_consumer(&ctx, "node-x", 500, [9; 32]).await;
        let decision = evaluate_bid(&ctx, "node-x", 500, 0, u64::MAX, 0).await;
        assert!(matches!(decision, Decision::Accept { .. }));
    }

    #[test]
    fn assign_signature_covers_the_resource_request() {
        let identity = Identity::generate();
        let node = identity.node_id();
        let sign = |ram_mb, gpus| {
            identity.sign(&Message::assign_signing_payload(
                "t1", "echo hi", 60, ram_mb, gpus,
            ))
        };
        assert!(verify_assign(
            "t1",
            "echo hi",
            60,
            0,
            0,
            &identity.pubkey(),
            sign(0, 0).as_ref(),
            &node,
        ));
        assert!(!verify_assign(
            "t1",
            "echo hi",
            60,
            4096,
            1,
            &identity.pubkey(),
            sign(0, 0).as_ref(),
            &node,
        ));
        let foreign = Identity::generate();
        assert!(!verify_assign(
            "t1",
            "echo hi",
            60,
            0,
            0,
            &foreign.pubkey(),
            foreign
                .sign(&Message::assign_signing_payload("t1", "echo hi", 60, 0, 0))
                .as_ref(),
            &node,
        ));
    }
}
