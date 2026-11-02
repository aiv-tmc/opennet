//! Bid-policy tests: capacity gating, the signed-snapshot trust floor,
//! audit-triggered refusals, surcharge pricing and assignment
//! signature binding.

use super::*;
use crate::node::state::genesis_head;
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
    let decision = evaluate_bid(&ctx, "node-x", 10_000, 0, u64::MAX, 0, 0).await;
    assert!(matches!(decision, Decision::Reject("at capacity")));
}

#[tokio::test]
async fn running_tasks_count_against_capacity() {
    let (ctx, _rx) = make_ctx("pol-capacity").await;
    ctx.state.lock().await.limits.max_tasks = 2;
    announce_consumer(&ctx, "node-x", 10_000, [9; 32]).await;
    // Both slots busy: refused even though the limits look generous
    // and the bidder can pay.
    let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 2, 0).await;
    assert!(matches!(decision, Decision::Reject("at capacity")));
    // One slot free: accepted at the same price.
    let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 1, 0).await;
    assert!(matches!(decision, Decision::Accept { .. }));
}

#[tokio::test]
async fn expired_bid_is_rejected() {
    let (ctx, _rx) = make_ctx("pol-expired").await;
    let decision = evaluate_bid(&ctx, "node-x", 100, 0, 1, 0, 0).await;
    assert!(matches!(decision, Decision::Reject("bid expired")));
}

#[tokio::test]
async fn trust_floor_uses_signed_snapshot_and_in_flight() {
    let (ctx, _rx) = make_ctx("pol-floor").await;
    announce_consumer(&ctx, "node-x", -5, [9; 32]).await;
    let decision = evaluate_bid(&ctx, "node-x", -5, 0, u64::MAX, 0, 0).await;
    assert!(matches!(decision, Decision::Reject("insufficient trust")));
    announce_consumer(&ctx, "node-y", 100, [9; 32]).await;
    let decision = evaluate_bid(&ctx, "node-y", 100, 60, u64::MAX, 0, 45).await;
    assert!(matches!(decision, Decision::Reject("insufficient trust")));
}

#[tokio::test]
async fn inflated_trust_claim_is_rejected() {
    let (ctx, _rx) = make_ctx("pol-inflate").await;
    announce_consumer(&ctx, "node-x", 40, [9; 32]).await;
    let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 0, 0).await;
    assert!(matches!(
        decision,
        Decision::Reject("trust claim exceeds announced value")
    ));
}

#[tokio::test]
async fn unknown_consumer_is_rejected() {
    let (ctx, _rx) = make_ctx("pol-unknown").await;
    let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 0, 0).await;
    assert!(matches!(decision, Decision::Reject("unknown consumer")));
}

#[tokio::test]
async fn known_consumer_is_accepted_with_base_units() {
    let (ctx, _rx) = make_ctx("pol-ok").await;
    // Trust at the genesis endowment: no audit trigger, base price.
    announce_consumer(&ctx, "node-x", 100, [9; 32]).await;
    let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 0, 0).await;
    let Decision::Accept { units } = decision else {
        panic!("expected acceptance");
    };
    assert_eq!(units, 120);
}

#[tokio::test]
async fn stranger_with_genesis_head_pays_the_surcharge() {
    let (ctx, _rx) = make_ctx("pol-stranger").await;
    announce_consumer(&ctx, "node-x", 100, genesis_head()).await;
    let decision = evaluate_bid(&ctx, "node-x", 100, 0, u64::MAX, 0, 0).await;
    let Decision::Accept { units } = decision else {
        panic!("expected acceptance");
    };
    assert_eq!(units, 240);
}

#[tokio::test]
async fn earned_trust_from_an_unreachable_peer_is_refused() {
    let (ctx, _rx) = make_ctx("pol-audit-refuse").await;
    // Claims trust above genesis with a non-genesis head but cannot
    // answer an audit: the bid is refused, so unverifiable trust
    // claims cannot trade at face value.
    announce_consumer(&ctx, "node-x", 500, [9; 32]).await;
    let decision = evaluate_bid(&ctx, "node-x", 500, 0, u64::MAX, 0, 0).await;
    assert!(matches!(
        decision,
        Decision::Reject("receipt chain audit unavailable")
    ));
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
