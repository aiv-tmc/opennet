//! Consumer-side market tests: mode gating, peer selection errors and
//! redundant-verification floor. Each case builds an isolated context
//! and never touches real system paths.

use super::compute;
use crate::node::identity::Identity;
use crate::node::state::Mode;
use crate::testutil::make_ctx;

#[tokio::test]
async fn seed_mode_cannot_request_tasks() {
    let (ctx, _rx) = make_ctx("cl-seed").await;
    ctx.state.lock().await.mode = Mode::Seed;
    let out = compute(&ctx, None, "echo hi".into(), 60, 0, 0, 1).await;
    assert!(
        out.contains("seed mode donates capacity only"),
        "unexpected output: {out}"
    );
}

#[tokio::test]
async fn unknown_peer_prefix_is_an_error() {
    let (ctx, _rx) = make_ctx("cl-unknown").await;
    let out = compute(&ctx, Some("nope"), "echo hi".into(), 60, 0, 0, 1).await;
    assert!(
        out.contains("no suitable peer known"),
        "unexpected output: {out}"
    );
}

#[tokio::test]
async fn unannounced_points_is_an_error() {
    let (ctx, _rx) = make_ctx("cl-no-points").await;
    let peer = Identity::generate();
    let addr = "tcp:127.0.0.1:7001";
    ctx.dht.lock().await.insert(addr);
    ctx.dht
        .lock()
        .await
        .apply_ann_ext(addr, &peer.node_id(), "peer", 100, 0, 0, [0; 32], 1);
    let out = compute(&ctx, Some(&peer.node_id()), "echo hi".into(), 60, 0, 0, 1).await;
    assert!(
        out.contains("has not announced its capacity points"),
        "unexpected output: {out}"
    );
}

#[tokio::test]
async fn gpu_request_above_offer_is_an_error() {
    let (ctx, _rx) = make_ctx("cl-gpu-floor").await;
    let peer = Identity::generate();
    let addr = "tcp:127.0.0.1:7002";
    ctx.dht.lock().await.insert(addr);
    ctx.dht
        .lock()
        .await
        .apply_ann_ext(addr, &peer.node_id(), "peer", 100, 44, 1, [0; 32], 1);
    let out = compute(&ctx, Some(&peer.node_id()), "echo hi".into(), 60, 0, 2, 1).await;
    assert!(
        out.contains("offers 1 GPU(s), 2 requested"),
        "unexpected output: {out}"
    );
}

#[tokio::test]
async fn verify_requires_enough_distinct_peers() {
    let (ctx, _rx) = make_ctx("cl-verify-count").await;
    let out = compute(&ctx, None, "echo hi".into(), 60, 0, 0, 3).await;
    assert!(
        out.contains("redundant verification needs 3 distinct peers"),
        "unexpected output: {out}"
    );
}
