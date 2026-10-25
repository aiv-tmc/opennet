//! Tests for the control socket command dispatch.

use super::dispatch;
use crate::node::state::Mode;
use crate::testutil::make_ctx;
use crate::trust::now_unix;

#[tokio::test]
async fn status_reports_trust_and_counters() {
    let (ctx, _rx) = make_ctx("ctl-status").await;
    ctx.state.lock().await.trust = 77;
    let out = dispatch(&ctx, "status").await;
    assert!(out.contains("trust: 77"), "unexpected output: {out}");
    assert!(out.contains("peers: 0"), "unexpected output: {out}");
    assert!(out.contains("consumed: 0"), "unexpected output: {out}");
}

#[tokio::test]
async fn mode_get_set_and_persist() {
    let (ctx, _rx) = make_ctx("ctl-mode").await;
    assert!(dispatch(&ctx, "mode").await.contains("peer"));
    let out = dispatch(&ctx, "mode seed").await;
    assert!(out.contains("mode set to seed"), "unexpected output: {out}");
    assert_eq!(ctx.state.lock().await.mode, Mode::Seed);
    let out = dispatch(&ctx, "mode bogus").await;
    assert!(out.contains("unknown mode"), "unexpected output: {out}");
}

#[tokio::test]
async fn peers_lists_announcement_fields() {
    let (ctx, _rx) = make_ctx("ctl-peers").await;
    assert_eq!(dispatch(&ctx, "peers").await, "no peers known\n");
    let addr = "tcp:10.3.3.3:6000";
    ctx.dht.lock().await.insert(addr);
    ctx.dht
        .lock()
        .await
        .apply_ann(addr, "cc55dd66", "seed", 88, 4, now_unix());
    let out = dispatch(&ctx, "peers").await;
    assert!(out.contains("cc55dd66"), "unexpected output: {out}");
    assert!(out.contains("seed"), "unexpected output: {out}");
    assert!(out.contains("88"), "unexpected output: {out}");
    assert!(out.contains("4"), "unexpected output: {out}");
}

#[tokio::test]
async fn limits_and_trust_report_pricing() {
    let (ctx, _rx) = make_ctx("ctl-limits").await;
    let out = dispatch(&ctx, "limits").await;
    assert!(out.contains("points"), "unexpected output: {out}");
    assert!(out.contains("genesis=100"), "unexpected output: {out}");
    let out = dispatch(&ctx, "trust").await;
    assert!(out.contains("trust: 100"), "unexpected output: {out}");
    assert!(out.contains("consumed: 0"), "unexpected output: {out}");
}

#[tokio::test]
async fn compute_requires_a_command() {
    let (ctx, _rx) = make_ctx("ctl-compute").await;
    let out = dispatch(&ctx, "compute -").await;
    assert!(out.contains("usage"), "unexpected output: {out}");
}

#[tokio::test]
async fn reputation_shows_recorded_entries() {
    let (ctx, _rx) = make_ctx("ctl-rep").await;
    assert_eq!(
        dispatch(&ctx, "reputation").await,
        "no reputation data recorded\n"
    );
    ctx.reputation.lock().await.record_valid("node-a");
    ctx.reputation.lock().await.record_invalid("node-b");
    let out = dispatch(&ctx, "reputation").await;
    assert!(out.contains("node-a"), "unexpected output: {out}");
    assert!(out.contains("node-b"), "unexpected output: {out}");
}

#[tokio::test]
async fn shutdown_help_and_unknown_commands() {
    let (ctx, _rx) = make_ctx("ctl-misc").await;
    assert_eq!(dispatch(&ctx, "shutdown").await, "shutting down\n");
    let out = dispatch(&ctx, "help").await;
    assert!(out.contains("compute"), "unexpected output: {out}");
    assert!(out.contains("shutdown"), "unexpected output: {out}");
    let out = dispatch(&ctx, "bogus").await;
    assert!(out.contains("commands:"), "unexpected output: {out}");
}
