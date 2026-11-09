//! Control surface tests: command dispatch, output formats, and the
//! compute command-line parsing including the resource options.

use super::dispatch::dispatch;
use crate::node::state::Mode;
use crate::testutil::make_ctx;
use crate::transport::Transport;
use std::time::Duration;

#[tokio::test]
async fn status_reports_identity_mode_and_counters() {
    let (ctx, _rx) = make_ctx("ctl-status").await;
    let out = dispatch(&ctx, "status").await;
    assert!(out.contains(&ctx.identity.node_id()));
    assert!(out.contains("mode: peer"));
    assert!(out.contains("trust: 100"));
}

#[tokio::test]
async fn mode_persists_across_reloads() {
    let (ctx, _rx) = make_ctx("ctl-mode").await;
    let out = dispatch(&ctx, "mode seed").await;
    assert!(out.contains("mode set to seed"));
    let out = dispatch(&ctx, "mode").await;
    assert!(out.contains("mode: seed"));
    let reloaded = crate::node::state::NodeState::load(
        &ctx.config.paths.state_dir,
        Mode::Peer,
        ctx.config.limits.clone(),
        &ctx.config.trust,
    )
    .unwrap();
    assert_eq!(reloaded.mode, Mode::Seed);
}

#[tokio::test]
async fn unknown_mode_is_an_error() {
    let (ctx, _rx) = make_ctx("ctl-bad-mode").await;
    let out = dispatch(&ctx, "mode bogus").await;
    assert!(out.contains("unknown mode"));
    assert_eq!(ctx.state.lock().await.mode, Mode::Peer);
}

#[tokio::test]
async fn peers_empty_reports_none() {
    let (ctx, _rx) = make_ctx("ctl-peers-empty").await;
    let out = dispatch(&ctx, "peers").await;
    assert_eq!(out, "no peers known\n");
}

#[tokio::test]
async fn limits_report_cpu_ram_and_gpu_pricing() {
    let (ctx, _rx) = make_ctx("ctl-limits").await;
    let out = dispatch(&ctx, "limits").await;
    assert!(out.contains("cpu_percent=50"));
    assert!(out.contains("ram_mb=2048"));
    assert!(out.contains("points"));
    assert!(out.contains("genesis=100"));
    assert!(out.contains("gpu_count=0"));
    assert!(out.contains("gpu_devices=auto"));
    assert!(out.contains("points_per_gpu=50"));
}

#[tokio::test]
async fn trust_reports_genesis_and_no_reservations() {
    let (ctx, _rx) = make_ctx("ctl-trust").await;
    let out = dispatch(&ctx, "trust").await;
    assert!(out.contains("trust: 100"));
    assert!(out.contains("reservations: none"));
}

#[tokio::test]
async fn reputation_empty_reports_none() {
    let (ctx, _rx) = make_ctx("ctl-rep-empty").await;
    let out = dispatch(&ctx, "reputation").await;
    assert_eq!(out, "no reputation data recorded\n");
}

#[tokio::test]
async fn reputation_lists_scored_entries() {
    let (ctx, _rx) = make_ctx("ctl-rep").await;
    ctx.reputation.lock().await.record_valid("node-a");
    ctx.reputation.lock().await.record_valid("node-a");
    let out = dispatch(&ctx, "reputation").await;
    assert!(out.contains("node-a"));
}

#[tokio::test]
async fn compute_without_command_shows_usage() {
    let (ctx, _rx) = make_ctx("ctl-compute-usage").await;
    let out = dispatch(&ctx, "compute -").await;
    assert!(out.contains("usage"));
}

#[tokio::test]
async fn compute_with_a_missing_gpus_value_is_an_error() {
    let (ctx, _rx) = make_ctx("ctl-compute-gpus").await;
    let out = dispatch(&ctx, "compute - --gpus").await;
    assert!(out.contains("error"));
}

#[tokio::test]
async fn unknown_command_shows_help() {
    let (ctx, _rx) = make_ctx("ctl-help").await;
    let out = dispatch(&ctx, "bogus").await;
    assert!(out.contains("commands:"));
    let out = dispatch(&ctx, "help").await;
    assert!(out.contains("compute"));
}

#[tokio::test]
async fn shutdown_flips_the_flag() {
    let (ctx, _rx) = make_ctx("ctl-shutdown").await;
    let mut rx = ctx.shutdown.subscribe();
    let out = dispatch(&ctx, "shutdown").await;
    assert_eq!(out, "shutting down\n");
    rx.changed().await.unwrap();
    assert!(*rx.borrow());
}

#[tokio::test]
async fn unannounced_points_peer_reports_capacity_error() {
    let (ctx, _rx) = make_ctx("ctl-compute-peer").await;
    let provider_side = Transport::new(
        crate::node::identity::Identity::generate(),
        0,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    ctx.dht.lock().await.insert(&provider_side.local_id());
    let out = dispatch(&ctx, "compute - echo hello").await;
    assert!(out.contains("no suitable peer") || out.contains("capacity points"));
}
