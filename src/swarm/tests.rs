//! Swarm admission and lifecycle tests: sender authorization of the
//! unsigned pipeline frames against plan membership and the
//! launch-time coordinator, the per-source sequence guard, readiness
//! accounting, output admission, checkpoint storage and redelivery,
//! and the role-based routing of done signals.

use super::*;
use crate::testutil::make_ctx;
use tokio::sync::{mpsc, oneshot};

/// Insert one coordinated plan with the given shard host addresses and
/// return the event receiver.
async fn coordinated_plan(
    ctx: &Arc<Ctx>,
    plan_id: &str,
    hosts: &[&str],
) -> mpsc::Receiver<PlanEvent> {
    let (events_tx, events_rx) = mpsc::channel(PLAN_EVENT_CAP);
    ctx.swarm_plans.lock().await.insert(
        plan_id.to_string(),
        PlanState {
            shards: hosts
                .iter()
                .enumerate()
                .map(|(index, addr)| ShardSlot {
                    addr: (*addr).to_string(),
                    node_id: format!("node-{index}"),
                })
                .collect(),
            ready: Default::default(),
            seqs: Default::default(),
            out_seq: 0,
            checkpoints: Default::default(),
            events: events_tx,
        },
    );
    events_rx
}

/// Register one local shard bridge for `plan_id`/`shard` claimed by
/// the given coordinator, returning the runner-bound receiver.
async fn local_shard(
    ctx: &Arc<Ctx>,
    plan_id: &str,
    shard: u32,
    coordinator: &str,
) -> mpsc::Receiver<Vec<u8>> {
    let (inbound_tx, inbound_rx) = mpsc::channel(SHARD_INBOUND_CAP);
    let (shutdown_tx, _shutdown_rx) = oneshot::channel();
    ctx.swarm_procs.lock().await.insert(
        proc_key(plan_id, shard),
        ShardProc {
            shard_index: shard,
            inbound: inbound_tx,
            shutdown: shutdown_tx,
            coordinator: coordinator.to_string(),
        },
    );
    inbound_rx
}

#[tokio::test]
async fn route_fwd_delivers_locally_or_emits_an_event_never_both() {
    let (ctx, _rx) = make_ctx("sw-route-dual").await;
    let local = ctx.transport.local_id();
    let host0 = "tcp:10.0.0.1:7000";
    let host2 = "tcp:10.0.0.2:7000";
    let mut events = coordinated_plan(&ctx, "p1", &[host0, "tcp:10.0.0.9:7000", host2]).await;
    let mut inbound = local_shard(&ctx, "p1", 2, host0).await;
    // Destination hosted locally: the runner queue takes the frame.
    route_fwd(&ctx, host0, "p1", 1, 0, 2, b"local".to_vec()).await;
    assert_eq!(inbound.try_recv().unwrap(), b"local");
    // Destination hosted elsewhere: exactly one relay event, and the
    // local runner queue stays untouched.
    route_fwd(&ctx, host0, "p1", 2, 0, 1, b"remote".to_vec()).await;
    match events.try_recv().unwrap() {
        PlanEvent::Fwd {
            seq,
            src,
            dst,
            payload,
        } => {
            assert_eq!((seq, src, dst), (2, 0, 1));
            assert_eq!(payload, b"remote");
        }
        other => panic!("unexpected event: {other:?}"),
    }
    assert!(inbound.try_recv().is_err());
    // The coordinator's own relay is an authorized sender.
    route_fwd(&ctx, &local, "p1", 3, 0, 2, b"self".to_vec()).await;
    assert_eq!(inbound.try_recv().unwrap(), b"self");
}

#[tokio::test]
async fn route_fwd_drops_replays_and_foreign_senders() {
    let (ctx, _rx) = make_ctx("sw-route-guard").await;
    let host0 = "tcp:10.0.0.1:7000";
    let host1 = "tcp:10.0.0.2:7000";
    let mut events = coordinated_plan(&ctx, "p1", &[host0, host1]).await;
    let foreign = "tcp:10.9.9.9:7000";
    // A peer that is no member of the plan cannot inject frames.
    route_fwd(&ctx, foreign, "p1", 1, 0, 1, b"forge".to_vec()).await;
    assert!(events.try_recv().is_err());
    // A member can only speak for its own shard index.
    route_fwd(&ctx, host1, "p1", 1, 0, 1, b"spoof".to_vec()).await;
    assert!(events.try_recv().is_err());
    // Genuine frames pass in order; equal and lower numbers replay.
    route_fwd(&ctx, host0, "p1", 1, 0, 1, b"a".to_vec()).await;
    route_fwd(&ctx, host0, "p1", 2, 0, 1, b"b".to_vec()).await;
    route_fwd(&ctx, host0, "p1", 2, 0, 1, b"replay".to_vec()).await;
    route_fwd(&ctx, host0, "p1", 1, 0, 1, b"old".to_vec()).await;
    let first = events.try_recv().unwrap();
    let second = events.try_recv().unwrap();
    assert!(events.try_recv().is_err());
    assert!(
        matches!(first, PlanEvent::Fwd { ref payload, .. } if payload == b"a")
            || matches!(second, PlanEvent::Fwd { ref payload, .. } if payload == b"b")
    );
}

#[tokio::test]
async fn route_fwd_at_a_shard_host_accepts_only_its_coordinator() {
    let (ctx, _rx) = make_ctx("sw-route-host").await;
    let coordinator = "tcp:10.0.0.1:7000";
    let mut inbound = local_shard(&ctx, "p1", 1, coordinator).await;
    // The coordinator's relay reaches the runner queue.
    route_fwd(&ctx, coordinator, "p1", 7, 0, 1, b"frame".to_vec()).await;
    assert_eq!(inbound.try_recv().unwrap(), b"frame");
    // Nobody else can feed this shard, member or not.
    route_fwd(&ctx, "tcp:10.0.0.2:7000", "p1", 8, 0, 1, b"evil".to_vec()).await;
    assert!(inbound.try_recv().is_err());
    // Unknown plans hit the log-and-drop path without panicking.
    route_fwd(&ctx, coordinator, "p-unknown", 1, 0, 1, b"x".to_vec()).await;
}

#[tokio::test]
async fn readiness_is_recorded_and_authorized() {
    let (ctx, _rx) = make_ctx("sw-ready").await;
    let host0 = "tcp:10.0.0.1:7000";
    let host1 = "tcp:10.0.0.2:7000";
    let mut events = coordinated_plan(&ctx, "p1", &[host0, host1]).await;
    // Foreign and misattributed readiness reports change nothing.
    handle_ready(&ctx, "tcp:10.9.9.9:7000", "p1", 0).await;
    handle_ready(&ctx, host1, "p1", 0).await;
    assert!(ctx
        .swarm_plans
        .lock()
        .await
        .get("p1")
        .unwrap()
        .ready
        .is_empty());
    // The shard's own host reports readiness: recorded and queued.
    handle_ready(&ctx, host0, "p1", 0).await;
    assert!(ctx
        .swarm_plans
        .lock()
        .await
        .get("p1")
        .unwrap()
        .ready
        .contains(&0));
    assert!(matches!(events.try_recv().unwrap(), PlanEvent::Ready(0)));
}

#[tokio::test]
async fn output_comes_only_from_the_last_shard_in_increasing_order() {
    let (ctx, _rx) = make_ctx("sw-out").await;
    let host0 = "tcp:10.0.0.1:7000";
    let host1 = "tcp:10.0.0.2:7000";
    let mut events = coordinated_plan(&ctx, "p1", &[host0, host1]).await;
    // A non-last shard cannot emit output at all.
    handle_out(&ctx, host0, "p1", 1, b"early".to_vec()).await;
    assert!(events.try_recv().is_err());
    // The last shard streams in strictly increasing order; equal and
    // lower numbers replay.
    handle_out(&ctx, host1, "p1", 1, b"one".to_vec()).await;
    handle_out(&ctx, host1, "p1", 2, b"two".to_vec()).await;
    handle_out(&ctx, host1, "p1", 2, b"replay".to_vec()).await;
    handle_out(&ctx, host1, "p1", 1, b"old".to_vec()).await;
    assert!(matches!(
        events.try_recv().unwrap(),
        PlanEvent::Out { seq: 1, .. }
    ));
    assert!(matches!(
        events.try_recv().unwrap(),
        PlanEvent::Out { seq: 2, .. }
    ));
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn checkpoints_store_per_shard_and_redeliver_on_ready() {
    let (ctx, _rx) = make_ctx("sw-checkpoint").await;
    let host0 = "tcp:10.0.0.1:7000";
    let _events = coordinated_plan(&ctx, "p1", &[host0]).await;
    // Only the shard's host stores a checkpoint.
    handle_checkpoint(&ctx, "tcp:10.9.9.9:7000", "p1", 0, b"forged".to_vec()).await;
    assert!(ctx
        .swarm_plans
        .lock()
        .await
        .get("p1")
        .unwrap()
        .checkpoints
        .is_empty());
    handle_checkpoint(&ctx, host0, "p1", 0, b"state".to_vec()).await;
    // After a spare relaunch the readiness report hands the stored
    // checkpoint to the replacement runner as one bridge frame.
    let mut inbound = local_shard(&ctx, "p1", 0, host0).await;
    handle_ready(&ctx, host0, "p1", 0).await;
    let frame = inbound.try_recv().expect("checkpoint frame");
    assert_eq!(frame[4], 5, "checkpoint tag");
    assert_eq!(&frame[5..], b"state");
}

#[tokio::test]
async fn done_signals_route_by_role_and_authorize_the_sender() {
    let (ctx, _rx) = make_ctx("sw-done").await;
    let host0 = "tcp:10.0.0.1:7000";
    let coordinator_addr = "tcp:10.0.0.9:7000";
    // Coordinator role: a member's failure report enters the plan
    // queue, where the coordinator loop turns it into failover.
    let mut events = coordinated_plan(&ctx, "p1", &[host0]).await;
    handle_done(
        &ctx,
        "tcp:10.8.8.8:7000",
        "p1",
        "shard 0 launch failed: no consent",
    )
    .await;
    assert!(events.try_recv().is_err(), "foreign done must be dropped");
    handle_done(&ctx, host0, "p1", "shard 0 launch failed: no consent").await;
    match events.try_recv().unwrap() {
        PlanEvent::Done(reason) => {
            assert!(reason.starts_with("shard 0 launch failed"));
        }
        other => panic!("unexpected event: {other:?}"),
    }
    ctx.swarm_plans.lock().await.remove("p1");
    // Shard-host role: only the launching coordinator tears the local
    // runners down.
    let _inbound = local_shard(&ctx, "p2", 0, coordinator_addr).await;
    handle_done(&ctx, host0, "p2", "plan ended").await;
    assert!(ctx
        .swarm_procs
        .lock()
        .await
        .contains_key(&proc_key("p2", 0)));
    handle_done(&ctx, coordinator_addr, "p2", "plan ended").await;
    assert!(!ctx
        .swarm_procs
        .lock()
        .await
        .contains_key(&proc_key("p2", 0)));
}

#[tokio::test]
async fn finish_plan_shuts_every_local_bridge() {
    let (ctx, _rx) = make_ctx("sw-finish").await;
    coordinated_plan(&ctx, "p1", &["tcp:10.0.0.1:7000"]).await;
    let mut shutdown_rx = {
        let (inbound_tx, _inbound_rx) = mpsc::channel(SHARD_INBOUND_CAP);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        ctx.swarm_procs.lock().await.insert(
            proc_key("p1", 0),
            ShardProc {
                shard_index: 0,
                inbound: inbound_tx,
                shutdown: shutdown_tx,
                coordinator: "tcp:10.0.0.1:7000".to_string(),
            },
        );
        shutdown_rx
    };
    finish_plan(&ctx, "p1", "completed").await;
    assert!(ctx.swarm_plans.lock().await.get("p1").is_none());
    assert!(ctx.swarm_procs.lock().await.is_empty());
    assert!(
        shutdown_rx.try_recv().is_ok(),
        "the bridge must receive the shutdown signal"
    );
}
