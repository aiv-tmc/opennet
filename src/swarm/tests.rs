//! Swarm pipeline routing tests: exactly-one delivery of pipeline
//! frames, the output sequence guard and checkpoint delivery at
//! readiness.

use super::*;
use crate::testutil::make_ctx;
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot};

/// Build one plan state with its bounded event queue, like the
/// coordinator does at plan start.
fn plan_with(shards: Vec<ShardSlot>) -> (PlanState, mpsc::Receiver<PlanEvent>) {
    let (events_tx, events_rx) = mpsc::channel(PLAN_EVENT_CAP);
    (
        PlanState {
            shards,
            ready: HashSet::new(),
            seqs: HashMap::new(),
            out_seq: 0,
            checkpoints: HashMap::new(),
            events: events_tx,
        },
        events_rx,
    )
}

fn slot(addr: &str) -> ShardSlot {
    ShardSlot {
        addr: addr.to_string(),
        node_id: format!("node-{addr}"),
    }
}

fn shard_proc(shard_index: u32) -> (ShardProc, mpsc::Receiver<Vec<u8>>) {
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(SHARD_INBOUND_CAP);
    let (shutdown_tx, _shutdown_rx) = oneshot::channel();
    (
        ShardProc {
            shard_index,
            inbound: inbound_tx,
            shutdown: shutdown_tx,
        },
        inbound_rx,
    )
}

#[tokio::test]
async fn route_fwd_delivers_locally_or_emits_an_event_never_both() {
    let (ctx, _rx) = make_ctx("rt-local").await;
    let (proc_, _inbound_rx) = shard_proc(2);
    ctx.swarm_procs
        .lock()
        .await
        .insert(proc_key("p1", 2), proc_);
    let (plan, mut events_rx) = plan_with(vec![slot("tcp:10.0.0.1:1"), slot("tcp:10.0.0.2:2")]);
    ctx.swarm_plans.lock().await.insert("p1".to_string(), plan);
    // Local destination: the frame enters the runner queue and no
    // coordination event is emitted.
    route_fwd(&ctx, "p1", 1, 0, 2, b"local".to_vec()).await;
    assert!(events_rx.try_recv().is_err());
    // Remote destination: exactly one coordination event is emitted.
    route_fwd(&ctx, "p1", 2, 0, 1, b"remote".to_vec()).await;
    let event = events_rx.try_recv().expect("one relay event");
    assert!(matches!(event, PlanEvent::Fwd { dst: 1, .. }));
    assert!(events_rx.try_recv().is_err(), "exactly one delivery");
}

#[tokio::test]
async fn pipeline_and_output_sequence_guards_drop_stale_frames() {
    let (ctx, _rx) = make_ctx("rt-seq").await;
    let (plan, _events_rx) = plan_with(vec![slot("tcp:10.0.0.1:1")]);
    ctx.swarm_plans.lock().await.insert("p1".to_string(), plan);
    // Strictly increasing pipeline numbers pass.
    route_fwd(&ctx, "p1", 1, 0, 0, b"a".to_vec()).await;
    route_fwd(&ctx, "p1", 2, 0, 0, b"b".to_vec()).await;
    // A replayed number is dropped.
    route_fwd(&ctx, "p1", 2, 0, 0, b"replay".to_vec()).await;
    {
        let plans = ctx.swarm_plans.lock().await;
        let plan = plans.get("p1").unwrap();
        assert_eq!(plan.seqs.get(&0), Some(&2));
    }
    // Output frames must strictly increase the plan's own counter.
    deliver_plan_event(
        &ctx,
        "p1",
        PlanEvent::Out {
            seq: 1,
            payload: b"x".to_vec(),
        },
    )
    .await;
    deliver_plan_event(
        &ctx,
        "p1",
        PlanEvent::Out {
            seq: 1,
            payload: b"y".to_vec(),
        },
    )
    .await;
    {
        let plans = ctx.swarm_plans.lock().await;
        assert_eq!(plans.get("p1").unwrap().out_seq, 1);
    }
}

#[tokio::test]
async fn a_stored_checkpoint_reaches_the_local_runner_at_readiness() {
    let (ctx, _rx) = make_ctx("rt-checkpoint").await;
    let (mut plan, mut events_rx) = plan_with(vec![slot("tcp:10.0.0.1:1")]);
    // The coordinator stored a checkpoint for shard 0 while the
    // previous runner was alive.
    plan.checkpoints.insert(0, b"state-blob".to_vec());
    let (proc_, mut inbound_rx) = shard_proc(0);
    ctx.swarm_procs
        .lock()
        .await
        .insert(proc_key("p1", 0), proc_);
    ctx.swarm_plans.lock().await.insert("p1".to_string(), plan);
    // The replacement shard reports ready; the readiness event both
    // reaches the coordinator queue and pushes the checkpoint frame
    // into the runner queue ahead of any input.
    deliver_plan_event(&ctx, "p1", PlanEvent::Ready(0)).await;
    assert!(matches!(events_rx.try_recv(), Ok(PlanEvent::Ready(0))));
    let frame = inbound_rx.try_recv().expect("checkpoint frame");
    // Bridge frame layout: [u32 len][u8 tag][payload], tag 5.
    assert_eq!(frame[4], 5, "checkpoint tag");
    assert_eq!(&frame[5..], b"state-blob");
    // No checkpoint for shard 1: a ready event delivers nothing.
    deliver_plan_event(&ctx, "p1", PlanEvent::Ready(1)).await;
    assert!(inbound_rx.try_recv().is_err());
}
