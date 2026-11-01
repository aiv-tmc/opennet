//! Swarm pipeline routing tests: exactly-one delivery of pipeline
//! frames and the output sequence guard.

use super::*;
use crate::testutil::make_ctx;

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

#[tokio::test]
async fn route_fwd_delivers_locally_or_emits_an_event_never_both() {
    let (ctx, _rx) = make_ctx("rt-local").await;
    ctx.swarm_procs.lock().await.insert(
        proc_key("p1", 2),
        ShardProc {
            shard_index: 2,
            inbound: {
                let (tx, _rx) = mpsc::channel(SHARD_INBOUND_CAP);
                tx
            },
            shutdown: {
                let (tx, _rx) = oneshot::channel();
                tx
            },
        },
    );
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
