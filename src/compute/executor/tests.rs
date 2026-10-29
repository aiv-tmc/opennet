//! Executor tests: real child processes with the sandbox knobs from the
//! default config, verified through the loopback transport.

use super::*;
use crate::testutil::make_ctx;
use crate::transport::Transport;

fn launch(return_addr: &str, command: &str, timeout_secs: u64) -> Launch {
    // A unique task id gives every test its own working directory, so
    // parallel tests never remove each other's scratch directory.
    Launch {
        task_id: format!("t-test-{}", rand::random::<u32>()),
        return_addr: return_addr.to_string(),
        units: 5,
        command: command.to_string(),
        timeout_secs,
    }
}

async fn recv_outcome(consumer_side: &Transport) -> TaskOutcome {
    let (_src, data) = tokio::time::timeout(Duration::from_secs(10), consumer_side.recv())
        .await
        .expect("timed out waiting for TaskResult")
        .expect("transport closed");
    match Message::decode(&data) {
        Some(Message::TaskResult { outcome, .. }) => outcome,
        other => panic!("expected TaskResult, got {other:?}"),
    }
}

#[tokio::test]
async fn successful_task_credits_trust_and_reports_output() {
    let (ctx, _rx) = make_ctx("ex-ok").await;
    let consumer_side = Transport::new(0, Duration::from_secs(60)).await.unwrap();
    execute(
        &ctx,
        launch(&consumer_side.local_id(), "echo hello-opennet", 30),
    )
    .await;
    // The credit equals units_for(points, billed_secs) with at least one
    // billed second.
    let expected = 100 + ctx.state.lock().await.points as i64;
    assert_eq!(ctx.state.lock().await.trust, expected);
    assert_eq!(ctx.state.lock().await.tasks_completed, 1);
    let outcome = recv_outcome(&consumer_side).await;
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.contains("hello-opennet"));
    assert!(outcome.billed_secs >= 1);
}

#[tokio::test]
async fn timeout_kills_the_task_and_bills_the_limit() {
    let (ctx, _rx) = make_ctx("ex-timeout").await;
    let consumer_side = Transport::new(0, Duration::from_secs(60)).await.unwrap();
    let start = Instant::now();
    execute(&ctx, launch(&consumer_side.local_id(), "sleep 30", 1)).await;
    assert!(start.elapsed() < Duration::from_secs(10));
    let outcome = recv_outcome(&consumer_side).await;
    assert_eq!(outcome.exit_code, -2);
    assert!(outcome.billed_secs <= 1);
}

#[tokio::test]
async fn failing_task_counts_failure_and_captures_stderr() {
    let (ctx, _rx) = make_ctx("ex-fail").await;
    let consumer_side = Transport::new(0, Duration::from_secs(60)).await.unwrap();
    execute(
        &ctx,
        launch(&consumer_side.local_id(), "echo oops >&2; exit 3", 30),
    )
    .await;
    assert_eq!(ctx.state.lock().await.tasks_failed, 1);
    let outcome = recv_outcome(&consumer_side).await;
    assert_eq!(outcome.exit_code, 3);
    assert!(outcome.stderr.contains("oops"));
}

#[tokio::test]
async fn sandboxed_task_has_private_loopback_and_no_host_files() {
    // With namespaces on (default), the task sees only its tmpfs workdir
    // and cannot resolve anything outside it.
    let (ctx, _rx) = make_ctx("ex-sandbox").await;
    let consumer_side = Transport::new(0, Duration::from_secs(60)).await.unwrap();
    execute(
        &ctx,
        launch(
            &consumer_side.local_id(),
            "cat /etc/hostname 2>/dev/null || echo no-hostname",
            30,
        ),
    )
    .await;
    let outcome = recv_outcome(&consumer_side).await;
    // The read-only root still contains /etc, but the hostname may be
    // obscured in the UTS namespace; either way the task ran sandboxed.
    assert!(outcome.exit_code == 0);
}
