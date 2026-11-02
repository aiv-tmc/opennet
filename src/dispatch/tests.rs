//! Dispatch tests: signature enforcement on bids and the waiter
//! binding of signed market decisions.

use super::*;
use crate::compute::TaskOutcome;
use crate::node::identity::Identity;
use crate::testutil::make_ctx;

#[tokio::test]
async fn bid_with_invalid_signature_is_rejected() {
    let (ctx, mut rx) = make_ctx("dp-bad-bid").await;
    let bid = Message::TaskBid {
        task_id: "t1".into(),
        trust: 50,
        consumed: 20,
        expires_unix: 9_999_999_999,
        pubkey: [7; 32],
        signature: vec![8; 64],
    };
    handle_frame(&ctx, "tcp:10.9.9.9:5555", &bid.encode()).await;
    assert_eq!(
        ctx.reputation.lock().await.score_of("tcp:10.9.9.9:5555"),
        -1
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn a_result_from_a_wrong_signer_cannot_complete_the_waiter() {
    let (ctx, _rx) = make_ctx("dp-waiter-bind").await;
    let (tx, mut rx) = tokio::sync::oneshot::channel::<ComputeEvent>();
    let provider = Identity::generate();
    ctx.result_waiters
        .lock()
        .await
        .insert("t1".to_string(), (provider.node_id(), tx));
    let outcome = TaskOutcome {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        billed_secs: 1,
    };
    let foreign = Identity::generate();
    let unix_ts = crate::trust::now_unix();
    let foreign_result = Message::TaskResult {
        task_id: "t1".into(),
        outcome: outcome.clone(),
        unix_ts,
        pubkey: foreign.pubkey(),
        signature: foreign
            .sign(&Message::result_signing_payload(
                "t1",
                &outcome.hash(),
                unix_ts,
            ))
            .to_vec(),
    };
    handle_frame(&ctx, "tcp:10.9.9.9:7999", &foreign_result.encode()).await;
    assert!(rx.try_recv().is_err());
    assert!(ctx.result_waiters.lock().await.contains_key("t1"));
    let signed_result = Message::TaskResult {
        task_id: "t1".into(),
        outcome: outcome.clone(),
        unix_ts,
        pubkey: provider.pubkey(),
        signature: provider
            .sign(&Message::result_signing_payload(
                "t1",
                &outcome.hash(),
                unix_ts,
            ))
            .to_vec(),
    };
    handle_frame(&ctx, "tcp:10.9.9.9:7999", &signed_result.encode()).await;
    assert!(matches!(
        rx.try_recv().expect("waiter must complete"),
        ComputeEvent::Outcome(_)
    ));
    assert!(!ctx.result_waiters.lock().await.contains_key("t1"));
}
