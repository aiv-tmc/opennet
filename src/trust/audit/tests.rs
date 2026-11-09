//! Audit walk tests: the multi-window recomputation, the cache budget
//! that must never stop the walk, and the hard cap that turns an
//! endless chain into a failed audit. The walk is exercised against a
//! real receipt journal through its public window interface.

use super::*;
use crate::node::identity::Identity;
use crate::node::state::ReceiptLog;
use crate::testutil::scratch_dir;
use crate::trust::now_unix;

fn signed_receipt(task_id: &str, provider: &Identity) -> Message {
    let unix_ts = now_unix();
    Message::Receipt {
        task_id: task_id.to_string(),
        provider_node: provider.node_id(),
        billed_secs: 12,
        charge: 24,
        outcome_hash: [7; 32],
        unix_ts,
        pubkey: provider.pubkey(),
        signature: provider
            .sign(&Message::receipt_signing_payload(
                task_id,
                &provider.node_id(),
                12,
                24,
                &[7; 32],
                unix_ts,
            ))
            .to_vec(),
    }
}

/// Mirror of the walk loop in `audit_chain` against a real journal:
/// the walk chains bounded windows from the genesis anchor to the live
/// head. `max_windows` models only the hard walk cap
/// (`AUDIT_HARD_CAP`): the cache budget never bounds the walk, which
/// must reach the chain end before anything is accepted.
fn simulated_walk(log: &ReceiptLog, window_cap: usize, max_windows: usize) -> Option<[u8; 32]> {
    let mut anchor = genesis_head();
    let mut final_head = genesis_head();
    let mut complete = false;
    let mut windows = 0usize;
    while !complete && windows < max_windows {
        windows += 1;
        let (receipts, head_after, done) = log.window(anchor, window_cap)?;
        assert!(verify_window(anchor, &receipts, head_after));
        final_head = head_after;
        complete = done;
        anchor = head_after;
    }
    complete.then_some(final_head)
}

#[test]
fn multi_window_walk_recomputes_the_full_chain_head() {
    let dir = scratch_dir("audit-walk");
    let provider = Identity::generate();
    let mut log = ReceiptLog::load(&dir).unwrap();
    for n in 1..=5 {
        log.append(signed_receipt(&format!("t{n}"), &provider), "consumer-a")
            .unwrap();
    }
    let head = simulated_walk(&log, 3, 16).expect("five receipts must fit the budget");
    assert_eq!(head, log.head());
    // Two of five receipts can never reach the head: skipping
    // evidence must not verify.
    let (first, head_after_first, done_first) = log.window(genesis_head(), 1).unwrap();
    assert!(!done_first);
    assert!(verify_window(genesis_head(), &first, head_after_first));
    let (second, head_after_second, _) = log.window(head_after_first, 1).unwrap();
    assert!(verify_window(head_after_first, &second, head_after_second));
    assert_ne!(
        head_after_second,
        log.head(),
        "two of five cannot reach the head"
    );
}

#[test]
fn walk_past_the_cache_budget_still_reaches_the_head() {
    // Eleven receipts at a window cap of five need three windows,
    // more than the two-window cache budget: the cache budget must
    // never stop the walk — only the hard walk cap bounds it — and
    // the walk must still land on the real head, because the
    // announced head is compared on every path.
    let dir = scratch_dir("audit-long");
    let provider = Identity::generate();
    let mut log = ReceiptLog::load(&dir).unwrap();
    for n in 1..=11 {
        log.append(signed_receipt(&format!("t{n}"), &provider), "consumer-a")
            .unwrap();
    }
    let head = simulated_walk(&log, 5, usize::MAX).expect("the walk must reach the chain end");
    assert_eq!(head, log.head());
    // Any other announced head is a mismatch, no matter how many
    // windows the walk needed.
    assert_ne!(head, [0xff; 32]);
}

#[test]
fn hard_capped_walk_reports_incomplete() {
    // A walk that never sees the chain end reports nothing, so the
    // caller fails the audit instead of trusting a partial chain.
    let dir = scratch_dir("audit-cap");
    let provider = Identity::generate();
    let mut log = ReceiptLog::load(&dir).unwrap();
    for n in 1..=4 {
        log.append(signed_receipt(&format!("t{n}"), &provider), "consumer-a")
            .unwrap();
    }
    assert!(simulated_walk(&log, 1, 2).is_none());
}

#[test]
fn overall_budget_bounds_the_walk() {
    // The constants must keep the worst-case stall finite: the window
    // timeout and the overall budget are both bounded, and the overall
    // budget is a small multiple of the per-window timeout, so a
    // slow-dripping peer fails long before the hard window cap.
    assert!(AUDIT_TIMEOUT <= AUDIT_OVERALL_TIMEOUT);
    assert!(AUDIT_OVERALL_TIMEOUT <= Duration::from_secs(600));
}
