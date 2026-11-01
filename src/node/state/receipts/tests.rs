//! Receipt journal tests: chaining, replay, windows, signature
//! enforcement, duplicate protection and ack binding. Every case uses
//! a scratch directory; no test touches real system paths.

use super::*;
use crate::node::identity::Identity;
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

fn signed_ack(task_id: &str, consumer: &Identity, receipt: &Message) -> Message {
    let unix_ts = now_unix();
    let hash = receipt_hash(receipt);
    Message::ReceiptAck {
        task_id: task_id.to_string(),
        receipt_hash: hash,
        unix_ts,
        pubkey: consumer.pubkey(),
        signature: consumer
            .sign(&Message::receipt_ack_signing_payload(
                task_id, &hash, unix_ts,
            ))
            .to_vec(),
    }
}

#[test]
fn genesis_head_is_stable_and_empty_log_reports_it() {
    let dir = scratch_dir("rcpt-genesis");
    let log = ReceiptLog::load(&dir).unwrap();
    assert!(log.is_empty());
    assert_eq!(log.head(), genesis_head());
    assert_eq!(log.count(), 0);
}

#[test]
fn chain_advances_per_receipt_and_replays_from_disk() {
    let dir = scratch_dir("rcpt-chain");
    let provider = Identity::generate();
    let head_after_two;
    {
        let mut log = ReceiptLog::load(&dir).unwrap();
        log.append(signed_receipt("t1", &provider)).unwrap();
        log.append(signed_receipt("t2", &provider)).unwrap();
        head_after_two = log.head();
        assert_ne!(head_after_two, genesis_head());
        assert_eq!(log.count(), 2);
    }
    let reloaded = ReceiptLog::load(&dir).unwrap();
    assert_eq!(reloaded.count(), 2);
    assert_eq!(reloaded.head(), head_after_two);
}

#[test]
fn duplicate_task_ids_are_rejected() {
    let dir = scratch_dir("rcpt-dup");
    let provider = Identity::generate();
    let mut log = ReceiptLog::load(&dir).unwrap();
    log.append(signed_receipt("t1", &provider)).unwrap();
    assert!(log.append(signed_receipt("t1", &provider)).is_err());
    assert_eq!(log.count(), 1);
}

#[test]
fn receipt_with_invalid_signature_is_refused() {
    let dir = scratch_dir("rcpt-badsig");
    let provider = Identity::generate();
    let mut log = ReceiptLog::load(&dir).unwrap();
    let mut receipt = signed_receipt("t1", &provider);
    if let Message::Receipt { signature, .. } = &mut receipt {
        signature[0] ^= 0xff;
    }
    assert!(log.append(receipt).is_err());
    assert_eq!(log.count(), 0);
}

#[test]
fn replay_aborts_on_tampered_evidence() {
    let dir = scratch_dir("rcpt-tamper");
    let provider = Identity::generate();
    {
        let mut log = ReceiptLog::load(&dir).unwrap();
        log.append(signed_receipt("t1", &provider)).unwrap();
    }
    // Corrupt the signature of the stored record; replay must refuse
    // to build a chain over unverifiable evidence.
    let file = dir.join("receipts.jsonl");
    let text = std::fs::read_to_string(&file).unwrap();
    let corrupted = text.replacen("\"signature\":[", "\"signature\":[1", 1);
    std::fs::write(&file, corrupted).unwrap();
    assert!(ReceiptLog::load(&dir).is_err());
}

#[test]
fn ack_must_match_an_issued_receipt() {
    let dir = scratch_dir("rcpt-ack-bind");
    let provider = Identity::generate();
    let consumer = Identity::generate();
    let mut log = ReceiptLog::load(&dir).unwrap();
    let receipt = signed_receipt("t1", &provider);
    log.append(receipt.clone()).unwrap();
    // A valid ack for the issued receipt is accepted.
    assert!(log
        .record_ack(signed_ack("t1", &consumer, &receipt))
        .is_ok());
    // An ack for a task that was never billed here is refused.
    assert!(log
        .record_ack(signed_ack("t9", &consumer, &receipt))
        .is_err());
    // An ack carrying the wrong hash is refused.
    let wrong_hash = {
        let unix_ts = now_unix();
        Message::ReceiptAck {
            task_id: "t1".to_string(),
            receipt_hash: [0x5a; 32],
            unix_ts,
            pubkey: consumer.pubkey(),
            signature: consumer
                .sign(&Message::receipt_ack_signing_payload(
                    "t1",
                    &[0x5a; 32],
                    unix_ts,
                ))
                .to_vec(),
        }
    };
    assert!(log.record_ack(wrong_hash).is_err());
    // An unverifiable signature is refused.
    let mut bad = signed_ack("t1", &consumer, &receipt);
    if let Message::ReceiptAck { signature, .. } = &mut bad {
        signature[3] ^= 0xff;
    }
    assert!(log.record_ack(bad).is_err());
}

#[test]
fn windows_serve_chain_slices_with_verifiable_heads() {
    let dir = scratch_dir("rcpt-window");
    let provider = Identity::generate();
    let mut log = ReceiptLog::load(&dir).unwrap();
    for n in 1..=5 {
        log.append(signed_receipt(&format!("t{n}"), &provider))
            .unwrap();
    }
    // Full window from the genesis head reaches the live head.
    let (receipts, head_after, complete) = log.window(genesis_head(), 16).unwrap();
    assert_eq!(receipts.len(), 5);
    assert!(complete);
    assert!(verify_window(genesis_head(), &receipts, head_after));
    assert_eq!(head_after, log.head());
    // A bounded window is internally consistent and incomplete.
    let (receipts, head_after, complete) = log.window(genesis_head(), 2).unwrap();
    assert_eq!(receipts.len(), 2);
    assert!(!complete);
    assert!(verify_window(genesis_head(), &receipts, head_after));
    // Chaining from the wrong anchor fails.
    assert!(!verify_window([9; 32], &receipts, head_after));
    // An unknown anchor serves nothing.
    assert!(log.window([8; 32], 2).is_none());
}
