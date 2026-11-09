//! Chain arithmetic of the receipt journal: the genesis head, the
//! per-receipt hash and the window recomputation auditors run. These
//! functions are pure — they own no state and touch no disk — so the
//! journal and the audit protocol share exactly one definition of
//! what a receipt chain is.

use crate::message::Message;

/// Genesis chain head: the announced head of a journal with no
/// receipts. Distinct from any real hash by construction.
pub fn genesis_head() -> [u8; 32] {
    *blake3::hash(b"opennet receipt journal v1").as_bytes()
}

/// Hash of one receipt: the canonical wire bytes.
pub fn receipt_hash(receipt: &Message) -> [u8; 32] {
    *blake3::hash(&receipt.encode()).as_bytes()
}

/// Chain hash over a window: start at `head_before`, fold every
/// receipt's canonical bytes in, and require the final head to equal
/// `head_after`. Returns `false` on any non-receipt entry or a broken
/// link; per-entry signatures are verified separately by the caller.
pub fn verify_window(head_before: [u8; 32], receipts: &[Message], head_after: [u8; 32]) -> bool {
    let mut head = head_before;
    for receipt in receipts {
        let Message::Receipt { .. } = receipt else {
            return false;
        };
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(&head);
        material.extend_from_slice(&receipt.encode());
        head = *blake3::hash(&material).as_bytes();
    }
    head == head_after
}
