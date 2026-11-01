//! Append-only billing receipt journal.
//!
//! Every settled task produces one provider-signed `Receipt`; the
//! consumer answers with a countersignature (`ReceiptAck`). The journal
//! chains receipts into a rolling hash — each entry commits to all
//! previous ones — and the chain head travels with the node's identity
//! announcement. Peers may request a window of the journal
//! (`ReceiptRequest`/`ReceiptResponse`) and recompute the chaining hash
//! to verify the announcement is backed by real receipts; a mismatch
//! costs the liar the market. The full journal is held in memory
//! (LAN-scale evidence; tens of bytes per entry) so any window can be
//! served without re-parsing the disk log.
//!
//! Storage layout in the state directory:
//!   receipts.jsonl — one `{"receipt": <wire message>}` per line
//!   receipts-acks.jsonl — one `{"ack": <wire message>}` per line
//! Each line stores the message through its standard serde encoding — the
//! on-disk format is the wire format replayed. Lines are appended and
//! flushed per record; files are owner-only.

use crate::message::Message;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

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

/// The receipt journal: a replayable chain, its on-disk append log and
/// the in-memory index that serves audit windows.
pub struct ReceiptLog {
    head: [u8; 32],
    count: u64,
    receipts_file: PathBuf,
    acks_file: PathBuf,
    /// Every receipt in chain order.
    entries: Vec<Message>,
    /// `heads[i]` is the chain head after `entries[i]`.
    heads: Vec<[u8; 32]>,
    /// Chain head *before* entry `i` -> `i`; the genesis head maps to 0.
    index: HashMap<[u8; 32], usize>,
}

impl ReceiptLog {
    /// Open (or create) the journal in `state_dir`, replaying every
    /// stored record to rebuild the chain, the in-memory entries and
    /// the window index. The directory is created when missing. A
    /// corrupt line aborts the load: the journal is evidence, and
    /// silently skipping evidence is worse than refusing to start.
    pub fn load(state_dir: &Path) -> Result<ReceiptLog> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("cannot create {}", state_dir.display()))?;
        let receipts_file = state_dir.join("receipts.jsonl");
        let acks_file = state_dir.join("receipts-acks.jsonl");
        let mut log = ReceiptLog {
            head: genesis_head(),
            count: 0,
            receipts_file: receipts_file.clone(),
            acks_file: acks_file.clone(),
            entries: Vec::new(),
            heads: Vec::new(),
            index: HashMap::new(),
        };
        log.index.insert(genesis_head(), 0);
        if receipts_file.exists() {
            let text =
                std::fs::read_to_string(&receipts_file).context("cannot read receipts.jsonl")?;
            for line in text.lines().filter(|line| !line.is_empty()) {
                let parsed: serde_json::Value =
                    serde_json::from_str(line).context("corrupt receipts.jsonl line")?;
                let receipt: Message = serde_json::from_value(
                    parsed
                        .get("receipt")
                        .cloned()
                        .context("receipts.jsonl line without receipt field")?,
                )
                .context("corrupt receipt record")?;
                log.chain(&receipt)?;
            }
        }
        if acks_file.exists() {
            let text =
                std::fs::read_to_string(&acks_file).context("cannot read receipts-acks.jsonl")?;
            for line in text.lines().filter(|line| !line.is_empty()) {
                let parsed: serde_json::Value =
                    serde_json::from_str(line).context("corrupt receipts-acks.jsonl line")?;
                let ack: Message = serde_json::from_value(
                    parsed
                        .get("ack")
                        .cloned()
                        .context("receipts-acks.jsonl line without ack field")?,
                )
                .context("corrupt ack record")?;
                if !matches!(ack, Message::ReceiptAck { .. }) {
                    bail!("receipts-acks.jsonl holds a non-ack record");
                }
            }
        }
        Ok(log)
    }

    /// Rolling head of the receipt chain; the genesis head while empty.
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// Number of receipts in the chain.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// True while no receipt has ever been recorded.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Serve one audit window: the receipts after `head_before` (at
    /// most `limit`), the chain head after the last returned receipt
    /// and `complete` when the window reached the chain end. Returns
    /// `None` when `head_before` is not a known chain position.
    pub fn window(
        &self,
        head_before: [u8; 32],
        limit: usize,
    ) -> Option<(Vec<Message>, [u8; 32], bool)> {
        let start = *self.index.get(&head_before)?;
        let end = (start + limit).min(self.entries.len());
        let receipts = self.entries[start..end].to_vec();
        let head_after = if end == 0 {
            head_before
        } else {
            self.heads[end - 1]
        };
        let complete = end == self.entries.len();
        Some((receipts, head_after, complete))
    }

    /// Append one provider-signed receipt: refuse duplicates (the
    /// chain is a set, not a multiset), advance the chain, persist and
    /// flush.
    pub fn append(&mut self, receipt: Message) -> Result<()> {
        let Message::Receipt { ref task_id, .. } = receipt else {
            bail!("only Receipt messages enter the receipt journal");
        };
        if self.entries.iter().any(|entry| {
            matches!(entry, Message::Receipt { task_id: recorded, .. } if recorded == task_id)
        }) {
            bail!("duplicate receipt for task {task_id}");
        }
        self.chain(&receipt)?;
        append_line(&self.receipts_file, "receipt", &receipt)?;
        Ok(())
    }

    /// Append one countersignature record.
    pub fn record_ack(&mut self, ack: Message) -> Result<()> {
        if !matches!(ack, Message::ReceiptAck { .. }) {
            bail!("only ReceiptAck messages enter the ack journal");
        }
        append_line(&self.acks_file, "ack", &ack)?;
        Ok(())
    }

    /// Advance the in-memory chain over one receipt, mirroring the
    /// on-disk append.
    fn chain(&mut self, receipt: &Message) -> Result<()> {
        if !matches!(receipt, Message::Receipt { .. }) {
            bail!("chain accepts receipts only");
        }
        self.index.insert(self.head, self.entries.len());
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(&self.head);
        material.extend_from_slice(&receipt.encode());
        self.head = *blake3::hash(&material).as_bytes();
        self.entries.push(receipt.clone());
        self.heads.push(self.head);
        self.count += 1;
        Ok(())
    }
}

/// Append one JSON line to a journal file, owner-only, flushed before
/// returning: a receipt that survives a crash must be visible on replay.
fn append_line(path: &Path, field: &str, message: &Message) -> Result<()> {
    let mut wrapper = serde_json::Map::new();
    wrapper.insert(field.to_string(), serde_json::to_value(message)?);
    let line = serde_json::to_string(&serde_json::Value::Object(wrapper))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "{line}")?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
