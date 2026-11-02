//! Append-only billing receipt journal.
//!
//! Every settled task produces one provider-signed `Receipt`; the
//! consumer answers with a countersignature (`ReceiptAck`). The journal
//! chains receipts into a rolling hash — each entry commits to all
//! previous ones — and the chain head travels with the node's identity
//! announcement. Peers may request a window of the journal
//! (`ReceiptRequest`/`ReceiptResponse`) and recompute the chaining hash
//! to verify the announcement is backed by real receipts; a mismatch
//! costs the liar the market.
//!
//! Evidence integrity is enforced at the journal boundary: every receipt
//! must carry a signature that verifies against its embedded provider
//! key before it enters the chain (both on append and on every replay
//! from disk), duplicate task ids are refused, and every ack must verify
//! against a receipt this node actually issued — unknown task ids and
//! hash mismatches are refused and never touch the ack journal. The
//! full journal is held in memory (LAN-scale evidence; tens of bytes
//! per entry) so any window can be served without re-parsing the disk
//! log and every membership or binding check is constant time.
//!
//! Storage layout in the state directory:
//!   receipts.jsonl — one `{"receipt": <wire message>}` per line
//!   receipts-acks.jsonl — one `{"ack": <wire message>}` per line
//! Each line stores the message through its standard serde encoding —
//! the on-disk format is the wire format replayed. Lines are appended
//! and flushed per record; files are owner-only.

use crate::message::Message;
use crate::trust::verify::{verify_receipt, verify_receipt_ack};
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
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
    /// Task ids already in the chain: duplicate protection in O(1).
    task_ids: HashSet<String>,
    /// Task id -> position in `entries`: ack binding checks in O(1).
    task_index: HashMap<String, usize>,
}

impl ReceiptLog {
    /// Open (or create) the journal in `state_dir`, replaying every
    /// stored record to rebuild the chain, the in-memory entries and
    /// the window index. The directory is created when missing. A
    /// corrupt line, an unverifiable signature or an unbound ack aborts
    /// the load: the journal is evidence, and silently skipping
    /// evidence is worse than refusing to start.
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
            task_ids: HashSet::new(),
            task_index: HashMap::new(),
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
                log.verify_ack_binding(&ack)?;
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

    /// Append one provider-signed receipt: the signature must verify
    /// against the embedded provider key and the task id must be new —
    /// the chain is a set, not a multiset — then the chain advances and
    /// the record is persisted and flushed.
    pub fn append(&mut self, receipt: Message) -> Result<()> {
        if !matches!(receipt, Message::Receipt { .. }) {
            bail!("only Receipt messages enter the receipt journal");
        }
        self.chain(&receipt)?;
        append_line(&self.receipts_file, "receipt", &receipt)?;
        Ok(())
    }

    /// Append one countersignature record. The ack is evidence of the
    /// consumer's consent to one exact charge, so it is bound to a
    /// receipt this node actually issued: the task id must be known and
    /// the carried hash must equal the stored receipt's hash, and the
    /// signature must verify. Anything else is refused and never
    /// reaches the ack journal.
    pub fn record_ack(&mut self, ack: Message) -> Result<()> {
        self.verify_ack_binding(&ack)?;
        append_line(&self.acks_file, "ack", &ack)?;
        Ok(())
    }

    /// Check one ack against the issued-receipt set: type, signature,
    /// known task id and matching receipt hash.
    fn verify_ack_binding(&self, ack: &Message) -> Result<()> {
        let Message::ReceiptAck {
            task_id,
            receipt_hash: ack_hash,
            unix_ts,
            pubkey,
            signature,
        } = ack
        else {
            bail!("only ReceiptAck messages enter the ack journal");
        };
        if verify_receipt_ack(task_id, ack_hash, *unix_ts, pubkey, signature).is_none() {
            bail!("ack signature does not verify");
        }
        let Some(&position) = self.task_index.get(task_id) else {
            bail!("ack references unknown task {task_id}");
        };
        if receipt_hash(&self.entries[position]) != *ack_hash {
            bail!("ack hash does not match the issued receipt");
        }
        Ok(())
    }

    /// Advance the in-memory chain over one receipt, mirroring the
    /// on-disk append. Refuses non-receipts, unverifiable signatures
    /// and duplicate task ids before touching any state.
    fn chain(&mut self, receipt: &Message) -> Result<()> {
        let Message::Receipt {
            task_id,
            provider_node,
            billed_secs,
            charge,
            outcome_hash,
            unix_ts,
            pubkey,
            signature,
        } = receipt
        else {
            bail!("chain accepts receipts only");
        };
        if verify_receipt(
            task_id,
            provider_node,
            *billed_secs,
            *charge,
            outcome_hash,
            *unix_ts,
            pubkey,
            signature,
        )
        .is_none()
        {
            bail!("receipt signature does not verify");
        }
        if !self.task_ids.insert(task_id.clone()) {
            bail!("duplicate receipt for task {task_id}");
        }
        self.index.insert(self.head, self.entries.len());
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(&self.head);
        material.extend_from_slice(&receipt.encode());
        self.head = *blake3::hash(&material).as_bytes();
        self.task_index.insert(task_id.clone(), self.entries.len());
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
mod tests;
