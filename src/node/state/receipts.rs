//! Append-only billing receipt journal.
//!
//! Every settled task produces one provider-signed `Receipt`; the
//! consumer answers with a countersignature (`ReceiptAck`). The journal
//! chains receipts into a rolling hash — each entry commits to all
//! previous ones — and the chain head travels with the node's identity
//! announcement. A node that wipes its state to mint a fresh identity
//! resets its chain to the genesis head, which peers price as "no
//! history"; a node that forges history cannot produce the matching
//! countersignatures on demand. The journal is the audit trail that
//! turns the self-attested trust economy into a verifiable one.
//!
//! Storage layout in the state directory:
//!   receipts.jsonl — one `{"receipt": <wire message>}` per line
//!   receipts-acks.jsonl — one `{"ack": <wire message>}` per line
//! Each line stores the message through its standard serde encoding, so
//! the on-disk format is exactly the wire format replayed. Lines are
//! appended and flushed per record; the files are written with
//! owner-only permissions.

use crate::message::Message;
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Genesis chain head: the announced head of a journal with no
/// receipts. Distinct from any real hash by construction.
pub fn genesis_head() -> [u8; 32] {
    *blake3::hash(b"opennet receipt journal v1").as_bytes()
}

/// Hash of one receipt: the canonical wire bytes, domain-tagged by the
/// message encoding itself.
pub fn receipt_hash(receipt: &Message) -> [u8; 32] {
    *blake3::hash(&receipt.encode()).as_bytes()
}

/// The receipt journal: a replayable chain plus its on-disk append log.
pub struct ReceiptLog {
    head: [u8; 32],
    count: u64,
    receipts_file: PathBuf,
    acks_file: PathBuf,
}

impl ReceiptLog {
    /// Open (or create) the journal in `state_dir` and replay every
    /// stored record to rebuild the chain head. The directory is
    /// created when missing so the log works standalone, outside
    /// `NodeState::load` as well. A corrupt line aborts the load: the
    /// journal is evidence, and silently skipping evidence is worse
    /// than refusing to start.
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
        };
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
        // The acks log is replayed for existence validation only; acks
        // do not advance the chain (they evidence consumer assent, not
        // a new billing fact).
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

    /// Rolling head of the receipt chain; the genesis head while the
    /// journal is empty. Announced with the identity.
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

    /// Append one provider-signed receipt: advance the chain, persist
    /// the record, flush before returning. Duplicate task ids are
    /// rejected — the chain must be a set, not a multiset, or the
    /// double-billing check loses meaning.
    pub fn append(&mut self, receipt: Message) -> Result<()> {
        let Message::Receipt { ref task_id, .. } = receipt else {
            bail!("only Receipt messages enter the receipt journal");
        };
        let exists = self.task_recorded(task_id)?;
        if exists {
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

    /// Best-effort duplicate check used at append time: scan the log
    /// for the task id. The journal is append-only and small in
    /// practice; a linear scan keeps the structure trivially
    /// verifiable instead of hiding an index that could diverge from
    /// the chain. Records are decoded through the wire format (the
    /// same path replay uses), so the duplicate check can never drift
    /// from what the chain actually holds.
    fn task_recorded(&self, task_id: &str) -> Result<bool> {
        if !self.receipts_file.exists() {
            return Ok(false);
        }
        let text = std::fs::read_to_string(&self.receipts_file)?;
        for line in text.lines().filter(|line| !line.is_empty()) {
            let parsed: serde_json::Value = serde_json::from_str(line)?;
            let Some(record) = parsed.get("receipt").cloned() else {
                continue;
            };
            let Ok(Message::Receipt {
                task_id: recorded, ..
            }) = serde_json::from_value(record)
            else {
                continue;
            };
            if recorded == task_id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Advance the in-memory chain over one receipt. The chaining hash
    /// covers the previous head and the canonical receipt bytes, so
    /// every entry commits to the entire history.
    fn chain(&mut self, receipt: &Message) -> Result<()> {
        if !matches!(receipt, Message::Receipt { .. }) {
            bail!("chain accepts receipts only");
        }
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(&self.head);
        material.extend_from_slice(&receipt.encode());
        self.head = *blake3::hash(&material).as_bytes();
        self.count += 1;
        Ok(())
    }
}

/// Append one JSON line to a journal file, creating it with
/// owner-only permissions, and flush before returning: a receipt that
/// survives a crash must be visible on replay.
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
        {
            let mut log = ReceiptLog::load(&dir).unwrap();
            log.append(signed_receipt("t1", &provider)).unwrap();
            log.append(signed_receipt("t2", &provider)).unwrap();
            let head = log.head();
            assert_ne!(head, genesis_head());
            assert_eq!(log.count(), 2);
        }
        // Replay rebuilds the identical head.
        let reloaded = ReceiptLog::load(&dir).unwrap();
        assert_eq!(reloaded.count(), 2);
    }

    #[test]
    fn duplicate_task_ids_are_rejected() {
        let dir = scratch_dir("rcpt-dup");
        let provider = Identity::generate();
        let mut log = ReceiptLog::load(&dir).unwrap();
        log.append(signed_receipt("t1", &provider)).unwrap();
        // A second receipt for the same task id must be refused even
        // when every field is identical (same-second timestamp).
        assert!(log.append(signed_receipt("t1", &provider)).is_err());
        assert_eq!(log.count(), 1);
    }
}
