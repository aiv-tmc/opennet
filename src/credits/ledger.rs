//! Append-only log of credit movements with the most recent entries cached.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Direction of a logged credit movement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TransferKind {
    /// Credits sent to a peer.
    Outgoing,
    /// Credits received from a peer.
    Incoming,
    /// Credits returned because the peer rejected the transfer.
    Refund,
}

/// One entry of the transfer log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    /// Unique identifier of the transfer.
    pub task_id: String,
    /// Node id of the counterparty.
    pub counterparty: String,
    /// Number of credits moved.
    pub amount: u64,
    /// Direction of the movement.
    pub kind: TransferKind,
    /// Unix timestamp of the event.
    pub unix_ts: u64,
}

/// How many recent records are kept in memory for display.
const RECENT_CAP: usize = 100;

/// Append-only transfer log backed by a JSON-lines file on disk.
pub struct Ledger {
    log_file: PathBuf,
    recent: Vec<TransferRecord>,
}

impl Ledger {
    /// Open `<state_dir>/transfers.log` and cache its last entries in memory.
    ///
    /// Malformed lines are skipped with a warning because the log must
    /// survive partial writes from an interrupted process.
    pub fn load(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let log_file = state_dir.join("transfers.log");
        let mut recent: Vec<TransferRecord> = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&log_file) {
            for line in text.lines() {
                match serde_json::from_str::<TransferRecord>(line) {
                    Ok(record) => recent.push(record),
                    Err(_) => eprintln!("[ledger] skipping malformed log line"),
                }
            }
        }
        recent.drain(..recent.len().saturating_sub(RECENT_CAP));
        Ok(Self { log_file, recent })
    }

    /// Append a record to the on-disk log and the in-memory cache.
    pub fn append(&mut self, record: TransferRecord) -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
            .with_context(|| format!("cannot open ledger {}", self.log_file.display()))?;
        let line = serde_json::to_string(&record)?;
        writeln!(file, "{line}")?;
        self.recent.push(record);
        if self.recent.len() > RECENT_CAP {
            self.recent.drain(..self.recent.len() - RECENT_CAP);
        }
        Ok(())
    }

    /// The most recent records, oldest first, up to `limit` entries.
    pub fn tail(&self, limit: usize) -> &[TransferRecord] {
        let start = self.recent.len().saturating_sub(limit);
        &self.recent[start..]
    }
}

/// Current unix time in seconds; used to timestamp transfer records.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
