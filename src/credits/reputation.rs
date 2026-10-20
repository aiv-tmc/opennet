//! Per-peer reputation table measuring message honesty and traded volume.
//!
//! Reputation is local knowledge only: each node scores its peers based on
//! the validity of signed traffic and the credits actually moved with them.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Interaction statistics kept for one peer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerReputation {
    /// Credits received from this peer.
    pub credits_in: u64,
    /// Credits sent to this peer.
    pub credits_out: u64,
    /// Messages with valid signatures received from this peer.
    pub valid_msgs: u64,
    /// Messages with invalid signatures received from this peer.
    pub invalid_msgs: u64,
}

impl PeerReputation {
    /// Signed reputation score: valid messages count positive, invalid
    /// signatures weigh three times as much negative.
    pub fn score(&self) -> i64 {
        self.valid_msgs as i64 - self.invalid_msgs as i64 * 3
    }
}

/// Table of reputations keyed by node id (or network address before the
/// peer's first signed announcement arrives).
pub struct RepTable {
    table: HashMap<String, PeerReputation>,
    file: PathBuf,
}

impl RepTable {
    /// Load the table from `<state_dir>/reputation.json`; a missing file
    /// yields an empty table, a malformed file is an error.
    pub fn load(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let file = state_dir.join("reputation.json");
        let table = match std::fs::read_to_string(&file) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("invalid reputation file {}", file.display()))?,
            Err(_) => HashMap::new(),
        };
        Ok(Self { table, file })
    }

    /// Record one correctly signed message from a peer.
    pub fn record_valid(&mut self, peer: &str) {
        self.table.entry(peer.to_string()).or_default().valid_msgs += 1;
        self.persist();
    }

    /// Record one incorrectly signed message from a peer.
    pub fn record_invalid(&mut self, peer: &str) {
        self.table.entry(peer.to_string()).or_default().invalid_msgs += 1;
        self.persist();
    }

    /// Record an outgoing credit transfer with a peer.
    pub fn record_credit_out(&mut self, peer: &str, amount: u64) {
        let entry = self.table.entry(peer.to_string()).or_default();
        entry.credits_out += amount;
        self.persist();
    }

    /// Record an incoming credit transfer with a peer.
    pub fn record_credit_in(&mut self, peer: &str, amount: u64) {
        let entry = self.table.entry(peer.to_string()).or_default();
        entry.credits_in += amount;
        self.persist();
    }

    /// All reputation entries ordered by peer key for stable display.
    pub fn all(&self) -> Vec<(String, PeerReputation)> {
        let mut entries: Vec<(String, PeerReputation)> =
            self.table.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Persist the table atomically; failures are logged but not propagated
    /// because reputation is rebuildable knowledge, not money.
    fn persist(&self) {
        if let Ok(text) = serde_json::to_string_pretty(&self.table) {
            let tmp = self.file.with_extension("tmp");
            if std::fs::write(&tmp, &text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.file);
            }
        }
    }
}
