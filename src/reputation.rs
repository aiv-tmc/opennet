//! Per-peer reputation table measuring message honesty.
//!
//! Reputation is local knowledge only: each node scores its peers based on
//! the validity of signed traffic. Invalid announcements and provably
//! fraudulent bids lower the score and persist across restarts, so repeated
//! misbehaviour accumulates even when the trust coefficient does not.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Interaction statistics kept for one peer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerReputation {
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

    /// Record one incorrectly signed or provably fraudulent message from a
    /// peer.
    pub fn record_invalid(&mut self, peer: &str) {
        self.table.entry(peer.to_string()).or_default().invalid_msgs += 1;
        self.persist();
    }

    /// All reputation entries ordered by peer key for stable display.
    pub fn all(&self) -> Vec<(String, PeerReputation)> {
        let mut entries: Vec<(String, PeerReputation)> = self
            .table
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Persist the table atomically; failures are logged but not propagated
    /// because reputation is rebuildable knowledge.
    fn persist(&self) {
        if let Ok(text) = serde_json::to_string_pretty(&self.table) {
            let tmp = self.file.with_extension("tmp");
            if std::fs::write(&tmp, &text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.file);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch_dir;

    #[test]
    fn fresh_table_is_empty() {
        let table = RepTable::load(&scratch_dir("rep-fresh")).unwrap();
        assert!(table.all().is_empty());
    }

    #[test]
    fn counts_accumulate_and_score_weighs_invalid_threefold() {
        let mut table = RepTable::load(&scratch_dir("rep-score")).unwrap();
        table.record_valid("node-a");
        table.record_valid("node-a");
        table.record_invalid("node-a");
        let (_, rep) = table.all().pop().expect("entry missing");
        assert_eq!(rep.valid_msgs, 2);
        assert_eq!(rep.invalid_msgs, 1);
        assert_eq!(rep.score(), -1);
    }

    #[test]
    fn table_persists_across_loads() {
        let dir = scratch_dir("rep-persist");
        {
            let mut table = RepTable::load(&dir).unwrap();
            table.record_valid("node-a");
            table.record_invalid("node-b");
        }
        let table = RepTable::load(&dir).unwrap();
        let entries = table.all();
        assert_eq!(entries.len(), 2);
        let a = entries.iter().find(|(k, _)| k == "node-a").unwrap();
        let b = entries.iter().find(|(k, _)| k == "node-b").unwrap();
        assert_eq!(a.1.valid_msgs, 1);
        assert_eq!(b.1.invalid_msgs, 1);
    }

    #[test]
    fn entries_are_sorted_by_key() {
        let mut table = RepTable::load(&scratch_dir("rep-sort")).unwrap();
        table.record_valid("node-b");
        table.record_valid("node-a");
        let keys: Vec<String> = table.all().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["node-a".to_string(), "node-b".to_string()]);
    }

    #[test]
    fn malformed_file_is_an_error() {
        let dir = scratch_dir("rep-bad");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("reputation.json"), "not json").unwrap();
        assert!(RepTable::load(&dir).is_err());
    }
}
