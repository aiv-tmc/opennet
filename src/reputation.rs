//! Peer reputation table: tracks valid and invalid messages per peer and
//! derives a simple score used to break ties when the compute client
//! picks a provider. Scores are persisted to `<state_dir>/reputation.json`.
//!
//! Every table write is small and rare (one per announcement or failed
//! verification), so persisting on each record keeps the table durable
//! without measurable overhead.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Counters kept for one peer identity or connection address.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Rep {
    /// Messages that passed full verification.
    pub valid_msgs: u64,
    /// Messages that failed verification.
    pub invalid_msgs: u64,
}

impl Rep {
    /// Net reputation: valid minus invalid messages.
    pub fn score(&self) -> i64 {
        self.valid_msgs as i64 - self.invalid_msgs as i64
    }
}

/// Table of reputation counters keyed by node id or connection address.
pub struct RepTable {
    entries: HashMap<String, Rep>,
    file: PathBuf,
}

impl RepTable {
    /// Load the table from `<state_dir>/reputation.json`; a missing file
    /// yields an empty table and a malformed file is an error.
    pub fn load(state_dir: &Path) -> Result<Self> {
        let file = state_dir.join("reputation.json");
        let entries = match std::fs::read_to_string(&file) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("invalid reputation file {}", file.display()))?,
            Err(_) => HashMap::new(),
        };
        Ok(Self { entries, file })
    }

    /// Record one fully verified message from `peer` and persist.
    pub fn record_valid(&mut self, peer: &str) {
        let entry = self.entries.entry(peer.to_string()).or_insert(Rep {
            valid_msgs: 0,
            invalid_msgs: 0,
        });
        entry.valid_msgs += 1;
        let _ = self.save();
    }

    /// Record one failed verification attributed to `peer` and persist.
    pub fn record_invalid(&mut self, peer: &str) {
        let entry = self.entries.entry(peer.to_string()).or_insert(Rep {
            valid_msgs: 0,
            invalid_msgs: 0,
        });
        entry.invalid_msgs += 1;
        let _ = self.save();
    }

    /// Net score of one peer; unknown peers score zero.
    pub fn score_of(&self, peer: &str) -> i64 {
        self.entries.get(peer).map(|rep| rep.score()).unwrap_or(0)
    }

    /// All entries ordered by score, highest first.
    pub fn all(&self) -> Vec<(String, Rep)> {
        let mut entries: Vec<(String, Rep)> = self.entries.clone().into_iter().collect();
        entries.sort_by_key(|(_, rep)| std::cmp::Reverse(rep.score()));
        entries
    }

    /// Persist the table atomically (temp file plus rename), creating the
    /// parent directory first so early records cannot be lost to a missing
    /// state directory.
    fn save(&self) -> Result<()> {
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(&self.entries)?;
        let tmp = self.file.with_extension("tmp");
        std::fs::write(&tmp, &text)?;
        std::fs::rename(&tmp, &self.file)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch_dir;

    #[test]
    fn scores_grow_and_shrink_with_verification_outcomes() {
        let mut table = RepTable::load(&scratch_dir("rep-basic")).unwrap();
        table.record_valid("node-a");
        table.record_valid("node-a");
        table.record_invalid("node-a");
        assert_eq!(table.score_of("node-a"), 1);
        assert_eq!(table.score_of("stranger"), 0);
    }

    #[test]
    fn table_persists_between_loads() {
        let dir = scratch_dir("rep-persist");
        {
            let mut table = RepTable::load(&dir).unwrap();
            table.record_valid("node-b");
            table.record_invalid("node-c");
        }
        let reloaded = RepTable::load(&dir).unwrap();
        assert_eq!(reloaded.score_of("node-b"), 1);
        assert_eq!(reloaded.score_of("node-c"), -1);
    }

    #[test]
    fn all_orders_by_descending_score() {
        let mut table = RepTable::load(&scratch_dir("rep-order")).unwrap();
        table.record_valid("good");
        table.record_valid("good");
        table.record_invalid("bad");
        let entries = table.all();
        assert_eq!(entries[0].0, "good");
        assert_eq!(entries[1].0, "bad");
    }
}
