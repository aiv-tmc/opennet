//! Peer reputation table: tracks valid and invalid messages per peer
//! and derives a simple score used to break ties when the compute
//! client picks a provider.
//!
//! Two guards keep the table cheap at steady state: disk writes are
//! debounced to at most one per interval (records mark the table dirty
//! and are persisted on the next debounced save or an explicit flush),
//! and the table is capped, evicting the weakest entries when a burst
//! of new peers would push it past the cap. The counter updates
//! themselves are always in-memory and immediate.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Upper bound on tracked peers; when a new record would exceed it,
/// the weakest entry is evicted so a flood of fresh identities cannot
/// grow the table without bound.
const MAX_ENTRIES: usize = 1024;

/// Minimum time between disk writes; records inside the window only
/// set the dirty flag and are persisted by the first record after the
/// window or by an explicit `flush`.
const SAVE_DEBOUNCE: Duration = Duration::from_secs(30);

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
    /// Whether the in-memory counters hold changes not yet on disk.
    dirty: bool,
    /// When the last disk write completed; the debounce window is
    /// measured from this instant.
    last_save: Instant,
}

impl RepTable {
    /// Load the table from `<state_dir>/reputation.json`; a missing file
    /// yields an empty table and a malformed file is an error. The
    /// debounce clock starts one full window in the past so the first
    /// record of a session persists immediately.
    pub fn load(state_dir: &Path) -> Result<Self> {
        let file = state_dir.join("reputation.json");
        let entries = match std::fs::read_to_string(&file) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("invalid reputation file {}", file.display()))?,
            Err(_) => HashMap::new(),
        };
        Ok(Self {
            entries,
            file,
            dirty: false,
            last_save: Instant::now()
                .checked_sub(SAVE_DEBOUNCE)
                .unwrap_or_else(Instant::now),
        })
    }

    /// Record one fully verified message from `peer`. The counter
    /// updates immediately; the disk write is debounced.
    pub fn record_valid(&mut self, peer: &str) {
        let entry = self.entries.entry(peer.to_string()).or_insert(Rep {
            valid_msgs: 0,
            invalid_msgs: 0,
        });
        entry.valid_msgs += 1;
        self.note_change();
    }

    /// Record one failed verification attributed to `peer`. The counter
    /// updates immediately; the disk write is debounced.
    pub fn record_invalid(&mut self, peer: &str) {
        let entry = self.entries.entry(peer.to_string()).or_insert(Rep {
            valid_msgs: 0,
            invalid_msgs: 0,
        });
        entry.invalid_msgs += 1;
        self.note_change();
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

    /// Persist any pending records now; the daemon calls this during
    /// graceful shutdown so no verification outcome recorded in the
    /// last debounce window is lost.
    pub fn flush(&mut self) {
        if self.dirty {
            self.persist();
        }
    }

    /// Mark the table dirty after a counter change and run the
    /// debounced save when the window has elapsed. Eviction runs
    /// before the save so the cap always bounds what reaches disk.
    fn note_change(&mut self) {
        self.dirty = true;
        // When the table is full, a record weaker than every resident
        // is itself the weakest entry and is evicted: established
        // peers are retained over fresh identities.
        while self.entries.len() > MAX_ENTRIES {
            self.evict_weakest();
        }
        if self.last_save.elapsed() >= SAVE_DEBOUNCE {
            self.persist();
        }
    }

    /// Remove the weakest entry: lowest score first, then fewest valid
    /// messages, then the key, so the eviction order is deterministic.
    fn evict_weakest(&mut self) {
        let weakest = self
            .entries
            .iter()
            .map(|(key, rep)| (rep.score(), rep.valid_msgs, key.clone()))
            .min()
            .map(|(_, _, key)| key);
        if let Some(key) = weakest {
            self.entries.remove(&key);
        }
    }

    /// Write the table atomically (temp file plus rename), creating the
    /// parent directory first so early records cannot be lost to a
    /// missing state directory. On failure the dirty flag stays set so
    /// the next window retries instead of silently dropping the record.
    fn persist(&mut self) {
        let result = (|| -> Result<()> {
            if let Some(parent) = self.file.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let text = serde_json::to_string_pretty(&self.entries)?;
            let tmp = self.file.with_extension("tmp");
            std::fs::write(&tmp, &text)?;
            std::fs::rename(&tmp, &self.file)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.dirty = false;
                self.last_save = Instant::now();
            }
            Err(err) => eprintln!("[opennetd] cannot save reputation table: {err:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch_dir;

    /// Fill the table with `count` distinct peers holding `strength`
    /// valid records each.
    fn fill(table: &mut RepTable, count: usize, strength: u64) {
        for index in 0..count {
            let key = format!("peer-{index:05}");
            for _ in 0..strength {
                table.record_valid(&key);
            }
        }
    }

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
    fn records_survive_a_reload_after_an_explicit_flush() {
        let dir = scratch_dir("rep-persist");
        {
            let mut table = RepTable::load(&dir).unwrap();
            table.record_valid("node-b");
            table.record_invalid("node-c");
            table.flush();
        }
        let reloaded = RepTable::load(&dir).unwrap();
        assert_eq!(reloaded.score_of("node-b"), 1);
        assert_eq!(reloaded.score_of("node-c"), -1);
    }

    #[test]
    fn unflushed_records_are_not_on_disk_yet() {
        // The debounce window keeps recent records in memory only; a
        // reload before the first save sees the table as it was on the
        // last disk write.
        let dir = scratch_dir("rep-debounce");
        {
            let mut table = RepTable::load(&dir).unwrap();
            table.record_valid("fresh-node");
            table.flush();
            table.record_valid("fresh-node");
            table.record_valid("fresh-node");
        }
        let reloaded = RepTable::load(&dir).unwrap();
        assert_eq!(reloaded.score_of("fresh-node"), 1);
    }

    #[test]
    fn the_cap_holds_and_a_stronger_challenger_evicts_the_weakest_resident() {
        let dir = scratch_dir("rep-cap");
        let mut table = RepTable::load(&dir).unwrap();
        // Every resident holds the same score, so the eviction order is
        // decided purely by the deterministic key tiebreak: the
        // challenger key sorts after every resident key.
        fill(&mut table, MAX_ENTRIES, 1);
        assert_eq!(table.entries.len(), MAX_ENTRIES);
        for _ in 0..4 {
            table.record_valid("zzz-challenger");
        }
        // The cap still holds exactly; the challenger entered and the
        // weakest resident (smallest key among equals) made room.
        assert_eq!(table.entries.len(), MAX_ENTRIES);
        assert_eq!(table.score_of("zzz-challenger"), 4);
        assert_eq!(table.score_of("peer-00000"), 0);
        assert!(table.score_of("peer-00001") > 0);
    }

    #[test]
    fn a_weaker_newcomer_is_not_tracked_while_the_table_is_full() {
        let dir = scratch_dir("rep-cap-full");
        let mut table = RepTable::load(&dir).unwrap();
        fill(&mut table, MAX_ENTRIES, 2);
        assert_eq!(table.entries.len(), MAX_ENTRIES);
        // A single weak record is weaker than every resident, so the
        // newcomer itself is the eviction victim and never enters.
        table.record_valid("weak-newcomer");
        assert_eq!(table.entries.len(), MAX_ENTRIES);
        assert_eq!(table.score_of("weak-newcomer"), 0);
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
