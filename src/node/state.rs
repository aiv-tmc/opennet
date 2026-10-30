//! Node state: operating mode, trust coefficient, consumption counter,
//! message counters, task statistics, and in-memory task reservations.
//!
//! The trust economy is local double-entry bookkeeping. This node tracks
//! its own trust (`trust`) and the units it has effectively spent on
//! remote work (`consumed`). Providers credit their own trust by the same
//! amounts they bill, so units are conserved network-wide.
//!
//! Reservations are held in memory only: a task's price is deducted
//! from `trust` for the lifetime of the task and either settled
//! (partially refunded) or released (fully refunded) afterwards. A daemon
//! restart therefore discards outstanding reservations; state files
//! written by older versions persisted their reservation maps, and those
//! are refunded at load time so nothing is owed across restarts either
//! way.
//!
//! The state file is written atomically (tmp file + rename) with
//! owner-only permissions: trust and consumption data is sensitive local
//! state and must not be world-readable.

use crate::config::{Limits, TrustCfg};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Operating mode of a node. Serialized lowercase (`"peer"`, `"seed"`,
/// `"leech"`) in both TOML config and JSON state files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Donates capacity and requests tasks.
    #[default]
    Peer,
    /// Donates capacity only; accumulates trust.
    Seed,
    /// Requests tasks only; never donates.
    Leech,
}

impl Mode {
    /// Config-file representation of the mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Peer => "peer",
            Mode::Seed => "seed",
            Mode::Leech => "leech",
        }
    }

    /// Parse the config-file representation; unknown values are an
    /// error so a typo never silently changes the operating mode.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "peer" => Ok(Mode::Peer),
            "seed" => Ok(Mode::Seed),
            "leech" => Ok(Mode::Leech),
            other => Err(format!("unknown mode '{other}' (expected peer|seed|leech)")),
        }
    }

    /// Whether this mode donates capacity to the network.
    pub fn donates(self) -> bool {
        !matches!(self, Mode::Leech)
    }
}

/// Mutable node state guarded by the daemon.
#[derive(Clone, Debug)]
pub struct NodeState {
    /// Operating mode: peer, seed or leech.
    pub mode: Mode,
    /// Trust coefficient: grows when this node donates compute, shrinks
    /// when it spends trust on remote work.
    pub trust: i64,
    /// Total units this node has been charged for remote work.
    pub consumed: u64,
    /// Capacity points this node charges for its donated capacity.
    pub points: u32,
    /// Lifetime message counters for the status report.
    pub msgs_sent: u64,
    pub msgs_received: u64,
    /// Completed and failed tasks executed for remote consumers.
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    /// Advertised resource limits.
    pub limits: Limits,
    /// Outstanding reservations keyed by task id. Public for read-only
    /// renderers; mutated only through `reserve` / `release` / `settle`.
    pub reservations: HashMap<String, i64>,
    /// Directory the state file lives in.
    state_dir: PathBuf,
    /// Daemon start time for the uptime report.
    started: Instant,
}

/// Persistent portion of the node state.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedState {
    mode: Mode,
    trust: i64,
    consumed: u64,
    points: u32,
    msgs_sent: u64,
    msgs_received: u64,
    tasks_completed: u64,
    tasks_failed: u64,
    /// Outstanding reservations keyed by task id; only populated by
    /// state files written by older versions (current versions keep
    /// reservations in memory), and refunded at load time by
    /// `refund_stale_reservations`.
    #[serde(default)]
    reservations: HashMap<String, i64>,
}

impl NodeState {
    /// Load persisted state from `state_dir`, falling back to fresh
    /// genesis state when the file is missing or unreadable.
    pub fn load(
        state_dir: &Path,
        default_mode: Mode,
        limits: Limits,
        trust_cfg: &TrustCfg,
    ) -> std::io::Result<Self> {
        let file = state_file(state_dir);
        let mut state = match std::fs::read_to_string(&file) {
            Ok(text) => {
                let persisted: PersistedState = serde_json::from_str(&text)?;
                Self {
                    mode: persisted.mode,
                    trust: persisted.trust,
                    consumed: persisted.consumed,
                    points: persisted.points,
                    msgs_sent: persisted.msgs_sent,
                    msgs_received: persisted.msgs_received,
                    tasks_completed: persisted.tasks_completed,
                    tasks_failed: persisted.tasks_failed,
                    limits,
                    reservations: persisted.reservations,
                    state_dir: state_dir.to_path_buf(),
                    started: Instant::now(),
                }
            }
            Err(_) => Self {
                mode: default_mode,
                trust: trust_cfg.genesis_trust,
                consumed: 0,
                points: 0,
                msgs_sent: 0,
                msgs_received: 0,
                tasks_completed: 0,
                tasks_failed: 0,
                limits,
                reservations: HashMap::new(),
                state_dir: state_dir.to_path_buf(),
                started: Instant::now(),
            },
        };
        state.refund_stale_reservations();
        Ok(state)
    }

    /// Persist mode, trust, consumption and counters atomically to this
    /// node's state file. The tmp file is created owner-readable-only
    /// before the rename so the state never exists with default umask
    /// permissions.
    pub fn save(&self) -> std::io::Result<()> {
        let file = state_file(&self.state_dir);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let persisted = PersistedState {
            mode: self.mode,
            trust: self.trust,
            consumed: self.consumed,
            points: self.points,
            msgs_sent: self.msgs_sent,
            msgs_received: self.msgs_received,
            tasks_completed: self.tasks_completed,
            tasks_failed: self.tasks_failed,
            reservations: self.reservations.clone(),
        };
        let text = serde_json::to_string_pretty(&persisted)?;
        let tmp = file.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &file)?;
        Ok(())
    }

    /// Refund reservations loaded from an older state file: a task whose
    /// reservation survived a crash never settled, so its units return
    /// to the coefficient here.
    fn refund_stale_reservations(&mut self) {
        let stale: i128 = self.reservations.values().map(|units| *units as i128).sum();
        if stale > 0 {
            self.trust =
                (self.trust as i128 + stale).clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        }
        self.reservations.clear();
    }

    /// Deduct `units` from trust and register `task_id` as outstanding.
    /// The floor check uses the effective trust after the deduction, so
    /// concurrent reservations compose correctly.
    pub fn reserve(&mut self, task_id: &str, units: i64, floor: i64) -> Result<(), String> {
        let available = self.trust as i128 - units as i128;
        if available < floor as i128 {
            return Err(format!(
                "insufficient trust: need {units} units, have {} (floor {floor})",
                self.trust
            ));
        }
        self.trust -= units;
        self.reservations.insert(task_id.to_string(), units);
        Ok(())
    }

    /// Refund a reservation in full when the task never ran: rejection,
    /// timeout, or an error before the assignment completed.
    pub fn release(&mut self, task_id: &str) {
        if let Some(units) = self.reservations.remove(task_id) {
            self.trust = self.trust.saturating_add(units);
        }
    }

    /// Settle a finished task: the reservation registered under
    /// `task_id` is compared against the final `billed` units, the
    /// difference is refunded and the consumption counter grows by the
    /// charge. Settling an unknown task id is a no-op, so retried
    /// outcome frames cannot double-charge.
    pub fn settle(&mut self, task_id: &str, billed: i64) -> i64 {
        let Some(reserved) = self.reservations.remove(task_id) else {
            return 0;
        };
        let refund = reserved - billed;
        if refund > 0 {
            self.trust = self.trust.saturating_add(refund);
        }
        self.consumed = self.consumed.saturating_add(billed.max(0) as u64);
        refund
    }

    /// Total outstanding reservation units; used by the provider's
    /// acceptance policy together with the announced consumption.
    pub fn reserved_total(&self) -> i64 {
        self.reservations.values().copied().sum()
    }

    /// Snapshot of outstanding reservation ids for the status report.
    pub fn reservation_ids(&self) -> Vec<String> {
        self.reservations.keys().cloned().collect()
    }

    /// Daemon uptime for the status report.
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Path of the persisted state file inside `state_dir`.
fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join("state.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trust_cfg() -> TrustCfg {
        TrustCfg {
            genesis_trust: 100,
            min_trust: 0,
            points_per_core: 10,
            points_per_gb: 2,
        }
    }

    fn limits() -> Limits {
        Limits {
            cpu_percent: 50,
            ram_mb: 512,
            max_tasks: 4,
        }
    }

    fn state(trust: i64) -> NodeState {
        let mut s = NodeState::load(
            Path::new("/nonexistent-state-dir"),
            Mode::Peer,
            limits(),
            &trust_cfg(),
        )
        .unwrap();
        s.trust = trust;
        s
    }

    #[test]
    fn mode_serializes_lowercase_for_toml_and_json() {
        assert_eq!(serde_json::to_string(&Mode::Peer).unwrap(), "\"peer\"");
        assert_eq!(serde_json::to_string(&Mode::Seed).unwrap(), "\"seed\"");
        assert_eq!(serde_json::to_string(&Mode::Leech).unwrap(), "\"leech\"");
    }

    #[test]
    fn mode_parse_roundtrip_and_errors() {
        assert_eq!(Mode::parse("peer").unwrap(), Mode::Peer);
        assert_eq!(Mode::parse("seed").unwrap(), Mode::Seed);
        assert_eq!(Mode::parse("leech").unwrap(), Mode::Leech);
        assert!(Mode::parse("bogus").is_err());
        assert!(Mode::Seed.donates());
        assert!(!Mode::Leech.donates());
    }

    #[test]
    fn reserve_deducts_and_enforces_floor() {
        let mut s = state(100);
        s.reserve("a", 40, 0).unwrap();
        assert_eq!(s.trust, 60);
        assert!(s.reserve("b", 70, 0).is_err());
        assert_eq!(s.trust, 60);
    }

    #[test]
    fn release_refunds_only_live_reservations() {
        let mut s = state(100);
        s.reserve("a", 40, 0).unwrap();
        s.release("a");
        assert_eq!(s.trust, 100);
        // A duplicate release for the same id must not mint trust.
        s.release("a");
        assert_eq!(s.trust, 100);
    }

    #[test]
    fn settle_refunds_the_difference_and_records_consumption() {
        let mut s = state(100);
        s.reserve("a", 50, 0).unwrap();
        let refund = s.settle("a", 20);
        assert_eq!(refund, 30);
        assert_eq!(s.trust, 80);
        assert_eq!(s.consumed, 20);
        // Settling the same task again is a no-op.
        assert_eq!(s.settle("a", 20), 0);
        assert_eq!(s.trust, 80);
        assert_eq!(s.consumed, 20);
    }

    #[test]
    fn stale_reservations_are_refunded_and_file_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("opennet-state-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        s.trust = 100;
        s.reservations.insert("crash-task".to_string(), 40);
        s.save().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("state.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let loaded = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        assert_eq!(loaded.trust, 140);
        assert!(loaded.reservation_ids().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
