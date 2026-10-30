//! Node state: operating mode, trust coefficient, consumption counter,
//! task statistics, and in-memory task reservations.
//!
//! The trust economy is local double-entry bookkeeping. This node tracks
//! its own trust (`trust`) and the units it has effectively spent on
//! remote work (`consumed`). Providers credit their own trust by the
//! same amounts they bill, so units are conserved network-wide.
//!
//! Reservations are held in memory only: a task's price is deducted
//! from `trust` for the lifetime of the task and either settled
//! (partially refunded) or released (fully refunded) afterwards. A
//! daemon restart therefore discards outstanding reservations; state
//! files written by older versions persisted their reservation maps,
//! and those are refunded at load time so nothing is owed across
//! restarts either way.
//!
//! The state file is written atomically (tmp file + rename) with
//! owner-only permissions: trust and consumption data is sensitive
//! local state and must not be world-readable. The first boot (and a
//! boot that refunded stale reservations) materializes the file so it
//! always exists; clean reloads never rewrite it on load.

use crate::config::{Limits, TrustCfg};
use crate::trust::points::compute_points;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// How the node participates in the network. Serialized lowercase in
/// both TOML config and JSON state files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Give and take compute capacity.
    Peer,
    /// Only donate capacity and accumulate trust.
    Seed,
    /// Only consume capacity from the network.
    Leech,
}

impl Mode {
    /// Machine-readable mode name used on the wire and in the control
    /// socket.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Seed => "seed",
            Self::Leech => "leech",
        }
    }

    /// Parse a mode name; unknown names are rejected.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "peer" => Ok(Self::Peer),
            "seed" => Ok(Self::Seed),
            "leech" => Ok(Self::Leech),
            other => bail!("unknown mode '{other}', expected peer, seed or leech"),
        }
    }
}

/// State fields persisted to disk between daemon restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    mode: Mode,
    trust: i64,
    consumed: u64,
    #[serde(default)]
    tasks_completed: u64,
    #[serde(default)]
    tasks_failed: u64,
    /// Trust units held by tasks that were reserved but not yet
    /// settled; only populated by older versions, since reservations
    /// now stay in memory.
    #[serde(default)]
    reservations: HashMap<String, i64>,
}

/// Mutable runtime state shared across daemon tasks.
pub struct NodeState {
    pub mode: Mode,
    /// Trust coefficient earned by donating compute and spent by
    /// consuming it; providers gate acceptance on this value as last
    /// announced. Reservations are already deducted from this value.
    pub trust: i64,
    /// Cumulative trust units consumed on remote providers, announced
    /// in every bid so providers can audit the claimed trust
    /// arithmetic.
    pub consumed: u64,
    /// Static capacity price of this node's offered hardware,
    /// announced to peers and used to charge consumers for executed
    /// tasks.
    pub points: u32,
    /// Total wire messages sent to peers.
    pub msgs_sent: u64,
    /// Total wire messages received from peers.
    pub msgs_received: u64,
    /// Number of remote tasks that finished with exit code zero.
    pub tasks_completed: u64,
    /// Number of remote tasks that failed or timed out.
    pub tasks_failed: u64,
    started: Instant,
    state_file: PathBuf,
    /// Resource limits offered to the network.
    pub limits: Limits,
    /// Units currently reserved by in-flight local tasks, keyed by
    /// task id. In-memory only; a crash refunds them on boot.
    pub reservations: HashMap<String, i64>,
}

impl NodeState {
    /// Load persisted state from `<state_dir>/state.json` or start
    /// with the genesis trust endowment; a malformed file is reported
    /// as an error.
    ///
    /// On first boot (no state file) the initial state is written to
    /// disk so the file always exists. Reservations surviving from
    /// older state files are refunded into trust on the spot: their
    /// tasks can never complete after a restart, so keeping the
    /// deduction would silently burn the user's trust. Clean restarts
    /// never rewrite the file.
    pub fn load(
        state_dir: &Path,
        default_mode: Mode,
        limits: Limits,
        trust_cfg: &TrustCfg,
    ) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("cannot create state dir {}", state_dir.display()))?;
        let state_file = state_dir.join("state.json");
        let existed = state_file.exists();
        let mut mode = default_mode;
        let mut trust = trust_cfg.genesis_trust;
        let mut consumed = 0u64;
        let mut tasks_completed = 0u64;
        let mut tasks_failed = 0u64;
        let mut reservations = HashMap::new();
        if existed {
            let text = std::fs::read_to_string(&state_file)
                .with_context(|| format!("cannot read state file {}", state_file.display()))?;
            let persisted: PersistedState = serde_json::from_str(&text)
                .with_context(|| format!("invalid state file {}", state_file.display()))?;
            mode = persisted.mode;
            trust = persisted.trust;
            consumed = persisted.consumed;
            tasks_completed = persisted.tasks_completed;
            tasks_failed = persisted.tasks_failed;
            reservations = persisted.reservations;
        }
        // Saturating: a corrupt legacy reservation map must never wrap
        // the coefficient below its floor through plain addition.
        let refunded: i64 = reservations
            .values()
            .copied()
            .fold(0i64, |acc, units| acc.saturating_add(units));
        if refunded != 0 {
            trust = trust.saturating_add(refunded);
            reservations.clear();
        }
        let state = Self {
            mode,
            trust,
            consumed,
            points: compute_points(trust_cfg, &limits),
            msgs_sent: 0,
            msgs_received: 0,
            tasks_completed,
            tasks_failed,
            started: Instant::now(),
            state_file,
            limits,
            reservations,
        };
        if !existed || refunded != 0 {
            // First boot: materialize the initial state so the file
            // always exists. Refund: persist it so a second crash
            // cannot double-release. Clean reloads skip the write.
            let _ = state.save();
        }
        Ok(state)
    }

    /// Persist mode, trust, consumption counter, task statistics and
    /// any leftover reservation map atomically (temp file plus rename)
    /// so an interrupted write cannot corrupt the state. The temp
    /// file is made owner-readable-only before the rename. Failures
    /// are logged to stderr and returned — callers on the hot path
    /// discard the result, but a broken state file never fails
    /// silently twice in a row.
    pub fn save(&self) -> Result<()> {
        let persisted = PersistedState {
            mode: self.mode,
            trust: self.trust,
            consumed: self.consumed,
            tasks_completed: self.tasks_completed,
            tasks_failed: self.tasks_failed,
            reservations: self.reservations.clone(),
        };
        let text = serde_json::to_string(&persisted)?;
        let tmp = self.state_file.with_extension("tmp");
        if let Err(err) = std::fs::write(&tmp, &text) {
            eprintln!(
                "[opennetd] cannot persist state to {}: {err:#}",
                self.state_file.display()
            );
            return Err(err.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        if let Err(err) = std::fs::rename(&tmp, &self.state_file) {
            eprintln!(
                "[opennetd] cannot commit state file {}: {err:#}",
                self.state_file.display()
            );
            return Err(err.into());
        }
        Ok(())
    }

    /// Total trust units currently held by in-flight reservations.
    pub fn reserved_total(&self) -> i64 {
        self.reservations.values().copied().sum()
    }

    /// Reserve `units` trust units for `task_id`, deducting them from
    /// the coefficient immediately so concurrent tasks cannot
    /// overspend. The floor check compares the remaining coefficient
    /// against the new reservation only, because previous reservations
    /// are already deducted from `trust`. Nothing is persisted here: a
    /// crash refunds the reservation on boot, so only the final
    /// settlement needs disk.
    pub fn reserve(&mut self, task_id: &str, units: i64, floor: i64) -> Result<(), String> {
        let available = self.trust as i128 - units as i128;
        if available < floor as i128 {
            return Err(format!(
                "insufficient trust (remaining {}, need {})",
                self.trust, units
            ));
        }
        self.trust -= units;
        self.reservations.insert(task_id.to_string(), units);
        Ok(())
    }

    /// Release a reservation after a refused, failed or timed-out
    /// task, returning the units to the trust coefficient. In-memory
    /// only, like `reserve`.
    pub fn release(&mut self, task_id: &str) {
        if let Some(units) = self.reservations.remove(task_id) {
            self.trust = self.trust.saturating_add(units);
        }
    }

    /// Settle a completed task: charge `billed_units` to the
    /// consumption counter and refund the difference between the
    /// reservation and the actual bill, returning that difference.
    /// Persists immediately — this is the financial finality point of
    /// the task.
    pub fn settle(&mut self, task_id: &str, billed_units: i64) -> i64 {
        let Some(reserved) = self.reservations.remove(task_id) else {
            return 0;
        };
        let refund = reserved - billed_units;
        if refund > 0 {
            self.trust = self.trust.saturating_add(refund);
        }
        self.consumed = self.consumed.saturating_add(billed_units.max(0) as u64);
        let _ = self.save();
        refund
    }

    /// Time since the daemon started.
    pub fn uptime(&self) -> std::time::Duration {
        self.started.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch_dir;

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
            ram_mb: 2048,
            max_tasks: 4,
        }
    }

    #[test]
    fn fresh_state_uses_genesis_trust_materializes_the_file_and_zero_counters() {
        let dir = scratch_dir("st-fresh");
        let state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        assert_eq!(state.trust, 100);
        assert_eq!(state.consumed, 0);
        assert!(state.reservations.is_empty());
        assert!(state.points >= 1);
        // First boot must materialize the state file, owner-readable
        // only.
        assert!(dir.join("state.json").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("state.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn mode_names_roundtrip_lowercase() {
        assert_eq!(Mode::parse("peer").unwrap(), Mode::Peer);
        assert_eq!(Mode::parse("seed").unwrap(), Mode::Seed);
        assert_eq!(Mode::parse("leech").unwrap(), Mode::Leech);
        assert!(Mode::parse("bogus").is_err());
        assert_eq!(serde_json::to_string(&Mode::Seed).unwrap(), "\"seed\"");
    }

    #[test]
    fn reserve_deducts_and_enforces_the_floor() {
        let mut state = NodeState::load(
            &scratch_dir("st-reserve"),
            Mode::Peer,
            limits(),
            &trust_cfg(),
        )
        .unwrap();
        state.reserve("t1", 30, 0).unwrap();
        assert_eq!(state.trust, 70);
        assert!(state.reserve("t2", 80, 0).is_err());
        state.reserve("t2", 60, 0).unwrap();
        assert_eq!(state.reserved_total(), 90);
        assert_eq!(state.trust, 10);
    }

    #[test]
    fn release_restores_units() {
        let mut state = NodeState::load(
            &scratch_dir("st-release"),
            Mode::Peer,
            limits(),
            &trust_cfg(),
        )
        .unwrap();
        state.reserve("t1", 30, 0).unwrap();
        state.release("t1");
        assert_eq!(state.trust, 100);
        assert!(state.reservations.is_empty());
    }

    #[test]
    fn settle_charges_consumed_and_refunds_the_difference() {
        let mut state = NodeState::load(
            &scratch_dir("st-settle"),
            Mode::Peer,
            limits(),
            &trust_cfg(),
        )
        .unwrap();
        state.reserve("t1", 50, 0).unwrap();
        // 50 were reserved, 20 are billed: 30 return to the
        // coefficient, leaving genesis 100 minus the actual
        // consumption of 20.
        let refund = state.settle("t1", 20);
        assert_eq!(refund, 30);
        assert_eq!(state.trust, 80);
        assert_eq!(state.consumed, 20);
        // Settlement is the persistence point: the file must exist now.
        assert!(state.state_file.exists());
    }

    #[test]
    fn crashed_reservation_leaves_genesis_trust_on_boot() {
        // Reservations are in-memory: dropping the state object (a
        // crash) before settlement must not burn the reserved units.
        let dir = scratch_dir("st-crash");
        let mut state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        state.reserve("t1", 40, 0).unwrap();
        assert_eq!(state.trust, 60);
        drop(state);
        let reloaded = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        assert_eq!(reloaded.trust, 100);
        assert!(reloaded.reservations.is_empty());
    }

    #[test]
    fn persisted_reservations_from_older_versions_are_refunded_on_boot() {
        // Simulate an older state.json that persisted a reservation.
        let dir = scratch_dir("st-legacy");
        let mut state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        state.reservations.insert("t1".into(), 40);
        state.trust -= 40;
        state.save().unwrap();
        drop(state);
        let reloaded = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        assert_eq!(reloaded.trust, 100);
        assert!(reloaded.reservations.is_empty());
    }

    #[test]
    fn state_roundtrips_through_disk() {
        let dir = scratch_dir("st-roundtrip");
        let mut state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        state.mode = Mode::Seed;
        state.trust = 42;
        state.consumed = 7;
        state.save().unwrap();
        let reloaded = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        assert_eq!(reloaded.mode, Mode::Seed);
        assert_eq!(reloaded.trust, 42);
        assert_eq!(reloaded.consumed, 7);
    }
}
