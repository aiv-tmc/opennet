//! Runtime node state: operating mode, trust coefficient, consumption
//! counter, capacity points and task statistics.

use crate::config::{Limits, TrustCfg};
use crate::trust::points::compute_points;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// How the node participates in the network.
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
    /// Machine-readable mode name used on the wire and in the control socket.
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
}

/// Mutable runtime state shared across daemon tasks.
pub struct NodeState {
    pub mode: Mode,
    /// Trust coefficient earned by donating compute and spent by consuming
    /// it; providers gate acceptance on this value as last announced.
    pub trust: i64,
    /// Cumulative trust units consumed on remote providers, announced in
    /// every bid so providers can audit the claimed trust arithmetic.
    pub consumed: u64,
    /// Static capacity price of this node's hardware, announced to peers
    /// and used to charge consumers for executed tasks.
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
}

impl NodeState {
    /// Load persisted state from `<state_dir>/state.json` or start with the
    /// genesis trust endowment; a malformed file is reported as an error.
    pub fn load(
        state_dir: &Path,
        default_mode: Mode,
        limits: Limits,
        trust_cfg: &TrustCfg,
    ) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("cannot create state dir {}", state_dir.display()))?;
        let state_file = state_dir.join("state.json");
        let (mode, trust, consumed, tasks_completed, tasks_failed) =
            match std::fs::read_to_string(&state_file) {
                Ok(text) => {
                    let persisted: PersistedState = serde_json::from_str(&text)
                        .with_context(|| format!("invalid state file {}", state_file.display()))?;
                    (
                        persisted.mode,
                        persisted.trust,
                        persisted.consumed,
                        persisted.tasks_completed,
                        persisted.tasks_failed,
                    )
                }
                Err(_) => (default_mode, trust_cfg.genesis_trust, 0, 0, 0),
            };
        Ok(Self {
            mode,
            trust,
            consumed,
            points: compute_points(trust_cfg),
            msgs_sent: 0,
            msgs_received: 0,
            tasks_completed,
            tasks_failed,
            started: Instant::now(),
            state_file,
            limits,
        })
    }

    /// Persist mode, trust, consumption counter and task statistics
    /// atomically so an interrupted write cannot corrupt the state.
    pub fn save(&self) -> Result<()> {
        let persisted = PersistedState {
            mode: self.mode,
            trust: self.trust,
            consumed: self.consumed,
            tasks_completed: self.tasks_completed,
            tasks_failed: self.tasks_failed,
        };
        let text = serde_json::to_string_pretty(&persisted)?;
        let tmp = self.state_file.with_extension("tmp");
        std::fs::write(&tmp, &text)?;
        std::fs::rename(&tmp, &self.state_file)?;
        Ok(())
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
            genesis_trust: 42,
            min_trust: 0,
            points_per_core: 1,
            points_per_gb: 1,
        }
    }

    fn limits() -> Limits {
        Limits {
            cpu_percent: 50,
            ram_mb: 1024,
            max_tasks: 2,
        }
    }

    #[test]
    fn fresh_state_gets_genesis_trust_and_hardware_points() {
        let dir = scratch_dir("state-fresh");
        let state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        assert_eq!(state.mode, Mode::Peer);
        assert_eq!(state.trust, 42);
        assert_eq!(state.consumed, 0);
        assert_eq!(state.tasks_completed, 0);
        assert_eq!(state.tasks_failed, 0);
        assert!(state.points >= 1);
    }

    #[test]
    fn save_and_reload_persist_all_fields() {
        let dir = scratch_dir("state-roundtrip");
        {
            let mut state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
            state.mode = Mode::Seed;
            state.trust = 7;
            state.consumed = 13;
            state.tasks_completed = 3;
            state.tasks_failed = 1;
            state.save().unwrap();
        }
        let state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
        assert_eq!(state.mode, Mode::Seed);
        assert_eq!(state.trust, 7);
        assert_eq!(state.consumed, 13);
        assert_eq!(state.tasks_completed, 3);
        assert_eq!(state.tasks_failed, 1);
    }

    #[test]
    fn malformed_state_file_is_an_error() {
        let dir = scratch_dir("state-bad");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("state.json"), "not json").unwrap();
        assert!(NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).is_err());
    }

    #[test]
    fn mode_names_roundtrip_and_garbage_is_rejected() {
        for mode in [Mode::Peer, Mode::Seed, Mode::Leech] {
            assert_eq!(Mode::parse(mode.as_str()).unwrap(), mode);
        }
        assert!(Mode::parse("PEER").is_err());
        assert!(Mode::parse("").is_err());
    }
}
