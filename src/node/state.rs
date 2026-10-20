//! Runtime node state: operating mode, credit balance, task statistics.

use crate::config::Limits;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Credits granted to a fresh node so the market can bootstrap without an
/// external faucet; earned credits replace this endowment over time.
pub const GENESIS_CREDITS: u64 = 100;

/// How the node participates in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Give and take compute capacity.
    Peer,
    /// Only donate capacity and accumulate credits.
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
    credits: u64,
    #[serde(default)]
    tasks_completed: u64,
    #[serde(default)]
    tasks_failed: u64,
}

/// Mutable runtime state shared across daemon tasks.
pub struct NodeState {
    pub mode: Mode,
    /// Credit balance earned by donating capacity to the network.
    pub credits: u64,
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
    /// genesis balance; a malformed file is reported as an error.
    pub fn load(state_dir: &Path, default_mode: Mode, limits: Limits) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("cannot create state dir {}", state_dir.display()))?;
        let state_file = state_dir.join("state.json");
        let (mode, credits, tasks_completed, tasks_failed) =
            match std::fs::read_to_string(&state_file) {
                Ok(text) => {
                    let persisted: PersistedState = serde_json::from_str(&text)
                        .with_context(|| {
                            format!("invalid state file {}", state_file.display())
                        })?;
                    (
                        persisted.mode,
                        persisted.credits,
                        persisted.tasks_completed,
                        persisted.tasks_failed,
                    )
                }
                Err(_) => (default_mode, GENESIS_CREDITS, 0, 0),
            };
        Ok(Self {
            mode,
            credits,
            msgs_sent: 0,
            msgs_received: 0,
            tasks_completed,
            tasks_failed,
            started: Instant::now(),
            state_file,
            limits,
        })
    }

    /// Persist balance, mode and task statistics atomically.
    pub fn save(&self) -> Result<()> {
        let persisted = PersistedState {
            mode: self.mode,
            credits: self.credits,
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
