//! Node state: operating mode, trust coefficient, consumption counter,
//! capacity points, wire counters and the in-memory reservation map,
//! persisted atomically to `state.json`. Also owns the append-only
//! billing receipt journal (see `receipts`) whose rolling head is
//! announced with the identity.

use crate::config::{Limits, TrustCfg};
use crate::trust::points::compute_points;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

mod receipts;
#[cfg(test)]
mod tests;

pub use receipts::{genesis_head, receipt_hash, ReceiptLog};

/// Operating mode of the node.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Donates capacity and requests tasks (workstations).
    Peer,
    /// Donates capacity only (servers accumulating trust).
    Seed,
    /// Requests tasks only (small devices).
    Leech,
}

impl Mode {
    /// Lowercase wire/TOML spelling of the mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Peer => "peer",
            Mode::Seed => "seed",
            Mode::Leech => "leech",
        }
    }

    /// Parse the lowercase spelling; anything else is an error so a
    /// config typo fails loudly at load time.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "peer" => Ok(Mode::Peer),
            "seed" => Ok(Mode::Seed),
            "leech" => Ok(Mode::Leech),
            other => anyhow::bail!("unknown mode '{other}'"),
        }
    }
}

/// Persisted subset of the node state.
#[derive(Clone, Serialize, Deserialize)]
struct PersistedState {
    mode: Mode,
    trust: i64,
    consumed: u64,
    tasks_completed: u64,
    tasks_failed: u64,
}

/// Mutable node state behind the daemon-wide lock.
pub struct NodeState {
    pub mode: Mode,
    pub trust: i64,
    pub consumed: u64,
    /// Announced capacity points for the CPU/RAM offer; the GPU offer
    /// is added on top at announce time (see `heartbeat`).
    pub points: u32,
    pub reservations: HashMap<String, i64>,
    pub msgs_sent: u64,
    pub msgs_received: u64,
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    started: Instant,
    state_file: PathBuf,
    /// Advertised resource limits, kept for the capacity checks.
    pub limits: Limits,
    /// Append-only billing receipt journal; its rolling head
    /// (`self.receipts.head()`) is announced with the identity.
    pub receipts: ReceiptLog,
}

impl NodeState {
    /// Load state from `state_dir`, creating the directory and the
    /// genesis state on first run. Legacy persisted reservations from
    /// older versions are deliberately dropped and refunded by absence:
    /// reservations are in-memory by design and nothing is owed across
    /// restarts either way.
    pub fn load(
        state_dir: &Path,
        default_mode: Mode,
        limits: Limits,
        trust_cfg: &TrustCfg,
    ) -> Result<NodeState> {
        std::fs::create_dir_all(state_dir).context("cannot create state dir")?;
        let state_file = state_dir.join("state.json");
        let persisted: Option<PersistedState> = if state_file.exists() {
            let text = std::fs::read_to_string(&state_file).context("cannot read state.json")?;
            Some(serde_json::from_str(&text).context("cannot parse state.json")?)
        } else {
            None
        };
        let mode = persisted.as_ref().map(|p| p.mode).unwrap_or(default_mode);
        let trust = persisted
            .as_ref()
            .map(|p| p.trust)
            .unwrap_or(trust_cfg.genesis_trust);
        let consumed = persisted.as_ref().map(|p| p.consumed).unwrap_or(0);
        let points = compute_points(trust_cfg, &limits);
        Ok(NodeState {
            mode,
            trust,
            consumed,
            points,
            reservations: HashMap::new(),
            msgs_sent: 0,
            msgs_received: 0,
            tasks_completed: persisted.as_ref().map(|p| p.tasks_completed).unwrap_or(0),
            tasks_failed: persisted.as_ref().map(|p| p.tasks_failed).unwrap_or(0),
            started: Instant::now(),
            state_file,
            limits,
            receipts: ReceiptLog::load(state_dir)?,
        })
    }

    /// Persist the state atomically: write a temp file in the same
    /// directory, then rename over the target, with owner-only
    /// permissions on the temp file before it is visible.
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
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.state_file)?;
        Ok(())
    }

    /// Total units currently held by all reservations.
    pub fn reserved_total(&self) -> i64 {
        self.reservations.values().copied().sum()
    }

    /// Reserve `units` for one task; the effective floor
    /// `trust - consumed - reserved >= floor` must hold, where `floor`
    /// is the configured `min_trust`. Returns an error naming the
    /// shortage when the balance cannot cover the reservation.
    pub fn reserve(
        &mut self,
        task_id: &str,
        units: i64,
        floor: i64,
    ) -> std::result::Result<(), String> {
        let available = self.trust - self.consumed as i64 - self.reserved_total();
        if available - units < floor {
            return Err(format!(
                "insufficient trust: available {available}, need {units} above floor {floor}"
            ));
        }
        self.reservations.insert(task_id.to_string(), units);
        Ok(())
    }

    /// Release one reservation without settling (refused, failed or
    /// timed-out tasks); a missing reservation is not an error.
    pub fn release(&mut self, task_id: &str) {
        self.reservations.remove(task_id);
    }

    /// Settle one reservation: move `charge` units from trust to the
    /// consumption counter and drop the reservation. The charge is
    /// already capped by the consumer side to the reservation size.
    pub fn settle(&mut self, task_id: &str, charge: i64) {
        self.reservations.remove(task_id);
        self.trust -= charge;
        self.consumed = self.consumed.saturating_add(charge as u64);
    }

    /// Daemon uptime in whole seconds, for `opennetctl status`.
    pub fn uptime(&self) -> std::time::Duration {
        self.started.elapsed()
    }
}
