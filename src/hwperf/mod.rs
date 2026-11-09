//! Hardware performance scoring: the utility coefficient of this node.
//!
//! The daemon prices its capacity from *demonstrated* hardware
//! performance, never from component names or marketing strings. Every
//! component class (CPU, RAM, GPU) accumulates an observed maximum:
//! whenever the daemon sees the hardware deliver more than it has ever
//! seen before — a user pushing the GPU to 90% in a game, a compile
//! farm saturating every core, or the built-in stress test driving the
//! machine to its ceiling — that new maximum becomes the demonstrated
//! capacity and the credited points follow it. `opennetctl stress`
//! runs the OpenNet-optimized benchmark that performs this scoring on
//! demand in one bounded pass.
//!
//! Scores are bound to the hardware they were measured on through
//! per-component fingerprints (`fingerprint`): a component whose
//! fingerprint stops matching has its score reset and re-earns it from
//! zero, while a plain reboot leaves every fingerprint intact and the
//! accumulated points untouched.
//!
//! The derived capacity points are announced in the node's signed
//! heartbeat exactly like the static offer was; peers never see the
//! score table itself, only the resulting price.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub mod fingerprint;
pub mod probe;
mod score;
pub mod stress;

pub use score::{ComponentScore, GpuScore, HwPerfCfg};

/// Persisted score table: fingerprints plus one score per class.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScoreBoard {
    /// Schema version of the on-disk file.
    pub version: u32,
    /// Fingerprints the scores are bound to.
    pub fingerprints: fingerprint::Fingerprints,
    /// CPU throughput score (Mops/s).
    pub cpu: ComponentScore,
    /// RAM bandwidth score (MiB/s).
    pub ram: ComponentScore,
    /// GPU utilization score (percent).
    pub gpu: GpuScore,
}

/// Current on-disk schema version.
const SCORE_VERSION: u32 = 1;

/// Sanity ceiling for one component's derived points: measurements
/// above it are clamped so a corrupt score file cannot announce an
/// absurd price.
const COMPONENT_POINTS_CAP: u64 = 100_000;

/// The hardware performance store: the persisted score table, its file
/// and the runtime bookkeeping that does not belong on disk.
pub struct HwPerf {
    /// Score file path (`<state_dir>/hwperf.json`).
    file: PathBuf,
    /// The live score table.
    board: ScoreBoard,
    /// Moment of the last guided stress run; enforces the run rate
    /// limit without persisting a timestamp.
    last_stress: Option<Instant>,
    /// Dirty flag for the debounced save: counts unsaved updates.
    pending: AtomicU64,
}

/// Capacity points derived from measurements, per component; `None`
/// marks an unscored component whose static price still applies.
#[derive(Clone, Copy, Debug, Default)]
pub struct PerfPoints {
    /// Points from measured CPU throughput.
    pub cpu: Option<u32>,
    /// Points from measured RAM bandwidth.
    pub ram: Option<u32>,
    /// Points from measured GPU utilization.
    pub gpu: Option<u32>,
}

/// Minimum interval between two guided stress runs.
pub const STRESS_RATE_LIMIT: Duration = Duration::from_secs(30);

impl HwPerf {
    /// Load the score table from `<state_dir>/hwperf.json`; a missing
    /// file starts an empty table and a malformed file is refused by
    /// the caller-visible error, like every other state file.
    pub fn load(state_dir: &Path) -> anyhow::Result<HwPerf> {
        std::fs::create_dir_all(state_dir)?;
        let file = state_dir.join("hwperf.json");
        let board = match std::fs::read_to_string(&file) {
            Ok(text) => {
                let mut board: ScoreBoard = serde_json::from_str(&text)?;
                if board.version != SCORE_VERSION {
                    // Unknown schema: start clean rather than trusting
                    // fields whose meaning may have changed.
                    board = ScoreBoard::default();
                }
                board
            }
            Err(_) => ScoreBoard::default(),
        };
        Ok(HwPerf {
            file,
            board,
            last_stress: None,
            pending: AtomicU64::new(0),
        })
    }

    /// Compare the live hardware fingerprints with the stored ones and
    /// reset exactly the scores of the components whose hardware
    /// changed; a reboot leaves every fingerprint intact and resets
    /// nothing. Returns the names of the reset classes for the log.
    pub fn reconcile_fingerprints(&mut self) -> Vec<&'static str> {
        let current = fingerprint::collect();
        let mut reset = Vec::new();
        if current.cpu != self.board.fingerprints.cpu {
            self.board.cpu.reset();
            if !self.board.fingerprints.cpu.is_empty() {
                reset.push("cpu");
            }
        }
        if current.ram != self.board.fingerprints.ram {
            self.board.ram.reset();
            if !self.board.fingerprints.ram.is_empty() {
                reset.push("ram");
            }
        }
        if current.gpu != self.board.fingerprints.gpu {
            self.board.gpu = GpuScore::default();
            if !self.board.fingerprints.gpu.is_empty() {
                reset.push("gpu");
            }
        }
        self.board.fingerprints = current;
        if !reset.is_empty() {
            let _ = self.save();
        }
        reset
    }

    /// Record one CPU throughput sample (Mops/s); returns true when a
    /// new maximum was demonstrated.
    pub fn record_cpu(&mut self, mops: u64) -> bool {
        let new_max = self.board.cpu.record(mops, crate::trust::now_unix());
        self.note_change(new_max);
        new_max
    }

    /// Record one RAM bandwidth sample (MiB/s); returns true on a new
    /// maximum.
    pub fn record_ram(&mut self, mibs: u64) -> bool {
        let new_max = self.board.ram.record(mibs, crate::trust::now_unix());
        self.note_change(new_max);
        new_max
    }

    /// Record one GPU utilization sample (percent, clamped to 100);
    /// returns true on a new maximum.
    pub fn record_gpu_util(&mut self, percent: u32) -> bool {
        let percent = percent.min(100);
        self.board.gpu.seen = true;
        self.board.gpu.updated_unix = crate::trust::now_unix();
        let new_max = percent > self.board.gpu.util_max;
        if new_max {
            self.board.gpu.util_max = percent;
        }
        self.note_change(new_max);
        new_max
    }

    /// Certify the stress-run baseline for one component without
    /// lowering its observed maximum.
    pub fn certify_cpu(&mut self, mops: u64) {
        self.board.cpu.baseline = mops;
        self.record_cpu(mops);
    }

    /// Certify the stress-run RAM baseline without lowering the
    /// observed maximum.
    pub fn certify_ram(&mut self, mibs: u64) {
        self.board.ram.baseline = mibs;
        self.record_ram(mibs);
    }

    /// Capacity points derived from the current scores: measured
    /// components convert through the configured divisor with the
    /// sanity cap; unscored components stay `None` so the caller falls
    /// back to the static price of exactly that component.
    pub fn points(&self, cfg: &HwPerfCfg, gpu_count: u32, points_per_gpu: u32) -> PerfPoints {
        if !cfg.enabled {
            return PerfPoints::default();
        }
        let convert = |value: u64, per_point: u64| -> u32 {
            let divisor = per_point.max(1);
            (value / divisor).min(COMPONENT_POINTS_CAP) as u32
        };
        let cpu = (self.board.cpu.observed_max > 0)
            .then(|| convert(self.board.cpu.observed_max, cfg.cpu_mops_per_point));
        let ram = (self.board.ram.observed_max > 0)
            .then(|| convert(self.board.ram.observed_max, cfg.ram_mibs_per_point));
        let gpu = self.board.gpu.seen.then(|| {
            let full = u64::from(gpu_count) * u64::from(points_per_gpu);
            let scaled = full * u64::from(self.board.gpu.util_max.min(100)) / 100;
            scaled.min(COMPONENT_POINTS_CAP) as u32
        });
        PerfPoints { cpu, ram, gpu }
    }

    /// Total announced capacity points: measured components at their
    /// measured price, unscored components at their static price.
    pub fn total_points(
        &self,
        cfg: &crate::config::Config,
        limits: &crate::config::Limits,
    ) -> u32 {
        let static_cpu =
            crate::trust::points::offered_cores(limits.cpu_percent) * cfg.trust.points_per_core;
        let static_ram =
            crate::trust::points::offered_gib(limits.ram_mb) * cfg.trust.points_per_gb;
        let static_gpu = crate::trust::points::gpu_points(&cfg.gpu);
        if !cfg.hwperf.enabled {
            return static_cpu
                .saturating_add(static_ram)
                .saturating_add(static_gpu);
        }
        let measured = self.points(
            &cfg.hwperf,
            cfg.gpu.effective_count(),
            cfg.gpu.points_per_gpu,
        );
        measured
            .cpu
            .unwrap_or(static_cpu)
            .saturating_add(measured.ram.unwrap_or(static_ram))
            .saturating_add(measured.gpu.unwrap_or(static_gpu))
    }

    /// Read-only view of the score table for the control renderers.
    pub fn board(&self) -> &ScoreBoard {
        &self.board
    }

    /// Whether the guided stress test may run now; the rate limit
    /// keeps control-side floods from pinning the machine.
    pub fn stress_allowed(&self) -> bool {
        self.last_stress
            .map(|ran| ran.elapsed() >= STRESS_RATE_LIMIT)
            .unwrap_or(true)
    }

    /// Mark the start of one guided stress run.
    pub fn note_stress_run(&mut self) {
        self.last_stress = Some(Instant::now());
    }

    /// Persist the score table atomically (temp file plus rename) with
    /// owner-only permissions; failures are logged, never fatal.
    pub fn save(&self) -> anyhow::Result<()> {
        let mut board = self.board.clone();
        board.version = SCORE_VERSION;
        let text = serde_json::to_string_pretty(&board)?;
        let tmp = self.file.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.file)?;
        self.pending.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Flush when a debounce window worth of updates accumulated.
    pub fn save_if_pending(&self) {
        if self.pending.load(Ordering::Relaxed) >= 8 {
            let _ = self.save();
        }
    }

    /// Update bookkeeping after one sample: new maxima save promptly
    /// (they move the announced price), lesser samples debounce.
    fn note_change(&self, new_max: bool) {
        if new_max {
            let _ = self.save();
        } else {
            self.pending.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests;
