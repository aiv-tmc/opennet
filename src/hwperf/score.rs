//! Score types of the hardware performance board: the `[hwperf]`
//! configuration and the per-component score records. Pure data with
//! the smallest possible behavior (record/reset); the store that owns
//! them lives in `super`.

use serde::{Deserialize, Serialize};

/// Configuration of the hardware performance scorer (`[hwperf]`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HwPerfCfg {
    /// Master switch: measured pricing replaces the static offer once
    /// a component holds at least one measurement; unscored components
    /// keep their static price.
    pub enabled: bool,
    /// Seconds between passive observation rounds.
    pub probe_interval_secs: u64,
    /// Observed CPU throughput (million ALU ops per second) worth one
    /// capacity point.
    pub cpu_mops_per_point: u64,
    /// Observed RAM bandwidth (MiB per second) worth one capacity
    /// point.
    pub ram_mibs_per_point: u64,
}

impl Default for HwPerfCfg {
    fn default() -> Self {
        HwPerfCfg {
            enabled: true,
            probe_interval_secs: 60,
            cpu_mops_per_point: 400,
            ram_mibs_per_point: 1024,
        }
    }
}

/// One scalar component score: the demonstrated maximum plus the
/// baseline recorded by the last guided stress run.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ComponentScore {
    /// Highest value ever observed, in the component's native unit
    /// (CPU: Mops/s, RAM: MiB/s). Zero means "never measured".
    pub observed_max: u64,
    /// Value certified by the most recent guided stress run.
    pub baseline: u64,
    /// Number of samples recorded so far.
    pub samples: u64,
    /// Unix time of the last accepted sample.
    pub updated_unix: u64,
}

impl ComponentScore {
    /// Record one sample: the maximum can only grow, and the sample
    /// counter and timestamp always follow the newest observation.
    pub(super) fn record(&mut self, value: u64, unix_ts: u64) -> bool {
        self.samples = self.samples.saturating_add(1);
        self.updated_unix = unix_ts;
        if value > self.observed_max {
            self.observed_max = value;
            return true;
        }
        false
    }

    /// Zero the score; used when the component's fingerprint changes.
    pub(super) fn reset(&mut self) {
        *self = ComponentScore::default();
    }
}

/// GPU scoring: the highest utilization percent ever observed across
/// the offered devices. Zero percent with `seen == false` means "never
/// observed", which keeps the static GPU price.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct GpuScore {
    /// Highest utilization percent ever observed (0..=100).
    pub util_max: u32,
    /// Whether at least one utilization sample was ever recorded.
    pub seen: bool,
    /// Unix time of the last accepted sample.
    pub updated_unix: u64,
}
