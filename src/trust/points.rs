//! Capacity pricing: hardware offers are converted to integer capacity
//! points, and points plus time convert to trust units. Both sides of
//! the market compute prices from the same announced points, so the
//! reservation the consumer makes always matches the reservation the
//! provider checks and the units the executor credits.
//!
//! CPU capacity counts whole cores (50% of 8 cores = 4 cores) and RAM
//! capacity counts whole GiB; GPU capacity is priced separately per
//! device so an accelerator offer does not distort the CPU/RAM price.

use crate::config::{GpuCfg, Limits, TrustCfg};

/// Capacity points for the offered CPU/RAM capacity: whole cores times
/// the per-core price plus whole GiB times the per-GiB price.
pub fn compute_points(cfg: &TrustCfg, limits: &Limits) -> u32 {
    offered_cores(limits.cpu_percent) * cfg.points_per_core
        + offered_gib(limits.ram_mb) * cfg.points_per_gb
}

/// Capacity points contributed by the offered GPUs: one price per
/// device, regardless of model; nodes with no GPUs add zero.
pub fn gpu_points(gpu: &GpuCfg) -> u32 {
    gpu.count.saturating_mul(gpu.points_per_gpu)
}

/// Total announced capacity points: the CPU/RAM offer plus the GPU
/// offer. This is the number the heartbeat announces and the market
/// prices tasks against.
pub fn total_points(cfg: &TrustCfg, limits: &Limits, gpu: &GpuCfg) -> u32 {
    compute_points(cfg, limits).saturating_add(gpu_points(gpu))
}

/// Whole CPU cores offered at the given percent of a 4-core baseline.
pub fn offered_cores(cpu_percent: u32) -> u32 {
    (((u64::from(cpu_percent) * 4) / 100).max(1)) as u32
}

/// Whole GiB offered.
pub fn offered_gib(ram_mb: u64) -> u32 {
    ((ram_mb / 1024).max(1)) as u32
}

/// Trust units one task reserves and may be charged: points times the
/// number of started minutes, with any partial minute rounding up.
pub fn units_for(points: u32, timeout_secs: u64) -> i64 {
    let minutes = timeout_secs.div_ceil(60).max(1);
    (u64::from(points) * minutes) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TrustCfg;

    fn cfg() -> TrustCfg {
        TrustCfg {
            genesis_trust: 100,
            min_trust: 0,
            points_per_core: 10,
            points_per_gb: 2,
            new_node_units_factor: 2,
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
    fn points_come_from_whole_cores_and_whole_gib() {
        assert_eq!(compute_points(&cfg(), &limits()), 24);
        assert_eq!(offered_cores(25), 1);
        assert_eq!(offered_cores(200), 8);
        assert_eq!(offered_gib(1023), 1);
        assert_eq!(offered_gib(4096), 4);
    }

    #[test]
    fn gpu_points_scale_with_device_count_and_zero_by_default() {
        let mut gpu = GpuCfg::default();
        assert_eq!(gpu_points(&gpu), 0);
        gpu.count = 2;
        assert_eq!(gpu_points(&gpu), 100);
        gpu.points_per_gpu = 80;
        assert_eq!(gpu_points(&gpu), 160);
    }

    #[test]
    fn total_points_add_gpu_capacity_to_the_cpu_ram_offer() {
        let mut gpu = GpuCfg::default();
        assert_eq!(total_points(&cfg(), &limits(), &gpu), 24);
        gpu.count = 1;
        gpu.points_per_gpu = 50;
        assert_eq!(total_points(&cfg(), &limits(), &gpu), 74);
    }

    #[test]
    fn units_round_up_to_started_minutes() {
        assert_eq!(units_for(24, 1), 24);
        assert_eq!(units_for(24, 59), 24);
        assert_eq!(units_for(24, 60), 24);
        assert_eq!(units_for(24, 61), 48);
        assert_eq!(units_for(24, 300), 120);
    }

    #[test]
    fn units_survive_large_timeouts() {
        assert_eq!(units_for(24, 31_536_000), 24 * 525_600);
    }
}
