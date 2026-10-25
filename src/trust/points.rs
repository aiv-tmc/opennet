//! Capacity pricing: every node converts its hardware characteristics into
//! a static price tag measured in points, announces it to peers and uses it
//! to charge trust units for executed tasks.

use crate::config::TrustCfg;

/// Fallback RAM total (in megabytes) used when the kernel does not expose
/// /proc/meminfo, so pricing still works on non-Linux systems.
const FALLBACK_RAM_MB: u64 = 1024;

/// Extract the MemTotal value (in kB) from /proc/meminfo-formatted text;
/// returns `None` when no parseable MemTotal line exists.
fn memtotal_kb(text: &str) -> Option<u64> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("MemTotal:") else {
            continue;
        };
        let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
        return Some(kb);
    }
    None
}

/// Read the machine's total RAM in megabytes from /proc/meminfo; falls back
/// to a small constant when the file is missing or unparsable.
fn total_ram_mb() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| memtotal_kb(&text))
        .map(|kb| kb / 1024)
        .unwrap_or(FALLBACK_RAM_MB)
}

/// Compute this node's capacity points from its real hardware: one weight
/// per CPU core plus one weight per gibibyte of RAM, clamped to at least
/// one point so even tiny devices can participate in the market.
pub fn compute_points(cfg: &TrustCfg) -> u32 {
    let cores = std::thread::available_parallelism()
        .map(|count| count.get() as u64)
        .unwrap_or(1);
    let ram_gb = (total_ram_mb() / 1024).max(1);
    let points = cores * cfg.points_per_core as u64 + ram_gb * cfg.points_per_gb as u64;
    points.clamp(1, u32::MAX as u64) as u32
}

/// Trust units one task reserves and eventually moves: the provider's point
/// price per started minute of wall-clock limit, at least one minute; any
/// partially started minute counts as a full one. Both sides derive the
/// value from the announced points and the configured default task timeout,
/// so they always agree on the charge.
pub fn units_for(points: u32, timeout_secs: u64) -> i64 {
    let minutes = timeout_secs.div_ceil(60).max(1) as i64;
    points as i64 * minutes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memtotal_parses_standard_proc_meminfo() {
        let text = "MemTotal:        8167848 kB\nMemFree:          123456 kB\n";
        assert_eq!(memtotal_kb(text), Some(8_167_848));
    }

    #[test]
    fn memtotal_handles_whitespace_variants() {
        assert_eq!(memtotal_kb("MemTotal:   2048 kB"), Some(2048));
        assert_eq!(memtotal_kb("MemTotal:\t1048576 kB"), Some(1_048_576));
    }

    #[test]
    fn memtotal_rejects_missing_or_malformed_input() {
        assert_eq!(memtotal_kb(""), None);
        assert_eq!(memtotal_kb("MemFree: 100 kB\n"), None);
        assert_eq!(memtotal_kb("MemTotal: notanumber kB\n"), None);
        assert_eq!(memtotal_kb("MemTotal: 100"), Some(100));
    }

    #[test]
    fn units_charge_one_minute_minimum() {
        assert_eq!(units_for(10, 0), 10);
        assert_eq!(units_for(10, 1), 10);
        assert_eq!(units_for(10, 59), 10);
        assert_eq!(units_for(10, 60), 10);
    }

    #[test]
    fn units_scale_with_started_minutes() {
        assert_eq!(units_for(10, 61), 20);
        assert_eq!(units_for(10, 120), 20);
        assert_eq!(units_for(10, 300), 50);
        assert_eq!(units_for(3, 300), 15);
    }

    #[test]
    fn zero_weights_still_yield_participation_points() {
        let cfg = TrustCfg {
            genesis_trust: 0,
            min_trust: 0,
            points_per_core: 0,
            points_per_gb: 0,
        };
        assert_eq!(compute_points(&cfg), 1);
    }

    #[test]
    fn hardware_pricing_is_always_positive() {
        let cfg = TrustCfg {
            genesis_trust: 100,
            min_trust: 0,
            points_per_core: 10,
            points_per_gb: 2,
        };
        assert!(compute_points(&cfg) >= 1);
    }
}
