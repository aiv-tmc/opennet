//! Capacity pricing: every node converts its *offered* hardware into a
//! static price tag measured in points, announces it to peers and uses it
//! to charge trust units for executed tasks.
//!
//! Points reflect the capacity the node actually makes available to the
//! network (`limits`), not the raw machine size, so a large server that
//! offers little cannot price itself like a large server that offers a lot.

use crate::config::{Limits, TrustCfg};

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

/// Compute this node's capacity points from the hardware it offers to the
/// network: offered CPU cores (total cores scaled by `cpu_percent`) plus
/// offered gibibytes of RAM (total RAM capped by `ram_mb`), clamped to at
/// least one point so even tiny devices can participate in the market.
pub fn compute_points(cfg: &TrustCfg, limits: &Limits) -> u32 {
    let cores = std::thread::available_parallelism()
        .map(|count| count.get() as u64)
        .unwrap_or(1);
    let offered_cores = ((cores * limits.cpu_percent as u64) / 100).max(1);
    let offered_ram_gb = (total_ram_mb().min(limits.ram_mb) / 1024).max(1);
    let points =
        offered_cores * cfg.points_per_core as u64 + offered_ram_gb * cfg.points_per_gb as u64;
    points.clamp(1, u32::MAX as u64) as u32
}

/// Trust units a task reserves and eventually moves: the provider's point
/// price per started minute of the billing window, at least one minute;
/// any partially started minute counts as a full one. Both sides derive the
/// value from the announced points and one agreed duration, so they always
/// agree on the charge.
pub fn units_for(points: u32, secs: u64) -> i64 {
    let minutes = secs.div_ceil(60).max(1) as i64;
    points as i64 * minutes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TrustCfg {
        TrustCfg {
            genesis_trust: 100,
            min_trust: 0,
            points_per_core: 10,
            points_per_gb: 2,
        }
    }

    #[test]
    fn memtotal_parses_standard_proc_meminfo() {
        let text = "MemTotal:        8167848 kB\nMemFree:          123456 kB\n";
        assert_eq!(memtotal_kb(text), Some(8_167_848));
    }

    #[test]
    fn memtotal_rejects_missing_or_malformed_input() {
        assert_eq!(memtotal_kb(""), None);
        assert_eq!(memtotal_kb("MemFree: 100 kB\n"), None);
        assert_eq!(memtotal_kb("MemTotal: notanumber kB\n"), None);
    }

    #[test]
    fn offered_limits_cap_the_point_price() {
        let cheap = compute_points(
            &cfg(),
            &Limits {
                cpu_percent: 10,
                ram_mb: 1024,
                max_tasks: 1,
            },
        );
        let rich = compute_points(
            &cfg(),
            &Limits {
                cpu_percent: 100,
                ram_mb: 1_048_576,
                max_tasks: 64,
            },
        );
        assert!(rich > cheap);
        assert!(cheap >= 1);
    }

    #[test]
    fn units_follow_billed_seconds() {
        assert_eq!(units_for(2, 0), 2);
        assert_eq!(units_for(2, 61), 4);
        assert_eq!(units_for(3, 300), 15);
    }
}
