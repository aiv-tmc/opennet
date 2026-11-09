//! Passive performance probe.
//!
//! The probe samples the machine while it runs real workloads (games,
//! compiles, renders) and remembers the highest throughput it has ever
//! observed. It never manufactures load by itself; the deliberate benchmark
//! lives in `stress`. All samples feed the observed-maximum score board.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use super::{HwPerf, HwPerfCfg};

/// A CPU probe is only started when the 1-minute load average exceeds this
/// fraction of the core count, so idle machines are not benchmarked.
const LOAD_TRIGGER: f64 = 0.65;
/// Operations performed by one CPU probe round per worker thread.
const CPU_PROBE_OPS: u64 = 4_000_000;
/// Buffer size for the RAM bandwidth probe (64 MiB).
const RAM_PROBE_BYTES: usize = 64 * 1024 * 1024;

/// Snapshot of /proc/stat aggregate CPU counters.
#[derive(Clone, Copy)]
struct CpuTimes {
    idle: u64,
    total: u64,
}

/// Read aggregate CPU counters (first "cpu" line of /proc/stat).
fn read_cpu_times() -> Option<CpuTimes> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let mut idle = 0u64;
    let mut total = 0u64;
    for (index, field) in fields.enumerate() {
        let value: u64 = field.parse().ok()?;
        total = total.saturating_add(value);
        // Column 3 is idle, column 4 is iowait; both count as not-busy.
        if index == 3 || index == 4 {
            idle = idle.saturating_add(value);
        }
    }
    Some(CpuTimes { idle, total })
}

/// Busy fraction (0.0..=1.0) between two counter snapshots.
fn busy_fraction(before: CpuTimes, after: CpuTimes) -> f64 {
    let total = after.total.saturating_sub(before.total);
    let idle = after.idle.saturating_sub(before.idle);
    if total == 0 {
        return 0.0;
    }
    1.0 - (idle as f64 / total as f64)
}

/// Read the 1-minute load average and divide it by the core count.
fn load_factor() -> f64 {
    let loadavg = match std::fs::read_to_string("/proc/loadavg") {
        Ok(text) => text,
        Err(_) => return 0.0,
    };
    let load: f64 = match loadavg
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
    {
        Some(v) => v,
        None => return 0.0,
    };
    let cores = std::thread::available_parallelism()
        .map(|n| n.get() as f64)
        .unwrap_or(1.0);
    load / cores
}

/// One probe round: a bounded integer mix measured across all cores.
///
/// Returns millions of operations per second. The mix of xor, rotate and
/// multiply-add mirrors the stress test so passive and guided samples are
/// directly comparable on the score board.
pub fn cpu_probe_round() -> u64 {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(64);
    let start = Instant::now();
    std::thread::scope(|scope| {
        for worker in 0..threads {
            scope.spawn(move || {
                let mut acc = 0x9e37_79b9_7f4a_7c15u64 ^ (worker as u64);
                for _ in 0..CPU_PROBE_OPS {
                    acc ^= acc << 13;
                    acc ^= acc >> 7;
                    acc = acc.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(1);
                    std::hint::black_box(acc);
                }
            });
        }
    });
    let ops = CPU_PROBE_OPS
        .saturating_mul(threads as u64)
        .saturating_mul(3);
    let secs = start.elapsed().as_secs_f64().max(0.001);
    ((ops as f64 / secs) / 1_000_000.0) as u64
}

/// Measure RAM write bandwidth with a capped buffer; returns MiB per second.
pub fn ram_probe_round() -> u64 {
    let mut buf = vec![0u8; RAM_PROBE_BYTES];
    let start = Instant::now();
    // Fill twice so caches and page-fault warm-up average out.
    for pass in 0..2u64 {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i as u8) ^ (pass as u8);
        }
        std::hint::black_box(&buf);
    }
    let secs = start.elapsed().as_secs_f64().max(0.001);
    ((RAM_PROBE_BYTES as f64 * 2.0 / secs) / (1024.0 * 1024.0)) as u64
}

/// Sample current GPU utilisation (0..=100) averaged across DRM devices.
///
/// Falls back to nvidia-smi when the DRM busy-percent files are absent.
pub fn gpu_utilisation() -> Option<u32> {
    let mut sum = 0u64;
    let mut count = 0u64;
    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("card") || name.contains('-') {
                continue;
            }
            let busy = entry.path().join("device/gpu_busy_percent");
            if let Ok(text) = std::fs::read_to_string(&busy) {
                if let Ok(v) = text.trim().parse::<u64>() {
                    sum += v.min(100);
                    count += 1;
                }
            }
        }
    }
    if count == 0 {
        if let Ok(out) = std::process::Command::new("nvidia-smi")
            .args([
                "--query-gpu=utilization.gpu",
                "--format=csv,noheader,nounits",
            ])
            .output()
        {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Ok(v) = line.trim().parse::<u64>() {
                        sum += v.min(100);
                        count += 1;
                    }
                }
            }
        }
    }
    // No adapter answered on either path: report "no GPU".
    sum.checked_div(count).map(|avg| avg as u32)
}

/// Background sampler: wakes up on the configured interval, records GPU
/// utilisation whenever it is high, and runs a short CPU/RAM probe only
/// when the machine is already busy (the observed-maximum principle).
pub async fn run(perf: Arc<Mutex<HwPerf>>, cfg: HwPerfCfg) {
    let interval = Duration::from_secs(cfg.probe_interval_secs.max(10));
    let mut tick = tokio::time::interval(interval);
    // Skip the immediate first tick; the daemon just started.
    tick.tick().await;
    loop {
        tick.tick().await;
        // GPU sampling is cheap, so it runs on every tick. A high reading
        // means the user is pushing the card (game, render) right now.
        if let Some(util) = gpu_utilisation() {
            if util >= 50 {
                let mut guard = perf.lock().await;
                guard.record_gpu_util(util);
            }
        }
        // CPU/RAM probes inject a few hundred milliseconds of load, so they
        // run only when the system is busy anyway and after a full busy
        // window has been observed.
        if load_factor() >= LOAD_TRIGGER {
            let before = read_cpu_times();
            let mops = cpu_probe_round();
            let mib = ram_probe_round();
            // The CPU sample is meaningful only if the machine stayed busy
            // during the window; otherwise the round mostly measured the
            // probe itself, which duplicates the guided stress test.
            let genuinely_busy = matches!((before, read_cpu_times()),
                (Some(b), Some(a)) if busy_fraction(b, a) >= LOAD_TRIGGER);
            let mut guard = perf.lock().await;
            if genuinely_busy {
                guard.record_cpu(mops);
            }
            guard.record_ram(mib);
        }
        let guard = perf.lock().await;
        guard.save_if_pending();
    }
}
