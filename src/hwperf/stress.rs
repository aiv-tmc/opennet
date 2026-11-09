//! Guided OpenNet stress test.
//!
//! One command (`opennet stress`) runs a short, deterministic benchmark that
//! deliberately pushes every scored component to its ceiling, so the daemon
//! observes the true maximum instead of waiting for it to occur naturally.
//! The benchmark writes results straight into the score board via `certify`,
//! which marks them as trusted (not inflation-prone passive samples).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use super::{probe, HwPerf};

/// CPU benchmark duration. Long enough to reach steady clocks, short enough
/// to stay polite on a shared machine.
const CPU_RUN: Duration = Duration::from_secs(5);
/// RAM benchmark duration.
const RAM_RUN: Duration = Duration::from_secs(3);
/// GPU observation window: the benchmark asks the user to keep the GPU busy
/// (or drives the display pipeline) while it samples utilisation.
const GPU_RUN: Duration = Duration::from_secs(6);
/// RAM bandwidth buffer (64 MiB), matching the passive probe.
const RAM_BYTES: usize = 64 * 1024 * 1024;

/// Human-readable report produced by the stress run.
#[derive(Debug, Clone)]
pub struct StressReport {
    /// Measured CPU throughput in millions of integer operations per second.
    pub cpu_mops: u64,
    /// Measured RAM bandwidth in MiB per second.
    pub ram_mibs: u64,
    /// Highest GPU utilisation observed during the window, if a GPU exists.
    pub gpu_util: Option<u32>,
    /// Total hardware points after certification.
    pub total_points: u32,
    /// Whether the GPU window saw meaningful load. When false, the report
    /// tells the operator to run a GPU workload during the test.
    pub gpu_exercised: bool,
}

/// Render the report for the CLI.
pub fn render(report: &StressReport) -> String {
    let mut out = String::new();
    out.push_str("OpenNet stress test results\n");
    out.push_str(&format!("  CPU : {} Mops/s\n", report.cpu_mops));
    out.push_str(&format!("  RAM : {} MiB/s\n", report.ram_mibs));
    match report.gpu_util {
        Some(u) if report.gpu_exercised => {
            out.push_str(&format!("  GPU : {u}% utilisation observed\n"));
        }
        Some(u) => {
            out.push_str(&format!(
                "  GPU : only {u}% observed; run a GPU workload (game, render) during the test to certify more\n"
            ));
        }
        None => out.push_str("  GPU : no adapter detected\n"),
    }
    out.push_str(&format!(
        "  Total hardware points: {}\n",
        report.total_points
    ));
    out
}

/// Run the full benchmark and certify the results on the score board.
///
/// The CPU and RAM phases drive the hardware directly. The GPU phase only
/// samples utilisation; on headless nodes the operator is expected to run
/// their own GPU workload during the window, which mirrors exactly how
/// passive scoring works. `cfg` and `limits` recompute the announced
/// capacity points after certification for the report.
pub async fn run(
    perf: Arc<Mutex<HwPerf>>,
    cfg: &crate::config::Config,
    limits: &crate::config::Limits,
) -> StressReport {
    // Phase 1: CPU throughput across all cores for CPU_RUN seconds.
    let stop = Arc::new(AtomicBool::new(false));
    let cpu_mops = tokio::task::spawn_blocking({
        let stop = stop.clone();
        move || cpu_phase(stop)
    })
    .await
    .unwrap_or(0);

    // Phase 2: RAM write bandwidth for RAM_RUN seconds.
    let ram_mibs = tokio::task::spawn_blocking(ram_phase).await.unwrap_or(0);

    // Phase 3: GPU observation window. Sample at 250 ms and keep the peak.
    let mut gpu_peak: Option<u32> = None;
    let deadline = Instant::now() + GPU_RUN;
    while Instant::now() < deadline {
        if let Some(util) = probe::gpu_utilisation() {
            gpu_peak = Some(gpu_peak.map_or(util, |p: u32| p.max(util)));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    stop.store(true, Ordering::Relaxed);

    let gpu_exercised = gpu_peak.map(|u| u >= 80).unwrap_or(false);

    let mut guard = perf.lock().await;
    guard.certify_cpu(cpu_mops);
    guard.certify_ram(ram_mibs);
    if let Some(util) = gpu_peak {
        guard.record_gpu_util(util);
    }
    let total_points = guard.total_points(cfg, limits);
    guard.note_stress_run();
    let _ = guard.save();
    StressReport {
        cpu_mops,
        ram_mibs,
        gpu_util: gpu_peak,
        total_points,
        gpu_exercised,
    }
}

/// CPU phase: xorshift-multiply mix on every core until the time budget
/// expires; the same instruction mix as the passive probe keeps both
/// measurement paths comparable.
fn cpu_phase(stop: Arc<AtomicBool>) -> u64 {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(64);
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let start = Instant::now();
    std::thread::scope(|scope| {
        for worker in 0..threads {
            let stop = stop.clone();
            let counter = counter.clone();
            scope.spawn(move || {
                let mut acc = 0x9e37_79b9_7f4a_7c15u64 ^ (worker as u64);
                let deadline = Instant::now() + CPU_RUN;
                while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                    for _ in 0..100_000u64 {
                        acc ^= acc << 13;
                        acc ^= acc >> 7;
                        acc = acc.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(1);
                        std::hint::black_box(acc);
                    }
                    counter.fetch_add(300_000, Ordering::Relaxed);
                }
            });
        }
    });
    let ops = counter.load(Ordering::Relaxed);
    let secs = start.elapsed().as_secs_f64().max(0.001);
    ((ops as f64 / secs) / 1_000_000.0) as u64
}

/// RAM phase: repeated full-buffer writes for RAM_RUN seconds.
fn ram_phase() -> u64 {
    let mut buf = vec![0u8; RAM_BYTES];
    let mut written = 0u64;
    let start = Instant::now();
    let deadline = start + RAM_RUN;
    let mut pass = 0u64;
    while Instant::now() < deadline {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i as u8) ^ (pass as u8);
        }
        std::hint::black_box(&buf);
        written += RAM_BYTES as u64;
        pass += 1;
    }
    let secs = start.elapsed().as_secs_f64().max(0.001);
    ((written as f64 / secs) / (1024.0 * 1024.0)) as u64
}
