//! Unit tests for the hardware performance score board.

use super::*;

/// Build a store backed by a fresh scratch directory.
fn temp_perf() -> (HwPerf, PathBuf) {
    let dir = crate::testutil::scratch_dir("hwperf");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let perf = HwPerf::load(&dir).expect("load empty board");
    (perf, dir)
}

#[test]
fn observed_max_only_grows() {
    let (mut perf, _dir) = temp_perf();
    assert!(perf.record_cpu(1_000));
    assert!(!perf.record_cpu(900));
    assert!(perf.record_cpu(1_500));
    assert_eq!(perf.board().cpu.observed_max, 1_500);
    assert_eq!(perf.board().cpu.samples, 3);
}

#[test]
fn gpu_util_is_clamped_and_tracked() {
    let (mut perf, _dir) = temp_perf();
    assert!(perf.record_gpu_util(90));
    assert!(!perf.record_gpu_util(80));
    assert!(perf.record_gpu_util(250));
    let gpu = perf.board().gpu;
    assert_eq!(gpu.util_max, 100);
    assert!(gpu.seen);
}

#[test]
fn certify_sets_baseline_without_lowering_max() {
    let (mut perf, _dir) = temp_perf();
    perf.record_cpu(2_000);
    perf.certify_cpu(1_800);
    assert_eq!(perf.board().cpu.baseline, 1_800);
    assert_eq!(perf.board().cpu.observed_max, 2_000);
}

#[test]
fn fingerprint_change_resets_only_that_component() {
    let (mut perf, _dir) = temp_perf();
    // First reconcile binds the current machine's fingerprints; only
    // samples recorded after binding are protected from the reset.
    assert!(perf.reconcile_fingerprints().is_empty());
    perf.record_cpu(5_000);
    perf.record_ram(4_096);
    perf.record_gpu_util(90);
    // Simulate a GPU swap by corrupting the stored GPU fingerprint.
    perf.board.fingerprints.gpu = "deadbeefdeadbeef".to_string();
    let reset = perf.reconcile_fingerprints();
    assert_eq!(reset, vec!["gpu"]);
    assert_eq!(perf.board().gpu.util_max, 0);
    assert!(!perf.board().gpu.seen);
    // CPU and RAM scores survive: reboot-like events reset nothing.
    assert_eq!(perf.board().cpu.observed_max, 5_000);
    assert_eq!(perf.board().ram.observed_max, 4_096);
}

#[test]
fn reboot_keeps_every_score() {
    let (mut perf, dir) = temp_perf();
    perf.reconcile_fingerprints();
    perf.record_cpu(3_000);
    perf.record_gpu_util(75);
    perf.save().expect("save");
    // Reload from disk as the daemon does after a reboot.
    let mut reloaded = HwPerf::load(&dir).expect("reload");
    let reset = reloaded.reconcile_fingerprints();
    assert!(reset.is_empty());
    assert_eq!(reloaded.board().cpu.observed_max, 3_000);
    assert_eq!(reloaded.board().gpu.util_max, 75);
}

#[test]
fn measured_points_replace_static_per_component() {
    let (mut perf, _dir) = temp_perf();
    perf.reconcile_fingerprints();
    perf.record_cpu(4_000);
    let cfg = HwPerfCfg::default();
    let pts = perf.points(&cfg, 2, 50);
    // 4000 Mops/s at 400 Mops per point gives 10 points.
    assert_eq!(pts.cpu, Some(10));
    // RAM was never measured: no measured price, static fallback.
    assert_eq!(pts.ram, None);
    assert_eq!(pts.gpu, None);
}

#[test]
fn gpu_points_scale_with_utilisation() {
    let (mut perf, _dir) = temp_perf();
    perf.record_gpu_util(50);
    let cfg = HwPerfCfg::default();
    let pts = perf.points(&cfg, 2, 50);
    // Two GPUs at 50 points each, 50% observed utilisation -> 50 points.
    assert_eq!(pts.gpu, Some(50));
}

#[test]
fn disabled_config_yields_no_measured_points() {
    let (mut perf, _dir) = temp_perf();
    perf.record_cpu(4_000);
    let cfg = HwPerfCfg {
        enabled: false,
        ..HwPerfCfg::default()
    };
    let pts = perf.points(&cfg, 0, 50);
    assert_eq!(pts.cpu, None);
}

#[test]
fn stress_rate_limit_blocks_immediate_rerun() {
    let (mut perf, _dir) = temp_perf();
    assert!(perf.stress_allowed());
    perf.note_stress_run();
    assert!(!perf.stress_allowed());
}

#[test]
fn corrupt_schema_version_starts_clean() {
    let dir = crate::testutil::scratch_dir("hwperf-corrupt");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let file = dir.join("hwperf.json");
    // A structurally valid board stamped with an unknown schema version.
    let board = ScoreBoard {
        version: 99,
        ..Default::default()
    };
    std::fs::write(&file, serde_json::to_string(&board).expect("serialize")).expect("write");
    let perf = HwPerf::load(&dir).expect("load");
    assert_eq!(perf.board().cpu.observed_max, 0);
}
