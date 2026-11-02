//! Consent registry tests: granting, revoking, persistence and the
//! legacy single-program migration. Every case uses scratch
//! directories; no test touches real system paths.

use super::*;
use crate::config::SwarmCfg;
use crate::testutil::scratch_dir;

fn cfg() -> SwarmCfg {
    SwarmCfg {
        enabled: false,
        program: String::new(),
        max_shard_ram_mb: 4096,
        max_shard_cpu_percent: 50,
        artifacts_dir: scratch_dir("consent-artifacts"),
    }
}

#[test]
fn grant_and_revoke_track_each_program() {
    let mut consent = Consent::load(&scratch_dir("consent-map"), &cfg());
    assert!(consent.is_empty());
    consent.grant("demo");
    consent.grant("llm");
    assert!(consent.allows("demo"));
    assert!(consent.allows("llm"));
    assert!(!consent.allows("other"));
    // Revoking one program leaves the other consented.
    assert!(consent.revoke(Some("demo")));
    assert!(!consent.allows("demo"));
    assert!(consent.allows("llm"));
    // Revoking everything empties the registry.
    assert!(!consent.revoke(None));
    assert!(consent.is_empty());
}

#[test]
fn roundtrip_persists_every_program() {
    let dir = scratch_dir("consent-save");
    fs::create_dir_all(&dir).unwrap();
    let mut consent = Consent::load(&dir, &cfg());
    consent.grant("demo");
    consent.grant("llm");
    consent.save(&dir).unwrap();
    let reloaded = Consent::load(&dir, &cfg());
    assert!(reloaded.allows("demo"));
    assert!(reloaded.allows("llm"));
    assert_eq!(reloaded.programs.len(), 2);
}

#[test]
fn legacy_single_program_file_migrates() {
    let dir = scratch_dir("consent-legacy");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("swarm.toml"),
        "enabled = true\nprogram = \"demo\"\nmax_shard_ram_mb = 2048\nmax_shard_cpu_percent = 25\n",
    )
    .unwrap();
    let consent = Consent::load(&dir, &cfg());
    assert!(consent.allows("demo"));
    assert_eq!(
        consent.limits("demo"),
        Some(ProgramConsent {
            max_shard_ram_mb: 2048,
            max_shard_cpu_percent: 25,
        })
    );
}

#[test]
fn missing_file_starts_empty() {
    let consent = Consent::load(&scratch_dir("consent-none"), &cfg());
    assert!(consent.is_empty());
}

#[test]
fn verified_program_requires_consent_and_manifest() {
    let mut consent = Consent::load(&scratch_dir("consent-verify"), &cfg());
    // No consent: refused before the manifest is even considered.
    assert!(consent.verified_program("demo").is_err());
    consent.grant("demo");
    // Consent alone is not enough: the manifest and the artifact
    // digest must verify too.
    assert!(consent.verified_program("demo").is_err());
    assert!(consent.verified_program("other").is_err());
}
