//! User consent for swarm hosting.
//!
//! Consent defaults to disabled with an empty program. It can be granted
//! only for a named program whose manifest and artifact live in the local
//! artifacts directory, and the artifact digest must match the manifest.
//! The consent is persisted to `<state_dir>/swarm.toml` so a daemon restart
//! never silently drops or grants it; runtime changes go through
//! `set_enabled` / `set_program`, which rewrite the file.

use crate::config::SwarmCfg;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Effective consent state, mirrored from config and persisted separately.
#[derive(Debug, Clone)]
pub struct Consent {
    /// Whether the user agreed to host a shared program.
    pub enabled: bool,
    /// Name of the consented program; empty means none.
    pub program: String,
    /// RAM cap for one shard process, in megabytes.
    pub max_shard_ram_mb: u64,
    /// CPU cap for shard processes, in percent.
    pub max_shard_cpu_percent: u32,
    /// Directory holding manifests and verified artifacts.
    pub artifacts_dir: PathBuf,
}

/// A verified program artifact ready for sharding.
#[derive(Debug, Clone)]
pub struct ProgramSpec {
    /// Name of the program, equal to the manifest file stem.
    pub name: String,
    /// blake3 hex digest the artifact must match.
    pub artifact_hash: String,
    /// Absolute path of the verified artifact.
    pub artifact_path: PathBuf,
    /// Total layer count of the program, used for placement.
    pub layers: u32,
    /// RAM needed to hold one shard in memory, in megabytes.
    pub shard_ram_mb: u64,
    /// Runner command template; each element may reference the environment
    /// variables exported to the shard process (ARTIFACT, PORT, PLAN_ID,
    /// SHARD_INDEX, LAYER_FROM, LAYER_TO, NEXT_ADDR, COORD_ADDR, RAM_MB).
    pub runner_cmd: Vec<String>,
}

impl Consent {
    /// Load the consent file from the state directory, falling back to the
    /// config defaults when no consent file exists; the fallback always
    /// carries `enabled = false`.
    pub fn load(state_dir: &Path, cfg: &SwarmCfg) -> Self {
        let file = state_dir.join("swarm.toml");
        let mut consent = Self {
            enabled: false,
            program: String::new(),
            max_shard_ram_mb: cfg.max_shard_ram_mb,
            max_shard_cpu_percent: cfg.max_shard_cpu_percent,
            artifacts_dir: cfg.artifacts_dir.clone(),
        };
        if let Ok(text) = fs::read_to_string(&file) {
            match toml::from_str::<SwarmCfg>(&text) {
                Ok(parsed) => {
                    consent.enabled = parsed.enabled;
                    consent.program = parsed.program;
                    consent.max_shard_ram_mb = parsed.max_shard_ram_mb;
                    consent.max_shard_cpu_percent = parsed.max_shard_cpu_percent;
                    consent.artifacts_dir = parsed.artifacts_dir;
                }
                Err(err) => eprintln!("[swarm] ignoring malformed consent file: {err:#}"),
            }
        }
        consent
    }

    /// Persist the consent to `<state_dir>/swarm.toml`.
    pub fn save(&self, state_dir: &Path) -> Result<()> {
        let cfg = SwarmCfg {
            enabled: self.enabled,
            program: self.program.clone(),
            max_shard_ram_mb: self.max_shard_ram_mb,
            max_shard_cpu_percent: self.max_shard_cpu_percent,
            artifacts_dir: self.artifacts_dir.clone(),
        };
        let text = toml::to_string_pretty(&cfg).context("cannot serialize consent")?;
        let file = state_dir.join("swarm.toml");
        let tmp = file.with_extension("tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, &file)?;
        Ok(())
    }

    /// Whether hosting `program` is consented.
    pub fn allows(&self, program: &str) -> bool {
        self.enabled && !self.program.is_empty() && self.program == program
    }

    /// Verified program spec for the consented program; consent, manifest
    /// presence and artifact digest are all enforced here.
    pub fn verified_spec(&self) -> Result<ProgramSpec> {
        if !self.enabled || self.program.is_empty() {
            bail!("no swarm consent granted on this node");
        }
        ProgramSpec::load(&self.artifacts_dir, &self.program)
    }
}

impl ProgramSpec {
    /// Load and verify `<artifacts_dir>/<name>.manifest.json` plus the
    /// artifact it references. Verification covers the name, the manifest
    /// schema, the artifact path staying inside the artifacts directory and
    /// the blake3 digest matching the manifest.
    pub fn load(artifacts_dir: &Path, name: &str) -> Result<Self> {
        if name.is_empty()
            || name.contains('/')
            || name.contains("..")
            || name.chars().any(|ch| ch.is_whitespace())
        {
            bail!("invalid program name '{name}'");
        }
        let root = artifacts_dir
            .canonicalize()
            .with_context(|| format!("cannot resolve artifacts dir {}", artifacts_dir.display()))?;
        let manifest_path = root.join(format!("{name}.manifest.json"));
        let text = fs::read_to_string(&manifest_path)
            .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
        let value: serde_json::Value =
            serde_json::from_str(&text).context("manifest is not valid JSON")?;
        let artifact_name = value
            .get("artifact")
            .and_then(|v| v.as_str())
            .context("manifest: missing 'artifact'")?;
        let expected_hash = value
            .get("blake3")
            .and_then(|v| v.as_str())
            .context("manifest: missing 'blake3'")?;
        let layers = value
            .get("layers")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .clamp(1, u32::MAX as u64) as u32;
        let shard_ram_mb = value
            .get("shard_ram_mb")
            .and_then(|v| v.as_u64())
            .unwrap_or(1024);
        let runner_cmd: Vec<String> = value
            .get("runner")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .filter(|cmd: &Vec<String>| !cmd.is_empty())
            .context("manifest: missing 'runner' command")?;
        let artifact_path = root.join(artifact_name);
        let inside_root = artifact_path
            .canonicalize()
            .map(|resolved| resolved.starts_with(&root))
            .unwrap_or(false);
        if !inside_root {
            bail!("artifact path escapes the artifacts directory");
        }
        let bytes = fs::read(&artifact_path)
            .with_context(|| format!("cannot read artifact {}", artifact_path.display()))?;
        let digest = blake3::hash(&bytes).to_hex().to_string();
        if digest != expected_hash {
            bail!("artifact digest mismatch: got {digest}, manifest wants {expected_hash}");
        }
        Ok(Self {
            name: name.to_string(),
            artifact_hash: expected_hash.to_string(),
            artifact_path,
            layers,
            shard_ram_mb,
            runner_cmd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch_dir;

    fn write_manifest(dir: &Path, name: &str, artifact: &str, hash: &str) {
        let text = format!(
            r#"{{"artifact": "{artifact}", "blake3": "{hash}", "layers": 10,
                 "shard_ram_mb": 256, "runner": ["./run-shard.sh"]}}"#
        );
        fs::write(dir.join(format!("{name}.manifest.json")), text).unwrap();
    }

    #[test]
    fn disabled_consent_denies_every_program() {
        let consent = Consent {
            enabled: false,
            program: "demo".into(),
            max_shard_ram_mb: 4096,
            max_shard_cpu_percent: 50,
            artifacts_dir: scratch_dir("cn-off"),
        };
        assert!(!consent.allows("demo"));
        assert!(consent.verified_spec().is_err());
    }

    #[test]
    fn consent_roundtrips_through_the_state_file() {
        let dir = scratch_dir("cn-persist");
        fs::create_dir_all(&dir).unwrap();
        let cfg = SwarmCfg {
            enabled: false,
            program: String::new(),
            max_shard_ram_mb: 2048,
            max_shard_cpu_percent: 25,
            artifacts_dir: scratch_dir("cn-art"),
        };
        let mut consent = Consent::load(&dir, &cfg);
        assert!(!consent.enabled);
        consent.enabled = true;
        consent.program = "demo".into();
        consent.save(&dir).unwrap();
        let reloaded = Consent::load(&dir, &cfg);
        assert!(reloaded.allows("demo"));
        assert!(!reloaded.allows("other"));
    }

    #[test]
    fn spec_loads_and_verifies_matching_artifact() {
        let dir = scratch_dir("cn-ok");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("model.bin"), b"weights-bytes").unwrap();
        let hash = blake3::hash(b"weights-bytes").to_hex().to_string();
        write_manifest(&dir, "demo", "model.bin", &hash);
        let consent = Consent {
            enabled: true,
            program: "demo".into(),
            max_shard_ram_mb: 4096,
            max_shard_cpu_percent: 50,
            artifacts_dir: dir.clone(),
        };
        let spec = consent.verified_spec().unwrap();
        assert_eq!(spec.layers, 10);
        assert_eq!(spec.artifact_hash, hash);
        assert_eq!(spec.runner_cmd, vec!["./run-shard.sh".to_string()]);
    }

    #[test]
    fn spec_rejects_tampered_artifact() {
        let dir = scratch_dir("cn-tamper");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("model.bin"), b"original").unwrap();
        write_manifest(
            &dir,
            "demo",
            "model.bin",
            blake3::hash(b"other").to_hex().as_ref(),
        );
        let consent = Consent {
            enabled: true,
            program: "demo".into(),
            max_shard_ram_mb: 4096,
            max_shard_cpu_percent: 50,
            artifacts_dir: dir,
        };
        assert!(consent.verified_spec().is_err());
    }

    #[test]
    fn spec_rejects_path_escape_in_manifest() {
        let dir = scratch_dir("cn-escape");
        fs::create_dir_all(&dir).unwrap();
        let outside = scratch_dir("cn-outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("evil.bin"), b"x").unwrap();
        let hash = blake3::hash(b"x").to_hex().to_string();
        write_manifest(&dir, "demo", "../cn-outside/evil.bin", &hash);
        let consent = Consent {
            enabled: true,
            program: "demo".into(),
            max_shard_ram_mb: 4096,
            max_shard_cpu_percent: 50,
            artifacts_dir: dir,
        };
        assert!(consent.verified_spec().is_err());
    }
}
