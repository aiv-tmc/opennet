//! Verified program spec: one program's manifest parsed, constrained
//! and digest-checked against its artifact.
//!
//! A program is a directory entry in the artifacts dir: the manifest
//! `{name}.manifest.json` names the artifact file, the total layer
//! count, the per-shard RAM/CPU/GPU contract and the runner command
//! template. Loading verifies the manifest schema, confines the
//! artifact path inside the artifacts directory (no traversal), reads
//! the artifact and requires its blake3 digest to equal the manifest's
//! `blake3` field. Anything else refuses the program before a single
//! runner spawns.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

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
    /// GPU devices one shard requires; 0 = CPU-only shard. Placement
    /// only considers peers whose swarm offer covers this count.
    pub gpus_per_shard: u32,
    /// Runner command template; each element may reference the
    /// environment variables exported to the shard process (ARTIFACT,
    /// PORT, PLAN_ID, SHARD_INDEX, LAYER_FROM, LAYER_TO, NEXT_ADDR,
    /// COORD_ADDR, RAM_MB).
    pub runner_cmd: Vec<String>,
}

impl ProgramSpec {
    /// Load and verify `<artifacts_dir>/<name>.manifest.json` plus the
    /// artifact it references. Verification covers the name, the
    /// manifest schema, the artifact path staying inside the artifacts
    /// directory and the blake3 digest matching the manifest.
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
        // GPU devices per shard; absent means a CPU-only program, so
        // existing manifests keep working unchanged.
        let gpus_per_shard = value
            .get("gpus_per_shard")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .clamp(0, u32::MAX as u64) as u32;
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
            gpus_per_shard,
            runner_cmd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch_dir;

    fn write_manifest(dir: &Path, name: &str, artifact: &str, hash: &str, extra: &str) {
        let text = format!(
            r#"{{"artifact": "{artifact}", "blake3": "{hash}", "layers": 10,
                 "shard_ram_mb": 256, "runner": ["./run-shard.sh"]{extra}}}"#
        );
        fs::write(dir.join(format!("{name}.manifest.json")), text).unwrap();
    }

    #[test]
    fn spec_loads_and_verifies_matching_artifact() {
        let dir = scratch_dir("spec-ok");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("model.bin"), b"weights-bytes").unwrap();
        let hash = blake3::hash(b"weights-bytes").to_hex().to_string();
        write_manifest(&dir, "demo", "model.bin", &hash, "");
        let spec = ProgramSpec::load(&dir, "demo").unwrap();
        assert_eq!(spec.layers, 10);
        assert_eq!(spec.artifact_hash, hash);
        assert_eq!(spec.gpus_per_shard, 0, "cpu programs need no gpu");
        assert_eq!(spec.runner_cmd, vec!["./run-shard.sh".to_string()]);
    }

    #[test]
    fn spec_honors_the_gpu_contract_when_declared() {
        let dir = scratch_dir("spec-gpu");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("model.bin"), b"weights").unwrap();
        let hash = blake3::hash(b"weights").to_hex().to_string();
        write_manifest(&dir, "demo", "model.bin", &hash, r#", "gpus_per_shard": 1"#);
        let spec = ProgramSpec::load(&dir, "demo").unwrap();
        assert_eq!(spec.gpus_per_shard, 1);
    }

    #[test]
    fn digest_mismatch_refuses_the_program() {
        let dir = scratch_dir("spec-digest");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("model.bin"), b"tampered").unwrap();
        write_manifest(&dir, "demo", "model.bin", &"0".repeat(64), "");
        assert!(ProgramSpec::load(&dir, "demo").is_err());
    }

    #[test]
    fn traversal_outside_the_artifacts_dir_is_refused() {
        let dir = scratch_dir("spec-escape");
        fs::create_dir_all(&dir).unwrap();
        // The manifest points outside the root; the artifact itself
        // never gets read because the path check fires first.
        write_manifest(&dir, "demo", "../outside.bin", &"0".repeat(64), "");
        assert!(ProgramSpec::load(&dir, "demo").is_err());
    }

    #[test]
    fn invalid_program_names_are_refused() {
        let dir = scratch_dir("spec-name");
        fs::create_dir_all(&dir).unwrap();
        for name in ["", "a/b", "..", "has space"] {
            assert!(ProgramSpec::load(&dir, name).is_err(), "name '{name}'");
        }
    }

    #[test]
    fn missing_runner_is_refused() {
        let dir = scratch_dir("spec-norunner");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("m.bin"), b"x").unwrap();
        let hash = blake3::hash(b"x").to_hex().to_string();
        let text = format!(r#"{{"artifact": "m.bin", "blake3": "{hash}", "layers": 1}}"#);
        fs::write(dir.join("demo.manifest.json"), text).unwrap();
        assert!(ProgramSpec::load(&dir, "demo").is_err());
    }
}
