//! Local consent registry for swarm hosting: which programs this node
//! agrees to shard, with the per-program resource ceilings that cap
//! every offer made for them.
//!
//! Consent is strictly opt-in per program — nothing is hosted without
//! an explicit `swarm enable <program>` — and persists across restarts
//! in `swarm.toml` so the operator's choice survives daemon cycles.
//! Granting consent never spawns anything by itself: a shard launches
//! only when a signed [`crate::message::Message::ShardLaunch`] for a
//! consented program arrives.
//!
//! Every program additionally declares a per-shard resource contract
//! inside its manifest — RAM, CPU share and GPU devices
//! (`gpus_per_shard`, default 0 = CPU-only) — which capability-aware
//! placement honors when it picks shard hosts. The manifest and the
//! artifact digest are verified by [`ProgramSpec::load`] before any
//! spawn, so a tampered artifact never runs.

mod spec;
#[cfg(test)]
mod tests;

pub use spec::ProgramSpec;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Per-program consent ceilings: the resource limits every shard offer
/// and every incoming launch request for this program is checked
/// against.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramConsent {
    /// Maximum memory one shard of this program may reserve, MB.
    pub max_shard_ram_mb: u64,
    /// Maximum CPU share one shard of this program may reserve, percent.
    pub max_shard_cpu_percent: u32,
}

/// The full local consent registry.
#[derive(Debug, Clone)]
pub struct Consent {
    /// Consented programs keyed by name, ceilings inside.
    pub programs: BTreeMap<String, ProgramConsent>,
    /// Ceilings applied to every newly granted program (from
    /// `[swarm]` in the daemon config).
    pub max_shard_ram_mb: u64,
    pub max_shard_cpu_percent: u32,
    /// Directory holding manifests and verified artifacts for every
    /// consented program.
    pub artifacts_dir: PathBuf,
}

/// On-disk form of the registry: one `[programs.<name>]` table per
/// consented program. The flat legacy fields migrate into `programs`
/// when the table is absent, so an existing grant survives the
/// upgrade.
#[derive(Serialize, Deserialize)]
struct ConsentFile {
    #[serde(default)]
    programs: BTreeMap<String, ProgramConsent>,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    program: String,
    #[serde(default)]
    max_shard_ram_mb: u64,
    #[serde(default)]
    max_shard_cpu_percent: u32,
}

impl Consent {
    /// Load the consent registry from `state_dir/swarm.toml`, migrating
    /// the legacy single-program format, or start empty when the file is
    /// missing. A malformed file logs a warning and yields an empty
    /// registry: consent never silently widens.
    pub fn load(state_dir: &Path, cfg: &crate::config::SwarmCfg) -> Self {
        let mut consent = Consent {
            programs: BTreeMap::new(),
            max_shard_ram_mb: cfg.max_shard_ram_mb,
            max_shard_cpu_percent: cfg.max_shard_cpu_percent,
            artifacts_dir: cfg.artifacts_dir.clone(),
        };
        let file = state_dir.join("swarm.toml");
        let Ok(text) = fs::read_to_string(&file) else {
            return consent;
        };
        match toml::from_str::<ConsentFile>(&text) {
            Ok(mut parsed) => {
                if parsed.programs.is_empty() && parsed.enabled && !parsed.program.is_empty() {
                    parsed.programs.insert(
                        parsed.program.clone(),
                        ProgramConsent {
                            max_shard_ram_mb: parsed.max_shard_ram_mb,
                            max_shard_cpu_percent: parsed.max_shard_cpu_percent,
                        },
                    );
                }
                consent.programs = parsed.programs;
            }
            Err(err) => eprintln!("[swarm] ignoring malformed consent file: {err:#}"),
        }
        consent
    }

    /// Persist the registry to `state_dir/swarm.toml`, atomically:
    /// write the temp file in the same directory, then rename over the
    /// target, with owner-only permissions before it is visible.
    pub fn save(&self, state_dir: &Path) -> Result<()> {
        let file = ConsentFile {
            programs: self.programs.clone(),
            enabled: false,
            program: String::new(),
            max_shard_ram_mb: self.max_shard_ram_mb,
            max_shard_cpu_percent: self.max_shard_cpu_percent,
        };
        let text = toml::to_string_pretty(&file).context("cannot serialize consent")?;
        let path = state_dir.join("swarm.toml");
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// True while nothing is consented; placement excludes this node.
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    /// Whether hosting `program` is consented at all; the resource
    /// ceilings are enforced separately against each launch request.
    pub fn allows(&self, program: &str) -> bool {
        self.programs.contains_key(program)
    }

    /// Grant consent to one program with the registry's default
    /// ceilings; re-granting refreshes nothing (idempotent).
    pub fn grant(&mut self, program: &str) {
        self.programs.insert(
            program.to_string(),
            ProgramConsent {
                max_shard_ram_mb: self.max_shard_ram_mb,
                max_shard_cpu_percent: self.max_shard_cpu_percent,
            },
        );
    }

    /// Revoke one program's consent, or every program when `program`
    /// is `None`. Returns whether anything remains consented.
    pub fn revoke(&mut self, program: Option<&str>) -> bool {
        match program {
            Some(name) => {
                self.programs.remove(name);
            }
            None => self.programs.clear(),
        }
        !self.programs.is_empty()
    }

    /// The ceilings recorded for one consented program.
    pub fn limits(&self, program: &str) -> Option<ProgramConsent> {
        self.programs.get(program).copied()
    }

    /// Verified program spec for one consented program: consent, the
    /// manifest's presence and the artifact digest are all enforced
    /// here, so the result is safe to shard.
    pub fn verified_program(&self, program: &str) -> Result<ProgramSpec> {
        if !self.allows(program) {
            bail!("no swarm consent granted for '{program}' on this node");
        }
        ProgramSpec::load(&self.artifacts_dir, program)
    }
}
