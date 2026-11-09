//! TOML configuration: every field has a working default, the daemon
//! runs correctly with no config file at all, and unknown keys abort
//! boot so a typo can never silently disable a guard.
//!
//! Sections: top-level `mode`; `[limits]` CPU/RAM/concurrency offered
//! to the network; `[gpu]` accelerators offered to the network (count,
//! explicit device indices and their price in capacity points); `[trust]`
//! economy parameters; `[network]` discovery, heartbeat, freshness
//! windows and WAN knobs; `[paths]` state and control socket; `[swarm]`
//! consent defaults; `[sandbox]` execution isolation. Every section
//! carries a container-level `serde(default)` (placed after `derive`,
//! where derive-helper attributes belong), so a partially written
//! table fills its omitted fields from the defaults instead of failing
//! to parse, and `deny_unknown_fields` turns a mistyped key into a
//! boot-time error naming it. Cross-field validation lives in
//! `config/validate.rs` and runs once at boot from `load`.
//!
//! The operating mode type is shared with node state: there is exactly
//! one `Mode` enum in the crate (`node::state::Mode`), so config, state
//! files and the wire always agree on its lowercase spelling.

use crate::node::state::Mode;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

mod validate;

#[cfg(test)]
mod tests;

fn default_mode() -> Mode {
    Mode::Peer
}

pub fn load(path: Option<PathBuf>) -> Result<Config> {
    let path = path
        .or_else(|| std::env::var_os("OPENNET_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/opennet/config.toml"));
    if !path.exists() {
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                crate::log::warn(
                    module_path!(),
                    &format!("[config] cannot create {}: {err:#}", parent.display()),
                );
            }
        }
        if let Ok(text) = default_toml() {
            if let Err(err) = std::fs::write(&path, text) {
                eprintln!(
                    "[config] cannot materialize default config at {}: {err:#}",
                    path.display()
                );
            }
        }
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read config {}", path.display()))?;
    let config: Config =
        toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

pub fn default_toml() -> Result<String> {
    Ok(toml::to_string_pretty(&Config::default())?)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub cpu_percent: u32,
    pub ram_mb: u64,
    pub max_tasks: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            cpu_percent: 50,
            ram_mb: 2048,
            max_tasks: 4,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GpuCfg {
    #[serde(default)]
    pub count: u32,
    #[serde(default)]
    pub devices: Vec<u32>,
    #[serde(default = "default_points_per_gpu")]
    pub points_per_gpu: u32,
}

fn default_points_per_gpu() -> u32 {
    50
}

impl GpuCfg {
    /// Number of GPUs actually offered: an explicit device list defines
    /// the offer, so its length wins over `count`; with no list, the
    /// plain count applies. This is the only number pricing and
    /// announcements may use, so the two never disagree.
    pub fn effective_count(&self) -> u32 {
        if self.devices.is_empty() {
            self.count
        } else {
            self.devices.len() as u32
        }
    }
}

impl Default for GpuCfg {
    fn default() -> Self {
        GpuCfg {
            count: 0,
            devices: Vec::new(),
            points_per_gpu: default_points_per_gpu(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustCfg {
    pub genesis_trust: i64,
    pub min_trust: i64,
    pub points_per_core: u32,
    pub points_per_gb: u32,
    #[serde(default = "default_new_node_units_factor")]
    pub new_node_units_factor: u32,
}

fn default_new_node_units_factor() -> u32 {
    2
}

impl Default for TrustCfg {
    fn default() -> Self {
        TrustCfg {
            genesis_trust: 100,
            min_trust: 0,
            points_per_core: 10,
            points_per_gb: 2,
            new_node_units_factor: default_new_node_units_factor(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkCfg {
    /// Fixed TCP listen port for peer connections. A concrete default
    /// (rather than an ephemeral port) keeps firewall rules and the
    /// documented container port meaningful.
    pub port: u16,
    pub multicast_addr: String,
    pub multicast_port: u16,
    pub hello_interval_secs: u64,
    pub heartbeat_interval_secs: u64,
    pub task_timeout_secs: u64,
    pub ann_max_age_secs: u64,
    pub ann_future_skew_secs: u64,
    /// WAN mode: relay routing-table snapshots through the mesh so
    /// nodes beyond one multicast domain discover each other through
    /// the seeds they share. Off by default (pure LAN multicast).
    #[serde(default)]
    pub wan: bool,
    /// Static seed addresses (`host:port`) inserted into the routing
    /// table at startup and dialed on demand — the rendezvous points
    /// of a WAN deployment. Empty by default.
    #[serde(default)]
    pub seeds: Vec<String>,
}

impl Default for NetworkCfg {
    fn default() -> Self {
        NetworkCfg {
            port: 7000,
            multicast_addr: "239.255.0.1".to_string(),
            multicast_port: 9999,
            hello_interval_secs: 5,
            heartbeat_interval_secs: 30,
            task_timeout_secs: 300,
            ann_max_age_secs: 120,
            ann_future_skew_secs: 120,
            wan: false,
            seeds: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Paths {
    pub state_dir: PathBuf,
    pub socket_path: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            state_dir: PathBuf::from("/var/lib/opennet"),
            socket_path: PathBuf::from("/run/opennet/control.sock"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SwarmCfg {
    pub enabled: bool,
    pub program: String,
    pub max_shard_ram_mb: u64,
    pub max_shard_cpu_percent: u32,
    pub artifacts_dir: PathBuf,
}

impl Default for SwarmCfg {
    fn default() -> Self {
        SwarmCfg {
            enabled: false,
            program: String::new(),
            max_shard_ram_mb: 4096,
            max_shard_cpu_percent: 50,
            artifacts_dir: PathBuf::from("/var/lib/opennet/swarm"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxCfg {
    pub namespaces: bool,
    pub read_only_root: bool,
    pub cgroup: bool,
    pub memory_mb: u64,
    pub cpu_percent: u32,
    pub pids_max: u32,
}

impl Default for SandboxCfg {
    fn default() -> Self {
        SandboxCfg {
            namespaces: true,
            read_only_root: true,
            cgroup: true,
            memory_mb: 0,
            cpu_percent: 0,
            pids_max: 512,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub gpu: GpuCfg,
    #[serde(default)]
    pub trust: TrustCfg,
    #[serde(default)]
    pub network: NetworkCfg,
    #[serde(default)]
    pub paths: Paths,
    #[serde(default)]
    pub swarm: SwarmCfg,
    #[serde(default)]
    pub sandbox: SandboxCfg,
    #[serde(default)]
    pub hwperf: crate::hwperf::HwPerfCfg,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: default_mode(),
            limits: Limits::default(),
            gpu: GpuCfg::default(),
            trust: TrustCfg::default(),
            network: NetworkCfg::default(),
            paths: Paths::default(),
            swarm: SwarmCfg::default(),
            sandbox: SandboxCfg::default(),
            hwperf: crate::hwperf::HwPerfCfg::default(),
        }
    }
}
