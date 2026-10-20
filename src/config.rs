//! Static daemon configuration loaded from a TOML file.

use crate::node::state::Mode;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Operating mode of this node (peer, seed or leech).
    pub mode: Mode,
    /// Resource limits this node offers to the network.
    pub limits: Limits,
    /// Network and discovery tuning parameters.
    pub network: NetworkCfg,
    /// Filesystem locations used by the daemon.
    pub paths: Paths,
}

/// Resource limits advertised to and enforced for the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum share of local CPU offered to remote tasks, in percent.
    pub cpu_percent: u32,
    /// Maximum amount of local RAM offered to remote tasks, in megabytes.
    pub ram_mb: u64,
    /// Maximum number of remote tasks executed concurrently.
    pub max_tasks: u32,
}

/// Network transport and discovery tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCfg {
    /// TCP port to listen on; 0 picks an ephemeral port.
    pub port: u16,
    /// IPv4 multicast group used for LAN discovery announcements.
    pub multicast_addr: String,
    /// UDP port of the multicast discovery group.
    pub multicast_port: u16,
    /// Interval between HELLO announcements on the multicast group, in seconds.
    pub hello_interval_secs: u64,
    /// Interval between peer announcements over TCP, in seconds.
    pub heartbeat_interval_secs: u64,
    /// Default wall-clock limit for one executed task, in seconds.
    pub task_timeout_secs: u64,
}

/// Filesystem locations used by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paths {
    /// Directory holding the node identity key and persisted state.
    pub state_dir: PathBuf,
    /// Path of the local control socket served by the daemon.
    pub socket_path: PathBuf,
}

impl Default for Config {
    /// Built-in defaults used when no configuration file exists.
    fn default() -> Self {
        Self {
            mode: Mode::Peer,
            limits: Limits {
                cpu_percent: 50,
                ram_mb: 2048,
                max_tasks: 4,
            },
            network: NetworkCfg {
                port: 0,
                multicast_addr: "239.255.0.1".to_string(),
                multicast_port: 9999,
                hello_interval_secs: 5,
                heartbeat_interval_secs: 30,
                task_timeout_secs: 300,
            },
            paths: Paths {
                state_dir: PathBuf::from("/var/lib/opennet"),
                socket_path: PathBuf::from("/run/opennet/control.sock"),
            },
        }
    }
}

/// Load configuration from TOML.
///
/// Resolution order: explicit path argument, the `OPENNET_CONFIG` environment
/// variable, then `/etc/opennet/config.toml`. If the resolved file does not
/// exist, built-in defaults are returned and a note is printed to stderr.
pub fn load(explicit: Option<PathBuf>) -> Result<Config> {
    let path = explicit
        .or_else(|| std::env::var_os("OPENNET_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/opennet/config.toml"));
    if !path.exists() {
        eprintln!(
            "[opennetd] config file {} not found, using built-in defaults",
            path.display()
        );
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    let config: Config = toml::from_str(&text)
        .with_context(|| format!("invalid TOML in config file {}", path.display()))?;
    Ok(config)
}

/// Render the default configuration as TOML for `--print-default-config`.
pub fn default_toml() -> Result<String> {
    toml::to_string_pretty(&Config::default()).context("cannot serialize default config")
}
