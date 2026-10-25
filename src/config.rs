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
    /// Trust coefficient economy and capacity pricing parameters.
    pub trust: TrustCfg,
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

/// Parameters of the trust coefficient economy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCfg {
    /// Trust granted to a fresh node so it can request a few tasks before it
    /// must donate compute back to the network.
    pub genesis_trust: i64,
    /// Floor the consumer's effective trust may not drop below when a new
    /// task is accepted; a value of zero blocks pure leeching.
    pub min_trust: i64,
    /// Capacity points awarded per CPU core when pricing this node's
    /// hardware.
    pub points_per_core: u32,
    /// Capacity points awarded per gibibyte of RAM when pricing this node's
    /// hardware.
    pub points_per_gb: u32,
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
    /// Announcements older than this are rejected as replays, in seconds.
    pub ann_max_age_secs: u64,
    /// Announcements timestamped further than this into the future are
    /// rejected, in seconds.
    pub ann_future_skew_secs: u64,
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
            trust: TrustCfg {
                genesis_trust: 100,
                min_trust: 0,
                points_per_core: 10,
                points_per_gb: 2,
            },
            network: NetworkCfg {
                port: 0,
                multicast_addr: "239.255.0.1".to_string(),
                multicast_port: 9999,
                hello_interval_secs: 5,
                heartbeat_interval_secs: 30,
                task_timeout_secs: 300,
                ann_max_age_secs: 120,
                ann_future_skew_secs: 120,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch_dir;

    #[test]
    fn missing_config_file_yields_defaults() {
        let cfg = load(Some(scratch_dir("cfg-missing").join("absent.toml"))).unwrap();
        assert_eq!(cfg.mode, Mode::Peer);
        assert_eq!(cfg.limits.max_tasks, 4);
        assert_eq!(cfg.trust.genesis_trust, 100);
        assert_eq!(cfg.trust.min_trust, 0);
        assert_eq!(cfg.trust.points_per_core, 10);
        assert_eq!(cfg.network.multicast_port, 9999);
        assert_eq!(cfg.network.ann_max_age_secs, 120);
        assert_eq!(
            cfg.paths.socket_path,
            PathBuf::from("/run/opennet/control.sock")
        );
    }

    #[test]
    fn written_config_loads_custom_values() {
        let dir = scratch_dir("cfg-custom");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let text = concat!(
            "mode = \"seed\"\n\n",
            "[limits]\n",
            "cpu_percent = 25\n",
            "ram_mb = 512\n",
            "max_tasks = 1\n\n",
            "[trust]\n",
            "genesis_trust = 7\n",
            "min_trust = -3\n",
            "points_per_core = 3\n",
            "points_per_gb = 1\n\n",
            "[network]\n",
            "port = 0\n",
            "multicast_addr = \"239.255.0.1\"\n",
            "multicast_port = 9999\n",
            "hello_interval_secs = 5\n",
            "heartbeat_interval_secs = 30\n",
            "task_timeout_secs = 300\n",
            "ann_max_age_secs = 120\n",
            "ann_future_skew_secs = 120\n\n",
            "[paths]\n",
            "state_dir = \"/tmp/x\"\n",
            "socket_path = \"/tmp/x.sock\"\n",
        );
        std::fs::write(&path, text).unwrap();
        let cfg = load(Some(path)).unwrap();
        assert_eq!(cfg.mode, Mode::Seed);
        assert_eq!(cfg.limits.max_tasks, 1);
        assert_eq!(cfg.trust.genesis_trust, 7);
        assert_eq!(cfg.trust.min_trust, -3);
        assert_eq!(cfg.trust.points_per_core, 3);
    }

    #[test]
    fn invalid_toml_is_an_error() {
        let dir = scratch_dir("cfg-bad");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "mode = [").unwrap();
        assert!(load(Some(path)).is_err());
    }

    #[test]
    fn default_config_renders_and_reparses() {
        let text = default_toml().unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.mode, Mode::Peer);
        assert_eq!(parsed.limits.cpu_percent, 50);
        assert_eq!(parsed.trust.genesis_trust, 100);
        assert_eq!(parsed.trust.points_per_gb, 2);
        assert_eq!(parsed.network.heartbeat_interval_secs, 30);
        assert_eq!(parsed.network.ann_future_skew_secs, 120);
    }
}
