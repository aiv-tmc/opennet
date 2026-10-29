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
    /// Defaults for the opt-in swarm consent; the effective consent can be
    /// toggled at runtime and is persisted separately in the state dir.
    pub swarm: SwarmCfg,
    /// Execution sandbox for compute tasks and swarm shard runners; the
    /// section may be omitted, in which case the defaults apply.
    #[serde(default)]
    pub sandbox: SandboxCfg,
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
    /// Trust granted to a fresh node so it can request a few tasks before
    /// it must donate compute back to the network.
    pub genesis_trust: i64,
    /// Floor the consumer's effective trust may not drop below when a new
    /// task is accepted; a value of zero blocks pure leeching.
    pub min_trust: i64,
    /// Capacity points awarded per offered CPU core when pricing this
    /// node's hardware.
    pub points_per_core: u32,
    /// Capacity points offered per gibibyte of offered RAM when pricing
    /// this node's hardware.
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
    /// Directory holding the node identity key, persisted state and the
    /// swarm consent file.
    pub state_dir: PathBuf,
    /// Path of the local control socket served by the daemon.
    pub socket_path: PathBuf,
}

/// Opt-in consent for hosting shards of one shared program.
///
/// Everything is disabled by default: with `enabled = false` the node never
/// announces swarm capacity, never enters a placement plan and refuses every
/// shard launch before any process is spawned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmCfg {
    /// Whether the user agreed to host a shared program on this node.
    pub enabled: bool,
    /// Name of the program this node agreed to host; empty means none.
    pub program: String,
    /// Maximum RAM in megabytes this node offers to one shard.
    pub max_shard_ram_mb: u64,
    /// Maximum CPU share in percent this node offers to shard processes.
    pub max_shard_cpu_percent: u32,
    /// Directory holding program manifests and verified artifacts; shard
    /// processes only ever read files from this directory.
    pub artifacts_dir: PathBuf,
}

/// Execution sandbox for compute tasks and swarm shard runners.
///
/// Both layers degrade gracefully: when namespaces cannot be unshared or
/// the cgroup hierarchy is unavailable, the task still runs under whatever
/// restrictions could be applied instead of failing to start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCfg {
    /// Isolate tasks in fresh mount/UTS/IPC/PID/network namespaces.
    pub namespaces: bool,
    /// Inside the mount namespace, remount the root read-only and give the
    /// task a private tmpfs over its working directory.
    pub read_only_root: bool,
    /// Enforce memory/CPU/PID limits through a per-task cgroup v2.
    pub cgroup: bool,
    /// Memory cap per task in megabytes; 0 inherits `limits.ram_mb`.
    pub memory_mb: u64,
    /// CPU cap per task in percent; 0 inherits `limits.cpu_percent`.
    pub cpu_percent: u32,
    /// Maximum number of tasks processes per task; 0 leaves pids unlimited.
    pub pids_max: u64,
}

impl Default for SandboxCfg {
    /// Sandboxed execution with full limits on all knobs.
    fn default() -> Self {
        Self {
            namespaces: true,
            read_only_root: true,
            cgroup: true,
            memory_mb: 0,
            cpu_percent: 0,
            pids_max: 512,
        }
    }
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
            swarm: SwarmCfg {
                enabled: false,
                program: String::new(),
                max_shard_ram_mb: 4096,
                max_shard_cpu_percent: 50,
                artifacts_dir: PathBuf::from("/var/lib/opennet/swarm"),
            },
            sandbox: SandboxCfg::default(),
        }
    }
}

/// Load configuration from TOML.
///
/// Resolution order: explicit path argument, the `OPENNET_CONFIG` environment
/// variable, then `/etc/opennet/config.toml`.
///
/// First-run behavior: when the resolved file does not exist, the default
/// configuration is materialized at that path (parent directories included)
/// whenever the daemon has write privileges there — package installs ship
/// the file already, so this mainly serves manual `cargo install` setups.
/// When the file cannot be written, the built-in defaults apply from memory
/// and the daemon still starts fully functional.
pub fn load(explicit: Option<PathBuf>) -> Result<Config> {
    let path = explicit
        .or_else(|| std::env::var_os("OPENNET_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/opennet/config.toml"));
    if !path.exists() {
        let config = Config::default();
        if let Ok(text) = toml::to_string_pretty(&config) {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(&path, &text).is_ok() {
                eprintln!("[opennetd] wrote default config to {}", path.display());
            }
        }
        return Ok(config);
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
    fn missing_config_file_materializes_defaults_on_first_run() {
        let dir = scratch_dir("cfg-missing");
        let path = dir.join("absent.toml");
        let cfg = load(Some(path.clone())).unwrap();
        assert_eq!(cfg.mode, Mode::Peer);
        assert_eq!(cfg.limits.max_tasks, 4);
        assert_eq!(cfg.trust.genesis_trust, 100);
        assert!(!cfg.swarm.enabled);
        assert!(cfg.sandbox.namespaces);
        assert_eq!(cfg.sandbox.pids_max, 512);
        assert_eq!(
            cfg.paths.socket_path,
            PathBuf::from("/run/opennet/control.sock")
        );
        // The first run must have written the file so the next start
        // reads it from disk.
        let text = std::fs::read_to_string(&path).expect("default config not materialized");
        assert!(text.contains("[sandbox]"));
        let reloaded = load(Some(path)).unwrap();
        assert_eq!(reloaded.network.heartbeat_interval_secs, 30);
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
            "socket_path = \"/tmp/x.sock\"\n\n",
            "[swarm]\n",
            "enabled = true\n",
            "program = \"demo-llm\"\n",
            "max_shard_ram_mb = 2048\n",
            "max_shard_cpu_percent = 25\n",
            "artifacts_dir = \"/tmp/art\"\n\n",
            "[sandbox]\n",
            "namespaces = false\n",
            "read_only_root = false\n",
            "cgroup = false\n",
            "memory_mb = 128\n",
            "cpu_percent = 10\n",
            "pids_max = 64\n",
        );
        std::fs::write(&path, text).unwrap();
        let cfg = load(Some(path)).unwrap();
        assert_eq!(cfg.mode, Mode::Seed);
        assert_eq!(cfg.trust.min_trust, -3);
        assert!(cfg.swarm.enabled);
        assert!(!cfg.sandbox.namespaces);
        assert_eq!(cfg.sandbox.memory_mb, 128);
        assert_eq!(cfg.sandbox.pids_max, 64);
    }

    #[test]
    fn config_without_sandbox_section_uses_defaults() {
        let dir = scratch_dir("cfg-nosandbox");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let text = concat!(
            "mode = \"peer\"\n\n",
            "[limits]\ncpu_percent = 50\nram_mb = 2048\nmax_tasks = 4\n\n",
            "[trust]\ngenesis_trust = 100\nmin_trust = 0\npoints_per_core = 10\npoints_per_gb = 2\n\n",
            "[network]\nport = 0\nmulticast_addr = \"239.255.0.1\"\nmulticast_port = 9999\n",
            "hello_interval_secs = 5\nheartbeat_interval_secs = 30\ntask_timeout_secs = 300\n",
            "ann_max_age_secs = 120\nann_future_skew_secs = 120\n\n",
            "[paths]\nstate_dir = \"/tmp/y\"\nsocket_path = \"/tmp/y.sock\"\n\n",
            "[swarm]\nenabled = false\nprogram = \"\"\nmax_shard_ram_mb = 4096\n",
            "max_shard_cpu_percent = 50\nartifacts_dir = \"/tmp/art\"\n",
        );
        std::fs::write(&path, text).unwrap();
        let cfg = load(Some(path)).unwrap();
        assert!(cfg.sandbox.namespaces);
        assert!(cfg.sandbox.read_only_root);
        assert_eq!(cfg.sandbox.pids_max, 512);
    }
}
