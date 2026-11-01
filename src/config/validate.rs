//! Startup validation of the daemon configuration.
//!
//! `load` runs these checks after parsing so a typo in a production
//! config aborts boot with a message naming the offending key instead
//! of surfacing later as a silently misbehaving subsystem. Every check
//! here is a cross-field constraint that TOML structure alone cannot
//! express; type-level correctness is already guaranteed by serde.

use super::*;
use anyhow::{bail, Result};
use std::net::{Ipv4Addr, SocketAddr};

impl Config {
    /// Verify every subsystem constraint; the first violation aborts
    /// startup with the offending key in the error message.
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        self.gpu.validate()?;
        self.trust.validate()?;
        self.network.validate()?;
        self.paths.validate()?;
        self.swarm.validate()?;
        self.sandbox.validate()?;
        Ok(())
    }
}

impl Limits {
    /// Offered capacity must be nonzero and the CPU share must be a
    /// real percentage, otherwise pricing and scheduling divide by
    /// zero or advertise nonsense.
    fn validate(&self) -> Result<()> {
        if self.cpu_percent == 0 || self.cpu_percent > 100 {
            bail!("limits.cpu_percent must be within 1..=100");
        }
        if self.ram_mb == 0 {
            bail!("limits.ram_mb must be at least 1");
        }
        if self.max_tasks == 0 {
            bail!("limits.max_tasks must be at least 1");
        }
        Ok(())
    }
}

impl GpuCfg {
    /// A node either donates nothing (all defaults) or a coherent
    /// device set: an explicit device list defines the offer, so a
    /// non-zero `count` must agree with its length; indices must be
    /// unique, and the offer must stay within a sane ceiling.
    fn validate(&self) -> Result<()> {
        if self.count > 128 {
            bail!("gpu.count must be at most 128");
        }
        if !self.devices.is_empty() {
            if self.count != 0 && self.count as usize != self.devices.len() {
                bail!("gpu.count must be 0 or match the length of gpu.devices");
            }
            let mut sorted = self.devices.clone();
            sorted.sort_unstable();
            if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
                bail!("gpu.devices must not contain duplicate indices");
            }
        }
        Ok(())
    }
}

impl TrustCfg {
    /// Pricing coefficients must be positive, the genesis endowment
    /// must not be negative, and the stranger surcharge must be at
    /// least 1 (a zero would cancel every reservation). `min_trust`
    /// stays unrestricted because a negative floor models a network
    /// that allows debt.
    fn validate(&self) -> Result<()> {
        if self.genesis_trust < 0 {
            bail!("trust.genesis_trust must not be negative");
        }
        if self.points_per_core == 0 {
            bail!("trust.points_per_core must be at least 1");
        }
        if self.points_per_gb == 0 {
            bail!("trust.points_per_gb must be at least 1");
        }
        if self.new_node_units_factor == 0 {
            bail!("trust.new_node_units_factor must be at least 1");
        }
        Ok(())
    }
}

impl NetworkCfg {
    /// Every interval must be positive (a zero interval would spin a
    /// task or heartbeat loop) and the discovery group must be a real
    /// IPv4 multicast address, otherwise discovery joins fail with an
    /// opaque OS error. Every WAN seed must be a concrete `host:port`
    /// dial target.
    fn validate(&self) -> Result<()> {
        let group: Ipv4Addr = self
            .multicast_addr
            .parse()
            .map_err(|_| anyhow::anyhow!("network.multicast_addr is not a valid IPv4 address"))?;
        if !group.is_multicast() {
            bail!("network.multicast_addr must be a multicast address");
        }
        if self.hello_interval_secs == 0 {
            bail!("network.hello_interval_secs must be at least 1");
        }
        if self.heartbeat_interval_secs == 0 {
            bail!("network.heartbeat_interval_secs must be at least 1");
        }
        if self.task_timeout_secs == 0 {
            bail!("network.task_timeout_secs must be at least 1");
        }
        if self.ann_max_age_secs == 0 {
            bail!("network.ann_max_age_secs must be at least 1");
        }
        if self.ann_future_skew_secs == 0 {
            bail!("network.ann_future_skew_secs must be at least 1");
        }
        for seed in &self.seeds {
            let _: SocketAddr = seed
                .parse()
                .map_err(|_| anyhow::anyhow!("network.seeds entry '{seed}' is not host:port"))?;
        }
        Ok(())
    }
}

impl Paths {
    /// Daemon paths must be absolute: the daemon never changes its
    /// working directory, and a relative path would silently resolve
    /// against whatever directory the init system started it in.
    fn validate(&self) -> Result<()> {
        require_absolute(&self.state_dir, "paths.state_dir")?;
        require_absolute(&self.socket_path, "paths.socket_path")?;
        Ok(())
    }
}

impl SwarmCfg {
    /// Shard capacity must be nonzero so placement math never divides
    /// by an empty offer, and the artifacts directory must be absolute
    /// for the same reason as the other daemon paths.
    fn validate(&self) -> Result<()> {
        if self.max_shard_ram_mb == 0 {
            bail!("swarm.max_shard_ram_mb must be at least 1");
        }
        if self.max_shard_cpu_percent == 0 || self.max_shard_cpu_percent > 100 {
            bail!("swarm.max_shard_cpu_percent must be within 1..=100");
        }
        require_absolute(&self.artifacts_dir, "swarm.artifacts_dir")?;
        Ok(())
    }
}

impl SandboxCfg {
    /// Only the CPU percentage is constrained: 0 is the documented
    /// inherit sentinel, so any other value must be a real percentage.
    fn validate(&self) -> Result<()> {
        if self.cpu_percent > 100 {
            bail!("sandbox.cpu_percent must be within 0..=100");
        }
        Ok(())
    }
}

/// Reject one relative filesystem location with `key` naming the
/// offending config key in the error message.
fn require_absolute(path: &std::path::Path, key: &str) -> Result<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        bail!("{key} must be an absolute path");
    }
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
        assert_eq!(cfg.trust.new_node_units_factor, 2);
        assert!(!cfg.network.wan);
        assert!(cfg.network.seeds.is_empty());
        let text = std::fs::read_to_string(&path).expect("default config not materialized");
        assert!(text.contains("[sandbox]"));
    }

    #[test]
    fn wan_seeds_must_be_host_port() {
        let dir = scratch_dir("cfg-wan");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "[network]\nseeds = [\"not-a-socket\"]\n").unwrap();
        let err = load(Some(path.clone())).unwrap_err().to_string();
        assert!(err.contains("network.seeds"), "unexpected error: {err}");
        std::fs::write(&path, "[network]\nseeds = [\"203.0.113.7:7000\"]\n").unwrap();
        assert!(load(Some(path)).is_ok());
    }

    #[test]
    fn default_config_passes_validation() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn gpu_section_must_describe_a_coherent_device_set() {
        let dir = scratch_dir("cfg-gpu");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "[gpu]\ncount = 3\ndevices = [0, 1]\n").unwrap();
        let err = load(Some(path.clone())).unwrap_err().to_string();
        assert!(err.contains("gpu.count"), "unexpected error: {err}");
        std::fs::write(&path, "[gpu]\ndevices = [0, 1]\n").unwrap();
        assert!(load(Some(path)).is_ok());
    }

    #[test]
    fn invalid_values_abort_the_load_with_the_offending_key() {
        let dir = scratch_dir("cfg-invalid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, config_with("limits.cpu_percent", 0.into())).unwrap();
        let err = load(Some(path.clone())).unwrap_err().to_string();
        assert!(
            err.contains("limits.cpu_percent"),
            "unexpected error: {err}"
        );
        std::fs::write(
            &path,
            config_with("network.multicast_addr", "10.0.0.1".into()),
        )
        .unwrap();
        let err = load(Some(path)).unwrap_err().to_string();
        assert!(
            err.contains("network.multicast_addr"),
            "unexpected error: {err}"
        );
    }

    /// Serialize a modified copy of the default config: dotted keys
    /// cannot be appended to a TOML document directly (they would land
    /// in the last section), so parse, set and re-serialize.
    fn config_with(key: &str, value: toml::Value) -> String {
        let mut doc: toml::Value = toml::from_str(&default_toml().unwrap()).unwrap();
        let table = doc.as_table_mut().unwrap();
        let mut parts = key.split('.');
        let section = parts.next().unwrap();
        let field = parts.next().unwrap();
        table
            .get_mut(section)
            .and_then(toml::Value::as_table_mut)
            .unwrap()
            .insert(field.to_string(), value);
        toml::to_string(&doc).unwrap()
    }
}
