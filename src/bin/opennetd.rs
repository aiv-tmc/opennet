//! Daemon binary: parses arguments, loads configuration and runs the
//! daemon event loop until the control interface requests shutdown.

use anyhow::{bail, Result};
use std::path::PathBuf;
use tokio::sync::watch;

fn main() -> Result<()> {
    let mut config_path: Option<PathBuf> = None;
    let mut socket_override: Option<PathBuf> = None;
    let mut print_default_config = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--print-default-config" => print_default_config = true,
            "--config" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config requires a file path"))?;
                config_path = Some(PathBuf::from(path));
            }
            "--socket" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--socket requires a file path"))?;
                socket_override = Some(PathBuf::from(path));
            }
            other if other.starts_with("--config=") => {
                config_path = Some(PathBuf::from(other.trim_start_matches("--config=")));
            }
            other if other.starts_with("--socket=") => {
                socket_override = Some(PathBuf::from(other.trim_start_matches("--socket=")));
            }
            other => bail!("unknown argument {other}"),
        }
    }
    let mut config = opennet::config::load(config_path)?;
    if let Some(socket) = socket_override {
        config.paths.socket_path = socket;
    }
    if print_default_config {
        print!("{}", opennet::config::default_toml()?);
        return Ok(());
    }
    let (shutdown, _rx) = watch::channel(false);
    opennet::daemon::run(config, shutdown)
}
