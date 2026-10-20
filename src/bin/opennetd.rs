//! Entry point of the OpenNet daemon binary.

use anyhow::Result;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let mut config_path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let value = args.next().expect("--config requires a path argument");
                config_path = Some(PathBuf::from(value));
            }
            "--print-default-config" => {
                print!("{}", opennet::config::default_toml()?);
                return Ok(());
            }
            "--help" | "-h" => {
                println!("Usage: opennetd [--config <path>] [--print-default-config]");
                return Ok(());
            }
            other => anyhow::bail!("unknown argument: {other} (try --help)"),
        }
    }
    let config = opennet::config::load(config_path)?;
    opennet::daemon::run(config).await
}
