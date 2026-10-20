//! CLI client for the OpenNet control socket.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<()> {
    // Socket path: --socket flag, then OPENNET_SOCKET env, then the default.
    let mut socket_path: Option<PathBuf> = None;
    let mut words: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            let value = args.next().context("--socket requires a path argument")?;
            socket_path = Some(PathBuf::from(value));
        } else {
            words.push(arg);
        }
    }
    let socket_path = socket_path
        .or_else(|| std::env::var_os("OPENNET_SOCKET").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/run/opennet/control.sock"));
    if words.is_empty() {
        words.push("help".to_string());
    }

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("cannot connect to control socket {}", socket_path.display()))?;
    let command = format!("{}\n", words.join(" "));
    stream.write_all(command.as_bytes()).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    print!("{response}");
    Ok(())
}
