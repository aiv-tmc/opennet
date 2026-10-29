//! Control client binary: sends one command line to the daemon over the
//! local control socket and prints the answer.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut socket = std::env::var_os("OPENNET_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/opennet/control.sock"));
    let mut words = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            let path = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("--socket requires a file path"))?;
            socket = PathBuf::from(path);
        } else {
            words.push(arg);
        }
    }
    if words.is_empty() {
        eprintln!("usage: opennetctl [--socket <path>] <command...>");
        eprintln!(
            "commands: status, mode, peers, limits, compute, trust, reputation, swarm, shutdown"
        );
        std::process::exit(2);
    }
    let command = words.join(" ");
    let mut stream = UnixStream::connect(&socket)
        .await
        .with_context(|| format!("cannot connect to control socket {}", socket.display()))?;
    stream
        .write_all(command.as_bytes())
        .await
        .context("cannot send command")?;
    stream
        .write_all(b"\n")
        .await
        .context("cannot send command terminator")?;
    let _ = stream.shutdown().await;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .context("cannot read response")?;
    std::io::stdout().write_all(response.as_bytes())?;
    Ok(())
}
