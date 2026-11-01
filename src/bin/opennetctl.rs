//! `opennetctl`: command-line client for the daemon's local control
//! interface. One short-lived connection per invocation: the command
//! line is sent as one request, the rendered response is printed to
//! stdout, exit status follows the daemon's view of the command.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(not(unix))]
use tokio::net::TcpStream;

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start tokio runtime")?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        print!("{}", opennet::control::render::help());
        return Ok(());
    };
    let socket = control_path();
    let mut command_line = command.clone();
    for arg in &args[1..] {
        command_line.push(' ');
        command_line.push_str(arg);
    }
    let response = exchange(&socket, &command_line).await?;
    print!("{response}");
    Ok(())
}

/// The control endpoint discovery path: the environment override wins,
/// else the platform default.
fn control_path() -> PathBuf {
    if let Ok(path) = std::env::var("OPENNET_SOCKET") {
        return PathBuf::from(path);
    }
    #[cfg(unix)]
    {
        PathBuf::from("/run/opennet/control.sock")
    }
    #[cfg(not(unix))]
    {
        // The daemon records its loopback listener address in the
        // state directory on this platform.
        PathBuf::from("control.sock")
    }
}

/// Connect to the daemon and run one request/response exchange. The
/// Unix path is a filesystem socket; elsewhere the file at the path
/// holds the `host:port` line of the daemon's loopback listener.
#[cfg(unix)]
async fn exchange(socket: &std::path::Path, command: &str) -> Result<String> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("cannot connect to control socket {}", socket.display()))?;
    let (reader, writer) = stream.into_split();
    transact(reader, writer, command).await
}

#[cfg(not(unix))]
async fn exchange(socket: &std::path::Path, command: &str) -> Result<String> {
    let addr_text = std::fs::read_to_string(socket)
        .with_context(|| format!("cannot read control address {}", socket.display()))?;
    let addr: std::net::SocketAddr = addr_text
        .trim()
        .parse()
        .context("corrupt control address record")?;
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("cannot connect to control listener {addr}"))?;
    let (reader, writer) = stream.into_split();
    transact(reader, writer, command).await
}

/// Send one command and read the whole response; the daemon answers on
/// the same connection and shuts its write half, so end of stream is
/// the response boundary.
async fn transact(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    command: &str,
) -> Result<String> {
    writer
        .write_all(command.as_bytes())
        .await
        .context("cannot send control command")?;
    writer.shutdown().await.context("cannot flush command")?;
    let mut response = String::new();
    reader
        .read_to_string(&mut response)
        .await
        .context("cannot read control response")?;
    if response.is_empty() {
        bail!("empty control response");
    }
    Ok(response)
}
