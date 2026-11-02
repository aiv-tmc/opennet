//! `opennetctl`: command-line client for the daemon's local control
//! interface. One short-lived connection per invocation: the command
//! line is sent as one request, the rendered response is printed to
//! stdout, exit status follows the daemon's view of the command.
//!
//! On Unix the endpoint is a filesystem socket authenticated by peer
//! credentials. Elsewhere the endpoint is a loopback listener whose
//! address is recorded in the state directory, and the client
//! authenticates with the shared token stored next to that discovery
//! file — anyone who can read the token file (the daemon's own user,
//! or an administrator) can command the daemon.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(not(unix))]
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

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

/// The shared control token path next to one discovery file.
#[cfg(not(unix))]
fn token_path(discovery: &std::path::Path) -> PathBuf {
    discovery
        .parent()
        .map(|dir| dir.join("control.token"))
        .unwrap_or_else(|| PathBuf::from("control.token"))
}

/// Connect to the daemon and run one request/response exchange. The
/// Unix path is a filesystem socket; elsewhere the file at the path
/// holds the `host:port` line of the daemon's loopback listener and
/// the connection opens with the shared token line.
#[cfg(unix)]
async fn exchange(socket: &std::path::Path, command: &str) -> Result<String> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("cannot connect to control socket {}", socket.display()))?;
    let (reader, writer) = stream.into_split();
    transact(reader, writer, None, command).await
}

#[cfg(not(unix))]
async fn exchange(socket: &std::path::Path, command: &str) -> Result<String> {
    let addr_text = std::fs::read_to_string(socket)
        .with_context(|| format!("cannot read control address {}", socket.display()))?;
    let addr: std::net::SocketAddr = addr_text
        .trim()
        .parse()
        .context("corrupt control address record")?;
    let token = std::fs::read_to_string(token_path(socket)).with_context(|| {
        format!(
            "cannot read control token {}; the daemon creates it on first start",
            token_path(socket).display()
        )
    })?;
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("cannot connect to control listener {addr}"))?;
    let (reader, writer) = stream.into_split();
    transact(reader, writer, Some(token.trim().to_string()), command).await
}

/// Send one command and read the whole response; the daemon answers on
/// the same connection and shuts its write half, so end of stream is
/// the response boundary. On platforms without peer credentials the
/// shared token travels as the first line, before the command.
async fn transact(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    token: Option<String>,
    command: &str,
) -> Result<String> {
    if let Some(token) = token {
        writer
            .write_all(token.as_bytes())
            .await
            .context("cannot send control token")?;
        writer
            .write_all(b"\n")
            .await
            .context("cannot flush token")?;
    }
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
