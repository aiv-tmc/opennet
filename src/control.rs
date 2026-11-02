//! Local control interface: `opennetctl` talks to the daemon over one
//! short-lived connection per command, request in, rendered response
//! out. On Unix the endpoint is a filesystem socket guarded by peer
//! credentials (root or the daemon's own uid); elsewhere the endpoint
//! is a loopback TCP listener, the socket path names a small discovery
//! file holding the `host:port` line the client reads back, and every
//! connection must additionally present a shared token stored next to
//! the discovery file with owner-only permissions. Both transports are
//! also capped on in-flight connections so a misbehaving local client
//! cannot pin the daemon.

use crate::compute;
use crate::daemon::Ctx;
use crate::node::state::Mode;
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(not(unix))]
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

pub mod render;

/// Maximum concurrently served control connections; excess accepts are
/// dropped so control traffic cannot starve the daemon's other tasks.
const MAX_INFLIGHT_CONTROL: usize = 32;

/// Process-wide counter of in-flight control connections.
static INFLIGHT_CONTROL: AtomicUsize = AtomicUsize::new(0);

/// Spawn the control interface task.
pub fn spawn(ctx: Arc<Ctx>) {
    tokio::spawn(async move {
        if let Err(err) = run(ctx).await {
            crate::log::warn(module_path!(), &format!("[control] fatal: {err:#}"));
        }
    });
}

/// Accept control connections until the process ends.
async fn run(ctx: Arc<Ctx>) -> Result<()> {
    let path = &ctx.config.paths.socket_path;
    if path.exists() {
        std::fs::remove_file(path).context("cannot remove stale socket")?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        let listener = UnixListener::bind(path).context("cannot bind control socket")?;
        crate::log::warn(
            module_path!(),
            &format!("[opennetd] control socket {}", path.display()),
        );
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        serve_guarded(&ctx, stream).await;
                    });
                }
                Err(err) => eprintln!("[opennetd] control accept error: {err}"),
            }
        }
    }
    #[cfg(not(unix))]
    {
        // No peer credentials exist on this platform, so the listener
        // is confined to loopback, the socket path becomes a discovery
        // file recording the address the client dials, and a shared
        // token next to that file authenticates every connection.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("cannot bind control listener")?;
        let addr = listener.local_addr().context("control listener addr")?;
        std::fs::write(path, format!("{addr}\n")).context("cannot record control address")?;
        let token = load_or_create_token(&token_path(path))?;
        eprintln!(
            "[opennetd] control listener on {addr} (recorded in {})",
            path.display()
        );
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let ctx = ctx.clone();
                    let token = token.clone();
                    tokio::spawn(async move {
                        serve_guarded_token(&ctx, stream, token).await;
                    });
                }
                Err(err) => eprintln!("[opennetd] control accept error: {err}"),
            }
        }
    }
}

/// The token file path next to one discovery file.
#[cfg(not(unix))]
fn token_path(discovery: &std::path::Path) -> std::path::PathBuf {
    discovery
        .parent()
        .map(|dir| dir.join("control.token"))
        .unwrap_or_else(|| std::path::PathBuf::from("control.token"))
}

/// Load the existing control token or create a fresh one with
/// owner-only permissions. The token is 32 random bytes as hex,
/// unguessable to other local users and stable across daemon restarts
/// so long-lived clients keep working.
#[cfg(not(unix))]
fn load_or_create_token(path: &std::path::Path) -> Result<String> {
    if let Ok(token) = std::fs::read_to_string(path) {
        let token = token.trim().to_string();
        if token.len() >= 32 {
            return Ok(token);
        }
    }
    let token = hex::encode(rand::random::<[u8; 32]>());
    std::fs::write(path, format!("{token}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(token)
}

/// Constant-time equality for the control token: the comparison never
/// short-circuits on the first differing byte, so response timing
/// leaks nothing about how much of a guess was right. The length
/// check runs separately — a token's length is not secret — and the
/// byte loop accumulates into one byte so no platform type quirks can
/// leak in.
#[cfg(not(unix))]
fn token_matches(expected: &str, presented: &str) -> bool {
    let a = expected.as_bytes();
    let b = presented.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for index in 0..a.len() {
        diff |= a[index] ^ b[index];
    }
    diff == 0
}

/// Serve one Unix control connection behind the in-flight cap.
#[cfg(unix)]
async fn serve_guarded(ctx: &Arc<Ctx>, stream: UnixStream) {
    if INFLIGHT_CONTROL.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT_CONTROL {
        INFLIGHT_CONTROL.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let _ = serve_conn(ctx, stream).await;
    INFLIGHT_CONTROL.fetch_sub(1, Ordering::SeqCst);
}

/// Serve one non-Unix control connection behind the in-flight cap.
#[cfg(not(unix))]
async fn serve_guarded_token(ctx: &Arc<Ctx>, stream: TcpStream, token: String) {
    if INFLIGHT_CONTROL.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT_CONTROL {
        INFLIGHT_CONTROL.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let _ = serve_conn(ctx, stream, token).await;
    INFLIGHT_CONTROL.fetch_sub(1, Ordering::SeqCst);
}

/// Peer credentials on Linux: SO_PEERCRED on the socket fd; root or the
/// daemon's own uid may command.
#[cfg(all(unix, target_os = "linux"))]
fn peer_allowed(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return false;
    }
    cred.uid == 0 || cred.uid == unsafe { libc::getuid() }
}

/// Peer credentials on other Unix systems (macOS, BSD): getpeereid on
/// the socket fd; root or the daemon's own uid may command.
#[cfg(all(unix, not(target_os = "linux")))]
fn peer_allowed(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return false;
    }
    uid == 0 || uid == unsafe { libc::getuid() }
}

/// Handle one accepted Unix connection after the credential check.
#[cfg(unix)]
async fn serve_conn(ctx: &Arc<Ctx>, stream: UnixStream) -> Result<()> {
    if !peer_allowed(&stream) {
        return Ok(());
    }
    let (reader, writer) = stream.into_split();
    command_loop(ctx, reader, writer).await
}

/// Handle one accepted connection on platforms without peer
/// credentials: the loopback bind confines reachability and the shared
/// token confines control to holders of the token file. The token is
/// the first line of the connection; a missing or wrong token ends the
/// session without any response.
#[cfg(not(unix))]
async fn serve_conn(ctx: &Arc<Ctx>, stream: TcpStream, token: String) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let Ok(Some(presented)) = lines.next_line().await else {
        return Ok(());
    };
    if !token_matches(&token, presented.trim()) {
        return Ok(());
    }
    command_loop(ctx, lines.into_inner(), writer).await
}

/// Read one command line, execute it and write the response; shared
/// by every control transport.
async fn command_loop(
    ctx: &Arc<Ctx>,
    reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<()> {
    let mut lines = BufReader::new(reader).lines();
    // `next_line` yields Result<Option<String>>: end of stream or an
    // I/O error both end the session silently.
    let Ok(Some(command)) = lines.next_line().await else {
        return Ok(());
    };
    let response = dispatch(ctx, &command).await;
    writer.write_all(response.as_bytes()).await?;
    writer.shutdown().await?;
    Ok(())
}

/// Execute one control command and render its response. The output
/// format is a contract: `src/control/tests.rs` pins it (genesis
/// trust 100, the `commands:` help list, the `no reputation data
/// recorded` line).
async fn dispatch(ctx: &Arc<Ctx>, command: &str) -> String {
    let mut parts = command.split_whitespace();
    let Some(head) = parts.next() else {
        return render::help();
    };
    match (head, parts.next()) {
        ("status", None) => render::status(ctx).await,
        ("mode", None) => {
            let mode = ctx.state.lock().await.mode;
            format!("mode: {}\n", mode.as_str())
        }
        ("mode", Some(name)) => match Mode::parse(name) {
            Ok(mode) => {
                {
                    let mut state = ctx.state.lock().await;
                    state.mode = mode;
                    let _ = state.save();
                }
                format!("mode set to {}\n", mode.as_str())
            }
            Err(err) => format!("error: {err}\n"),
        },
        ("peers", None) => render::peers(ctx).await,
        ("limits", None) => render::limits(&ctx.config),
        ("compute", Some(peer_token)) => {
            // Leading options before the command text: `--gpus N`
            // requests GPU devices, `--ram-mb M` requests a memory cap,
            // `--verify N` runs the task on N peers and keeps the
            // majority output; the first non-option token starts the
            // command.
            let mut gpus = 0u32;
            let mut ram_mb = 0u64;
            let mut verify = 1u32;
            let mut rest: Vec<&str> = Vec::new();
            let mut args = parts.peekable();
            while let Some(arg) = args.next() {
                match arg {
                    "--gpus" => match args.next().and_then(|value| value.parse().ok()) {
                        Some(count) => gpus = count,
                        None => return "error: --gpus needs a device count\n".to_string(),
                    },
                    "--ram-mb" => match args.next().and_then(|value| value.parse().ok()) {
                        Some(megabytes) => ram_mb = megabytes,
                        None => return "error: --ram-mb needs a size\n".to_string(),
                    },
                    "--verify" => match args.next().and_then(|value| value.parse().ok()) {
                        Some(count) if count >= 1 => verify = count,
                        _ => return "error: --verify needs a count >= 1\n".to_string(),
                    },
                    other => {
                        rest.push(other);
                        rest.extend(args);
                        break;
                    }
                }
            }
            if rest.is_empty() {
                return "usage: compute <node_prefix|-> [--gpus N] [--ram-mb M] [--verify N] <command...>\n"
                    .to_string();
            }
            let command_text = rest.join(" ");
            let prefix = (peer_token != "-").then_some(peer_token);
            compute::client::compute(
                ctx,
                prefix,
                command_text,
                ctx.config.network.task_timeout_secs,
                ram_mb,
                gpus,
                verify,
            )
            .await
        }
        ("trust", None) => render::trust(ctx).await,
        ("reputation", None) => render::reputation(ctx).await,
        ("swarm", None) | ("swarm", Some("status")) => render::swarm_status(ctx).await,
        ("swarm", Some("enable")) => render::swarm_set(ctx, parts.next(), true).await,
        ("swarm", Some("disable")) => render::swarm_set(ctx, None, false).await,
        ("swarm", Some("run")) => {
            let (Some(program), Some(prompt_path)) = (parts.next(), parts.next()) else {
                return "error: usage: swarm run <program> <prompt-file>\n".to_string();
            };
            match crate::swarm::coordinator::run_program(ctx, program, prompt_path).await {
                Ok(output) => output,
                Err(err) => format!("error: {err:#}\n"),
            }
        }
        ("shutdown", None) => {
            let _ = ctx.shutdown.send(true);
            "shutting down\n".to_string()
        }
        _ => render::help(),
    }
}
