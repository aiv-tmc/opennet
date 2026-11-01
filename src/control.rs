//! Local control interface: a unix domain socket where `opennetctl`
//! sends one command line per connection and reads the daemon's answer.
//!
//! Every connection gets its own task, so a slow or stuck client never
//! blocks the others. The parser takes the subcommand token and hands
//! the remainder of the line to the handler, so multi-word arguments
//! (like the command of `compute`) survive intact; `compute` recognizes
//! leading `--gpus N`, `--ram-mb M` and `--verify N` options before the
//! command text. All response rendering lives in `render.rs` so this
//! file stays focused on I/O.
//!
//! Peer credentials: every connection must come from the root user or
//! the daemon's own user id. The socket directory is root-only by
//! default, but a deployment that loosens the directory permissions
//! must not silently widen the command surface — `SO_PEERCRED` closes
//! that hole at the socket level.

use crate::compute;
use crate::daemon::Ctx;
use crate::node::state::Mode;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

mod render;

/// Spawn the control socket server in the background; the socket file
/// is replaced on every start so a crashed daemon cannot leave a stale
/// one behind.
pub fn spawn(ctx: Arc<Ctx>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = run(ctx).await {
            eprintln!("[control] task terminated: {err:#}");
        }
    })
}

/// Bind the control socket and serve connections until the daemon exits.
async fn run(ctx: Arc<Ctx>) -> Result<()> {
    let path = &ctx.config.paths.socket_path;
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("cannot remove stale socket {}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create socket dir {}", parent.display()))?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("cannot bind control socket {}", path.display()))?;
    eprintln!("[opennetd] control socket listening on {}", path.display());
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(err) = serve_conn(&ctx, stream).await {
                        eprintln!("[control] connection error: {err:#}");
                    }
                });
            }
            Err(err) => eprintln!("[control] accept failed: {err:#}"),
        }
    }
}

/// Refuse control connections from any uid other than root and the
/// daemon's own effective user; the filesystem permissions on the
/// socket directory are the first line of defense, this is the second.
#[cfg(unix)]
fn peer_allowed(stream: &UnixStream) -> bool {
    match stream.peer_cred() {
        Ok(cred) => {
            let peer = cred.uid();
            let own = unsafe { libc::geteuid() };
            if peer == 0 || peer == own {
                true
            } else {
                eprintln!("[control] refusing connection from uid {peer}");
                false
            }
        }
        Err(err) => {
            eprintln!("[control] cannot identify peer credentials: {err:#}");
            false
        }
    }
}

/// Answer one control connection: read one command line, run it and
/// write the response back, until the client hangs up.
async fn serve_conn(ctx: &Arc<Ctx>, stream: UnixStream) -> Result<()> {
    #[cfg(unix)]
    if !peer_allowed(&stream) {
        return Ok(());
    }
    let (reader, mut writer) = stream.into_split();
    let mut lines = tokio::io::BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let response = dispatch(ctx, line.trim()).await;
        let mut out = response.into_bytes();
        if out.last() != Some(&b'\n') {
            out.push(b'\n');
        }
        writer.write_all(&out).await?;
    }
    Ok(())
}

/// Route one command line to its handler; every handler returns the
/// text shown to the user.
pub async fn dispatch(ctx: &Arc<Ctx>, command: &str) -> String {
    let mut parts = command.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let token = parts.next();
    match (cmd, token) {
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
