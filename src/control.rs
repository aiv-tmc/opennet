//! Local control interface: a Unix socket accepting one command per line.

use crate::compute;
use crate::daemon::Ctx;
use crate::node::state::Mode;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// Spawn the control socket server in the background.
pub fn spawn(ctx: Arc<Ctx>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = run(ctx).await {
            eprintln!("[control] server terminated: {err:#}");
        }
    })
}

async fn run(ctx: Arc<Ctx>) -> Result<()> {
    let socket_path = &ctx.config.paths.socket_path;
    if let Some(dir) = socket_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Remove a stale socket left behind by an unclean previous shutdown.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("cannot bind control socket {}", socket_path.display()))?;
    println!("[control] listening on {}", socket_path.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_conn(&ctx, stream).await {
                eprintln!("[control] connection error: {err:#}");
            }
        });
    }
}

/// Read a single command line, execute it and stream the text response back.
async fn handle_conn(ctx: &Arc<Ctx>, stream: UnixStream) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut line = String::new();
    BufReader::new(reader).read_line(&mut line).await?;
    let response = dispatch(ctx, line.trim()).await;
    writer.write_all(response.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;
    Ok(())
}

/// Execute one control command and return the text response for the client.
async fn dispatch(ctx: &Arc<Ctx>, command: &str) -> String {
    let mut parts = command.split_whitespace();
    let cmd = parts.next().unwrap_or("help");
    match (cmd, parts.next(), parts.next()) {
        ("status", None, None) => status(ctx).await,
        ("mode", None, None) => format!("mode: {}\n", ctx.state.lock().await.mode.as_str()),
        ("mode", Some(name), None) => set_mode(ctx, name).await,
        ("peers", None, None) => peers(ctx).await,
        ("limits", None, None) => limits(ctx).await,
        ("compute", Some(peer_token), _) => {
            let command_text = parts.collect::<Vec<_>>().join(" ");
            compute_cmd(ctx, peer_token, &command_text).await
        }
        ("trust", None, None) => trust(ctx).await,
        ("reputation", None, None) => reputation(ctx).await,
        ("shutdown", None, None) => {
            let _ = ctx.shutdown.send(true);
            "shutting down\n".to_string()
        }
        _ => help(),
    }
}

/// Human-readable overview of this node and its network view.
async fn status(ctx: &Arc<Ctx>) -> String {
    let state = ctx.state.lock().await;
    let dht = ctx.dht.lock().await;
    let reserved = ctx.reservations.lock().await.len();
    format!(
        "node_id: {node}\nmode: {mode}\ntrust: {trust}\nconsumed: {consumed}\npoints: {points}\nreservations: {reserved}\ntasks_running: {queued}\ntasks_completed: {done}\ntasks_failed: {failed}\nuptime_secs: {uptime}\npeers: {peers}\nmsgs_sent: {sent}\nmsgs_received: {recv}\nlimits: cpu={cpu}% ram={ram}MB tasks={tasks}\n",
        node = ctx.identity.node_id(),
        mode = state.mode.as_str(),
        trust = state.trust,
        consumed = state.consumed,
        points = state.points,
        reserved = reserved,
        queued = ctx.running_tasks.load(std::sync::atomic::Ordering::Relaxed),
        done = state.tasks_completed,
        failed = state.tasks_failed,
        uptime = state.uptime().as_secs(),
        peers = dht.peer_count(),
        sent = state.msgs_sent,
        recv = state.msgs_received,
        cpu = state.limits.cpu_percent,
        ram = state.limits.ram_mb,
        tasks = state.limits.max_tasks,
    )
}

/// Switch the operating mode and persist the new state.
async fn set_mode(ctx: &Arc<Ctx>, name: &str) -> String {
    match Mode::parse(name) {
        Ok(mode) => {
            let mut state = ctx.state.lock().await;
            state.mode = mode;
            match state.save() {
                Ok(()) => format!("mode set to {}\n", mode.as_str()),
                Err(err) => format!("error: mode changed but state not saved: {err:#}\n"),
            }
        }
        Err(err) => format!("error: {err}\n"),
    }
}

/// List known peers with their verified announcement fields.
async fn peers(ctx: &Arc<Ctx>) -> String {
    let peers = ctx.dht.lock().await.all_peers();
    if peers.is_empty() {
        return "no peers known\n".to_string();
    }
    let mut out = String::from("node_id addr mode trust points age_secs\n");
    for peer in peers {
        let id = if peer.node_id.is_empty() {
            "-"
        } else {
            &peer.node_id
        };
        out.push_str(&format!(
            "{id} {} {} {} {} {}\n",
            peer.addr,
            peer.mode,
            peer.trust,
            peer.points,
            peer.last_seen.elapsed().as_secs()
        ));
    }
    out
}

/// Show resource limits and capacity pricing parameters.
async fn limits(ctx: &Arc<Ctx>) -> String {
    let state = ctx.state.lock().await;
    format!(
        "limits: cpu={cpu}% ram={ram}MB tasks={tasks}\ncapacity: {points} points ({ppc}/core {ppg}/GiB)\ntrust: genesis={genesis} min={min}\n",
        cpu = state.limits.cpu_percent,
        ram = state.limits.ram_mb,
        tasks = state.limits.max_tasks,
        points = state.points,
        ppc = ctx.config.trust.points_per_core,
        ppg = ctx.config.trust.points_per_gb,
        genesis = ctx.config.trust.genesis_trust,
        min = ctx.config.trust.min_trust,
    )
}

/// Submit one compute task to the market; `-` selects the peer
/// automatically. The task price is derived from the provider's capacity
/// points, so no manual offer is needed.
async fn compute_cmd(ctx: &Arc<Ctx>, peer_token: &str, command_text: &str) -> String {
    if command_text.is_empty() {
        return "error: usage: compute <node_prefix|-> <command...>\n".to_string();
    }
    let prefix = if peer_token == "-" {
        None
    } else {
        Some(peer_token)
    };
    let timeout_secs = ctx.config.network.task_timeout_secs;
    compute::client::compute(ctx, prefix, command_text.to_string(), timeout_secs).await
}

/// Show the local trust coefficient, consumption counter and reservations.
async fn trust(ctx: &Arc<Ctx>) -> String {
    let state = ctx.state.lock().await;
    let reservations = ctx.reservations.lock().await;
    let reserved: i64 = reservations.values().sum();
    format!(
        "trust: {}\nconsumed: {}\npoints: {}\nreserved: {} ({} tasks)\n",
        state.trust,
        state.consumed,
        state.points,
        reserved,
        reservations.len()
    )
}

/// Render the peer reputation table.
async fn reputation(ctx: &Arc<Ctx>) -> String {
    let table = ctx.reputation.lock().await;
    let entries = table.all();
    if entries.is_empty() {
        return "no reputation data recorded\n".to_string();
    }
    let mut out = String::from("peer valid invalid score\n");
    for (peer, rep) in entries {
        out.push_str(&format!(
            "{peer} {} {} {}\n",
            rep.valid_msgs,
            rep.invalid_msgs,
            rep.score()
        ));
    }
    out
}

/// List all supported commands.
fn help() -> String {
    "commands:\n  status                              node id, mode, trust, task and peer counters\n  mode [peer|seed|leech]              show or set operating mode\n  peers                               known peers with node id, mode, trust, points, age\n  limits                              resource limits and capacity pricing\n  compute <node_prefix|-> <command...>   run a command on a peer\n  trust                               trust coefficient, consumption and reservations\n  reputation                          peer reputation table\n  shutdown                            stop the daemon gracefully\n"
        .to_string()
}

#[cfg(test)]
mod tests;
