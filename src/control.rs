//! Local control interface: a Unix socket accepting one command per line.

use crate::compute;
use crate::credits::ledger::TransferKind;
use crate::credits::transfer::send_transfer;
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
        ("transfer", Some(peer), Some(amount)) => send_transfer(ctx, peer, amount).await,
        ("compute", Some(peer_token), Some(offer_text)) => {
            let command_text = parts.collect::<Vec<_>>().join(" ");
            compute_cmd(ctx, peer_token, offer_text, &command_text).await
        }
        ("ledger", count, None) => ledger(ctx, count).await,
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
    let pending = ctx.pending.lock().await.len();
    let queued = ctx.running_tasks.load(std::sync::atomic::Ordering::Relaxed);
    format!(
        "node_id: {node}\nmode: {mode}\ncredits: {credits}\npending_transfers: {pending}\ntasks_running: {queued}\ntasks_completed: {done}\ntasks_failed: {failed}\nuptime_secs: {uptime}\npeers: {peers}\nmsgs_sent: {sent}\nmsgs_received: {recv}\nlimits: cpu={cpu}% ram={ram}MB tasks={tasks}\n",
        node = ctx.identity.node_id(),
        mode = state.mode.as_str(),
        credits = state.credits,
        pending = pending,
        queued = queued,
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

/// Submit one compute task to the market; `-` selects the peer automatically.
async fn compute_cmd(
    ctx: &Arc<Ctx>,
    peer_token: &str,
    offer_text: &str,
    command_text: &str,
) -> String {
    if command_text.is_empty() {
        return "error: usage: compute <node_prefix|-> <offer> <command...>\n".to_string();
    }
    let offer: u64 = match offer_text.parse() {
        Ok(offer) => offer,
        Err(_) => return format!("error: invalid offer '{offer_text}'\n"),
    };
    let prefix = if peer_token == "-" {
        None
    } else {
        Some(peer_token)
    };
    let timeout_secs = ctx.config.network.task_timeout_secs;
    compute::client::compute(ctx, prefix, offer, command_text.to_string(), timeout_secs).await
}

/// Show the most recent transfer log entries (default 10, max 100).
async fn ledger(ctx: &Arc<Ctx>, count: Option<&str>) -> String {
    let limit: usize = count
        .and_then(|text| text.parse().ok())
        .unwrap_or(10)
        .clamp(1, 100);
    let ledger = ctx.ledger.lock().await;
    let entries = ledger.tail(limit);
    if entries.is_empty() {
        return "no transfers recorded\n".to_string();
    }
    let mut out = String::new();
    for record in entries {
        let kind = match record.kind {
            TransferKind::Outgoing => "out",
            TransferKind::Incoming => "in",
            TransferKind::Refund => "refund",
        };
        out.push_str(&format!(
            "  {} {kind:>6} {} credits with {} at {}\n",
            record.task_id,
            record.amount,
            record.counterparty,
            record.unix_ts
        ));
    }
    out
}

/// Show the local reputation table for all known peers.
async fn reputation(ctx: &Arc<Ctx>) -> String {
    let table = ctx.reputation.lock().await;
    let entries = table.all();
    if entries.is_empty() {
        return "no reputation data yet\n".to_string();
    }
    let mut out = String::new();
    for (peer, rep) in entries {
        out.push_str(&format!(
            "  {peer} score={} valid={} invalid={} in={} out={}\n",
            rep.score(),
            rep.valid_msgs,
            rep.invalid_msgs,
            rep.credits_in,
            rep.credits_out
        ));
    }
    out
}

/// List all known peers with their announced parameters and age.
async fn peers(ctx: &Arc<Ctx>) -> String {
    let peers = ctx.dht.lock().await.all_peers();
    if peers.is_empty() {
        return "no peers known\n".to_string();
    }
    let mut out = format!("{} peer(s), freshest first:\n", peers.len());
    for peer in peers {
        let node_id = if peer.node_id.is_empty() {
            "-"
        } else {
            &peer.node_id
        };
        out.push_str(&format!(
            "  {node_id} {} mode={} credits={} last_seen={}s ago\n",
            peer.addr,
            peer.mode,
            peer.credits,
            peer.last_seen.elapsed().as_secs()
        ));
    }
    out
}

/// Show the resource limits this node offers to the network.
async fn limits(ctx: &Arc<Ctx>) -> String {
    let state = ctx.state.lock().await;
    format!(
        "cpu_percent: {}\nram_mb: {}\nmax_tasks: {}\n",
        state.limits.cpu_percent, state.limits.ram_mb, state.limits.max_tasks
    )
}

/// Command summary served for `help` and empty commands.
fn help() -> String {
    "commands:\n  status                  show node overview\n  mode [peer|seed|leech]  show or set operating mode\n  peers                   list known peers\n  limits                  show resource limits\n  transfer <node_prefix> <amount>\n                          send signed credits to a peer\n  compute <node_prefix|-> <offer> <command...>\n                          run a command on a peer and pay on success\n  ledger [count]          show recent transfers (default 10)\n  reputation              show peer reputation table\n  shutdown                stop the daemon\n".to_string()
}
