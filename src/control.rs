//! Local control interface: a unix domain socket where `opennetctl` sends
//! one command line per connection and reads the daemon's answer.
//!
//! Every connection gets its own task, so a slow or stuck client never
//! blocks the others. The parser takes the subcommand token and hands the
//! remainder of the line to the handler, so multi-word arguments (like the
//! command of `compute`) survive intact.

use crate::compute;
use crate::config::Config;
use crate::daemon::Ctx;
use crate::node::state::Mode;
use crate::swarm;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// Spawn the control socket server in the background; the socket file is
/// replaced on every start so a crashed daemon cannot leave a stale one.
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

/// Answer one control connection: read one command line, run it and write
/// the response back, until the client hangs up.
async fn serve_conn(ctx: &Arc<Ctx>, stream: UnixStream) -> Result<()> {
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

/// Route one command line to its handler; every handler returns the text
/// shown to the user.
pub async fn dispatch(ctx: &Arc<Ctx>, command: &str) -> String {
    let mut parts = command.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let token = parts.next();
    match (cmd, token) {
        ("status", None) => status(ctx).await,
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
        ("peers", None) => peers(ctx).await,
        ("limits", None) => limits(&ctx.config),
        ("compute", Some(peer_token)) => {
            let command_text = parts.collect::<Vec<_>>().join(" ");
            if command_text.is_empty() {
                return "error: compute needs a command to run\n".to_string();
            }
            let prefix = (peer_token != "-").then_some(peer_token);
            compute::client::compute(
                ctx,
                prefix,
                command_text,
                ctx.config.network.task_timeout_secs,
            )
            .await
        }
        ("trust", None) => trust(ctx).await,
        ("reputation", None) => reputation(ctx).await,
        ("swarm", None) | ("swarm", Some("status")) => swarm_status(ctx).await,
        ("swarm", Some("enable")) => swarm_set(ctx, parts.next(), true).await,
        ("swarm", Some("disable")) => swarm_set(ctx, None, false).await,
        ("swarm", Some("run")) => {
            let (Some(program), Some(prompt_path)) = (parts.next(), parts.next()) else {
                return "error: usage: swarm run <program> <prompt-file>\n".to_string();
            };
            match swarm::coordinator::run_program(ctx, program, prompt_path).await {
                Ok(output) => output,
                Err(err) => format!("error: {err:#}\n"),
            }
        }
        ("shutdown", None) => {
            let _ = ctx.shutdown.send(true);
            "shutting down\n".to_string()
        }
        _ => help(),
    }
}

/// Render the full node overview.
async fn status(ctx: &Arc<Ctx>) -> String {
    let (mode, trust, consumed, points, completed, failed, sent, received, uptime) = {
        let state = ctx.state.lock().await;
        (
            state.mode,
            state.trust,
            state.consumed,
            state.points,
            state.tasks_completed,
            state.tasks_failed,
            state.msgs_sent,
            state.msgs_received,
            state.uptime().as_secs(),
        )
    };
    let (peer_count, swarm_line) = {
        let dht = ctx.dht.lock().await;
        let offers = dht
            .all_peers()
            .iter()
            .filter(|peer| !peer.swarm_program.is_empty())
            .count();
        let line = {
            let consent = ctx.swarm.lock().await;
            if consent.enabled && !consent.program.is_empty() {
                format!(
                    "hosting '{}' (offers from {} peers)",
                    consent.program, offers
                )
            } else {
                format!("disabled (offers from {} peers)", offers)
            }
        };
        (dht.peer_count(), line)
    };
    let plans = ctx.swarm_plans.lock().await.len();
    let shards = ctx.swarm_procs.lock().await.len();
    format!(
        "node_id: {node_id}\nmode: {mode}\ntrust: {trust}\nconsumed: {consumed}\npoints: {points}\n\
         peers: {peer_count}\ntasks_completed: {completed}\ntasks_failed: {failed}\n\
         msgs_sent: {sent}\nmsgs_received: {received}\nswarm: {swarm_line}\n\
         swarm_plans: {plans}\nlocal_shards: {shards}\nuptime_s: {uptime}\n",
        node_id = ctx.identity.node_id(),
        mode = mode.as_str(),
    )
}

/// Render the peer table with identity, mode, trust, points and age,
/// newest first.
async fn peers(ctx: &Arc<Ctx>) -> String {
    let peers = ctx.dht.lock().await.all_peers_by_recency();
    if peers.is_empty() {
        return "no peers known\n".to_string();
    }
    let mut out = String::from("node_id           mode   trust   points   addr\n");
    for peer in peers {
        out.push_str(&format!(
            "{:<17} {:<6} {:>7} {:>6}   {} ({}s ago)\n",
            if peer.node_id.is_empty() {
                "-"
            } else {
                &peer.node_id
            },
            peer.mode,
            peer.trust,
            peer.points,
            peer.addr,
            peer.last_seen.elapsed().as_secs(),
        ));
    }
    out
}

/// Render the resource limits and pricing parameters.
fn limits(config: &Config) -> String {
    format!(
        "cpu_percent: {cpu}%\nram_mb: {ram}\nmax_tasks: {tasks}\n\
         points_per_core: {ppc}\npoints_per_gb: {ppg}\nmin_trust: {min_trust}\n\
         genesis_trust: {genesis}\ntask_timeout_secs: {timeout}\n",
        cpu = config.limits.cpu_percent,
        ram = config.limits.ram_mb,
        tasks = config.limits.max_tasks,
        ppc = config.trust.points_per_core,
        ppg = config.trust.points_per_gb,
        min_trust = config.trust.min_trust,
        genesis = config.trust.genesis_trust,
        timeout = config.network.task_timeout_secs,
    )
}

/// Render the trust coefficient, consumption counter and reservations.
async fn trust(ctx: &Arc<Ctx>) -> String {
    let state = ctx.state.lock().await;
    let reserved = state.reserved_total();
    let mut out = format!(
        "trust: {trust}\nconsumed: {consumed}\npoints: {points}\n",
        trust = state.trust,
        consumed = state.consumed,
        points = state.points,
    );
    if state.reservations.is_empty() {
        out.push_str("reservations: none\n");
    } else {
        out.push_str("reservations:\n");
        for (task_id, units) in &state.reservations {
            out.push_str(&format!("  {task_id}: {units} units\n"));
        }
        out.push_str(&format!("  total: {reserved} units\n"));
    }
    out
}

/// Render the reputation table, highest score first.
async fn reputation(ctx: &Arc<Ctx>) -> String {
    let entries = ctx.reputation.lock().await.all();
    if entries.is_empty() {
        return "no reputation data yet\n".to_string();
    }
    let mut out = String::new();
    for (peer, rep) in entries {
        out.push_str(&format!(
            "{peer}: score {} ({} valid / {} invalid)\n",
            rep.score(),
            rep.valid_msgs,
            rep.invalid_msgs,
        ));
    }
    out
}

/// Render swarm consent, local shards and live plans.
async fn swarm_status(ctx: &Arc<Ctx>) -> String {
    let consent = ctx.swarm.lock().await.clone();
    let mut out = if consent.enabled && !consent.program.is_empty() {
        format!(
            "swarm: hosting '{}' (ram cap {} MB, cpu cap {}%)\n",
            consent.program, consent.max_shard_ram_mb, consent.max_shard_cpu_percent,
        )
    } else {
        "swarm: disabled (no consent granted)\n".to_string()
    };
    let procs = ctx.swarm_procs.lock().await;
    if procs.is_empty() {
        out.push_str("local_shards: none\n");
    } else {
        out.push_str("local_shards:\n");
        for (key, proc_) in procs.iter() {
            out.push_str(&format!("  {key} (shard {})\n", proc_.shard_index));
        }
    }
    drop(procs);
    let plans = ctx.swarm_plans.lock().await;
    out.push_str(&format!("active_plans: {}\n", plans.len()));
    for (plan_id, plan) in plans.iter() {
        out.push_str(&format!(
            "  {plan_id}: {} shards, {} ready\n",
            plan.shards.len(),
            plan.ready.len(),
        ));
    }
    out
}

/// Grant or revoke swarm consent and persist it to the state directory so
/// the choice survives daemon restarts; the change takes effect on the
/// next heartbeat round. Revoking consent stops future launches and
/// announcements, while already running shards finish their plan lifetime.
async fn swarm_set(ctx: &Arc<Ctx>, program: Option<&str>, enabled: bool) -> String {
    let state_dir = ctx.config.paths.state_dir.clone();
    let mut consent = ctx.swarm.lock().await;
    let program = if enabled {
        match program {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => return "error: usage: swarm enable <program>\n".to_string(),
        }
    } else {
        String::new()
    };
    consent.enabled = enabled;
    consent.program = program;
    match consent.save(&state_dir) {
        Ok(()) => {
            if enabled {
                format!("swarm consent granted for '{}'\n", consent.program)
            } else {
                "swarm consent revoked\n".to_string()
            }
        }
        Err(err) => format!("error: cannot persist consent: {err:#}\n"),
    }
}

/// Usage text shown for empty or unknown commands.
fn help() -> String {
    "opennetctl <command>\n  \
     status                          node overview\n  \
     mode [peer|seed|leech]          show or set operating mode\n  \
     peers                           known peers\n  \
     limits                          resource limits and capacity pricing\n  \
     compute <node_prefix|-> <cmd>   run a command on a peer\n  \
     trust                           trust coefficient and reservations\n  \
     reputation                      peer reputation table\n  \
     swarm status                    swarm consent, shards and plans\n  \
     swarm enable <program>          consent to host a program\n  \
     swarm disable                   revoke swarm consent\n  \
     swarm run <program> <file>      run a program across the swarm\n  \
     shutdown                        stop the daemon gracefully\n"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::make_ctx;

    #[tokio::test]
    async fn status_reports_identity_mode_and_counters() {
        let (ctx, _rx) = make_ctx("ctl-status").await;
        let out = dispatch(&ctx, "status").await;
        assert!(out.contains(&ctx.identity.node_id()));
        assert!(out.contains("mode: peer"));
        assert!(out.contains("trust: 100"));
        assert!(out.contains("swarm: disabled"));
    }

    #[tokio::test]
    async fn mode_persists_across_reloads() {
        let (ctx, _rx) = make_ctx("ctl-mode").await;
        let out = dispatch(&ctx, "mode seed").await;
        assert!(out.contains("mode set to seed"));
        let out = dispatch(&ctx, "mode").await;
        assert!(out.contains("mode: seed"));
        let reloaded = crate::node::state::NodeState::load(
            &ctx.config.paths.state_dir,
            Mode::Peer,
            ctx.config.limits.clone(),
            &ctx.config.trust,
        )
        .unwrap();
        assert_eq!(reloaded.mode, Mode::Seed);
    }

    #[tokio::test]
    async fn swarm_consent_toggles_and_persists() {
        let (ctx, _rx) = make_ctx("ctl-swarm").await;
        let out = dispatch(&ctx, "swarm enable demo").await;
        assert!(out.contains("granted for 'demo'"));
        let out = dispatch(&ctx, "swarm status").await;
        assert!(out.contains("hosting 'demo'"));
        let reloaded = swarm::Consent::load(&ctx.config.paths.state_dir, &ctx.config.swarm);
        assert!(reloaded.allows("demo"));
        let out = dispatch(&ctx, "swarm disable").await;
        assert!(out.contains("revoked"));
        let reloaded = swarm::Consent::load(&ctx.config.paths.state_dir, &ctx.config.swarm);
        assert!(!reloaded.enabled);
    }

    #[tokio::test]
    async fn unknown_command_shows_help() {
        let (ctx, _rx) = make_ctx("ctl-help").await;
        let out = dispatch(&ctx, "bogus").await;
        assert!(out.contains("opennetctl <command>"));
        assert!(out.contains("compute <node_prefix|->"));
    }
}
