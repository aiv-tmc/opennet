//! Response rendering for the control socket: every handler returns
//! the exact text shown to the user, keeping the socket plumbing in
//! `control.rs` free of presentation logic.

use crate::config::Config;
use crate::daemon::Ctx;
use crate::swarm;
use std::sync::Arc;

/// Render the full node overview: identity, economy counters, wire
/// health, sandbox capability and swarm state.
pub async fn status(ctx: &Arc<Ctx>) -> String {
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
         msgs_sent: {sent}\nmsgs_received: {received}\nsandbox: {sandbox}\nswarm: {swarm_line}\n\
         swarm_plans: {plans}\nlocal_shards: {shards}\nuptime_s: {uptime}\n",
        node_id = ctx.identity.node_id(),
        mode = mode.as_str(),
        sandbox = sandbox_line(&ctx.config),
    )
}

/// One human-readable sandbox capability line: what the config asks
/// for, and — based on the daemon's privileges — whether namespace
/// isolation will actually engage or degrade to cgroup limits only, so
/// an operator hosting untrusted tasks always knows which boundary is
/// really in place.
fn sandbox_line(config: &Config) -> &'static str {
    #[cfg(unix)]
    let privileged = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let privileged = false;
    match (config.sandbox.namespaces, config.sandbox.cgroup, privileged) {
        (false, false, _) => "disabled",
        (false, true, _) => "cgroup limits only (namespaces off)",
        (true, _, true) => "active (namespaces + cgroup, best-effort)",
        (true, _, false) => "degraded (no privileges: cgroup limits only, no namespace isolation)",
    }
}

/// Render the peer table with identity, mode, trust, points, GPUs and
/// age, newest first.
pub async fn peers(ctx: &Arc<Ctx>) -> String {
    let peers = ctx.dht.lock().await.all_peers_by_recency();
    if peers.is_empty() {
        return "no peers known\n".to_string();
    }
    let mut out = String::from("node_id           mode   trust   points   gpus   addr\n");
    for peer in peers {
        out.push_str(&format!(
            "{:<17} {:<6} {:>7} {:>6}   {:>4}   {} ({}s ago)\n",
            if peer.node_id.is_empty() {
                "-"
            } else {
                &peer.node_id
            },
            peer.mode,
            peer.trust,
            peer.points,
            peer.gpus,
            peer.addr,
            peer.last_seen.elapsed().as_secs(),
        ));
    }
    out
}

/// Render the resource limits and pricing parameters in `key=value`
/// form, including the GPU offer (device count, explicit device list
/// and per-device price).
pub fn limits(config: &Config) -> String {
    let devices = if config.gpu.devices.is_empty() {
        "auto".to_string()
    } else {
        config
            .gpu
            .devices
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "cpu_percent={cpu}\nram_mb={ram}\nmax_tasks={tasks}\n\
         gpu_count={gpus}\ngpu_devices={devices}\npoints_per_gpu={ppgpu}\n\
         points_per_core={ppc}\npoints_per_gb={ppg}\nmin_trust={min_trust}\n\
         genesis={genesis}\ntask_timeout_secs={timeout}\n",
        cpu = config.limits.cpu_percent,
        ram = config.limits.ram_mb,
        tasks = config.limits.max_tasks,
        gpus = config.gpu.count,
        devices = devices,
        ppgpu = config.gpu.points_per_gpu,
        ppc = config.trust.points_per_core,
        ppg = config.trust.points_per_gb,
        min_trust = config.trust.min_trust,
        genesis = config.trust.genesis_trust,
        timeout = config.network.task_timeout_secs,
    )
}

/// Render the trust coefficient, consumption counter and reservations.
pub async fn trust(ctx: &Arc<Ctx>) -> String {
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
pub async fn reputation(ctx: &Arc<Ctx>) -> String {
    let entries = ctx.reputation.lock().await.all();
    if entries.is_empty() {
        return "no reputation data recorded\n".to_string();
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
pub async fn swarm_status(ctx: &Arc<Ctx>) -> String {
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

/// Grant or revoke swarm consent and persist it to the state directory
/// so the choice survives daemon restarts; the change takes effect on
/// the next heartbeat round. Revoking consent announces a signed
/// retraction to every known peer immediately, so placement stops
/// instead of waiting for offers to age out; already running shards
/// finish their plan lifetime.
pub async fn swarm_set(ctx: &Arc<Ctx>, program: Option<&str>, enabled: bool) -> String {
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
                drop(consent);
                swarm::broadcast_leave(ctx).await;
                "swarm consent revoked\n".to_string()
            }
        }
        Err(err) => format!("error: cannot persist consent: {err:#}\n"),
    }
}

/// Usage text shown for empty, `help` or unknown commands.
pub fn help() -> String {
    "commands:\n  \
     status                          node overview\n  \
     mode [peer|seed|leech]          show or set operating mode\n  \
     peers                           known peers\n  \
     limits                          resource limits and capacity pricing\n  \
     compute <node_prefix|-> [--gpus N] [--ram-mb M] <cmd...>\n  \
     trust                           trust coefficient and reservations\n  \
     reputation                      peer reputation table\n  \
     swarm status                    swarm consent, shards and plans\n  \
     swarm enable <program>          consent to host a program\n  \
     swarm disable                   revoke swarm consent\n  \
     swarm run <program> <file>      run a program across the swarm\n  \
     shutdown                        stop the daemon gracefully\n"
        .to_string()
}
