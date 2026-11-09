//! Response rendering for the control socket: every handler returns
//! the exact text shown to the user, keeping the socket plumbing in
//! `control.rs` free of presentation logic.

use crate::config::Config;
use crate::daemon::Ctx;
use crate::swarm;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Render the full node overview: identity, economy counters, wire
/// health, billing metrics, sandbox capability, hardware-performance
/// pricing and swarm state. The shown capacity is the unified
/// announced total: measured where the hardware proved a score,
/// static otherwise.
pub async fn status(ctx: &Arc<Ctx>) -> String {
    let points = ctx
        .hwperf
        .lock()
        .await
        .total_points(&ctx.config, &ctx.config.limits);
    let (mode, trust, consumed, completed, failed, sent, received, uptime) = {
        let state = ctx.state.lock().await;
        (
            state.mode,
            state.trust,
            state.consumed,
            state.tasks_completed,
            state.tasks_failed,
            state.msgs_sent,
            state.msgs_received,
            state.uptime().as_secs(),
        )
    };
    let (tasks_started, receipts_settled, audits_failed) = (
        ctx.counters.tasks_started.load(Ordering::Relaxed),
        ctx.counters.receipts_settled.load(Ordering::Relaxed),
        ctx.counters.audits_failed.load(Ordering::Relaxed),
    );
    let (peer_count, swarm_line) = {
        let dht = ctx.dht.lock().await;
        let offers = dht
            .all_peers()
            .iter()
            .filter(|peer| !peer.swarm.is_empty())
            .count();
        let line = {
            let consent = ctx.swarm.lock().await;
            if consent.is_empty() {
                format!("disabled (offers from {} peers)", offers)
            } else {
                let names: Vec<&str> = consent.programs.keys().map(String::as_str).collect();
                format!(
                    "hosting {} (offers from {} peers)",
                    names.join(", "),
                    offers
                )
            }
        };
        (dht.peer_count(), line)
    };
    let plans = ctx.swarm_plans.lock().await.len();
    let shards = ctx.swarm_procs.lock().await.len();
    format!(
        "node_id: {node_id}\nmode: {mode}\ntrust: {trust}\nconsumed: {consumed}\npoints: {points}\n\
         peers: {peer_count}\ntasks_completed: {completed}\ntasks_failed: {failed}\n\
         tasks_started: {tasks_started}\nreceipts_settled: {receipts_settled}\n\
         audits_failed: {audits_failed}\n\
         msgs_sent: {sent}\nmsgs_received: {received}\nsandbox: {sandbox}\nswarm: {swarm_line}\n\
         swarm_plans: {plans}\nlocal_shards: {shards}\nuptime_s: {uptime}\n",
        node_id = ctx.identity.node_id(),
        mode = mode.as_str(),
        sandbox = crate::sandbox::capability_line(&ctx.config),
    )
}

/// Render the known-peer table, one verified line per peer.
pub async fn peers(ctx: &Arc<Ctx>) -> String {
    let peers = ctx.dht.lock().await.all_peers();
    if peers.is_empty() {
        return "no peers known\n".to_string();
    }
    let mut out = String::new();
    for peer in peers {
        let swarm = if peer.swarm.is_empty() {
            String::new()
        } else {
            let programs: Vec<String> = peer.swarm.keys().cloned().collect();
            format!(" swarm=[{}]", programs.join(", "))
        };
        out.push_str(&format!(
            "{addr}  {node}  mode={mode} trust={trust} points={points} gpus={gpus}{swarm}\n",
            addr = peer.addr,
            node = peer.node_id,
            mode = peer.mode,
            trust = peer.trust,
            points = peer.points,
            gpus = peer.gpus,
        ));
    }
    out
}

/// Render the configured resource limits and the derived capacity
/// pricing so an operator can sanity-check the economy settings. The
/// `key=value` spelling is the output-format contract for this
/// command; an empty GPU device list renders as `auto` (the first
/// `count` devices are offered).
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
        "limits: cpu_percent={cpu} ram_mb={ram} max_tasks={tasks}\n\
         gpu: gpu_count={gpus} gpu_devices={devices} points_per_gpu={ppg}\n\
         trust: genesis={genesis} min_trust={min} points_per_core={ppc} points_per_gb={ppg2}\n\
         timeout: {timeout}s\n",
        cpu = config.limits.cpu_percent,
        ram = config.limits.ram_mb,
        tasks = config.limits.max_tasks,
        gpus = config.gpu.effective_count(),
        devices = devices,
        ppg = config.gpu.points_per_gpu,
        ppc = config.trust.points_per_core,
        ppg2 = config.trust.points_per_gb,
        min = config.trust.min_trust,
        genesis = config.trust.genesis_trust,
        timeout = config.network.task_timeout_secs,
    )
}

/// Render the trust coefficient, consumption counter, unified
/// announced capacity and reservations.
pub async fn trust(ctx: &Arc<Ctx>) -> String {
    let points = ctx
        .hwperf
        .lock()
        .await
        .total_points(&ctx.config, &ctx.config.limits);
    let state = ctx.state.lock().await;
    let reserved = state.reserved_total();
    let mut out = format!(
        "trust: {trust}\nconsumed: {consumed}\npoints: {points}\n",
        trust = state.trust,
        consumed = state.consumed,
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
    let mut out = if consent.is_empty() {
        "swarm: disabled (no consent granted)\n".to_string()
    } else {
        let mut text = String::from("swarm: hosting\n");
        for (program, limits) in &consent.programs {
            text.push_str(&format!(
                "  {program}: ram cap {} MB, cpu cap {}%\n",
                limits.max_shard_ram_mb, limits.max_shard_cpu_percent,
            ));
        }
        text
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

/// Grant consent to one program, or revoke one program (or every
/// program when no name is given). Grants persist to the state
/// directory and publish the offer to every known peer immediately.
/// A revocation that empties the registry broadcasts a signed
/// retraction to every peer that carries any of our offers, so remote
/// placement stops instead of waiting for offers to age out. A partial
/// revocation (one program of several) takes effect locally and on the
/// next restart; the wire retraction is all-or-nothing, so revoking the
/// last program is what signals the network.
pub async fn swarm_set(ctx: &Arc<Ctx>, program: Option<&str>, enabled: bool) -> String {
    let state_dir = ctx.config.paths.state_dir.clone();
    let mut consent = ctx.swarm.lock().await;
    if enabled {
        let Some(name) = program.filter(|name| !name.is_empty()) else {
            return "error: usage: swarm enable <program>\n".to_string();
        };
        consent.grant(name);
        match consent.save(&state_dir) {
            Ok(()) => {
                drop(consent);
                swarm::announce_offers(ctx).await;
                format!("swarm consent granted for '{name}'\n")
            }
            Err(err) => format!("error: cannot persist consent: {err:#}\n"),
        }
    } else {
        let remaining = consent.revoke(program);
        match consent.save(&state_dir) {
            Ok(()) => {
                drop(consent);
                if !remaining {
                    swarm::leave::broadcast_leave(ctx).await;
                    "swarm consent revoked (retraction broadcast)\n".to_string()
                } else {
                    "swarm consent revoked (local; retracts on full disable)\n".to_string()
                }
            }
            Err(err) => format!("error: cannot persist consent: {err:#}\n"),
        }
    }
}

/// Usage text shown for empty, `help` or unknown commands.
pub fn help() -> String {
    "commands:\n  \
     status                          node overview\n  \
     mode [peer|seed|leech]          show or set operating mode\n  \
     peers                           known peers\n  \
     limits                          resource limits and capacity pricing\n  \
     compute <node_prefix|-> [--gpus N] [--ram-mb M] [--verify N] <cmd...>\n  \
     trust                           trust coefficient and reservations\n  \
     reputation                      peer reputation table\n  \
     hwperf                          hardware performance scores and pricing\n  \
     stress                          certify hardware performance (guided test)\n  \
     swarm status                    swarm consent, shards and plans\n  \
     swarm enable <program>          consent to host a program\n  \
     swarm disable [program]         revoke one program or all consent\n  \
     swarm run <program> <file>      run a program across the swarm\n  \
     shutdown                        stop the daemon gracefully\n"
        .to_string()
}
