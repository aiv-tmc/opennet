//! Launching local shard runners for swarm placement plans.
//!
//! A `Message::ShardLaunch` arrives signed by the coordinator. Every
//! constraint is re-verified before any process exists: signature and
//! freshness, known verified peer, explicit local consent for exactly
//! this program, manifest digest match against the on-disk artifact,
//! the consent RAM cap, a sane layer range, no duplicate shard index
//! for the plan, and a global cap on concurrently hosted shards. Only
//! then does the runner spawn — exec'd directly from the local manifest
//! argv (the runner command never travels on the wire) with the runner
//! sandbox profile, which keeps the host network namespace so the
//! runner can reach the worker's loopback listener.

use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::identity::Identity;
use crate::sandbox;
use anyhow::{bail, Result};
use std::os::unix::process::CommandExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

/// Time the runner gets to connect back to the worker listener before
/// the shard is considered failed. Generous on purpose: the runner may
/// be unpacking or mmap-ing a large artifact inside its sandbox.
const RUNNER_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard cap on concurrently hosted shard runners per node; one consent
/// cannot be turned into an unbounded process fleet.
const MAX_LOCAL_SHARDS: usize = 16;

/// Verify a coordinator's launch request and, when every check passes,
/// spawn the local shard runner and register its bridge. Errors are
/// reported back to the coordinator as a failed plan.
pub async fn handle_launch(ctx: &Arc<Ctx>, src: &str, launch: Message) -> Result<()> {
    if let Err(err) = try_launch(ctx, src, &launch).await {
        let plan_id = match &launch {
            Message::ShardLaunch { plan_id, .. } => plan_id.clone(),
            _ => String::new(),
        };
        // A failed shard ends the whole plan everywhere: every other
        // host tears its runner down on the retraction.
        let _ = send_msg(
            ctx,
            src,
            &Message::SwarmDone {
                plan_id,
                reason: format!("shard launch failed: {err:#}"),
            },
        )
        .await;
        return Err(err);
    }
    Ok(())
}

/// The full launch pipeline, separated so the caller can translate any
/// failure into a plan-wide retraction.
async fn try_launch(ctx: &Arc<Ctx>, src: &str, launch: &Message) -> Result<()> {
    let Message::ShardLaunch {
        plan_id,
        shard_index,
        program,
        artifact_hash,
        layer_from,
        layer_to,
        ram_mb,
        next_addr,
        unix_ts,
        pubkey,
        signature,
    } = launch
    else {
        bail!("not a shard launch");
    };
    // The launch must be signed by the coordinator over the exact fields
    // it carries; any tamper breaks the binding.
    let sig: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed shard launch signature"))?;
    let payload = Message::launch_signing_payload(
        plan_id,
        *shard_index,
        program,
        artifact_hash,
        *layer_from,
        *layer_to,
        next_addr,
        *unix_ts,
    );
    if !Identity::verify(pubkey, &payload, &sig) {
        ctx.reputation.lock().await.record_invalid(src);
        bail!("bad shard launch signature");
    }
    let coordinator = Identity::node_id_from_pubkey(pubkey);
    if !crate::swarm::timestamp_fresh(ctx, *unix_ts) {
        bail!("stale shard launch");
    }
    // The coordinator must be a verified, previously announced peer.
    if ctx
        .dht
        .lock()
        .await
        .find_by_exact_node_id(&coordinator)
        .is_none()
    {
        bail!("launch from unknown coordinator");
    }
    // Explicit consent for exactly this program is required; without it
    // nothing is spawned, regardless of signature validity.
    let consent = ctx.swarm.lock().await.clone();
    if !consent.allows(program) {
        bail!("no consent for program {program}");
    }
    // The manifest must exist, parse and hash-match the on-disk
    // artifact; the launch's digest must equal the manifest's.
    let spec = consent.verified_spec()?;
    if artifact_hash != &spec.artifact_hash {
        bail!("launch digest does not match the local manifest");
    }
    // The requested shard must fit the consent caps.
    if *ram_mb > consent.max_shard_ram_mb {
        bail!("launch exceeds local shard RAM cap");
    }
    if spec.runner_cmd.is_empty() {
        bail!("manifest declares no runner command");
    }
    // Sane layer range inside the manifest layer space.
    if layer_from >= layer_to || *layer_to > spec.layers {
        bail!("invalid layer range");
    }
    drop(consent);
    // One shard index per plan: a duplicate would silently orphan the
    // first runner, leaking it until the plan deadline.
    let key = crate::swarm::proc_key(plan_id, *shard_index);
    {
        let procs = ctx.swarm_procs.lock().await;
        if procs.contains_key(&key) {
            bail!("shard {key} already running");
        }
        if procs.len() >= MAX_LOCAL_SHARDS {
            bail!("local shard capacity reached");
        }
    }
    spawn_shard(
        ctx,
        src,
        plan_id,
        *shard_index,
        &spec,
        *layer_from,
        *layer_to,
        *ram_mb,
        consent_cpu(ctx).await,
        next_addr,
    )
    .await
}

/// Read the consent CPU cap without holding the lock across the spawn.
async fn consent_cpu(ctx: &Arc<Ctx>) -> u32 {
    ctx.swarm.lock().await.max_shard_cpu_percent
}

/// Spawn one shard runner process and its bridge task. The runner talks
/// to the worker over a loopback listener bound here in the daemon's
/// network namespace; the runner sandbox profile deliberately keeps the
/// host network namespace so that loopback stays reachable.
#[allow(clippy::too_many_arguments)]
async fn spawn_shard(
    ctx: &Arc<Ctx>,
    coord_addr: &str,
    plan_id: &str,
    shard_index: u32,
    spec: &crate::swarm::consent::ProgramSpec,
    layer_from: u32,
    layer_to: u32,
    ram_mb: u64,
    cpu_percent: u32,
    next_addr: &str,
) -> Result<()> {
    // Unique scratch directory; also the child's HOME/TMPDIR and, under
    // the mount sandbox, the only writable place the runner can see.
    let workdir = std::env::temp_dir().join(format!(
        "opennet-swarm-{}-{plan_id}-{shard_index}",
        std::process::id()
    ));
    std::fs::create_dir_all(&workdir)?;
    // The worker side of the runner protocol: raw length-prefixed
    // frames over loopback.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    // Direct exec of the manifest runner argv — no shell is involved,
    // so arguments pass through verbatim and nothing is re-parsed. The
    // tokio builder mirrors std's; sandbox and process-group tweaks go
    // through `as_std_mut`.
    let mut runner = Command::new(&spec.runner_cmd[0]);
    runner.args(&spec.runner_cmd[1..]);
    runner.current_dir(&workdir);
    runner.env_clear();
    runner.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    runner.env("HOME", workdir.to_string_lossy().as_ref());
    runner.env("TMPDIR", workdir.to_string_lossy().as_ref());
    runner.env("PLAN_ID", plan_id);
    runner.env("SHARD_INDEX", shard_index.to_string());
    runner.env("LAYER_FROM", layer_from.to_string());
    runner.env("LAYER_TO", layer_to.to_string());
    runner.env("ARTIFACT", spec.artifact_path.to_string_lossy().as_ref());
    runner.env("PORT", port.to_string());
    runner.env("NEXT_ADDR", next_addr);
    // The coordinator is whoever signed the launch; its address is the
    // connection the launch arrived on.
    runner.env("COORD_ADDR", coord_addr);
    runner.env("RAM_MB", ram_mb.to_string());
    runner.stdin(std::process::Stdio::null());
    runner.as_std_mut().process_group(0);
    sandbox::apply_to_runner(&mut runner, &workdir, &ctx.config.sandbox, ram_mb);
    let mut child = runner.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("spawned child has no pid"))? as i32;
    // Resource limits for the whole runner process group.
    let _cgroup = sandbox::CgroupGuard::attach(
        &format!("{plan_id}-{shard_index}"),
        pid as u32,
        &ctx.config.sandbox,
        ram_mb,
        cpu_percent,
    );
    // Wait for the runner's connect-back; a runner that never connects
    // (missing binary, sandbox misconfiguration) fails the shard instead
    // of blocking the plan forever.
    let Ok(connect) = tokio::time::timeout(RUNNER_CONNECT_TIMEOUT, listener.accept()).await else {
        // SAFETY: `pid` addresses the child's own process group (created
        // with `process_group(0)`); the daemon lives in a different one.
        unsafe { libc::killpg(pid, libc::SIGKILL) };
        let _ = child.wait().await;
        let _ = std::fs::remove_dir_all(&workdir);
        bail!("runner did not connect back");
    };
    let (socket, _) = connect?;
    // Bounded queue of pipeline frames waiting for the runner socket.
    let (inbound_tx, inbound_rx) = mpsc::channel(crate::swarm::SHARD_INBOUND_CAP);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    ctx.swarm_procs.lock().await.insert(
        crate::swarm::proc_key(plan_id, shard_index),
        crate::swarm::ShardProc {
            shard_index,
            inbound: inbound_tx,
            shutdown: shutdown_tx,
        },
    );
    // The bridge owns the child, the socket end and the cleanup.
    let ctx_bridge = ctx.clone();
    let plan_owned = plan_id.to_string();
    let coord_owned = coord_addr.to_string();
    let next_owned = next_addr.to_string();
    let workdir_owned = workdir.clone();
    tokio::spawn(async move {
        crate::swarm::runner::bridge(
            ctx_bridge,
            plan_owned,
            shard_index,
            socket,
            inbound_rx,
            shutdown_rx,
            pid,
            child,
            workdir_owned,
            next_owned,
            coord_owned,
        )
        .await;
    });
    Ok(())
}
