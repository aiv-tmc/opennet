//! Shard worker: hosts one slice of a consented program for one plan,
//! with the execution sandbox applied to the runner process.
//!
//! The consent gate runs before anything is spawned: without consent for
//! the exact program, with a mismatched artifact hash, with an oversized
//! RAM request or with an unknown coordinator, the launch is refused with
//! a `SwarmDone` answer and no process ever starts. On acceptance the
//! worker allocates a local listener, spawns the manifest's runner command
//! in a scrubbed environment with the shard variables exported, applies
//! namespace and cgroup sandboxing, and hands the connection to the runner
//! bridge (see `runner.rs`).

use super::consent::ProgramSpec;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::identity::Identity;
use crate::sandbox;
use crate::swarm::{timestamp_fresh, ShardProc};
use anyhow::{anyhow, bail, Result};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

/// Deadline for the runner process to connect back to the worker listener.
const RUNNER_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Handle an inbound signed `ShardLaunch`: authenticate the coordinator,
/// enforce consent, verify the artifact, spawn the runner and register the
/// local shard for pipeline traffic. Any refusal is reported back to the
/// coordinator as `SwarmDone` with the reason.
pub async fn handle_launch(ctx: &Arc<Ctx>, src: &str, launch: Message) {
    if let Err(err) = try_handle_launch(ctx, src, &launch).await {
        eprintln!("[swarm] refusing shard launch from {src}: {err:#}");
        let plan_id = match &launch {
            Message::ShardLaunch { plan_id, .. } => plan_id.clone(),
            _ => String::new(),
        };
        let _ = send_msg(
            ctx,
            src,
            &Message::SwarmDone {
                plan_id,
                reason: format!("{err:#}"),
            },
        )
        .await;
    }
}

/// Inner launch logic, returning the refusal reason as an error.
async fn try_handle_launch(ctx: &Arc<Ctx>, src: &str, launch: &Message) -> Result<()> {
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
    // Authenticate the coordinator: valid signature over the exact fields
    // and a fresh timestamp, plus a previously verified peer record.
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
    let sig: &[u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("bad signature length"))?;
    if !Identity::verify(pubkey, &payload, sig) {
        bail!("invalid launch signature");
    }
    if !timestamp_fresh(ctx, *unix_ts) {
        bail!("stale launch timestamp");
    }
    let coordinator_id = Identity::node_id_from_pubkey(pubkey);
    if ctx
        .dht
        .lock()
        .await
        .find_by_exact_node_id(&coordinator_id)
        .is_none()
    {
        bail!("coordinator is not a verified peer");
    }
    // Consent gate: enabled for this exact program, artifact verified
    // against the manifest, hash matching the launch, RAM within the cap.
    let consent = ctx.swarm.lock().await.clone();
    if !consent.allows(program) {
        bail!("no consent for program '{program}'");
    }
    let spec: ProgramSpec = consent.verified_spec().map_err(|err| anyhow!("{err:#}"))?;
    if spec.artifact_hash != *artifact_hash {
        bail!("artifact hash mismatch");
    }
    if *ram_mb > consent.max_shard_ram_mb {
        bail!(
            "shard RAM request {ram_mb} exceeds the consent cap {}",
            consent.max_shard_ram_mb
        );
    }
    if layer_from >= layer_to || *layer_to > spec.layers {
        bail!(
            "invalid layer range {}..{} for {} layers",
            layer_from,
            layer_to,
            spec.layers
        );
    }

    // Allocate the local runner listener before spawning so the port is
    // known in advance; the runner connects back within the deadline.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let workdir = std::env::temp_dir().join(format!(
        "opennet-swarm-{}-{shard_index}",
        &plan_id[..plan_id.len().min(16)]
    ));
    tokio::fs::create_dir_all(&workdir).await?;

    let mut runner = Command::new("sh");
    runner
        .arg("-c")
        .arg(spec.runner_cmd.join(" "))
        .current_dir(&workdir)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", workdir.to_string_lossy().as_ref())
        .env("PLAN_ID", plan_id)
        .env("SHARD_INDEX", shard_index.to_string())
        .env("LAYER_FROM", layer_from.to_string())
        .env("LAYER_TO", layer_to.to_string())
        .env("ARTIFACT", spec.artifact_path.to_string_lossy().as_ref())
        .env("PORT", port.to_string())
        .env("NEXT_ADDR", next_addr)
        .env("COORD_ADDR", src)
        .env("RAM_MB", ram_mb.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        // The runner and any children it spawns die together with the plan.
        .process_group(0);
    sandbox::apply_to_command(&mut runner, &workdir, &ctx.config.sandbox);

    let mut child = runner.spawn()?;
    let _cgroup = child.id().and_then(|pid| {
        sandbox::CgroupGuard::attach(
            &format!("swarm-{}-{shard_index}", &plan_id[..plan_id.len().min(16)]),
            pid,
            &ctx.config.sandbox,
            *ram_mb,
            consent.max_shard_cpu_percent,
        )
    });
    let pid = child.id().expect("freshly spawned runner has no pid") as i32;
    let accept = tokio::time::timeout(RUNNER_CONNECT_TIMEOUT, listener.accept());
    let runner_conn = match accept.await {
        Ok(Ok((stream, _))) => stream,
        Ok(Err(err)) => {
            unsafe { libc::killpg(pid, libc::SIGKILL) };
            let _ = child.wait().await;
            bail!("runner did not connect back: {err}");
        }
        Err(_) => {
            unsafe { libc::killpg(pid, libc::SIGKILL) };
            let _ = child.wait().await;
            bail!("runner connect deadline exceeded");
        }
    };

    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    ctx.swarm_procs.lock().await.insert(
        format!("{plan_id}:{shard_index}"),
        ShardProc {
            shard_index: *shard_index,
            inbound: inbound_tx,
            shutdown: shutdown_tx,
        },
    );
    let bridge_ctx = ctx.clone();
    let plan_id = plan_id.clone();
    let next_addr = next_addr.clone();
    tokio::spawn(super::runner::bridge(
        bridge_ctx,
        plan_id,
        *shard_index,
        runner_conn,
        inbound_rx,
        shutdown_rx,
        pid,
        child,
        next_addr,
        src.to_string(),
    ));
    Ok(())
}
