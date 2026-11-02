//! The runner spawn and bridge registration of one shard: process
//! setup, pinned environment, resource limits, the connect-back
//! listener and the bridge task handoff. Called only after every
//! launch-time check in the parent module has passed.

use crate::daemon::Ctx;
use crate::sandbox;
use crate::swarm::consent::ProgramSpec;
use anyhow::{bail, Result};
#[cfg(unix)]
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

/// Spawn one shard runner process and its bridge task. The runner talks
/// to the worker over a loopback listener bound here in the daemon's
/// network namespace; the runner sandbox profile deliberately keeps the
/// host network namespace so that loopback stays reachable. When the
/// manifest requires GPUs, the runner receives the pinned device set
/// through the accelerator environment variables. `coord_addr` is the
/// connection address the launch arrived on: it becomes the only
/// network sender this shard accepts pipeline frames and done signals
/// from.
#[allow(clippy::too_many_arguments)]
pub(super) async fn spawn_shard(
    ctx: &Arc<Ctx>,
    coord_addr: &str,
    plan_id: &str,
    shard_index: u32,
    spec: &ProgramSpec,
    layer_from: u32,
    layer_to: u32,
    ram_mb: u64,
    cpu_percent: u32,
    next_addr: &str,
    gpus: &[u32],
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
    if !gpus.is_empty() {
        let devices = gpus
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        // CUDA and ROCm honor their own variable; exporting both pins
        // the same device set across vendor toolchains.
        runner.env("CUDA_VISIBLE_DEVICES", &devices);
        runner.env("ROCR_VISIBLE_DEVICES", &devices);
    }
    runner.stdin(std::process::Stdio::null());
    // A new process group lets the timeout kill the whole runner tree;
    // platforms without process groups kill the direct child only.
    #[cfg(unix)]
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
    // (missing binary, sandbox misconfiguration) fails the shard
    // instead of blocking the plan forever.
    let Ok(connect) = tokio::time::timeout(RUNNER_CONNECT_TIMEOUT, listener.accept()).await else {
        // SAFETY: `pid` addresses the child's own process group (created
        // with `process_group(0)`); the daemon lives in a different one.
        // Off Unix there are no process groups: kill the direct child.
        #[cfg(unix)]
        unsafe {
            libc::killpg(pid, libc::SIGKILL)
        };
        #[cfg(not(unix))]
        let _ = child.start_kill();
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
            coordinator: coord_addr.to_string(),
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
