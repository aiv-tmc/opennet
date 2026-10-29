//! Provider-side executor: runs accepted commands inside the execution
//! sandbox and reports completion so the scheduler frees the slot.
//!
//! Safety properties: every task runs in a fresh temporary directory with a
//! scrubbed environment (PATH and HOME only), inside its own process group
//! that is killed wholesale on timeout, with namespace isolation and cgroup
//! resource limits applied when the platform allows it. Both output streams
//! are read with a hard cap so a flooding task cannot exhaust daemon memory.
//! Output reader tasks are awaited under a drain deadline after the child
//! dies and only aborted when they miss it, so captured output survives the
//! normal path while a detached grandchild holding a pipe open can still
//! never wedge an executor slot forever.
//!
//! Billing: the trust credit equals `units_for(points, billed_secs)` —
//! exactly what the consumer charges itself from the same `billed_secs`
//! carried in the outcome, so the economy stays conserved. The reservation
//! size carried in `Launch.units` serves only the scheduler's in-flight
//! accounting.

use crate::compute::provider::Cmd;
use crate::compute::{Launch, TaskOutcome};
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::sandbox;
use crate::trust::points::units_for;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::mpsc;

/// Maximum captured output per stream, in bytes.
const OUTPUT_CAP: usize = 64 * 1024;
/// Deadline for collecting output after the child has died; readers that
/// miss it are aborted so a stuck pipe cannot hold the slot.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Execution environment handed to every task process.
const TASK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Executor loop: runs launched commands and reports `Cmd::Freed` after
/// each so the scheduler can refill the freed slot from the pending heap.
pub async fn run(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<Launch>) {
    while let Some(launch) = rx.recv().await {
        let task_id = launch.task_id.clone();
        execute(&ctx, launch).await;
        let _ = ctx.compute.send(Cmd::Freed { task_id }).await;
    }
}

/// Run one command in a fresh working directory with a scrubbed
/// environment, a hard wall-clock limit and the sandbox applied, then
/// credit the billed units, update statistics and report the outcome.
async fn execute(ctx: &Arc<Ctx>, launch: Launch) {
    let workdir = std::env::temp_dir().join(format!("opennet-task-{}", launch.task_id));
    let _ = tokio::fs::create_dir_all(&workdir).await;
    // The consumer-supplied limit is clamped to the locally configured
    // maximum so a manipulated assignment cannot extend the wall clock.
    let timeout_secs = launch
        .timeout_secs
        .clamp(1, ctx.config.network.task_timeout_secs.max(1));
    let started = Instant::now();

    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(&launch.command)
        .current_dir(&workdir)
        .env_clear()
        .env("PATH", TASK_PATH)
        .env("HOME", workdir.to_string_lossy().as_ref())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Give the task its own process group so the timeout path can kill
        // the whole tree, including grandchildren the shell may spawn.
        .process_group(0);
    sandbox::apply_to_command(&mut command, &workdir, &ctx.config.sandbox);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            finish(
                ctx,
                &launch,
                &workdir,
                TaskOutcome {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: format!("failed to start task: {err}"),
                    billed_secs: 1,
                },
            )
            .await;
            return;
        }
    };
    // Resource limits ride in the same cgroup for the whole process group;
    // the guard outlives the child and cleans up on drop.
    let _cgroup = child.id().and_then(|pid| {
        sandbox::CgroupGuard::attach(
            &launch.task_id,
            pid,
            &ctx.config.sandbox,
            ctx.config.limits.ram_mb,
            ctx.config.limits.cpu_percent,
        )
    });
    // The child was just spawned, so its id is always available; it is
    // captured before waiting because the timeout and reap-failure paths
    // must address the process group by it.
    let pid = child.id().expect("freshly spawned child has no pid") as i32;
    let mut stdout_pipe = child.stdout.take().expect("stdout piped by spawn");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped by spawn");
    let out_handle = tokio::spawn(async move { read_capped(&mut stdout_pipe).await });
    let err_handle = tokio::spawn(async move { read_capped(&mut stderr_pipe).await });

    let wall = Duration::from_secs(timeout_secs);
    let (exit_code, stderr) = match tokio::time::timeout(wall, child.wait()).await {
        Ok(Ok(status)) => (status.code().unwrap_or(-1), String::new()),
        Ok(Err(err)) => {
            // The wait syscall itself failed and the child state is
            // unknown: kill the whole process group to avoid leaking the
            // task, then reap it.
            unsafe { libc::killpg(pid, libc::SIGKILL) };
            let _ = child.wait().await;
            (-1, format!("failed to reap task: {err}"))
        }
        Err(_) => {
            // SAFETY: killpg with the child's own pid targets exactly the
            // process group created above; the daemon lives in a different
            // group and cannot signal itself or its siblings.
            unsafe { libc::killpg(pid, libc::SIGKILL) };
            // Reap the killed child so it cannot linger as a zombie.
            let _ = child.wait().await;
            (
                -2,
                format!("task exceeded its {timeout_secs}s limit and was killed"),
            )
        }
    };
    // Readers finish on their own once the pipes close behind the dead
    // child; only a reader still stuck past the deadline is aborted.
    let stdout = collect_output(out_handle).await;
    let stderr = if stderr.is_empty() {
        to_text(collect_output(err_handle).await)
    } else {
        stderr
    };
    // Bill the real wall-clock time, at least one second and never more
    // than the enforced limit; both sides price the task from this value.
    let billed_secs = started.elapsed().as_secs().clamp(1, timeout_secs);
    finish(
        ctx,
        &launch,
        &workdir,
        TaskOutcome {
            exit_code,
            stdout: to_text(stdout),
            stderr,
            billed_secs,
        },
    )
    .await;
}

/// Await one reader task under the drain deadline, aborting it only when
/// it does not finish in time; its captured bytes are returned on success.
async fn collect_output(mut handle: tokio::task::JoinHandle<Vec<u8>>) -> Vec<u8> {
    match tokio::time::timeout(DRAIN_TIMEOUT, &mut handle).await {
        Ok(Ok(bytes)) => bytes,
        _ => {
            handle.abort();
            Vec::new()
        }
    }
}

/// Credit the billed units to the local trust coefficient, update task
/// statistics, persist the state and deliver the outcome to the consumer.
///
/// The credit is derived from the same `billed_secs` the consumer charges
/// itself, keeping the total trust across the network conserved.
async fn finish(ctx: &Arc<Ctx>, launch: &Launch, workdir: &std::path::Path, outcome: TaskOutcome) {
    let _ = tokio::fs::remove_dir_all(workdir).await;
    {
        let mut state = ctx.state.lock().await;
        if outcome.exit_code == 0 {
            state.tasks_completed += 1;
        } else {
            state.tasks_failed += 1;
        }
        // Donating compute to the network raises the trust coefficient by
        // exactly what the consumer paid for this task.
        let units = units_for(state.points, outcome.billed_secs);
        state.trust += units;
        let _ = state.save();
    }
    let _ = send_msg(
        ctx,
        &launch.return_addr,
        &Message::TaskResult {
            task_id: launch.task_id.clone(),
            outcome,
        },
    )
    .await;
}

/// Read one output stream into memory capped at `OUTPUT_CAP` bytes; bytes
/// beyond the cap are drained and discarded so the task never blocks on a
/// full pipe and daemon memory stays bounded.
async fn read_capped(reader: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
    let mut buf = Vec::with_capacity(OUTPUT_CAP.min(4096));
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => {
                if buf.len() < OUTPUT_CAP {
                    let take = read.min(OUTPUT_CAP - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                }
            }
            Err(_) => break,
        }
    }
    buf
}

/// Convert captured bytes to text, marking content that reached the cap.
fn to_text(bytes: Vec<u8>) -> String {
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.len() >= OUTPUT_CAP {
        text.push_str("\n...[truncated]");
    }
    text
}

#[cfg(test)]
mod tests;
