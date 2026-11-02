//! Task execution: spawn the assigned command under the sandbox
//! profile, stream-capture its output up to a hard cap, enforce the
//! wall-clock timeout by killing the whole process group, and settle
//! the billing. The executor is provider-side: it credits its own
//! trust coefficient with the same charge the consumer's receipt
//! carries (both derive it from the same announced points and the same
//! signed snapshot), appends the signed receipt to the local journal,
//! sends the signed receipt one frame ahead of the signed result so
//! the consumer can countersign exactly what it verified, and reports
//! the signed outcome back to the consumer.

use super::TaskOutcome;
use crate::compute::policy::stranger_factor;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::sandbox;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::mpsc;

/// Hard cap on captured output; beyond the cap the pipe keeps draining
/// (and discarding) so the child never blocks on a full pipe.
const OUTPUT_CAP: usize = 64 * 1024;

/// Wait for one launch from the provider scheduler and run it; the
/// loop ends when the launch channel closes (scheduler drained).
pub async fn run(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<super::Launch>) {
    while let Some(launch) = rx.recv().await {
        if execute(&ctx, launch.clone()).await.is_ok() {
            let _ = ctx
                .compute
                .send(crate::compute::provider::Cmd::Freed {
                    task_id: launch.task_id,
                })
                .await;
        }
    }
}

/// Spawn and supervise one task: settle the charge and credit the
/// provider-side coefficient on success, release the reservation on
/// failure. Returns the delivery result so the slot frees up exactly
/// once, on every path.
pub async fn execute(ctx: &Arc<Ctx>, launch: super::Launch) -> anyhow::Result<()> {
    ctx.counters
        .tasks_started
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Billing reference point: both sides of the receipt observe (and
    // clamp to) the same window.
    let started = Instant::now();
    // Whether the consumer is a known receipt-holder is a routing-table
    // fact; it is read before the state lock so no second mutex is
    // taken while the state lock is held (a fixed lock order across
    // the daemon keeps the economy tables deadlock-free).
    let known = ctx
        .dht
        .lock()
        .await
        .find_by_exact_node_id(&launch.from_node)
        .is_some();
    let mut command = Command::new("sh");
    command.arg("-c").arg(&launch.command);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // The pinned GPU set travels into the child's accelerator
    // environment: CUDA and ROCm honor their own variable, and both
    // pin the same device indices.
    if !launch.gpus.is_empty() {
        let devices = launch
            .gpus
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        command.env("CUDA_VISIBLE_DEVICES", &devices);
        command.env("ROCR_VISIBLE_DEVICES", &devices);
    }
    // One scratch dir per task under the state dir; the sandbox covers
    // it with a tmpfs so the child has exactly one writable place.
    let workdir = ctx
        .config
        .paths
        .state_dir
        .join("tasks")
        .join(launch.task_id.as_str());
    let _ = std::fs::create_dir_all(&workdir);
    sandbox::apply_to_command(&mut command, &workdir, &ctx.config.sandbox, launch.ram_mb);
    #[cfg(unix)]
    let child = {
        use std::os::unix::process::CommandExt;
        let std_command = command.as_std_mut();
        // New process group so the timeout kills the whole command
        // tree, not just the shell wrapper.
        std_command.process_group(0);
        command.spawn()
    };
    #[cfg(not(unix))]
    let child = command.spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(err) => {
            crate::log::warn(
                module_path!(),
                &format!("cannot spawn task {}: {err:#}", launch.task_id),
            );
            let mut state = ctx.state.lock().await;
            state.release(&launch.task_id);
            state.tasks_failed += 1;
            return Err(err.into());
        }
    };
    let pid = child.id().expect("a spawned child always has a pid");
    // The cgroup guard pins memory, CPU and process count for the
    // whole group; dropping it at the end of the scope kills
    // stragglers and removes the directory.
    #[cfg(unix)]
    let guard = sandbox::CgroupGuard::attach(
        &launch.task_id,
        pid,
        &ctx.config.sandbox,
        launch.ram_mb,
        ctx.config.limits.cpu_percent,
    );
    let outcome = run_command(&mut child, pid, &launch).await;
    let _ = std::fs::remove_dir_all(&workdir);
    let mut state = ctx.state.lock().await;
    match outcome {
        Ok(outcome) => {
            let billed_secs = started.elapsed().as_secs().clamp(1, launch.timeout_secs);
            // Credited with the same charge the consumer settles
            // against; saturating arithmetic keeps a pathological
            // configuration from panicking the executor.
            let charge = crate::trust::points::units_for(state.points, billed_secs)
                .saturating_mul(stranger_factor(&ctx.config, known));
            state.trust = state.trust.saturating_add(charge);
            state.tasks_completed += 1;
            if outcome.exit_code != 0 {
                // Non-zero exits complete the task and the receipt but
                // count against the provider's failure accounting.
                state.tasks_failed += 1;
            }
            ctx.counters
                .receipts_settled
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let receipt_unix_ts = crate::trust::now_unix();
            let receipt = Message::Receipt {
                signature: ctx
                    .identity
                    .sign(&Message::receipt_signing_payload(
                        &launch.task_id,
                        &ctx.identity.node_id(),
                        billed_secs,
                        charge,
                        &outcome.hash(),
                        receipt_unix_ts,
                    ))
                    .to_vec(),
                task_id: launch.task_id.clone(),
                provider_node: ctx.identity.node_id(),
                billed_secs,
                charge,
                outcome_hash: outcome.hash(),
                unix_ts: receipt_unix_ts,
                pubkey: ctx.identity.pubkey(),
            };
            state
                .receipts
                .append(receipt.clone())
                .expect("append to a loaded receipt journal cannot fail");
            let result_unix_ts = crate::trust::now_unix();
            let result = Message::TaskResult {
                signature: ctx
                    .identity
                    .sign(&Message::result_signing_payload(
                        &launch.task_id,
                        &outcome.hash(),
                        result_unix_ts,
                    ))
                    .to_vec(),
                task_id: launch.task_id.clone(),
                outcome,
                unix_ts: result_unix_ts,
                pubkey: ctx.identity.pubkey(),
            };
            drop(state);
            // The receipt travels one frame ahead of the result so the
            // consumer can countersign exactly the charge it verified;
            // a lost receipt falls back to the locally computed charge,
            // which honest arithmetic keeps identical.
            let _ = send_msg(ctx, &launch.return_addr, &receipt).await;
            let delivered = send_msg(ctx, &launch.return_addr, &result).await;
            #[cfg(unix)]
            drop(guard);
            delivered
        }
        Err(()) => {
            state.release(&launch.task_id);
            state.tasks_failed += 1;
            Err(anyhow::anyhow!("task failed"))
        }
    }
}

/// Supervise the child until exit or timeout. The wait future is
/// polled through `select!` against the timeout so the child handle
/// stays reachable on the timeout branch: the whole process group is
/// killed (on Unix, where the child leads its own group; elsewhere
/// the direct child is killed, which is all the platform offers), the
/// child is reaped, and the outcome reports the kill. Partial output
/// of a timed-out task is discarded: the bill is the full timeout
/// anyway.
async fn run_command(
    child: &mut tokio::process::Child,
    pid: u32,
    launch: &super::Launch,
) -> std::result::Result<TaskOutcome, ()> {
    let mut stdout_pipe = child
        .stdout
        .take()
        .expect("stdout is piped by construction");
    let mut stderr_pipe = child
        .stderr
        .take()
        .expect("stderr is piped by construction");
    let wait = async {
        let (stdout, stderr, status) = tokio::join!(
            read_capped(&mut stdout_pipe, OUTPUT_CAP),
            read_capped(&mut stderr_pipe, OUTPUT_CAP),
            child.wait()
        );
        (stdout, stderr, status)
    };
    let outcome = tokio::select! {
        finished = wait => Ok(finished),
        _ = tokio::time::sleep(Duration::from_secs(launch.timeout_secs)) => Err(()),
    };
    match outcome {
        Ok((stdout, stderr, Ok(status))) => Ok(TaskOutcome {
            exit_code: status.code().unwrap_or(-1),
            stdout,
            stderr,
            billed_secs: 0,
        }),
        Ok((_stdout, _stderr, Err(err))) => {
            crate::log::warn(
                module_path!(),
                &format!("wait failed for {}: {err:#}", launch.task_id),
            );
            Err(())
        }
        Err(()) => {
            // The select dropped the `wait` future (releasing its
            // child borrow), so the child handle is usable here.
            #[cfg(unix)]
            // SAFETY: `pid` addresses the child's own process group
            // (created with `process_group(0)`), which the daemon is
            // not a member of.
            unsafe {
                libc::killpg(pid as i32, libc::SIGKILL);
            }
            #[cfg(not(unix))]
            let _ = child.start_kill();
            // Reap the killed child so it cannot linger as a zombie.
            let _ = child.wait().await;
            Ok(TaskOutcome {
                exit_code: -2,
                stdout: String::new(),
                stderr: "task timed out and was killed".to_string(),
                billed_secs: 0,
            })
        }
    }
}

/// Read one output pipe up to the cap; after the cap is reached the
/// pipe keeps being drained (and discarded) until end of file, so the
/// child never blocks on a full pipe even when it prints megabytes.
async fn read_capped(pipe: &mut (impl AsyncRead + Unpin), cap: usize) -> String {
    let mut text = String::new();
    let mut buf = [0u8; 4096];
    let mut budget = cap;
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if budget > 0 {
                    let take = budget.min(n);
                    text.push_str(&String::from_utf8_lossy(&buf[..take]));
                    budget -= take;
                }
            }
            Err(_) => break,
        }
    }
    text
}

#[cfg(test)]
mod tests;
