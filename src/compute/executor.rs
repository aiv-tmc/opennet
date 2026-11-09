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
use std::time::Instant;
use tokio::process::Command;
use tokio::sync::mpsc;

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
    // Unified announced capacity: measured components price from their
    // demonstrated performance, the rest from the static offer. Read
    // before the state lock to keep the daemon-wide lock order.
    let points = ctx
        .hwperf
        .lock()
        .await
        .total_points(&ctx.config, &ctx.config.limits);
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
            let charge = crate::trust::points::units_for(points, billed_secs)
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
            // A journal append failure must not panic the executor: the
            // credit is rolled back, the task is accounted as failed and
            // no receipt leaves the node, so the local chain can never
            // silently diverge from what consumers countersigned.
            if let Err(err) = state.receipts.append(receipt.clone(), &launch.from_node) {
                crate::log::warn(
                    module_path!(),
                    &format!("cannot append receipt for {}: {err:#}", launch.task_id),
                );
                state.trust = state.trust.saturating_sub(charge);
                state.tasks_completed -= 1;
                state.tasks_failed += 1;
                state.release(&launch.task_id);
                return Err(err);
            }
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

mod run;

use run::run_command;

#[cfg(test)]
mod tests;
