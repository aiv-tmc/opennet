//! Sandboxed task execution: one launch becomes one sandboxed child
//! process whose output is captured under hard caps, whose runtime is
//! billed into `[1, timeout]`, and whose settlement — counters, trust
//! credit, signed billing receipt, journal entry and signed result —
//! completes before the caller continues. `run` is the scheduler-facing
//! loop around `execute`.
//!
//! Billing clamps the measured runtime into `[1, timeout]` so the
//! charge always reflects a task that really ran and never exceeds the
//! reservation window. The credited units are priced from the same
//! announced capacity points the consumer reserved against — CPU/RAM
//! points plus the GPU offer and the consumer's receipt history — so
//! settlement moves both ledgers by the same amount, and the receipt
//! binds the charge to the exact output hash the consumer verifies.

use crate::compute::policy::stranger_factor;
use crate::compute::provider::Cmd;
use crate::compute::{Launch, TaskOutcome};
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::state::genesis_head;
use crate::sandbox;
use crate::trust::now_unix;
use crate::trust::points::{gpu_points, units_for};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::mpsc;

/// Hard cap on one captured output stream: anything past the cap is
/// drained and discarded so the child never blocks on a full pipe.
const OUTPUT_CAP: usize = 64 * 1024;

/// Execute launches one at a time and report each finished slot back
/// to the scheduler; sequential execution keeps memory and GPU pressure
/// at exactly one task and preserves the billing order.
pub async fn run(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<Launch>) {
    tokio::spawn(async move {
        while let Some(launch) = rx.recv().await {
            let task_id = launch.task_id.clone();
            execute(&ctx, launch).await;
            let _ = ctx.compute.send(Cmd::Freed { task_id }).await;
        }
    });
}

/// Run one launch end to end: spawn the command under the sandbox
/// profile, capture both streams under the output cap, enforce the
/// timeout, bill the observed wall time clamped into `[1, timeout]`,
/// then settle — task counters, trust credit priced from the announced
/// points, the signed billing receipt appended to the local journal
/// and sent one frame ahead of the signed task result on the same
/// ordered connection.
pub async fn execute(ctx: &Arc<Ctx>, launch: Launch) -> TaskOutcome {
    let started = Instant::now();
    let outcome = match run_command(ctx, &launch).await {
        Ok(mut outcome) => {
            outcome.billed_secs = started
                .elapsed()
                .as_secs()
                .clamp(1, launch.timeout_secs.max(1));
            outcome
        }
        Err(()) => TaskOutcome {
            exit_code: -1,
            stdout: String::new(),
            stderr: "task failed to start".to_string(),
            billed_secs: 1,
        },
    };
    let unix_ts = now_unix();
    let mut receipt = Message::Receipt {
        task_id: launch.task_id.clone(),
        provider_node: ctx.identity.node_id(),
        billed_secs: outcome.billed_secs,
        charge: 0, // filled under the state lock below
        outcome_hash: outcome.hash(),
        unix_ts,
        pubkey: ctx.identity.pubkey(),
        signature: Vec::new(), // filled under the state lock below
    };
    {
        let mut state = ctx.state.lock().await;
        if outcome.exit_code == 0 {
            state.tasks_completed += 1;
        } else {
            state.tasks_failed += 1;
        }
        let points = state.points.saturating_add(gpu_points(&ctx.config.gpu));
        // Same surcharge the consumer applied to its reservation: both
        // sides read the consumer's receipt head from their routing
        // table view of the announcement.
        let known = ctx
            .dht
            .lock()
            .await
            .find_by_exact_node_id(&launch.from_node)
            .is_some_and(|peer| peer.receipt_head != genesis_head());
        let charge = units_for(points, outcome.billed_secs) * stranger_factor(&ctx.config, known);
        state.trust = state.trust.saturating_add(charge);
        if let Message::Receipt {
            charge: receipt_charge,
            signature,
            ..
        } = &mut receipt
        {
            *receipt_charge = charge;
            *signature = ctx
                .identity
                .sign(&Message::receipt_signing_payload(
                    &launch.task_id,
                    &ctx.identity.node_id(),
                    outcome.billed_secs,
                    charge,
                    &outcome.hash(),
                    unix_ts,
                ))
                .to_vec();
        }
        // The provider's own journal records the issued receipt so both
        // sides of the settlement hold the same evidence. A duplicate
        // (retried send of the same task id) is ignored.
        let _ = state.receipts.append(receipt.clone());
        let _ = state.save();
    }
    let _ = send_msg(ctx, &launch.return_addr, &receipt).await;
    // The result frame is signed by the provider over the outcome hash,
    // so the consumer binds the delivered output to this node id before
    // accepting it into its own settlement.
    let unix_ts = now_unix();
    let result = Message::TaskResult {
        signature: ctx
            .identity
            .sign(&Message::result_signing_payload(
                &launch.task_id,
                &outcome.hash(),
                unix_ts,
            ))
            .to_vec(),
        task_id: launch.task_id.clone(),
        outcome: outcome.clone(),
        unix_ts,
        pubkey: ctx.identity.pubkey(),
    };
    let _ = send_msg(ctx, &launch.return_addr, &result).await;
    outcome
}

/// Spawn the command with the sandbox profile and the launch's resource
/// binding: the pinned GPU device indices are exported to the
/// accelerator runtimes, and the memory cap is the task's explicit
/// request when present (the scheduler already checked it against the
/// advertised offer) or the provider default otherwise. Standard output
/// and error are piped and drained concurrently with the wait, so a
/// chatty task can neither deadlock on a full pipe nor exhaust memory.
async fn run_command(ctx: &Arc<Ctx>, launch: &Launch) -> Result<TaskOutcome, ()> {
    let workdir = ctx
        .config
        .paths
        .state_dir
        .join("tasks")
        .join(&launch.task_id);
    std::fs::create_dir_all(&workdir).map_err(|err| {
        eprintln!(
            "[executor] cannot create workdir for {}: {err:#}",
            launch.task_id
        );
    })?;
    let ram_mb = if launch.ram_mb > 0 {
        launch.ram_mb
    } else {
        ctx.config.limits.ram_mb
    };
    let mut command = Command::new("sh");
    command.arg("-c").arg(&launch.command);
    command.current_dir(&workdir);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    #[cfg(unix)]
    {
        // The whole process group joins the sandbox, so a timeout kill
        // cannot orphan grandchildren that keep billing.
        command.process_group(0);
    }
    if !launch.gpus.is_empty() {
        let devices = launch
            .gpus
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        // CUDA and ROCm honor their own variable; exporting both pins
        // the same device set across vendor toolchains.
        command.env("CUDA_VISIBLE_DEVICES", &devices);
        command.env("ROCR_VISIBLE_DEVICES", &devices);
    }
    sandbox::apply_to_command(&mut command, &workdir, &ctx.config.sandbox, ram_mb);
    let mut child = command.spawn().map_err(|err| {
        eprintln!("[executor] spawn failed for {}: {err:#}", launch.task_id);
    })?;
    let pid = child.id().expect("spawned child has a pid");
    #[cfg(unix)]
    let guard = sandbox::CgroupGuard::attach(
        &launch.task_id,
        pid,
        &ctx.config.sandbox,
        ram_mb,
        ctx.config.limits.cpu_percent,
    );
    // Take the pipes before waiting: the three sub-futures borrow three
    // disjoint values (stdout pipe, stderr pipe, child), so they run
    // concurrently inside the timeout without borrow conflicts.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let wait = async {
        let out = async {
            match stdout_pipe.as_mut() {
                Some(pipe) => read_capped(pipe, OUTPUT_CAP).await,
                None => String::new(),
            }
        };
        let err = async {
            match stderr_pipe.as_mut() {
                Some(pipe) => read_capped(pipe, OUTPUT_CAP).await,
                None => String::new(),
            }
        };
        let (stdout, stderr, status) = tokio::join!(out, err, child.wait());
        (stdout, stderr, status)
    };
    match tokio::time::timeout(Duration::from_secs(launch.timeout_secs), wait).await {
        Ok((stdout, stderr, Ok(status))) => {
            #[cfg(unix)]
            drop(guard);
            Ok(TaskOutcome {
                exit_code: status.code().unwrap_or(-1),
                stdout,
                stderr,
                billed_secs: 0, // filled by the caller
            })
        }
        Ok((_stdout, _stderr, Err(err))) => {
            eprintln!("[executor] wait failed for {}: {err:#}", launch.task_id);
            Err(())
        }
        Err(_) => {
            // Timeout: the timed-out future dropped the child handle
            // (which kills the direct child), and the process group is
            // killed explicitly so no grandchild survives.
            #[cfg(unix)]
            unsafe {
                libc::killpg(pid as i32, libc::SIGKILL);
            }
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
