//! Provider side of the compute market: a scheduler task owning the bid
//! queue and slot accounting, plus an executor task running commands.
//!
//! Both tasks communicate through channels only, so no future awaits another
//! future of the same cycle and every spawned task stays `Send`.

use crate::compute::queue::BidEntry;
use crate::compute::TaskOutcome;
use crate::credits::ledger::now_unix;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::state::Mode;
use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::{Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// How long a consumer has to send `TaskAssign` after `TaskAccept`.
const ASSIGN_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum captured output per stream, in bytes.
const OUTPUT_CAP: usize = 64 * 1024;
/// Execution environment handed to every task process.
const TASK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// Channel depth between the wire handler, scheduler and executor.
const QUEUE_DEPTH: usize = 64;

/// Commands accepted by the scheduler task.
pub enum Cmd {
    /// A consumer offered credits for one task.
    Bid {
        task_id: String,
        from_addr: String,
        offer: u64,
        expires_unix: u64,
    },
    /// A consumer sent the assignment for an accepted task.
    Assign {
        task_id: String,
        command: String,
        timeout_secs: u64,
    },
    /// Internal: an accepted task received its assignment in time.
    Launch {
        task_id: String,
        return_addr: String,
        command: String,
        timeout_secs: u64,
    },
    /// Internal: one slot freed up after finish or assign timeout.
    Freed,
}

/// One unit of work handed to the executor task.
struct Launch {
    task_id: String,
    return_addr: String,
    command: String,
    timeout_secs: u64,
}

/// Start the scheduler and executor tasks; consumes the command stream fed
/// by the wire handler via `Ctx::compute`.
pub fn run(ctx: Arc<Ctx>, cmds: mpsc::Receiver<Cmd>) {
    let (run_tx, run_rx) = mpsc::channel::<Launch>(QUEUE_DEPTH);
    tokio::spawn(executor(ctx.clone(), run_rx));
    tokio::spawn(scheduler(ctx, cmds, run_tx));
}

/// Scheduler loop: owns the bid heap, slot counter and assignment waiters.
async fn scheduler(
    ctx: Arc<Ctx>,
    mut cmds: mpsc::Receiver<Cmd>,
    run_tx: mpsc::Sender<Launch>,
) {
    let mut bids = BinaryHeap::<BidEntry>::new();
    let mut seq = 0u64;
    let mut running: u32 = 0;
    let mut waiters: HashMap<String, oneshot::Sender<Message>> = HashMap::new();

    while let Some(cmd) = cmds.recv().await {
        match cmd {
            Cmd::Bid {
                task_id,
                from_addr,
                offer,
                expires_unix,
            } => {
                if ctx.state.lock().await.mode == Mode::Leech {
                    reject(&ctx, &from_addr, &task_id, "node is in leech mode").await;
                    continue;
                }
                let max = ctx.state.lock().await.limits.max_tasks;
                if running >= max {
                    if expires_unix > now_unix() {
                        seq += 1;
                        bids.push(BidEntry {
                            task_id,
                            from_addr,
                            offer,
                            expires_unix,
                            seq,
                        });
                    }
                    continue;
                }
                accept(&ctx, &mut running, &mut waiters, from_addr, task_id).await;
            }
            Cmd::Assign {
                task_id,
                command,
                timeout_secs,
            } => {
                if let Some(tx) = waiters.remove(&task_id) {
                    let _ = tx.send(Message::TaskAssign {
                        task_id,
                        command,
                        timeout_secs,
                    });
                }
            }
            Cmd::Launch {
                task_id,
                return_addr,
                command,
                timeout_secs,
            } => {
                let _ = run_tx
                    .send(Launch {
                        task_id,
                        return_addr,
                        command,
                        timeout_secs,
                    })
                    .await;
            }
            Cmd::Freed => {
                running = running.saturating_sub(1);
                ctx.running_tasks.store(running, AtomicOrdering::Relaxed);
                drain(&ctx, &mut running, &mut waiters, &mut bids).await;
            }
        }
    }
}

/// Serve queued bids while execution slots are free.
async fn drain(
    ctx: &Arc<Ctx>,
    running: &mut u32,
    waiters: &mut HashMap<String, oneshot::Sender<Message>>,
    bids: &mut BinaryHeap<BidEntry>,
) {
    let max = ctx.state.lock().await.limits.max_tasks;
    while *running < max {
        let Some(bid) = bids.pop() else { return };
        if bid.expires_unix <= now_unix() {
            continue; // expired bid
        }
        accept(ctx, running, waiters, bid.from_addr, bid.task_id).await;
    }
}

/// Reserve a slot, notify the consumer and arm the assignment timer.
///
/// The timer runs as its own tiny task: on success it re-injects the work as
/// `Cmd::Launch`, on timeout as `Cmd::Freed`, so this future never awaits
/// the executor or the scheduler and stays `Send`.
async fn accept(
    ctx: &Arc<Ctx>,
    running: &mut u32,
    waiters: &mut HashMap<String, oneshot::Sender<Message>>,
    addr: String,
    task_id: String,
) {
    *running += 1;
    ctx.running_tasks.store(*running, AtomicOrdering::Relaxed);
    let (tx, rx) = oneshot::channel::<Message>();
    waiters.insert(task_id.clone(), tx);
    if let Err(err) = send_msg(
        ctx,
        &addr,
        &Message::TaskAccept {
            task_id: task_id.clone(),
        },
    )
    .await
    {
        eprintln!("[provider] cannot accept {task_id}: {err:#}");
        waiters.remove(&task_id);
        *running -= 1;
        ctx.running_tasks.store(*running, AtomicOrdering::Relaxed);
        return;
    }
    let wctx = ctx.clone();
    let wid = task_id.clone();
    tokio::spawn(async move {
        let result = tokio::time::timeout(ASSIGN_TIMEOUT, rx).await;
        let cmd = match result {
            Ok(Ok(Message::TaskAssign {
                command,
                timeout_secs,
                ..
            })) => Cmd::Launch {
                task_id: wid,
                return_addr: addr,
                command,
                timeout_secs,
            },
            _ => Cmd::Freed,
        };
        let _ = wctx.compute.send(cmd).await;
    });
}

async fn reject(ctx: &Arc<Ctx>, addr: &str, task_id: &str, reason: &str) {
    let _ = send_msg(
        ctx,
        addr,
        &Message::TaskReject {
            task_id: task_id.to_string(),
            reason: reason.to_string(),
        },
    )
    .await;
}

/// Executor loop: runs launched commands and reports `Cmd::Freed` after each.
async fn executor(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<Launch>) {
    while let Some(launch) = rx.recv().await {
        execute(&ctx, launch).await;
        let _ = ctx.compute.send(Cmd::Freed).await;
    }
}

/// Run one command in a fresh temporary directory with a scrubbed
/// environment and a hard wall-clock limit, then report the outcome.
async fn execute(ctx: &Arc<Ctx>, launch: Launch) {
    let workdir = std::env::temp_dir().join(format!("opennet-task-{}", launch.task_id));
    let _ = tokio::fs::create_dir_all(&workdir).await;
    let run = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&launch.command)
        .current_dir(&workdir)
        .env_clear()
        .env("PATH", TASK_PATH)
        .env("HOME", workdir.to_string_lossy().as_ref())
        .output();
    let wall = Duration::from_secs(launch.timeout_secs.max(1));
    let outcome = match tokio::time::timeout(wall, run).await {
        Ok(Ok(output)) => TaskOutcome {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: truncate(String::from_utf8_lossy(&output.stdout)),
            stderr: truncate(String::from_utf8_lossy(&output.stderr)),
        },
        Ok(Err(err)) => TaskOutcome {
            exit_code: -1,
            stdout: String::new(),
            stderr: format!("failed to start task: {err}"),
        },
        Err(_) => TaskOutcome {
            exit_code: -2,
            stdout: String::new(),
            stderr: format!(
                "task exceeded its {}s limit and was killed",
                launch.timeout_secs
            ),
        },
    };
    let _ = tokio::fs::remove_dir_all(&workdir).await;
    {
        let mut state = ctx.state.lock().await;
        if outcome.exit_code == 0 {
            state.tasks_completed += 1;
        } else {
            state.tasks_failed += 1;
        }
        let _ = state.save();
    }
    let _ = send_msg(
        ctx,
        &launch.return_addr,
        &Message::TaskResult {
            task_id: launch.task_id,
            outcome,
        },
    )
    .await;
}

fn truncate(text: std::borrow::Cow<'_, str>) -> String {
    let mut text = text.into_owned();
    if text.len() > OUTPUT_CAP {
        text.truncate(OUTPUT_CAP);
        text.push_str("\n...[truncated]");
    }
    text
}
