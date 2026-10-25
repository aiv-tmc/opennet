//! Provider-side scheduler: owns the bid queue, slot accounting and
//! assignment waiters, enforcing the trust policy before any execution.
//!
//! The scheduler never executes commands itself; it hands accepted work to
//! the executor through a channel, so no future awaits another future of
//! the same cycle and every spawned task stays `Send`.

use crate::compute::policy::{policy_allows, reject};
use crate::compute::queue::BidEntry;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::state::Mode;
use crate::trust::{handlers, now_unix};
use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// How long a consumer has to send `TaskAssign` after `TaskAccept`.
pub const ASSIGN_TIMEOUT: Duration = Duration::from_secs(10);
/// Channel depth between the wire handler, scheduler and executor.
const QUEUE_DEPTH: usize = 64;

/// Commands accepted by the scheduler task.
pub enum Cmd {
    /// An authenticated consumer requested one task execution.
    Bid {
        task_id: String,
        from_node: String,
        from_addr: String,
        trust: i64,
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
        units: i64,
        command: String,
        timeout_secs: u64,
    },
    /// Internal: one execution slot freed up after finish or assign
    /// timeout.
    Freed,
}

/// One unit of work handed to the executor task.
pub struct Launch {
    pub task_id: String,
    pub return_addr: String,
    pub units: i64,
    pub command: String,
    pub timeout_secs: u64,
}

/// Scheduler state bundled so helper functions stay short.
struct Scheduler {
    bids: BinaryHeap<BidEntry>,
    seq: u64,
    running: u32,
    /// Assignment waiters keyed by task id.
    waiters: HashMap<String, oneshot::Sender<Message>>,
}

/// Start the scheduler and executor tasks; consumes the command stream fed
/// by the wire handler via `Ctx::compute`.
pub fn run(ctx: Arc<Ctx>, cmds: mpsc::Receiver<Cmd>) {
    let (run_tx, run_rx) = mpsc::channel::<Launch>(QUEUE_DEPTH);
    tokio::spawn(crate::compute::executor::run(ctx.clone(), run_rx));
    tokio::spawn(scheduler(ctx, cmds, run_tx));
}

/// Scheduler loop: dispatches wire commands and internal lifecycle events.
async fn scheduler(ctx: Arc<Ctx>, mut cmds: mpsc::Receiver<Cmd>, run_tx: mpsc::Sender<Launch>) {
    let mut sched = Scheduler {
        bids: BinaryHeap::new(),
        seq: 0,
        running: 0,
        waiters: HashMap::new(),
    };

    while let Some(cmd) = cmds.recv().await {
        match cmd {
            Cmd::Bid {
                task_id,
                from_node,
                from_addr,
                trust,
                expires_unix,
            } => {
                let (mode, points, max) = {
                    let state = ctx.state.lock().await;
                    (state.mode, state.points, state.limits.max_tasks)
                };
                if mode == Mode::Leech {
                    reject(&ctx, &from_addr, &task_id, "node is in leech mode").await;
                    continue;
                }
                // Both sides price the task from these points and the
                // configured default timeout, so they agree on the charge.
                let units = handlers::bid_units(&ctx.config, points);
                if sched.running >= max {
                    // All slots are busy: queue fresh bids; the policy is
                    // re-checked against the stored claim when served.
                    if expires_unix > now_unix() {
                        sched.seq += 1;
                        sched.bids.push(BidEntry {
                            task_id,
                            from_node,
                            from_addr,
                            offer: units.max(1) as u64,
                            trust,
                            expires_unix,
                            seq: sched.seq,
                        });
                    }
                    continue;
                }
                if !policy_allows(&ctx, &from_node, &from_addr, trust).await {
                    continue;
                }
                accept(&ctx, &mut sched, from_addr, task_id, units).await;
            }
            Cmd::Assign {
                task_id,
                command,
                timeout_secs,
            } => {
                if let Some(tx) = sched.waiters.remove(&task_id) {
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
                units,
                command,
                timeout_secs,
            } => {
                let _ = run_tx
                    .send(Launch {
                        task_id,
                        return_addr,
                        units,
                        command,
                        timeout_secs,
                    })
                    .await;
            }
            Cmd::Freed => {
                sched.running = sched.running.saturating_sub(1);
                ctx.running_tasks
                    .store(sched.running, AtomicOrdering::Relaxed);
                let max = ctx.state.lock().await.limits.max_tasks;
                drain(&ctx, &mut sched, max).await;
            }
        }
    }
}

/// Serve queued bids while execution slots are free.
async fn drain(ctx: &Arc<Ctx>, sched: &mut Scheduler, max: u32) {
    while sched.running < max {
        let Some(bid) = sched.bids.pop() else { return };
        if bid.expires_unix <= now_unix() {
            continue; // expired bid
        }
        if !policy_allows(ctx, &bid.from_node, &bid.from_addr, bid.trust).await {
            continue;
        }
        accept(ctx, sched, bid.from_addr, bid.task_id, bid.offer as i64).await;
    }
}

/// Reserve a slot, notify the consumer and arm the assignment timer.
///
/// The timer runs as its own tiny task: on success it re-injects the work
/// as `Cmd::Launch`, on timeout as `Cmd::Freed`, so this future never
/// awaits the executor or the scheduler and stays `Send`.
async fn accept(
    ctx: &Arc<Ctx>,
    sched: &mut Scheduler,
    from_addr: String,
    task_id: String,
    units: i64,
) {
    sched.running += 1;
    ctx.running_tasks
        .store(sched.running, AtomicOrdering::Relaxed);
    let (tx, rx) = oneshot::channel::<Message>();
    sched.waiters.insert(task_id.clone(), tx);
    if let Err(err) = send_msg(
        ctx,
        &from_addr,
        &Message::TaskAccept {
            task_id: task_id.clone(),
        },
    )
    .await
    {
        eprintln!("[provider] cannot accept {task_id}: {err:#}");
        sched.waiters.remove(&task_id);
        sched.running -= 1;
        ctx.running_tasks
            .store(sched.running, AtomicOrdering::Relaxed);
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
                return_addr: from_addr,
                units,
                command,
                timeout_secs,
            },
            _ => Cmd::Freed,
        };
        let _ = wctx.compute.send(cmd).await;
    });
}
