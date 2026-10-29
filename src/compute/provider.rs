//! Provider-side scheduler: authenticates bids, tracks accepted work,
//! launches assigned tasks into the executor and keeps per-consumer
//! in-flight accounting for the accept policy.
//!
//! Flow: `Bid` -> policy check -> `TaskAccept` + queue entry; `Assign`
//! (its signature was verified by the dispatcher against the accepted bid)
//! -> immediate launch into a free slot, or the priority pending heap when
//! every slot is busy; `Freed` -> refills the freed slot from the pending
//! heap. Expired bids are purged periodically.

use crate::compute::executor;
use crate::compute::policy::{self, Decision};
use crate::compute::queue::{BidQueue, QueuedBid};
use crate::compute::Launch;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Commands accepted by the scheduler from the frame dispatcher.
pub enum Cmd {
    /// An authenticated bid arrived from `from_node` at `from_addr`.
    Bid {
        task_id: String,
        from_node: String,
        from_addr: String,
        trust: i64,
        consumed: u64,
        expires_unix: u64,
    },
    /// The authenticated consumer hands over the command of an accepted bid.
    Assign {
        task_id: String,
        command: String,
        timeout_secs: u64,
        from_node: String,
    },
    /// The executor finished one task and freed its slot.
    Freed { task_id: String },
}

/// A bid handed from the dispatcher to the scheduler in one piece.
struct IncomingBid {
    task_id: String,
    from_node: String,
    from_addr: String,
    trust: i64,
    consumed: u64,
    expires_unix: u64,
}

/// A bid that passed the policy check and waits for its assignment.
struct AcceptedBid {
    from_node: String,
    from_addr: String,
    units: i64,
    expires_unix: u64,
}

/// A task currently occupying one executor slot.
struct RunningTask {
    from_node: String,
    units: i64,
}

/// An assigned task waiting for a free slot, ordered by reservation size
/// and insertion order so equal-priced work is served FIFO.
struct PendingLaunch {
    units: i64,
    order: u64,
    from_node: String,
    launch: Launch,
}

impl Eq for PendingLaunch {}
impl PartialEq for PendingLaunch {
    fn eq(&self, other: &Self) -> bool {
        self.units == other.units && self.order == other.order
    }
}
impl Ord for PendingLaunch {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .units
            .cmp(&self.units)
            .then_with(|| other.order.cmp(&self.order))
    }
}
impl PartialOrd for PendingLaunch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Spawn the scheduler and its executor pipeline in the background.
pub fn run(ctx: Arc<Ctx>, rx: mpsc::Receiver<Cmd>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut scheduler = Scheduler::default();
        let (launch_tx, launch_rx) = mpsc::channel::<Launch>(8);
        tokio::spawn(executor::run(ctx.clone(), launch_rx));
        scheduler.serve(ctx, rx, launch_tx).await;
    })
}

/// Mutable scheduler state.
#[derive(Default)]
struct Scheduler {
    accepted: HashMap<String, AcceptedBid>,
    running: HashMap<String, RunningTask>,
    pending: BinaryHeap<PendingLaunch>,
    in_flight: HashMap<String, i64>,
    queue: BidQueue,
    order: u64,
}

impl Scheduler {
    /// Consume scheduler commands until the command stream closes.
    async fn serve(
        &mut self,
        ctx: Arc<Ctx>,
        mut rx: mpsc::Receiver<Cmd>,
        launch_tx: mpsc::Sender<Launch>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        Cmd::Bid {
                            task_id,
                            from_node,
                            from_addr,
                            trust,
                            consumed,
                            expires_unix,
                        } => {
                            self.on_bid(
                                &ctx,
                                IncomingBid {
                                    task_id,
                                    from_node,
                                    from_addr,
                                    trust,
                                    consumed,
                                    expires_unix,
                                },
                            )
                            .await;
                        }
                        Cmd::Assign {
                            task_id,
                            command,
                            timeout_secs,
                            from_node,
                        } => {
                            self.on_assign(&ctx, task_id, command, timeout_secs, from_node, &launch_tx)
                                .await;
                        }
                        Cmd::Freed { task_id } => {
                            self.on_freed(&ctx, task_id, &launch_tx).await;
                        }
                    }
                }
                _ = tick.tick() => self.purge_expired(),
            }
        }
    }

    /// Maximum number of concurrent tasks from the current limits.
    async fn max_tasks(&self, ctx: &Arc<Ctx>) -> usize {
        ctx.state.lock().await.limits.max_tasks as usize
    }

    /// Evaluate one authenticated bid; on acceptance record it, queue it
    /// and notify the consumer, otherwise answer with the refusal reason.
    async fn on_bid(&mut self, ctx: &Arc<Ctx>, bid: IncomingBid) {
        let in_flight = self.in_flight.get(&bid.from_node).copied().unwrap_or(0);
        match policy::evaluate_bid(
            ctx,
            &bid.from_node,
            bid.trust,
            bid.consumed,
            bid.expires_unix,
            in_flight,
        )
        .await
        {
            Decision::Accept { units } => {
                self.accepted.insert(
                    bid.task_id.clone(),
                    AcceptedBid {
                        from_node: bid.from_node,
                        from_addr: bid.from_addr.clone(),
                        units,
                        expires_unix: bid.expires_unix,
                    },
                );
                self.queue.push(QueuedBid {
                    task_id: bid.task_id.clone(),
                    units,
                    expires_unix: bid.expires_unix,
                });
                let _ = send_msg(
                    ctx,
                    &bid.from_addr,
                    &Message::TaskAccept {
                        task_id: bid.task_id,
                    },
                )
                .await;
            }
            Decision::Reject(reason) => {
                let _ = send_msg(
                    ctx,
                    &bid.from_addr,
                    &Message::TaskReject {
                        task_id: bid.task_id,
                        reason: reason.to_string(),
                    },
                )
                .await;
            }
        }
    }

    /// Honor an assignment only when it extends a bid this node accepted
    /// from the same consumer; then launch it or park it in the pending
    /// heap while every slot is busy.
    async fn on_assign(
        &mut self,
        ctx: &Arc<Ctx>,
        task_id: String,
        command: String,
        timeout_secs: u64,
        from_node: String,
        launch_tx: &mpsc::Sender<Launch>,
    ) {
        let Some(bid) = self.accepted.remove(&task_id) else {
            return;
        };
        if bid.from_node != from_node {
            eprintln!("[provider] assignment for {task_id} came from the wrong node");
            return;
        }
        self.queue.remove(&task_id);
        *self.in_flight.entry(bid.from_node.clone()).or_insert(0) += bid.units;
        let launch = Launch {
            task_id: task_id.clone(),
            return_addr: bid.from_addr,
            units: bid.units,
            command,
            timeout_secs,
        };
        if self.running.len() < self.max_tasks(ctx).await {
            self.running.insert(
                task_id,
                RunningTask {
                    from_node: bid.from_node,
                    units: bid.units,
                },
            );
            let _ = launch_tx.send(launch).await;
        } else {
            self.order += 1;
            self.pending.push(PendingLaunch {
                units: bid.units,
                order: self.order,
                from_node: bid.from_node,
                launch,
            });
        }
    }

    /// Settle one finished task back into the in-flight accounting and
    /// refill the freed slot from the most valuable pending assignment.
    async fn on_freed(
        &mut self,
        ctx: &Arc<Ctx>,
        task_id: String,
        launch_tx: &mpsc::Sender<Launch>,
    ) {
        if let Some(running) = self.running.remove(&task_id) {
            let left = self
                .in_flight
                .get(&running.from_node)
                .copied()
                .unwrap_or(0)
                .saturating_sub(running.units);
            if left <= 0 {
                self.in_flight.remove(&running.from_node);
            } else {
                self.in_flight.insert(running.from_node, left);
            }
        }
        while self.running.len() < self.max_tasks(ctx).await {
            let Some(next) = self.pending.pop() else {
                break;
            };
            self.running.insert(
                next.launch.task_id.clone(),
                RunningTask {
                    from_node: next.from_node,
                    units: next.units,
                },
            );
            if launch_tx.send(next.launch).await.is_err() {
                break;
            }
        }
    }

    /// Drop expired accepted bids and queue entries so stale reservations
    /// cannot block fresh work forever; consumers of purged bids time out
    /// and release their reservations on their own.
    fn purge_expired(&mut self) {
        let now = crate::trust::now_unix();
        self.accepted.retain(|_, bid| bid.expires_unix > now);
        self.queue.purge_expired(now);
    }
}
