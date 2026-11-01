//! Mutable provider-side scheduling state: accepted bids, running and
//! parked tasks, GPU device allocation and per-consumer in-flight
//! accounting used by the bid policy. The scheduler loop reacts to
//! scheduler commands (bids, assignments, executor slot frees), a
//! periodic purge of expired bids, and the shared shutdown flag, which
//! switches the loop into the bounded drain in the `drain` submodule.

use crate::compute::policy::{self, Decision};
use crate::compute::provider::{Cmd, IncomingBid};
use crate::compute::queue::{BidQueue, PendingLaunch, QueuedBid};
use crate::compute::Launch;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

mod drain;
mod gpu;

/// One accepted bid waiting for its assignment window.
#[derive(Clone)]
struct AcceptedBid {
    /// Node id of the consumer, matched against the assignment signature.
    from_node: String,
    /// Address the bid decision was sent to and assignments arrive from.
    from_addr: String,
    /// Trust units reserved for this task.
    units: i64,
    /// Unix time after which the accepted bid may be discarded.
    expires_unix: u64,
    /// Number of GPU devices requested in the assignment; the devices
    /// themselves are bound when the task starts.
    gpus: u32,
}

/// One task currently executing in the executor.
struct RunningTask {
    /// Node id of the consumer, for in-flight accounting on completion.
    from_node: String,
    /// Trust units reserved for this task.
    units: i64,
    /// GPU device indices held by this task until it finishes.
    gpus: Vec<u32>,
}

/// Provider scheduling state; fields are documented at their use sites.
/// Every field implements `Default` (empty maps and heaps, an empty
/// GPU pool, zero counters), so the default state is a fresh scheduler.
#[derive(Default)]
pub struct Scheduler {
    /// Accepted bids keyed by task id, awaiting `Assign`.
    accepted: HashMap<String, AcceptedBid>,
    /// Tasks currently executing in the executor.
    running: HashMap<String, RunningTask>,
    /// Assigned tasks waiting for a free executor slot, ordered by
    /// reservation size.
    pending: BinaryHeap<PendingLaunch>,
    /// Reserved-but-not-yet-billed units per consumer node id, holding
    /// the provider-side half of the bid policy inequality.
    in_flight: HashMap<String, i64>,
    /// Priority queue of accepted-but-unassigned bids.
    queue: BidQueue,
    /// GPU device pool offered to remote tasks; empty on CPU-only nodes.
    gpus: gpu::GpuPool,
    /// Insertion counter breaking price ties FIFO in the pending heap.
    order: u64,
    /// Set once a shutdown drain begins: bids are refused and the
    /// pending heap no longer refills freed slots.
    shutting_down: bool,
}

impl Scheduler {
    /// Run the scheduling loop until the shutdown flag fires and the
    /// drain completes; returning drops the launch channel, which ends
    /// the executor task.
    pub async fn serve(
        &mut self,
        ctx: &Arc<Ctx>,
        mut rx: mpsc::Receiver<Cmd>,
        launch_tx: mpsc::Sender<Launch>,
    ) {
        self.gpus = gpu::GpuPool::new(gpu::offered_gpus(ctx).await);
        let mut shutdown_rx = ctx.shutdown.subscribe();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        Cmd::Bid { task_id, from_node, from_addr, trust, consumed, expires_unix } => {
                            let bid = IncomingBid { task_id, from_node, from_addr, trust, consumed, expires_unix };
                            self.on_bid(ctx, bid).await;
                        }
                        assign @ Cmd::Assign { .. } => {
                            self.on_assign(ctx, assign, &launch_tx).await;
                        }
                        Cmd::Freed { task_id } => self.on_freed(ctx, task_id, &launch_tx).await,
                    }
                }
                _ = tick.tick() => self.purge_expired(),
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow_and_update() {
                        self.drain(ctx, &mut rx, &launch_tx).await;
                        break;
                    }
                }
            }
        }
    }

    /// Evaluate one bid against the local policy; on acceptance the
    /// reservation enters the priority queue and the decision is sent.
    async fn on_bid(&mut self, ctx: &Arc<Ctx>, bid: IncomingBid) {
        if self.shutting_down {
            let reject = Message::TaskReject {
                task_id: bid.task_id,
                reason: "daemon shutting down".to_string(),
            };
            let _ = send_msg(ctx, &bid.from_addr, &reject).await;
            return;
        }
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
                        from_node: bid.from_node.clone(),
                        from_addr: bid.from_addr.clone(),
                        units,
                        expires_unix: bid.expires_unix,
                        gpus: 0,
                    },
                );
                self.queue.push(QueuedBid {
                    task_id: bid.task_id.clone(),
                    units,
                    expires_unix: bid.expires_unix,
                });
                let accept = Message::TaskAccept {
                    task_id: bid.task_id,
                };
                let _ = send_msg(ctx, &bid.from_addr, &accept).await;
            }
            Decision::Reject(reason) => {
                let reject = Message::TaskReject {
                    task_id: bid.task_id,
                    reason: reason.to_string(),
                };
                let _ = send_msg(ctx, &bid.from_addr, &reject).await;
            }
        }
    }

    /// Launch the command of an accepted bid into a free executor slot,
    /// or park it in the pending heap when every slot is busy. The
    /// assignment is executed only when it comes from the exact node
    /// whose bid was accepted; unknown, mismatched or expired
    /// assignments are rejected so the consumer releases its
    /// reservation. The requested RAM ceiling and GPU count are checked
    /// against the advertised capacity before anything starts.
    async fn on_assign(&mut self, ctx: &Arc<Ctx>, assign: Cmd, launch_tx: &mpsc::Sender<Launch>) {
        let Cmd::Assign {
            task_id,
            command,
            timeout_secs,
            ram_mb,
            gpus,
            from_node,
        } = assign
        else {
            return; // the dispatcher only routes assignments here
        };
        let Some(mut bid) = self.accepted.remove(&task_id) else {
            return;
        };
        let reject = |reason: &str| Message::TaskReject {
            task_id: task_id.clone(),
            reason: reason.to_string(),
        };
        if bid.from_node != from_node {
            let _ = send_msg(
                ctx,
                &bid.from_addr,
                &reject("task assignment node mismatch"),
            )
            .await;
            return;
        }
        self.queue.remove(&task_id);
        if bid.expires_unix <= crate::trust::now_unix() {
            let _ = send_msg(ctx, &bid.from_addr, &reject("task assignment expired")).await;
            return;
        }
        let offered_ram = ctx.state.lock().await.limits.ram_mb;
        if ram_mb > offered_ram {
            let _ = send_msg(
                ctx,
                &bid.from_addr,
                &reject("ram request exceeds offered capacity"),
            )
            .await;
            return;
        }
        if gpus as usize > self.gpus.len() {
            let _ = send_msg(ctx, &bid.from_addr, &reject("no gpus available")).await;
            return;
        }
        bid.gpus = gpus;
        let launch = Launch {
            task_id: task_id.clone(),
            return_addr: bid.from_addr.clone(),
            from_node: bid.from_node.clone(),
            units: bid.units,
            command,
            timeout_secs,
            ram_mb,
            gpus: Vec::new(), // filled in when the task actually starts
        };
        if self.running.len() < self.max_tasks(ctx).await {
            self.start(ctx, task_id, bid, launch, launch_tx).await;
        } else {
            let in_flight = self.in_flight.entry(bid.from_node.clone()).or_insert(0);
            *in_flight += bid.units;
            self.order += 1;
            self.pending.push(PendingLaunch {
                units: bid.units,
                order: self.order,
                from_node: bid.from_node,
                launch,
            });
        }
    }

    /// Bind one task to a concrete GPU set and hand it to the executor;
    /// rolls the tracking back when the executor is gone.
    async fn start(
        &mut self,
        _ctx: &Arc<Ctx>,
        task_id: String,
        bid: AcceptedBid,
        mut launch: Launch,
        launch_tx: &mpsc::Sender<Launch>,
    ) {
        launch.gpus = self.gpus.alloc(bid.gpus as usize);
        self.running.insert(
            task_id.clone(),
            RunningTask {
                from_node: bid.from_node,
                units: bid.units,
                gpus: launch.gpus.clone(),
            },
        );
        if launch_tx.send(launch).await.is_err() {
            if let Some(running) = self.running.remove(&task_id) {
                self.gpus.free(running.gpus);
            }
        }
    }

    /// Free the slot of a finished task, return its reservation and its
    /// GPU devices, then refill the slot from the pending heap in
    /// price-then-FIFO order. A parked task whose GPUs are still busy
    /// stops the refill: GPU work must never start without devices.
    async fn on_freed(
        &mut self,
        ctx: &Arc<Ctx>,
        task_id: String,
        launch_tx: &mpsc::Sender<Launch>,
    ) {
        if let Some(running) = self.running.remove(&task_id) {
            self.return_units(&running.from_node, running.units);
            self.gpus.free(running.gpus);
        }
        while self.running.len() < self.max_tasks(ctx).await {
            let Some(next) = self.pending.pop() else {
                break;
            };
            let id = next.launch.task_id.clone();
            let Some(bid) = self.accepted.remove(&id) else {
                continue;
            };
            if bid.gpus as usize > self.gpus.len() {
                self.pending.push(next);
                break;
            }
            self.start(ctx, id.clone(), bid, next.launch, launch_tx)
                .await;
            if !self.running.contains_key(&id) {
                break;
            }
        }
    }

    /// Return `units` to one consumer's in-flight accounting, dropping
    /// the entry when nothing remains in flight.
    fn return_units(&mut self, from_node: &str, units: i64) {
        let left = self
            .in_flight
            .get(from_node)
            .copied()
            .unwrap_or(0)
            .saturating_sub(units);
        if left <= 0 {
            self.in_flight.remove(from_node);
        } else {
            self.in_flight.insert(from_node.to_string(), left);
        }
    }

    /// Drop expired accepted bids so expired reservations do not hold
    /// in-flight accounting.
    fn purge_expired(&mut self) {
        let now = crate::trust::now_unix();
        self.accepted.retain(|_, bid| bid.expires_unix > now);
        self.queue.purge_expired(now);
    }

    /// Advertised concurrency limit: leech mode disables task execution
    /// entirely, so the pending heap is drained by rejections on the
    /// next frees.
    async fn max_tasks(&self, ctx: &Arc<Ctx>) -> usize {
        let (mode, max_tasks) = {
            let state = ctx.state.lock().await;
            (state.mode, state.limits.max_tasks)
        };
        match mode {
            crate::node::state::Mode::Leech => 0,
            _ => max_tasks as usize,
        }
    }
}
