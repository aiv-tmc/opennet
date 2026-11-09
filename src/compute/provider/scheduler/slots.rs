//! Executor slot lifecycle: the scheduling loop, launching tasks into
//! free slots, refilling slots from the pending heap and returning
//! reservations when tasks finish. Methods called from the sibling
//! `scheduler` and `drain` modules are `pub(super)`.

use super::{AcceptedBid, IncomingBid, RunningTask, Scheduler};
use crate::compute::provider::Cmd;
use crate::compute::Launch;
use crate::daemon::Ctx;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

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
        self.gpus = super::gpu::GpuPool::new(super::gpu::offered_gpus(ctx).await);
        let mut shutdown_rx = ctx.shutdown.subscribe();
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
                            let bid = IncomingBid {
                                task_id,
                                from_node,
                                from_addr,
                                trust,
                                consumed,
                                expires_unix,
                            };
                            self.on_bid(ctx, bid).await;
                        }
                        assign @ Cmd::Assign { .. } => {
                            self.on_assign(ctx, assign, &launch_tx).await;
                        }
                        Cmd::Freed { task_id } => {
                            self.on_freed(ctx, task_id, &launch_tx).await;
                        }
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

    /// Bind one task to a concrete GPU set and hand it to the executor;
    /// rolls the tracking back when the executor is gone.
    pub(super) async fn start(
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
            // The executor is gone: the task will never run, so its
            // reservation returns with its devices.
            if let Some(running) = self.running.remove(&task_id) {
                self.gpus.free(running.gpus);
                self.return_units(&running.from_node, running.units);
            }
        }
    }

    /// Free the slot of a finished task, return its reservation and its
    /// GPU devices, then refill the slot from the pending heap in
    /// price-then-FIFO order. A parked task whose GPUs are still busy
    /// stops the refill: GPU work must never start without devices.
    pub(super) async fn on_freed(
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
    pub(super) fn return_units(&mut self, from_node: &str, units: i64) {
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

    /// Expire accepted bids and queued entries past their deadline,
    /// returning each expired bid's reservation to its consumer, then
    /// reclaim parked launches whose bid just expired: a parked launch
    /// only exists alongside its accepted bid, so once the bid is gone
    /// the heap entry is dead weight. The reservation returns exactly
    /// once — with the expired bid, never again with the heap entry.
    /// Without this the provider-side policy counter inflates forever
    /// and the consumer eventually reads as insolvent, and the heap
    /// grows without bound on nodes whose slots never free (for example
    /// a node switched to leech mode with parked tasks). The shutdown
    /// drain runs the same return, so a reservation never leaks on any
    /// exit path.
    fn purge_expired(&mut self) {
        let now = crate::trust::now_unix();
        let mut expired: Vec<(String, i64)> = Vec::new();
        self.accepted.retain(|_, bid| {
            if bid.expires_unix > now {
                true
            } else {
                expired.push((bid.from_node.clone(), bid.units));
                false
            }
        });
        for (from_node, units) in expired {
            self.return_units(&from_node, units);
        }
        self.queue.purge_expired(now);
        self.pending
            .retain(|pending| self.accepted.contains_key(&pending.launch.task_id));
    }

    /// Advertised concurrency limit: leech mode disables task execution
    /// entirely; assignments accepted before the mode switch stay
    /// parked until their bids expire, at which point the periodic
    /// purge reclaims them (see `purge_expired`).
    pub(super) async fn max_tasks(&self, ctx: &Arc<Ctx>) -> usize {
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
