//! Provider scheduling core: accepted bids, running and parked tasks
//! and per-consumer in-flight accounting used by the bid policy. Every
//! bid decision is signed with the local identity before it leaves the
//! node, so a consumer only acts on a decision that proves its origin.
//! The scheduling loop and slot lifecycle live in `slots.rs`; the
//! shutdown drain lives in `drain.rs`.

use crate::compute::policy::{self, Decision};
use crate::compute::provider::{Cmd, IncomingBid};
use crate::compute::queue::{BidQueue, PendingLaunch, QueuedBid};
use crate::compute::Launch;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use tokio::sync::mpsc;

mod drain;
mod gpu;
mod slots;

/// One accepted bid waiting for its assignment window.
#[derive(Clone)]
struct AcceptedBid {
    /// Node id of the consumer; the assignment must come signed by the
    /// same node.
    from_node: String,
    /// Address the bid decision was sent to and assignments arrive from.
    from_addr: String,
    /// Trust units reserved for this task.
    units: i64,
    /// Unix time after which the accepted bid may be discarded.
    expires_unix: u64,
    /// Number of GPU devices requested by the assignment; the concrete
    /// device indices are bound when the task starts.
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

/// Scheduling and accounting state. Every field implements `Default`,
/// so the default state is a fresh scheduler with no history.
#[derive(Default)]
pub struct Scheduler {
    /// Accepted bids keyed by task id, awaiting `Cmd::Assign`.
    accepted: HashMap<String, AcceptedBid>,
    /// Tasks currently executing in the executor.
    running: HashMap<String, RunningTask>,
    /// Assigned tasks waiting for a free executor slot, ordered by
    /// reservation size with FIFO tie-breaking.
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

/// Sign one TaskAccept decision with the local identity so the consumer
/// can bind the acceptance to this provider's node id.
fn signed_accept(ctx: &Arc<Ctx>, task_id: &str) -> Message {
    let unix_ts = crate::trust::now_unix();
    Message::TaskAccept {
        signature: ctx
            .identity
            .sign(&Message::accept_signing_payload(task_id, unix_ts))
            .to_vec(),
        task_id: task_id.to_string(),
        unix_ts,
        pubkey: ctx.identity.pubkey(),
    }
}

/// Sign one TaskReject decision with the local identity so the consumer
/// can bind the refusal to this provider's node id.
fn signed_reject(ctx: &Arc<Ctx>, task_id: &str, reason: &str) -> Message {
    let unix_ts = crate::trust::now_unix();
    Message::TaskReject {
        signature: ctx
            .identity
            .sign(&Message::reject_signing_payload(task_id, reason, unix_ts))
            .to_vec(),
        task_id: task_id.to_string(),
        reason: reason.to_string(),
        unix_ts,
        pubkey: ctx.identity.pubkey(),
    }
}

impl Scheduler {
    /// Evaluate one bid against the local policy; on acceptance the
    /// reservation enters the priority queue and the signed decision is
    /// sent, on refusal the signed reason is sent so the consumer can
    /// release its reservation immediately.
    async fn on_bid(&mut self, ctx: &Arc<Ctx>, bid: IncomingBid) {
        if self.shutting_down {
            let reject = signed_reject(ctx, &bid.task_id, "daemon shutting down");
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
            self.running.len(),
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
                let accept = signed_accept(ctx, &bid.task_id);
                let _ = send_msg(ctx, &bid.from_addr, &accept).await;
            }
            Decision::Reject(reason) => {
                let reject = signed_reject(ctx, &bid.task_id, reason);
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
        let Some(bid) = self.accepted.remove(&task_id) else {
            return;
        };
        if bid.from_node != from_node {
            let reject = signed_reject(ctx, &task_id, "task assignment node mismatch");
            let _ = send_msg(ctx, &bid.from_addr, &reject).await;
            return;
        }
        self.queue.remove(&task_id);
        if bid.expires_unix <= crate::trust::now_unix() {
            let reject = signed_reject(ctx, &task_id, "task assignment expired");
            let _ = send_msg(ctx, &bid.from_addr, &reject).await;
            return;
        }
        let offered_ram = ctx.state.lock().await.limits.ram_mb;
        if ram_mb > offered_ram {
            let reject = signed_reject(ctx, &task_id, "ram request exceeds offered capacity");
            let _ = send_msg(ctx, &bid.from_addr, &reject).await;
            return;
        }
        if gpus as usize > self.gpus.len() {
            let reject = signed_reject(ctx, &task_id, "no gpus available");
            let _ = send_msg(ctx, &bid.from_addr, &reject).await;
            return;
        }
        let mut bid = bid;
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
            started: std::time::Instant::now(),
        };
        if self.running.len() < self.max_tasks(ctx).await {
            self.start(ctx, task_id, bid, launch, launch_tx).await;
        } else {
            // Parked tasks hold their reservation on the provider side
            // exactly like running ones: the in-flight counter rises
            // here and returns when the task finishes, the bid expires
            // (see `purge_expired`) or the shutdown drain runs.
            let counter = self.in_flight.entry(bid.from_node.clone()).or_insert(0);
            *counter = counter.saturating_add(bid.units);
            self.order += 1;
            self.pending.push(PendingLaunch {
                units: bid.units,
                order: self.order,
                from_node: bid.from_node,
                launch,
            });
        }
    }
}
