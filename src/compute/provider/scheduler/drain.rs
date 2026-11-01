//! Graceful-shutdown drain of the compute scheduler, kept in its own
//! submodule so the scheduling core stays within a readable size. The
//! drain is entered once, when the shared shutdown flag fires: new bids
//! are refused, every accepted-but-unassigned bid and every parked
//! launch is rejected so consumers release their reserved trust
//! promptly, and the tasks already running finish within a bounded
//! window.

use super::Scheduler;
use crate::compute::provider::Cmd;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Grace period granted to running tasks during a graceful shutdown;
/// after the deadline the drain gives up and the daemon proceeds, so a
/// single stuck task can never hold the service past this window.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

impl Scheduler {
    /// Run the shutdown drain; after it returns, `serve` drops the
    /// launch channel and the executor ends after its current task.
    pub(super) async fn drain(
        &mut self,
        ctx: &Arc<Ctx>,
        rx: &mut mpsc::Receiver<Cmd>,
        launch_tx: &mpsc::Sender<crate::compute::Launch>,
    ) {
        self.shutting_down = true;
        // Reject every accepted bid so consumers learn the outcome now
        // instead of after their assignment timeout.
        let accepted = std::mem::take(&mut self.accepted);
        for (task_id, bid) in accepted {
            let _ = send_msg(
                ctx,
                &bid.from_addr,
                &Message::TaskReject {
                    task_id,
                    reason: "daemon shutting down".to_string(),
                },
            )
            .await;
        }
        // Every expiry is a positive unix timestamp, so purging at zero
        // clears the whole queue; the queue mirrors the accepted map,
        // which was just emptied.
        self.queue.purge_expired(0);
        // Reject every parked launch and return its reservation so no
        // consumer's in-flight accounting survives the daemon.
        let pending = std::mem::take(&mut self.pending);
        for parked in pending {
            self.return_units(&parked.from_node, parked.units);
            let _ = send_msg(
                ctx,
                &parked.launch.return_addr,
                &Message::TaskReject {
                    task_id: parked.launch.task_id,
                    reason: "daemon shutting down".to_string(),
                },
            )
            .await;
        }
        eprintln!("[provider] draining {} running task(s)", self.running.len());
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        while !self.running.is_empty() {
            // `Instant` has no saturating subtraction: a missing
            // duration means the deadline passed and the drain gives up.
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                eprintln!(
                    "[provider] drain deadline reached with {} task(s) still running",
                    self.running.len()
                );
                break;
            };
            tokio::select! {
                cmd = tokio::time::timeout(remaining, rx.recv()) => match cmd {
                    Ok(Some(Cmd::Freed { task_id })) => {
                        self.on_freed(ctx, task_id, launch_tx).await
                    }
                    Ok(Some(late)) => self.refuse_late(ctx, late).await,
                    // Deadline elapsed or every sender gone: stop waiting.
                    _ => break,
                },
            }
        }
        eprintln!("[provider] drain complete");
    }

    /// Answer one command that arrived after the drain began: bids are
    /// rejected so the consumer releases its reservation immediately
    /// instead of waiting for a timeout; anything else is ignored
    /// because the accepted map and the pending heap are already empty.
    async fn refuse_late(&mut self, ctx: &Arc<Ctx>, cmd: Cmd) {
        if let Cmd::Bid {
            task_id, from_addr, ..
        } = cmd
        {
            let _ = send_msg(
                ctx,
                &from_addr,
                &Message::TaskReject {
                    task_id,
                    reason: "daemon shutting down".to_string(),
                },
            )
            .await;
        }
    }
}
