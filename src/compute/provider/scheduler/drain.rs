//! Graceful-shutdown drain of the compute scheduler: new bids are
//! refused with signed rejections, accepted-but-unassigned bids and
//! parked launches are rejected so consumers release their reserved
//! trust promptly, and the tasks already running finish within a
//! bounded window.

use super::{signed_reject, Scheduler};
use crate::compute::provider::Cmd;
use crate::daemon::{send_msg, Ctx};
use std::sync::Arc;
use std::time::Duration;
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
        // Refuse every bid already sitting in the channel so the
        // consumers release their reservations now instead of after
        // their assignment timeout.
        while let Ok(cmd) = rx.try_recv() {
            if let Cmd::Bid {
                task_id, from_addr, ..
            } = cmd
            {
                let reject = signed_reject(ctx, &task_id, "daemon shutting down");
                let _ = send_msg(ctx, &from_addr, &reject).await;
            }
        }
        // Reject every accepted bid and return its reservation so the
        // consumer's in-flight accounting survives nothing. Parked
        // launches still sit in this map (their reservation returns
        // here), so the heap pass below must not return them again.
        let accepted = std::mem::take(&mut self.accepted);
        for (task_id, bid) in accepted {
            self.return_units(&bid.from_node, bid.units);
            let reject = signed_reject(ctx, &task_id, "daemon shutting down");
            let _ = send_msg(ctx, &bid.from_addr, &reject).await;
        }
        // Every expiry is a positive unix timestamp, so purging at zero
        // clears the whole queue; the queue mirrors the accepted map,
        // which was just emptied.
        self.queue.purge_expired(0);
        // Reject every parked launch; its reservation already returned
        // with its accepted bid above.
        let pending = std::mem::take(&mut self.pending);
        for parked in pending {
            let reject = signed_reject(ctx, &parked.launch.task_id, "daemon shutting down");
            let _ = send_msg(ctx, &parked.launch.return_addr, &reject).await;
        }
        crate::log::warn(
            module_path!(),
            &format!("[provider] draining {} running task(s)", self.running.len()),
        );
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        while !self.running.is_empty() {
            // `Instant` has no saturating subtraction: a missing
            // duration means the deadline passed and the drain gives up.
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
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
                    // Late bids during the drain are refused like the
                    // pre-drain ones; assignments have nothing to attach
                    // to and are ignored.
                    Ok(Some(Cmd::Bid {
                        task_id, from_addr, ..
                    })) => {
                        let reject = signed_reject(ctx, &task_id, "daemon shutting down");
                        let _ = send_msg(ctx, &from_addr, &reject).await;
                    }
                    Ok(_) => break,
                    // Deadline elapsed or every sender gone: stop waiting.
                    Err(_) => break,
                },
            }
        }
        crate::log::warn(module_path!(), "[provider] drain complete");
    }
}
