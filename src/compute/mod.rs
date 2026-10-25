//! Compute market shared between providers (executors) and consumers.
//!
//! A consumer spends trust units for one shell command executed on a
//! provider. Providers schedule queued bids by reservation size, highest
//! first, and never run more than `limits.max_tasks` tasks at once. Both
//! sides track the same trust coefficient: consuming lowers it, donating
//! raises it, and providers refuse consumers whose effective trust would
//! fall below the configured floor.

pub mod client;
pub mod executor;
pub mod policy;
pub mod provider;
pub mod queue;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::daemon::Ctx;

/// Exit status and captured output of a finished task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskOutcome {
    /// Process exit code; negative values mark daemon-side failures.
    pub exit_code: i32,
    /// Captured standard output, truncated to 64 KiB.
    pub stdout: String,
    /// Captured standard error, truncated to 64 KiB.
    pub stderr: String,
}

/// Events delivered to a waiting consumer session for one task.
#[derive(Debug)]
pub enum ComputeEvent {
    /// The provider accepted the bid.
    Accepted,
    /// The provider refused the bid with an explanation.
    Rejected(String),
    /// The task finished; carries the exit status and output.
    Outcome(TaskOutcome),
}

/// Forward one provider message to the consumer session waiting on `task_id`.
///
/// Messages arriving after the consumer gave up have no waiter and are
/// dropped; the consumer already released its reservation in that case.
pub async fn deliver_event(ctx: &Arc<Ctx>, task_id: &str, event: ComputeEvent) {
    if let Some(sender) = ctx.result_waiters.lock().await.remove(task_id) {
        let _ = sender.send(event);
    }
}
