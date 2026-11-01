//! Provider pipeline wiring: the command channel from dispatch, the
//! scheduler task owning all scheduling state and the executor task
//! running sandboxed commands. Keeping the channel here decouples
//! dispatch (protocol-facing) from scheduling (policy-facing).

use crate::compute::executor;
use crate::compute::provider::scheduler::Scheduler;
use crate::compute::Launch;
use crate::daemon::Ctx;
use std::sync::Arc;
use tokio::sync::mpsc;

pub mod scheduler;

/// Commands from dispatch into the scheduler.
pub enum Cmd {
    /// One verified bid with its signed trust snapshot.
    Bid {
        task_id: String,
        from_node: String,
        from_addr: String,
        trust: i64,
        consumed: u64,
        expires_unix: u64,
    },
    /// One verified assignment with its signed resource request.
    Assign {
        task_id: String,
        command: String,
        timeout_secs: u64,
        ram_mb: u64,
        gpus: u32,
        from_node: String,
    },
    /// One executor slot freed by a finished task.
    Freed { task_id: String },
}

/// A bid as seen by the scheduler.
pub struct IncomingBid {
    pub task_id: String,
    pub from_node: String,
    pub from_addr: String,
    pub trust: i64,
    pub consumed: u64,
    pub expires_unix: u64,
}

/// Spawn the provider pipeline: the executor consumes launches and the
/// scheduler consumes commands; both end when the scheduler stops.
pub fn run(ctx: Arc<Ctx>, rx: mpsc::Receiver<Cmd>) {
    let (launch_tx, launch_rx) = mpsc::channel::<Launch>(16);
    tokio::spawn(executor::run(ctx.clone(), launch_rx));
    tokio::spawn(async move {
        Scheduler::default().serve(&ctx, rx, launch_tx).await;
    });
}
