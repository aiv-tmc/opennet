//! Compute market shared between providers (executors) and consumers.
//!
//! A consumer spends trust units for one shell command executed on a
//! provider. Providers accept signed bids, serve the highest offers first
//! and never run more than `limits.max_tasks` tasks at once. Both sides
//! track the same trust coefficient: consuming lowers it, donating raises
//! it, and providers refuse consumers whose effective trust would fall
//! below the configured floor.

pub mod client;
pub mod executor;
pub mod policy;
pub mod provider;
pub mod queue;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::daemon::Ctx;

/// Exit status, captured output and billing basis of a finished task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskOutcome {
    /// Process exit code; negative values mark daemon-side failures.
    pub exit_code: i32,
    /// Captured standard output, truncated to 64 KiB.
    pub stdout: String,
    /// Captured standard error, truncated to 64 KiB.
    pub stderr: String,
    /// Actual wall-clock seconds the task consumed, clamped to the task
    /// limit; both sides price the task from this value so they always
    /// agree on the final charge.
    pub billed_secs: u64,
}

/// One accepted task handed from the scheduler to the executor.
pub struct Launch {
    /// Unique identifier of the task.
    pub task_id: String,
    /// Address the finished outcome must be reported to.
    pub return_addr: String,
    /// Reservation size tracked by the scheduler for in-flight accounting;
    /// the actual trust credit is derived from the billed seconds.
    pub units: i64,
    /// Shell command executed in a fresh working directory.
    pub command: String,
    /// Hard wall-clock limit for the execution, in seconds.
    pub timeout_secs: u64,
}

/// Events delivered to a waiting consumer session for one task.
#[derive(Debug)]
pub enum ComputeEvent {
    /// The provider accepted the bid.
    Accepted,
    /// The provider refused the bid with an explanation.
    Rejected(String),
    /// The task finished; carries the exit status, output and bill.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::make_ctx;
    use crate::trust::now_unix;

    /// Pump every inbound frame of a context through the dispatcher,
    /// mimicking the daemon's receive task.
    fn pump(ctx: &Arc<Ctx>) -> tokio::task::JoinHandle<()> {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            while let Some((src, data)) = ctx.transport.recv().await {
                crate::dispatch::handle_frame(&ctx, &src, &data).await;
            }
        })
    }

    /// Register both peers in each other's routing tables as verified
    /// peers with trust 100 and 20 capacity points, and align the
    /// provider's pricing with the announced value so both sides compute
    /// identical unit costs.
    async fn introduce(consumer: &Arc<Ctx>, provider: &Arc<Ctx>) {
        let provider_addr = provider.transport.local_id();
        let provider_id = provider.identity.node_id();
        consumer.dht.lock().await.insert(&provider_addr);
        consumer.dht.lock().await.apply_ann(
            &provider_addr,
            &provider_id,
            "peer",
            100,
            20,
            now_unix(),
        );
        let consumer_addr = consumer.transport.local_id();
        let consumer_id = consumer.identity.node_id();
        provider.dht.lock().await.insert(&consumer_addr);
        provider.dht.lock().await.apply_ann(
            &consumer_addr,
            &consumer_id,
            "peer",
            100,
            20,
            now_unix(),
        );
        provider.state.lock().await.points = 20;
    }

    /// Drive one whole market transaction across two real contexts: bid,
    /// acceptance, signed assignment, sandboxed execution and settlement,
    /// then check that exactly the billed units moved between the two
    /// trust coefficients.
    #[tokio::test]
    async fn full_market_flow_charges_and_credits_both_sides() {
        let (consumer, _rx) = make_ctx("flow-consumer").await;
        let (provider, provider_rx) = make_ctx("flow-provider").await;
        crate::compute::provider::run(provider.clone(), provider_rx);
        let pump_consumer = pump(&consumer);
        let pump_provider = pump(&provider);
        introduce(&consumer, &provider).await;

        let timeout = consumer.config.network.task_timeout_secs;
        let out = client::compute(
            &consumer,
            Some(&provider.identity.node_id()),
            "echo hello-e2e".to_string(),
            timeout,
        )
        .await;
        assert!(out.contains("exit_code: 0"), "unexpected result: {out}");
        assert!(out.contains("hello-e2e"), "stdout missing: {out}");

        // Points are 20 on both sides and the task bills one minute:
        // exactly 20 units move from the consumer (100 − 20) to the
        // provider (100 + 20).
        assert_eq!(consumer.state.lock().await.trust, 80);
        assert_eq!(consumer.state.lock().await.consumed, 20);
        assert_eq!(provider.state.lock().await.trust, 120);

        pump_consumer.abort();
        pump_provider.abort();
    }
}
