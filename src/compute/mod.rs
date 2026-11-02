//! Compute market: the consumer side (`client`), the provider side
//! (`provider` with its `scheduler`, `drain` and `queue`), the
//! sandboxed `executor` and the shared wire types.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

pub mod client;
pub mod executor;
pub mod policy;
pub mod provider;
pub mod queue;

/// Result of one executed task. The provider signs the TaskResult
/// frame over this outcome's hash, so the delivered exit code and both
/// captured output streams are bound to the provider's identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskOutcome {
    pub exit_code: i32,
    /// Captured standard output, truncated to the executor's cap.
    pub stdout: String,
    /// Captured standard error, truncated to the executor's cap.
    pub stderr: String,
    /// Billed seconds reported by the provider; the consumer clamps
    /// this by the observed wall time plus slack before settling.
    pub billed_secs: u64,
}

impl TaskOutcome {
    /// Commitment to the delivered output: every byte of stdout and
    /// stderr plus the exit code. Two providers returning the same
    /// output produce the same hash, which is what the consumer's
    /// redundant-execution verification compares; the billing receipt
    /// and the TaskResult signature both bind to this same hash.
    pub fn hash(&self) -> [u8; 32] {
        let mut material = Vec::with_capacity(self.stdout.len() + self.stderr.len() + 4);
        material.extend_from_slice(&self.exit_code.to_le_bytes());
        material.extend_from_slice(self.stdout.as_bytes());
        material.extend_from_slice(self.stderr.as_bytes());
        *blake3::hash(&material).as_bytes()
    }
}

/// One unit of work handed from the scheduler to the executor. The
/// resource binding is local state — it never crosses the wire: the
/// wire request lives in `Message::TaskAssign`, and the scheduler turns
/// it into this concrete binding (memory cap request and pinned GPU
/// device indices) after checking capacity.
#[derive(Clone, Debug)]
pub struct Launch {
    pub task_id: String,
    pub return_addr: String,
    /// Node id of the consumer, for receipt pricing and the receipt
    /// journal.
    pub from_node: String,
    pub command: String,
    pub timeout_secs: u64,
    /// Requested memory cap in MiB; 0 = the provider's default offer.
    pub ram_mb: u64,
    /// GPU device indices pinned for this task; empty = no GPU.
    pub gpus: Vec<u32>,
    /// Trust units reserved for this task.
    pub units: i64,
    /// Billing reference point: the moment the scheduler handed the
    /// task to the executor. The consumer measures its own wall clock
    /// from the accept moment, so both sides of the receipt observe
    /// (and clamp to) the same window.
    pub started: Instant,
}

/// Events the consumer's compute request waits for.
pub enum ComputeEvent {
    Accepted,
    Rejected(String),
    Outcome(TaskOutcome),
}

/// Complete one consumer waiter when the signed frame's signer is the
/// provider node id the request was booked with. The waiter stays
/// registered when the signer does not match, so an injected frame can
/// never satisfy an in-flight request and the request lives until its
/// own timeout.
pub async fn complete_waiter(
    ctx: &Arc<crate::daemon::Ctx>,
    signer: &str,
    task_id: &str,
    event: ComputeEvent,
) {
    let mut waiters = ctx.result_waiters.lock().await;
    let matches = waiters
        .get(task_id)
        .is_some_and(|(expected, _)| expected == signer);
    if matches {
        let (_, sender) = waiters.remove(task_id).expect("waiter checked above");
        let _ = sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use crate::testutil::make_ctx;

    /// Pump every inbound frame of one context into its dispatcher,
    /// like the daemon's frame loop does in production.
    fn pump(ctx: &Arc<crate::daemon::Ctx>) {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                let Some((src, data)) = ctx.transport.recv().await else {
                    break;
                };
                crate::dispatch::handle_frame(&ctx, &src, &data).await;
            }
        });
    }

    #[tokio::test]
    async fn outcome_roundtrips_through_the_wire() {
        let outcome = TaskOutcome {
            exit_code: 3,
            stdout: "hello".into(),
            stderr: "oops".into(),
            billed_secs: 7,
        };
        let message = Message::TaskResult {
            task_id: "t".into(),
            outcome: outcome.clone(),
            unix_ts: 1_700_000_000,
            pubkey: [1; 32],
            signature: vec![2; 64],
        };
        let Some(Message::TaskResult {
            outcome: decoded, ..
        }) = Message::decode(&message.encode())
        else {
            panic!("roundtrip failed");
        };
        assert_eq!(decoded.exit_code, 3);
        assert_eq!(decoded.stdout, "hello");
        assert_eq!(decoded.billed_secs, 7);
    }

    #[test]
    fn outcome_hash_commits_to_every_output_field() {
        let base = TaskOutcome {
            exit_code: 0,
            stdout: "hello".into(),
            stderr: String::new(),
            billed_secs: 5,
        };
        let mut changed = base.clone();
        changed.exit_code = 1;
        assert_ne!(base.hash(), changed.hash());
        changed = base.clone();
        changed.stdout = "hellO".into();
        assert_ne!(base.hash(), changed.hash());
        changed = base.clone();
        changed.stderr = "x".into();
        assert_ne!(base.hash(), changed.hash());
        // Billed seconds are billing metadata, not output: they do not
        // change the output commitment.
        changed = base.clone();
        changed.billed_secs = 99;
        assert_eq!(base.hash(), changed.hash());
    }

    #[tokio::test]
    async fn full_market_flow_bid_assign_outcome() {
        let (consumer, _rx) = make_ctx("mkt-flow").await;
        let (provider_ctx, provider_rx) = make_ctx("mkt-provider").await;
        // Both sides pump inbound frames into their dispatchers: the
        // consumer must see Receipt/TaskAccept/TaskResult through its
        // own frame loop, the provider must see the bid, the assignment
        // and the receipt ack.
        pump(&consumer);
        pump(&provider_ctx);
        // The consumer learns the provider's address and announced
        // points; the provider learns the consumer, because its bid
        // policy checks the bidder against the routing table. Both are
        // announced with a non-genesis receipt head so both price as
        // known participants.
        let provider_addr = provider_ctx.transport.local_id();
        consumer.dht.lock().await.insert(&provider_addr);
        consumer.dht.lock().await.apply_ann_ext(
            &provider_addr,
            &provider_ctx.identity.node_id(),
            "peer",
            100,
            44,
            0,
            [7; 32],
            1,
        );
        let consumer_addr = consumer.transport.advertise_id();
        provider_ctx.dht.lock().await.insert(&consumer_addr);
        provider_ctx.dht.lock().await.apply_ann_ext(
            &consumer_addr,
            &consumer.identity.node_id(),
            "peer",
            100,
            44,
            0,
            [7; 32],
            1,
        );
        crate::compute::provider::run(provider_ctx.clone(), provider_rx);
        let out = client::compute(&consumer, None, "echo hello".to_string(), 60, 0, 0, 1).await;
        assert!(
            out.contains("exit_code: 0"),
            "market flow must execute the command: {out}"
        );
        // The settlement produced a countersigned billing receipt on
        // both sides: the consumer accepted the provider's receipt into
        // its journal, and the provider recorded the issued receipt and
        // the consumer's ack.
        assert_eq!(consumer.state.lock().await.receipts.count(), 1);
        assert_eq!(provider_ctx.state.lock().await.receipts.count(), 1);
    }
}
