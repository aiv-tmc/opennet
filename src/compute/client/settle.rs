//! Settlement of one finished task against the provider's billing
//! receipt: verify the receipt, journal it, countersign the ack and
//! settle the reservation, with the identical locally computed charge
//! as the fallback when no usable receipt arrives.

use super::TaskOutcome;
use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::node::state::receipt_hash;
use crate::trust::{now_unix, points::units_for};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Extra seconds of billing slack beyond the measured elapsed time
/// before a provider's reported duration is cut; LAN clocks may skew
/// by a few seconds, so the cap must not bite honest providers.
const BILLING_SLACK_SECS: u64 = 5;

/// How long to wait for the provider's receipt to show up in the
/// dispatch stash. The receipt travels one frame ahead of the result
/// on the same ordered connection, so it is normally stashed before
/// the result completes the waiter; the poll is a scheduling safety net,
/// not a sync point.
const RECEIPT_PULL_ATTEMPTS: usize = 20;
const RECEIPT_PULL_DELAY: Duration = Duration::from_millis(50);

/// Settle one finished task against its receipt. When the provider's
/// receipt verifies — signature, provider identity, and the outcome
/// hash matching the delivered output — the receipt enters the local
/// journal and the consumer countersigns it back; the charge is the
/// provider's claim capped by the reservation. Without a usable receipt
/// the locally computed charge (identical formula) settles the
/// reservation.
#[allow(clippy::too_many_arguments)]
pub(super) async fn settle_with_receipt(
    ctx: &Arc<Ctx>,
    task_id: &str,
    peer: &PeerInfo,
    outcome: &TaskOutcome,
    started: Instant,
    timeout_secs: u64,
    points: u32,
    factor: i64,
    max_units: i64,
) -> i64 {
    let receipt = pull_receipt(ctx, task_id).await;
    let fallback_billed = outcome
        .billed_secs
        .min(started.elapsed().as_secs() + BILLING_SLACK_SECS)
        .min(timeout_secs);
    let fallback = units_for(points, fallback_billed) * factor;
    let Some(receipt) = receipt else {
        settle(ctx, task_id, fallback).await;
        return fallback;
    };
    let Message::Receipt {
        task_id: receipt_task,
        provider_node,
        billed_secs,
        charge: claimed,
        outcome_hash,
        unix_ts,
        pubkey,
        signature,
    } = receipt
    else {
        settle(ctx, task_id, fallback).await;
        return fallback;
    };
    let valid = receipt_task == task_id
        && provider_node == peer.node_id
        && outcome_hash == outcome.hash()
        && crate::trust::verify::verify_receipt(
            &receipt_task,
            &provider_node,
            billed_secs,
            claimed,
            &outcome_hash,
            unix_ts,
            &pubkey,
            &signature,
        )
        .is_some();
    if !valid {
        settle(ctx, task_id, fallback).await;
        return fallback;
    }
    // The claim settles inside two bounds: never below zero (a negative
    // charge would mint trust for the consumer), never above the local
    // formula for the claimed duration at the announced price the
    // consumer reserved against. A provider whose price moved since the
    // announcement is paid the announced price — the one the consumer
    // agreed to — and a discount claim is honored as claimed.
    let claimed_billed = billed_secs
        .min(started.elapsed().as_secs() + BILLING_SLACK_SECS)
        .min(timeout_secs);
    let honest = units_for(points, claimed_billed) * factor;
    let bounded = honest.min(max_units);
    // The receipt is evidence: enter it into the local journal, then
    // countersign and return the ack. Either side can later present
    // the pair to prove the exact charge and output.
    let receipt_record = Message::Receipt {
        task_id: receipt_task.clone(),
        provider_node: provider_node.clone(),
        billed_secs,
        charge: claimed,
        outcome_hash,
        unix_ts,
        pubkey,
        signature,
    };
    {
        // The consumer journals the receipt bound to itself, so only
        // this node's own countersignature can ever settle it.
        let self_id = ctx.identity.node_id();
        let mut state = ctx.state.lock().await;
        if state
            .receipts
            .append(receipt_record.clone(), &self_id)
            .is_err()
        {
            // A duplicate receipt (retried result) settles without
            // re-entering the journal, at the same bounded charge.
            let charge = claimed.clamp(0, bounded);
            state.settle(task_id, charge);
            ctx.counters
                .receipts_settled
                .fetch_add(1, Ordering::Relaxed);
            return charge;
        }
    }
    let hash = receipt_hash(&receipt_record);
    let ack_ts = now_unix();
    let ack = Message::ReceiptAck {
        task_id: task_id.to_string(),
        receipt_hash: hash,
        unix_ts: ack_ts,
        pubkey: ctx.identity.pubkey(),
        signature: ctx
            .identity
            .sign(&Message::receipt_ack_signing_payload(
                task_id, &hash, ack_ts,
            ))
            .to_vec(),
    };
    {
        let mut state = ctx.state.lock().await;
        let _ = state.receipts.record_ack(ack.clone());
    }
    let _ = send_msg(ctx, &peer.addr, &ack).await;
    let charge = claimed.clamp(0, bounded);
    settle(ctx, task_id, charge).await;
    charge
}

/// Pull the provider's receipt out of the dispatch stash, polling
/// briefly: the receipt normally precedes the result on the wire, but
/// the waiter wakes the client task before the dispatcher necessarily
/// finished stashing, so a short poll closes the race without a sync
/// point. Returns `None` when no receipt appears.
async fn pull_receipt(ctx: &Arc<Ctx>, task_id: &str) -> Option<Message> {
    for _ in 0..RECEIPT_PULL_ATTEMPTS {
        if let Some(receipt) = ctx.pending_receipts.lock().await.remove(task_id) {
            return Some(receipt);
        }
        tokio::time::sleep(RECEIPT_PULL_DELAY).await;
    }
    None
}

/// Settle the reservation with one charge and count the settlement
/// towards the node's billing metrics.
async fn settle(ctx: &Arc<Ctx>, task_id: &str, charge: i64) {
    ctx.state.lock().await.settle(task_id, charge);
    ctx.counters
        .receipts_settled
        .fetch_add(1, Ordering::Relaxed);
}

/// The settlement line shown above the task output.
pub(super) async fn settled_header(ctx: &Arc<Ctx>, charge: i64) -> String {
    let trust = ctx.state.lock().await.trust;
    format!("consumed {charge} units (trust now {trust})\n")
}
