//! Receipt-journal handlers: the audit window response builder and
//! the four inbound receipt-related frames.
//!
//! The audit itself (the consumer-side walk of a peer's journal) lives
//! in `super::audit`; this module serves windows of the local journal
//! and receives receipts, acks and audit traffic. Inbound receipts are
//! only stashed while a consumer request for the same task id is
//! waiting, which bounds the pending table to live requests.

use super::audit::AUDIT_WINDOW_CAP;
use super::verify::{
    verify_receipt, verify_receipt_ack, verify_receipt_request, verify_receipt_response,
};
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::state::ReceiptLog;
use std::sync::Arc;

/// Re-exported verifiers so long-standing import sites keep working.
pub use super::verify::{verify_bid, verify_gossip, verify_swarm_join};

/// Build the signed window response for one verified audit request from
/// the local journal. Returns `None` when the requested anchor is not a
/// known chain position.
pub fn build_receipt_response(
    log: &ReceiptLog,
    identity: &crate::node::identity::Identity,
    request_id: [u8; 32],
    head_before: [u8; 32],
    limit: u32,
) -> Option<Message> {
    let (receipts, head_after, complete) = log.window(head_before, limit as usize)?;
    let unix_ts = crate::trust::now_unix();
    Some(Message::ReceiptResponse {
        signature: identity
            .sign(&Message::receipt_response_signing_payload(
                &request_id,
                &head_before,
                &receipts,
                &head_after,
                complete,
                unix_ts,
            ))
            .to_vec(),
        request_id,
        head_before,
        receipts,
        head_after,
        complete,
        unix_ts,
        pubkey: identity.pubkey(),
    })
}

/// Handle one inbound signed Receipt: verify the provider signature,
/// then stash the receipt only while a consumer request for the same
/// task id is waiting. Receipts for unknown tasks are dropped and
/// penalized, which bounds the pending table to live requests.
pub async fn handle_receipt_frame(ctx: &Arc<Ctx>, src: &str, receipt: Message) {
    let Message::Receipt {
        task_id,
        provider_node,
        billed_secs,
        charge,
        outcome_hash,
        unix_ts,
        pubkey,
        signature,
    } = receipt
    else {
        return;
    };
    let Some(signer) = verify_receipt(
        &task_id,
        &provider_node,
        billed_secs,
        charge,
        &outcome_hash,
        unix_ts,
        &pubkey,
        &signature,
    ) else {
        ctx.reputation.lock().await.record_invalid(src);
        return;
    };
    if signer != provider_node {
        ctx.reputation.lock().await.record_invalid(src);
        return;
    }
    if !ctx.result_waiters.lock().await.contains_key(&task_id) {
        ctx.reputation.lock().await.record_invalid(src);
        return;
    }
    ctx.pending_receipts.lock().await.insert(
        task_id.clone(),
        Message::Receipt {
            task_id,
            provider_node,
            billed_secs,
            charge,
            outcome_hash,
            unix_ts,
            pubkey,
            signature,
        },
    );
}

/// Handle one inbound signed ReceiptAck: verified acknowledgements are
/// appended to the provider's local ack journal; anything else is
/// penalized against the connection address.
pub async fn handle_receipt_ack_frame(ctx: &Arc<Ctx>, src: &str, ack: Message) {
    let Message::ReceiptAck {
        task_id,
        receipt_hash,
        unix_ts,
        pubkey,
        signature,
    } = ack
    else {
        return;
    };
    if verify_receipt_ack(&task_id, &receipt_hash, unix_ts, &pubkey, &signature).is_none() {
        ctx.reputation.lock().await.record_invalid(src);
        return;
    }
    if ctx
        .state
        .lock()
        .await
        .receipts
        .record_ack(Message::ReceiptAck {
            task_id,
            receipt_hash,
            unix_ts,
            pubkey,
            signature,
        })
        .is_err()
    {
        ctx.reputation.lock().await.record_invalid(src);
    }
}

/// Handle one inbound signed ReceiptRequest: serve one journal window
/// from the requested anchor back over the transport. The window size
/// is capped at `AUDIT_WINDOW_CAP` regardless of the requested limit,
/// so a peer cannot demand an oversized evidence frame.
pub async fn handle_receipt_request_frame(ctx: &Arc<Ctx>, src: &str, request: Message) {
    let Message::ReceiptRequest {
        request_id,
        head_before,
        limit,
        unix_ts,
        pubkey,
        signature,
    } = request
    else {
        return;
    };
    if verify_receipt_request(
        &request_id,
        &head_before,
        limit,
        unix_ts,
        &pubkey,
        &signature,
    )
    .is_none()
    {
        ctx.reputation.lock().await.record_invalid(src);
        return;
    }
    let response = {
        let state = ctx.state.lock().await;
        build_receipt_response(
            &state.receipts,
            &ctx.identity,
            request_id,
            head_before,
            limit.min(AUDIT_WINDOW_CAP),
        )
    };
    if let Some(response) = response {
        let _ = send_msg(ctx, src, &response).await;
    }
}

/// Handle one inbound signed ReceiptResponse: deliver it to the audit
/// waiting on the echoed request id, if any.
pub async fn handle_receipt_response_frame(ctx: &Arc<Ctx>, src: &str, response: Message) {
    let Message::ReceiptResponse {
        request_id,
        head_before,
        receipts,
        head_after,
        complete,
        unix_ts,
        pubkey,
        signature,
    } = response
    else {
        return;
    };
    if verify_receipt_response(
        &request_id,
        &head_before,
        &receipts,
        &head_after,
        complete,
        unix_ts,
        &pubkey,
        &signature,
    )
    .is_none()
    {
        ctx.reputation.lock().await.record_invalid(src);
        return;
    }
    if let Some(waiter) = ctx
        .receipt_windows
        .lock()
        .await
        .remove(&hex::encode(request_id))
    {
        let _ = waiter.send(Message::ReceiptResponse {
            request_id,
            head_before,
            receipts,
            head_after,
            complete,
            unix_ts,
            pubkey,
            signature,
        });
    }
}
