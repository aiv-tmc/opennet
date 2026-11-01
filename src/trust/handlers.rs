//! Receipt-journal handlers: the chain audit, the audit window
//! response builder and the four inbound receipt-related frames.
//!
//! The audit demands one signed window of a peer's receipt journal and
//! recomputes the chaining hash: a consumer announcing trust above the
//! genesis endowment must present a chain whose recomputed head
//! matches the announced one, or the bid is refused. Inbound receipts
//! are only stashed while a consumer request for the same task id is
//! waiting, which bounds the pending table to live requests.

use super::verify::{
    verify_receipt, verify_receipt_ack, verify_receipt_request, verify_receipt_response,
};
use crate::config::Config;
use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::node::state::{genesis_head, verify_window, ReceiptLog};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;

/// Cap on receipts per audit window: keeps the response comfortably
/// inside the 1 MiB frame cap.
pub const AUDIT_WINDOW_CAP: u32 = 1024;

/// Ten seconds to fetch one audit window; a slow peer fails the audit.
const AUDIT_TIMEOUT: Duration = Duration::from_secs(10);

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
/// from the requested anchor back over the transport.
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
            limit,
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

/// Audit one peer's receipt chain against its announced head. Returns
/// `Ok(true)` when the chain verifies (or was already audited for this
/// head), `Ok(false)` on a mismatch and `Err` when the peer cannot be
/// reached — callers treat `Err` as "audit unavailable, do not block
/// the market" and `Ok(false)` as "liar, refuse".
pub async fn audit_chain(ctx: &Arc<Ctx>, peer: &PeerInfo, expected_head: [u8; 32]) -> Result<bool> {
    {
        let cache = ctx.audited_heads.lock().await;
        if cache
            .get(&peer.node_id)
            .is_some_and(|head| *head == expected_head)
        {
            return Ok(true);
        }
    }
    let request_id: [u8; 32] = rand::random();
    let (tx, rx) = tokio::sync::oneshot::channel::<Message>();
    let key = hex::encode(request_id);
    ctx.receipt_windows.lock().await.insert(key.clone(), tx);
    let unix_ts = crate::trust::now_unix();
    let request = Message::ReceiptRequest {
        signature: ctx
            .identity
            .sign(&Message::receipt_request_signing_payload(
                &request_id,
                &genesis_head(),
                AUDIT_WINDOW_CAP,
                unix_ts,
            ))
            .to_vec(),
        request_id,
        head_before: genesis_head(),
        limit: AUDIT_WINDOW_CAP,
        unix_ts,
        pubkey: ctx.identity.pubkey(),
    };
    let outcome = async {
        send_msg(ctx, &peer.addr, &request).await?;
        tokio::time::timeout(AUDIT_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("audit timed out"))?
            .map_err(|_| anyhow::anyhow!("audit waiter dropped"))
    }
    .await;
    ctx.receipt_windows.lock().await.remove(&key);
    let Ok(response) = outcome else {
        return Err(anyhow::anyhow!("audit unavailable"));
    };
    let Message::ReceiptResponse {
        request_id: echoed,
        head_before,
        receipts,
        head_after,
        complete,
        unix_ts,
        pubkey,
        signature,
        ..
    } = response
    else {
        return Err(anyhow::anyhow!("not a receipt response"));
    };
    if echoed != request_id {
        return Err(anyhow::anyhow!("stale audit response"));
    }
    if verify_receipt_response(
        &echoed,
        &head_before,
        &receipts,
        &head_after,
        complete,
        unix_ts,
        &pubkey,
        &signature,
    ) != Some(peer.node_id.clone())
    {
        ctx.reputation.lock().await.record_invalid(&peer.addr);
        return Ok(false);
    }
    if head_before != genesis_head() {
        return Ok(false);
    }
    if !complete {
        // Chains longer than one window are not auditable in this
        // version: accept without caching.
        eprintln!(
            "[audit] {} chain longer than one window; skipping",
            peer.node_id
        );
        return Ok(true);
    }
    if head_after != expected_head {
        return Ok(false);
    }
    for receipt in &receipts {
        let Message::Receipt {
            task_id,
            provider_node,
            billed_secs,
            charge,
            outcome_hash,
            unix_ts,
            pubkey,
            signature,
            ..
        } = receipt
        else {
            return Ok(false);
        };
        if verify_receipt(
            task_id,
            provider_node,
            *billed_secs,
            *charge,
            outcome_hash,
            *unix_ts,
            pubkey,
            signature,
        )
        .is_none()
        {
            return Ok(false);
        }
    }
    if !verify_window(genesis_head(), &receipts, head_after) {
        return Ok(false);
    }
    ctx.audited_heads
        .lock()
        .await
        .insert(peer.node_id.clone(), expected_head);
    Ok(true)
}

pub fn bid_units(config: &Config, points: u32) -> i64 {
    crate::trust::points::units_for(points, config.network.task_timeout_secs)
}
