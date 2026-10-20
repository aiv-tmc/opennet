//! Daemon-side handlers for signed announcements and credit settlement.

use crate::credits::ledger::{now_unix, TransferKind, TransferRecord};
use crate::credits::transfer::refund;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::identity::Identity;
use std::sync::Arc;

/// Convert a wire signature to the fixed-size array verification expects.
///
/// Returns `None` for malformed lengths, which callers treat as an invalid
/// signature.
fn sig_array(signature: &[u8]) -> Option<&[u8; 64]> {
    signature.try_into().ok()
}

/// Verify a signed announcement and either update the routing table or
/// penalize the sender for a bad signature.
pub async fn handle_ann(
    ctx: &Arc<Ctx>,
    src: &str,
    node_id: &str,
    mode: &str,
    credits: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) {
    let payload = Message::ann_signing_payload(node_id, mode, credits);
    let id_matches = node_id == Identity::node_id_from_pubkey(pubkey);
    let valid = match sig_array(signature) {
        Some(sig) => id_matches && Identity::verify(pubkey, &payload, sig),
        None => false,
    };
    if valid {
        ctx.reputation.lock().await.record_valid(node_id);
        ctx.dht.lock().await.apply_ann(src, node_id, mode, credits);
    } else {
        let key = if id_matches { node_id } else { src };
        ctx.reputation.lock().await.record_invalid(key);
        eprintln!("[opennetd] invalid announcement from {src}");
    }
}

/// Verify a signed credit transfer, apply it to the local balance and reply
/// with an acknowledgement so the payer can settle or refund the transfer.
pub async fn handle_credit(
    ctx: &Arc<Ctx>,
    src: &str,
    task_id: &str,
    from_node: &str,
    to_node: &str,
    amount: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) {
    let payload = Message::credit_signing_payload(task_id, from_node, to_node, amount);
    let valid = amount > 0
        && to_node == ctx.identity.node_id()
        && from_node == Identity::node_id_from_pubkey(pubkey)
        && sig_array(signature).is_some_and(|sig| Identity::verify(pubkey, &payload, sig));
    if !valid {
        ctx.reputation.lock().await.record_invalid(from_node);
        let _ = send_msg(ctx, src, &Message::CreditAck {
            task_id: task_id.to_string(),
            accepted: false,
        })
        .await;
        eprintln!("[opennetd] rejected invalid credit from {src}");
        return;
    }

    {
        let mut state = ctx.state.lock().await;
        state.credits += amount;
        if let Err(err) = state.save() {
            eprintln!("[opennetd] cannot persist balance after credit: {err:#}");
        }
    }
    ctx.reputation.lock().await.record_credit_in(from_node, amount);
    if let Err(err) = ctx.ledger.lock().await.append(TransferRecord {
        task_id: task_id.to_string(),
        counterparty: from_node.to_string(),
        amount,
        kind: TransferKind::Incoming,
        unix_ts: now_unix(),
    }) {
        eprintln!("[opennetd] cannot write ledger after credit: {err:#}");
    }
    println!("[opennetd] received {amount} credits from {from_node}");
    let _ = send_msg(ctx, src, &Message::CreditAck {
        task_id: task_id.to_string(),
        accepted: true,
    })
    .await;
}

/// Settle an outgoing transfer whose acknowledgement just arrived.
///
/// Accepted transfers are logged as outgoing and credited to the peer's
/// trade reputation; rejected ones are refunded and logged as refunds.
/// A control session or compute client waiting on the result is notified
/// through the waiter channel before any refund happens.
pub async fn handle_credit_ack(ctx: &Arc<Ctx>, task_id: &str, accepted: bool) {
    if let Some(sender) = ctx.ack_waiters.lock().await.remove(task_id) {
        let _ = sender.send(accepted);
    }
    if accepted {
        let pending = ctx.pending.lock().await.remove(task_id);
        if let Some(pending) = pending {
            ctx.reputation
                .lock()
                .await
                .record_credit_out(&pending.counterparty, pending.amount);
            if let Err(err) = ctx.ledger.lock().await.append(TransferRecord {
                task_id: task_id.to_string(),
                counterparty: pending.counterparty,
                amount: pending.amount,
                kind: TransferKind::Outgoing,
                unix_ts: now_unix(),
            }) {
                eprintln!("[opennetd] cannot log outgoing transfer: {err:#}");
            }
        }
        return;
    }
    let Some(pending) = ctx.pending.lock().await.remove(task_id) else {
        return;
    };
    refund(ctx, pending.amount).await;
    if let Err(err) = ctx.ledger.lock().await.append(TransferRecord {
        task_id: task_id.to_string(),
        counterparty: pending.counterparty,
        amount: pending.amount,
        kind: TransferKind::Refund,
        unix_ts: now_unix(),
    }) {
        eprintln!("[opennetd] cannot log refund: {err:#}");
    }
    eprintln!(
        "[opennetd] transfer {task_id} rejected, {} credits refunded",
        pending.amount
    );
}
