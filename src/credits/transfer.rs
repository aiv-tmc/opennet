//! Interactive signed credit transfer initiated from the control socket.

use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// How long a control session waits for the peer's acknowledgement.
const ACK_TIMEOUT: Duration = Duration::from_secs(15);

/// An outgoing transfer reserved on the local balance until its
/// acknowledgement settles it in `handle_credit_ack`.
pub struct PendingTransfer {
    /// Reserved amount in credits.
    pub amount: u64,
    /// Node id of the peer the transfer is addressed to.
    pub counterparty: String,
}

/// Return reserved credits to the local balance after a failed transfer.
pub async fn refund(ctx: &Arc<Ctx>, amount: u64) {
    if amount == 0 {
        return;
    }
    let mut state = ctx.state.lock().await;
    state.credits += amount;
    let _ = state.save();
}

/// Transfer `amount` credits to a peer identified by a node id prefix and
/// report the settlement outcome as control-socket text.
pub async fn send_transfer(ctx: &Arc<Ctx>, prefix: &str, amount_text: &str) -> String {
    let amount: u64 = match amount_text.parse() {
        Ok(amount) if amount > 0 => amount,
        _ => return format!("error: invalid amount '{amount_text}'\n"),
    };
    let peer = match ctx.dht.lock().await.find_by_node_id(prefix) {
        Some(peer) => peer,
        None => return format!("error: no known peer with node id starting '{prefix}'\n"),
    };
    if peer.node_id.is_empty() {
        return format!(
            "error: peer {} has not announced its identity yet\n",
            peer.addr
        );
    }
    {
        let mut state = ctx.state.lock().await;
        if state.credits < amount {
            return format!(
                "error: insufficient credits (have {}, need {})\n",
                state.credits, amount
            );
        }
        state.credits -= amount;
        if let Err(err) = state.save() {
            return format!("error: cannot persist balance: {err:#}\n");
        }
    }

    let task_id = format!("{:016x}", rand::random::<u64>());
    let from_node = ctx.identity.node_id();
    let payload = Message::credit_signing_payload(&task_id, &from_node, &peer.node_id, amount);
    let credit = Message::Credit {
        task_id: task_id.clone(),
        from_node,
        to_node: peer.node_id.clone(),
        amount,
        pubkey: ctx.identity.pubkey(),
        signature: ctx.identity.sign(&payload).to_vec(),
    };
    ctx.pending.lock().await.insert(
        task_id.clone(),
        PendingTransfer {
            amount,
            counterparty: peer.node_id.clone(),
        },
    );
    let (tx, rx) = oneshot::channel::<bool>();
    ctx.ack_waiters.lock().await.insert(task_id.clone(), tx);
    if let Err(err) = send_msg(ctx, &peer.addr, &credit).await {
        // The peer is unreachable: refund immediately and forget the transfer.
        ctx.pending.lock().await.remove(&task_id);
        ctx.ack_waiters.lock().await.remove(&task_id);
        refund(ctx, amount).await;
        return format!("error: transfer not sent, {amount} credits restored: {err:#}\n");
    }
    match tokio::time::timeout(ACK_TIMEOUT, rx).await {
        Ok(Ok(true)) => format!("delivered {amount} credits to {}\n", peer.node_id),
        Ok(Ok(false)) => "transfer rejected by peer, credits restored\n".to_string(),
        _ => format!(
            "sent {amount} credits to {} (ack pending, transfer {task_id})\n",
            peer.node_id
        ),
    }
}
