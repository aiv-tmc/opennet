//! Consumer side of the compute market: bid, assign, collect the outcome and
//! pay the provider.

use crate::compute::{ComputeEvent, TaskOutcome};
use crate::credits::ledger::now_unix;
use crate::credits::transfer::{refund, PendingTransfer};
use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::node::state::Mode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// How long to wait for the bid decision and for the payment acknowledgement.
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// Run `command` on a peer for `offer` credits and return the result as
/// control-socket text. `prefix` selects a peer by node id; `None` lets the
/// client pick the most suitable known peer automatically.
pub async fn compute(
    ctx: &Arc<Ctx>,
    prefix: Option<&str>,
    offer: u64,
    command: String,
    timeout_secs: u64,
) -> String {
    if ctx.state.lock().await.mode == Mode::Seed {
        return "error: seed mode donates capacity only and cannot request tasks\n".to_string();
    }
    let peer = match prefix {
        Some(prefix) => ctx.dht.lock().await.find_by_node_id(prefix),
        None => auto_pick(ctx).await,
    };
    let Some(peer) = peer else {
        return "error: no suitable peer known\n".to_string();
    };
    if peer.node_id.is_empty() {
        return format!(
            "error: peer {} has not announced its identity yet\n",
            peer.addr
        );
    }
    if offer > 0 && !reserve(ctx, offer).await {
        let balance = ctx.state.lock().await.credits;
        return format!("error: insufficient credits (have {balance}, need {offer})\n");
    }

    let task_id = format!("{:016x}", rand::random::<u64>());
    let (events_tx, mut events_rx) = oneshot::channel::<ComputeEvent>();
    ctx.result_waiters.lock().await.insert(task_id.clone(), events_tx);

    let bid = Message::TaskBid {
        task_id: task_id.clone(),
        offer,
        expires_unix: now_unix() + timeout_secs as u64 + 120,
    };
    if let Err(err) = send_msg(ctx, &peer.addr, &bid).await {
        ctx.result_waiters.lock().await.remove(&task_id);
        refund(ctx, offer).await;
        return format!("error: cannot reach peer: {err:#}\n");
    }

    // Wait for the bid decision before assigning real work.
    match tokio::time::timeout(REPLY_TIMEOUT, &mut events_rx).await {
        Ok(Ok(ComputeEvent::Accepted)) => {}
        Ok(Ok(ComputeEvent::Rejected(reason))) => {
            ctx.result_waiters.lock().await.remove(&task_id);
            refund(ctx, offer).await;
            return format!("error: bid rejected: {reason}\n");
        }
        _ => {
            ctx.result_waiters.lock().await.remove(&task_id);
            refund(ctx, offer).await;
            return "error: peer did not answer the bid, credits restored\n".to_string();
        }
    }

    if let Err(err) = send_msg(
        ctx,
        &peer.addr,
        &Message::TaskAssign {
            task_id: task_id.clone(),
            command,
            timeout_secs,
        },
    )
    .await
    {
        ctx.result_waiters.lock().await.remove(&task_id);
        refund(ctx, offer).await;
        return format!("error: cannot assign task: {err:#}\n");
    }

    let grace = Duration::from_secs(timeout_secs as u64 + 60);
    let outcome = match tokio::time::timeout(grace, events_rx).await {
        Ok(Ok(ComputeEvent::Outcome(outcome))) => outcome,
        _ => {
            refund(ctx, offer).await;
            return "error: task did not finish in time, credits restored\n".to_string();
        }
    };
    ctx.result_waiters.lock().await.remove(&task_id);

    let mut header = String::new();
    if offer > 0 {
        match pay(ctx, &peer, &task_id, offer).await {
            Ok(()) => header = format!("paid {offer} credits to {}\n", peer.node_id),
            Err(text) => return text,
        }
    }
    render(&header, &outcome)
}

/// Deduct the offer from the local balance; returns false when funds are short.
async fn reserve(ctx: &Arc<Ctx>, amount: u64) -> bool {
    let mut state = ctx.state.lock().await;
    if state.credits < amount {
        return false;
    }
    state.credits -= amount;
    state.save().is_ok()
}

/// Choose the peer most likely to serve well: seeds first, then the
/// highest-credit peers, freshest as the tiebreaker.
async fn auto_pick(ctx: &Arc<Ctx>) -> Option<PeerInfo> {
    let mut candidates: Vec<PeerInfo> = ctx
        .dht
        .lock()
        .await
        .all_peers()
        .into_iter()
        .filter(|peer| !peer.node_id.is_empty() && peer.mode != "leech")
        .collect();
    candidates.sort_by(|a, b| {
        let seed_a = (a.mode == "seed") as u8;
        let seed_b = (b.mode == "seed") as u8;
        seed_b
            .cmp(&seed_a)
            .then_with(|| b.credits.cmp(&a.credits))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
    });
    candidates.into_iter().next()
}

/// Send the signed payment for a finished task and wait for the provider's
/// acknowledgement; settlement and refund bookkeeping run centrally in
/// `handle_credit_ack`.
async fn pay(ctx: &Arc<Ctx>, peer: &PeerInfo, task_id: &str, amount: u64) -> Result<(), String> {
    let from_node = ctx.identity.node_id();
    let payload = Message::credit_signing_payload(task_id, &from_node, &peer.node_id, amount);
    let credit = Message::Credit {
        task_id: task_id.to_string(),
        from_node,
        to_node: peer.node_id.clone(),
        amount,
        pubkey: ctx.identity.pubkey(),
        signature: ctx.identity.sign(&payload).to_vec(),
    };
    ctx.pending.lock().await.insert(
        task_id.to_string(),
        PendingTransfer {
            amount,
            counterparty: peer.node_id.clone(),
        },
    );
    let (tx, rx) = oneshot::channel::<bool>();
    ctx.ack_waiters.lock().await.insert(task_id.to_string(), tx);
    if let Err(err) = send_msg(ctx, &peer.addr, &credit).await {
        ctx.pending.lock().await.remove(task_id);
        ctx.ack_waiters.lock().await.remove(task_id);
        refund(ctx, amount).await;
        return Err(format!(
            "task finished but payment undeliverable, {amount} credits restored: {err:#}\n"
        ));
    }
    match tokio::time::timeout(REPLY_TIMEOUT, rx).await {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err("error: provider rejected the payment, credits restored\n".into()),
        // Ack lost in transit: the provider applied the credit, so the
        // transfer stays reserved as pending instead of being refunded.
        _ => Ok(()),
    }
}

/// Format the finished task for the control socket, keeping the payment
/// header that `pay` produced.
fn render(header: &str, outcome: &TaskOutcome) -> String {
    format!(
        "{header}exit_code: {code}\nstdout:\n{stdout}\nstderr:\n{stderr}\n",
        code = outcome.exit_code,
        stdout = outcome.stdout,
        stderr = outcome.stderr,
    )
}
