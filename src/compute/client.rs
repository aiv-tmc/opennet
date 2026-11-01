//! Consumer side of the compute market: reserve trust units, bid with a
//! signed trust snapshot, assign the signed command, verify the
//! delivered output against the provider's signed billing receipt,
//! countersign it into both receipt journals, settle the reservation
//! and return the rendered result.
//!
//! Billing honesty bound: the reported billed seconds are capped by the
//! wall time actually observed between the accept and the outcome plus a
//! small slack, so a provider cannot charge for more seconds than the
//! task could possibly have run; the charge is additionally capped by
//! the reservation. With `--verify N` the identical task runs on N
//! distinct peers concurrently and the majority outcome hash wins —
//! the standard defense against a provider returning fabricated output.
//!
//! All trust accounting happens under the single state lock through
//! `NodeState::reserve` / `release` / `settle`. Settlement against the
//! provider's receipt lives in `settle.rs`; redundant-execution
//! verification lives in `verify.rs`.

use crate::compute::policy::{announced_points, stranger_factor};
use crate::compute::ComputeEvent;
use crate::compute::TaskOutcome;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::state::genesis_head;
use crate::node::state::Mode;
use crate::trust::{now_unix, points::units_for};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

mod settle;
#[cfg(test)]
mod tests;
mod verify;

/// How long to wait for the signed bid decision before giving up.
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// Run `command` on a peer and charge trust units for it. `prefix`
/// selects a peer by node id; `None` lets the client pick the most
/// suitable known peer automatically. `ram_mb` and `gpus` request
/// explicit resources (0 = the provider's defaults) and travel inside
/// the signed assignment. `verify` above 1 runs the identical task on
/// that many distinct peers and keeps the majority outcome.
pub async fn compute(
    ctx: &Arc<Ctx>,
    prefix: Option<&str>,
    command: String,
    timeout_secs: u64,
    ram_mb: u64,
    gpus: u32,
    verify: u32,
) -> String {
    if verify <= 1 {
        return match compute_once(ctx, prefix, command, timeout_secs, ram_mb, gpus).await {
            Ok((outcome, charge)) => settle::settled_header(ctx, charge).await + &render(&outcome),
            Err(err) => format!("error: {err}\n"),
        };
    }
    verify::run_verified(ctx, command, timeout_secs, ram_mb, gpus, verify).await
}

/// One market round against one peer. Returns the outcome and the
/// settled charge; the error string is rendered for the control socket.
async fn compute_once(
    ctx: &Arc<Ctx>,
    prefix: Option<&str>,
    command: String,
    timeout_secs: u64,
    ram_mb: u64,
    gpus: u32,
) -> Result<(TaskOutcome, i64), String> {
    if ctx.state.lock().await.mode == Mode::Seed {
        return Err("seed mode donates capacity only and cannot request tasks".to_string());
    }
    let peer = match prefix {
        Some(prefix) => ctx.dht.lock().await.find_by_node_id(prefix),
        None => verify::auto_pick(ctx).await,
    };
    let Some(peer) = peer else {
        return Err("no suitable peer known".to_string());
    };
    if gpus > peer.gpus {
        return Err(format!(
            "peer {} offers {} GPU(s), {} requested",
            peer.node_id, peer.gpus, gpus
        ));
    }
    // Both sides price the reservation from the provider's announced
    // points; the surcharge follows the consumer's receipt history, so
    // both sides read the same announced head.
    let points = {
        let dht = ctx.dht.lock().await;
        announced_points(&dht, &peer.node_id)
    };
    let Some(points) = points else {
        return Err(format!(
            "peer {} has not announced its capacity points yet",
            peer.addr
        ));
    };
    let factor = stranger_factor(&ctx.config, peer.receipt_head != genesis_head());
    let max_units = units_for(points, timeout_secs) * factor;
    // 128-bit random identifier: unguessable on the wire, unique across
    // retries, and the sole key of the reservation, the waiter and the
    // receipt journal entry.
    let task_id = format!("{:032x}", rand::random::<u128>());
    {
        let mut state = ctx.state.lock().await;
        state
            .reserve(&task_id, max_units, ctx.config.trust.min_trust)
            .map_err(|err| err.to_string())?;
    }
    let (events_tx, mut events_rx) = oneshot::channel::<ComputeEvent>();
    // The waiter binds the request to the provider's node id: the
    // signed accept, reject and result frames only complete it when
    // their signature verifies against that exact node (see dispatch).
    ctx.result_waiters
        .lock()
        .await
        .insert(task_id.clone(), (peer.node_id.clone(), events_tx));
    // Sign the post-reservation trust snapshot so the provider can verify
    // the claim against the last announced value.
    let bid = {
        let state = ctx.state.lock().await;
        let expires_unix = now_unix() + timeout_secs + 120;
        let payload =
            Message::bid_signing_payload(&task_id, state.trust, state.consumed, expires_unix);
        Message::TaskBid {
            task_id: task_id.clone(),
            trust: state.trust,
            consumed: state.consumed,
            expires_unix,
            pubkey: ctx.identity.pubkey(),
            signature: ctx.identity.sign(&payload).to_vec(),
        }
    };
    if let Err(err) = send_msg(ctx, &peer.addr, &bid).await {
        ctx.result_waiters.lock().await.remove(&task_id);
        ctx.pending_receipts.lock().await.remove(&task_id);
        ctx.state.lock().await.release(&task_id);
        return Err(format!("cannot reach peer: {err:#}"));
    }
    // Wait for the signed bid decision before assigning real work.
    match tokio::time::timeout(REPLY_TIMEOUT, &mut events_rx).await {
        Ok(Ok(ComputeEvent::Accepted)) => {}
        Ok(Ok(ComputeEvent::Rejected(reason))) => {
            ctx.result_waiters.lock().await.remove(&task_id);
            ctx.pending_receipts.lock().await.remove(&task_id);
            ctx.state.lock().await.release(&task_id);
            return Err(format!("bid rejected: {reason}"));
        }
        _ => {
            ctx.result_waiters.lock().await.remove(&task_id);
            ctx.pending_receipts.lock().await.remove(&task_id);
            ctx.state.lock().await.release(&task_id);
            return Err("peer did not answer the bid, reservation released".to_string());
        }
    }
    // The bid reply consumed the first one-shot waiter; arm a fresh one
    // for the outcome phase before handing the work to the provider.
    let (outcome_tx, outcome_rx) = oneshot::channel::<ComputeEvent>();
    ctx.result_waiters
        .lock()
        .await
        .insert(task_id.clone(), (peer.node_id.clone(), outcome_tx));
    // Billing reference point: the accept moment.
    let started = Instant::now();
    // The assignment is signed by the same key that made the bid; the
    // RAM/GPU request is part of the signed bytes.
    let assign = {
        let payload =
            Message::assign_signing_payload(&task_id, &command, timeout_secs, ram_mb, gpus);
        Message::TaskAssign {
            task_id: task_id.clone(),
            command,
            timeout_secs,
            ram_mb,
            gpus,
            pubkey: ctx.identity.pubkey(),
            signature: ctx.identity.sign(&payload).to_vec(),
        }
    };
    if let Err(err) = send_msg(ctx, &peer.addr, &assign).await {
        ctx.result_waiters.lock().await.remove(&task_id);
        ctx.pending_receipts.lock().await.remove(&task_id);
        ctx.state.lock().await.release(&task_id);
        return Err(format!("cannot assign task: {err:#}"));
    }
    let grace = Duration::from_secs(timeout_secs + 60);
    let outcome = match tokio::time::timeout(grace, outcome_rx).await {
        Ok(Ok(ComputeEvent::Outcome(outcome))) => outcome,
        _ => {
            ctx.result_waiters.lock().await.remove(&task_id);
            ctx.pending_receipts.lock().await.remove(&task_id);
            ctx.state.lock().await.release(&task_id);
            return Err("task did not finish in time, reservation released".to_string());
        }
    };
    // The provider's receipt travels one frame ahead of its result; a
    // missing or invalid receipt falls back to the locally computed
    // charge (both formulas agree for honest providers, so the ledgers
    // stay in lockstep either way).
    let charge = settle::settle_with_receipt(
        ctx,
        &task_id,
        &peer,
        &outcome,
        started,
        timeout_secs,
        points,
        factor,
        max_units,
    )
    .await;
    ctx.result_waiters.lock().await.remove(&task_id);
    Ok((outcome, charge))
}

/// Render one outcome for the control socket: the status line names
/// the exit code, then the captured standard output and standard
/// error each keep at most the display cap.
pub fn render(outcome: &TaskOutcome) -> String {
    let mut out = format!("exit_code: {}\n", outcome.exit_code);
    out.push_str(&truncate(&outcome.stdout, 4000));
    if !outcome.stderr.is_empty() {
        out.push_str("stderr:\n");
        out.push_str(&truncate(&outcome.stderr, 2000));
    }
    out
}

/// Keep at most `cap` bytes of one stream for display, ending with a
/// truncation marker when the cap bites.
fn truncate(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_string();
    }
    format!("{}… <truncated>\n", &text[..cap])
}
