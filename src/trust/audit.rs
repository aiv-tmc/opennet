//! Receipt-chain audit: window-walk verification of a peer's billing
//! journal against its announced head.
//!
//! The consumer requesting work may claim trust above the genesis
//! endowment; that claim is evidence-gated at bid time. This module
//! demands signed windows of the peer's receipt journal — receipts
//! after a given anchor, the head after the window, and a completeness
//! flag — and recomputes the chaining hash across however many windows
//! the chain needs, re-verifying every receipt's provider signature.
//! The walk stops when the peer reports the chain end; the recomputed
//! head must equal the announced one, or the bid is refused.
//!
//! Budget: each window carries at most `AUDIT_WINDOW_CAP` receipts
//! (comfortably inside the 1 MiB frame cap). A chain that outlasts
//! `AUDIT_MAX_WINDOWS` keeps being walked — the announced head must
//! verify no matter how long the chain is — but the result is not
//! cached, so an over-budget claim is re-verified on every bid. Two
//! backstops keep the walk from monopolizing the bidder: the window
//! count is capped at `AUDIT_HARD_CAP`, and the whole walk must finish
//! inside `AUDIT_OVERALL_TIMEOUT` no matter how the peer paces its
//! answers, so a slow-dripping peer cannot stall the scheduler for
//! hours one window at a time.

use super::verify::{verify_receipt, verify_receipt_response};
use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::node::state::{genesis_head, verify_window};
use anyhow::{bail, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cap on receipts per audit window: keeps the response comfortably
/// inside the 1 MiB frame cap.
pub const AUDIT_WINDOW_CAP: u32 = 1024;

/// Cap on windows whose result is cached: 16 windows x 1024 receipts
/// of evidence is the most one audit will remember. Longer chains
/// still verify, but every bid re-walks them.
const AUDIT_MAX_WINDOWS: usize = 16;

/// Backstop on the total walk length. A peer that keeps answering with
/// chaining-consistent windows without ever reporting the chain end
/// fails the audit at this wall; producing that many windows requires
/// a real journal of this size, so the cap only bites absurd evidence.
const AUDIT_HARD_CAP: usize = 4096;

/// Ten seconds per window; a slow peer fails the audit.
pub const AUDIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall wall-clock budget for one full walk, independent of the
/// per-window timeout: a peer answering every window just inside its
/// own deadline still fails here, so the total scheduler stall stays
/// bounded by one constant.
const AUDIT_OVERALL_TIMEOUT: Duration = Duration::from_secs(120);

/// One verified window's outcome.
enum Window {
    /// The window verified: verified head after it, and whether the
    /// chain end was reached.
    Verified {
        head_after: [u8; 32],
        complete: bool,
    },
    /// The window's content was provably dishonest: wrong signer,
    /// broken chain or a receipt whose signature fails.
    Forged,
}

/// Audit one peer's receipt chain against its announced head. Returns
/// `Ok(true)` when the chain verifies (or was already audited for this
/// head), `Ok(false)` when the presented evidence is a forgery, and
/// `Err` when the peer cannot produce evidence at all or the chain
/// outlasts the walk budgets — callers treat `Err` as "audit
/// unavailable" and `Ok(false)` as "liar, refuse".
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
    let deadline = Instant::now() + AUDIT_OVERALL_TIMEOUT;
    let mut head_before = genesis_head();
    let mut verified_head = genesis_head();
    let mut complete = false;
    let mut windows = 0usize;
    while !complete {
        if windows >= AUDIT_HARD_CAP {
            return Err(anyhow::anyhow!(
                "chain longer than {AUDIT_HARD_CAP} windows; audit aborted"
            ));
        }
        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!("audit exceeded its overall time budget"));
        }
        windows += 1;
        let request_id: [u8; 32] = rand::random();
        let (tx, rx) = tokio::sync::oneshot::channel::<Message>();
        let key = hex::encode(request_id);
        ctx.receipt_windows.lock().await.insert(key.clone(), tx);
        let unix_ts = super::now_unix();
        let request = Message::ReceiptRequest {
            signature: ctx
                .identity
                .sign(&Message::receipt_request_signing_payload(
                    &request_id,
                    &head_before,
                    AUDIT_WINDOW_CAP,
                    unix_ts,
                ))
                .to_vec(),
            request_id,
            head_before,
            limit: AUDIT_WINDOW_CAP,
            unix_ts,
            pubkey: ctx.identity.pubkey(),
        };
        // The per-window wait is the tighter of the window timeout and
        // the remaining overall budget, so the last window can never
        // overshoot the deadline.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let outcome = async {
            send_msg(ctx, &peer.addr, &request).await?;
            tokio::time::timeout(remaining.min(AUDIT_TIMEOUT), rx)
                .await
                .map_err(|_| anyhow::anyhow!("audit window timed out"))?
                .map_err(|_| anyhow::anyhow!("audit waiter dropped"))
        }
        .await;
        ctx.receipt_windows.lock().await.remove(&key);
        let Ok(response) = outcome else {
            return Err(anyhow::anyhow!("audit unavailable"));
        };
        match verify_window_response(ctx, peer, response, request_id, head_before).await? {
            Window::Forged => {
                ctx.counters.audits_failed.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            }
            Window::Verified {
                head_after,
                complete: done,
            } => {
                verified_head = head_after;
                complete = done;
                head_before = head_after;
            }
        }
    }
    // The announced head is checked on every path: a peer with a long
    // chain must still land exactly on the head it announced.
    if verified_head != expected_head {
        ctx.counters.audits_failed.fetch_add(1, Ordering::Relaxed);
        return Ok(false);
    }
    if windows <= AUDIT_MAX_WINDOWS {
        ctx.audited_heads
            .lock()
            .await
            .insert(peer.node_id.clone(), expected_head);
    } else {
        // Over-budget chains verify but are never cached: the next bid
        // re-walks the evidence instead of trusting this outcome.
        crate::log::warn(
            module_path!(),
            &format!(
                "audit walked {windows} windows for {}; result not cached",
                peer.node_id
            ),
        );
    }
    Ok(true)
}

/// Verify one window response: the signature must come from the
/// audited peer, the request id must echo ours, the anchor must match
/// where the walk stopped, every receipt's provider signature must
/// verify, and the chaining hash from the anchor must reproduce the
/// reported head after the window.
async fn verify_window_response(
    ctx: &Arc<Ctx>,
    peer: &PeerInfo,
    response: Message,
    request_id: [u8; 32],
    head_before: [u8; 32],
) -> Result<Window> {
    let Message::ReceiptResponse {
        request_id: echoed,
        head_before: anchor,
        receipts,
        head_after,
        complete,
        unix_ts,
        pubkey,
        signature,
        ..
    } = response
    else {
        bail!("not a receipt response");
    };
    if echoed != request_id {
        bail!("stale audit response");
    }
    if verify_receipt_response(
        &echoed,
        &anchor,
        &receipts,
        &head_after,
        complete,
        unix_ts,
        &pubkey,
        &signature,
    ) != Some(peer.node_id.clone())
    {
        ctx.reputation.lock().await.record_invalid(&peer.addr);
        return Ok(Window::Forged);
    }
    if anchor != head_before {
        return Ok(Window::Forged);
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
            return Ok(Window::Forged);
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
            return Ok(Window::Forged);
        }
    }
    if !verify_window(head_before, &receipts, head_after) {
        return Ok(Window::Forged);
    }
    Ok(Window::Verified {
        head_after,
        complete,
    })
}

#[cfg(test)]
mod tests;
