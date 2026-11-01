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
//! (comfortably inside the 1 MiB frame cap) and one audit walks at
//! most `AUDIT_MAX_WINDOWS` windows — 16 Ki receipts, roughly 16 MiB of
//! evidence. A chain longer than that is accepted without caching
//! (never trusted blindly on repeat) and logged loudly; window-walk
//! coverage beyond the budget is an explicit open item paired with
//! reputation-weighted pricing.

use super::verify::{verify_receipt, verify_receipt_response};
use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::node::state::{genesis_head, verify_window};
use anyhow::{bail, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Cap on receipts per audit window: keeps the response comfortably
/// inside the 1 MiB frame cap.
pub const AUDIT_WINDOW_CAP: u32 = 1024;

/// Cap on windows per audit: 16 windows × 1024 receipts ≈ 16 MiB of
/// evidence is the most one audit will fetch.
const AUDIT_MAX_WINDOWS: usize = 16;

/// Ten seconds per window; a slow peer fails the audit.
const AUDIT_TIMEOUT: Duration = Duration::from_secs(10);

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
/// `Err` when the peer cannot produce evidence at all — callers treat
/// `Err` as "audit unavailable" and `Ok(false)` as "liar, refuse".
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
    let mut head_before = genesis_head();
    let mut verified_head = genesis_head();
    let mut complete = false;
    for _ in 0..AUDIT_MAX_WINDOWS {
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
        let outcome = async {
            send_msg(ctx, &peer.addr, &request).await?;
            tokio::time::timeout(AUDIT_TIMEOUT, rx)
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
        if complete {
            break;
        }
    }
    if !complete {
        // The chain outlasted the audit budget: accept without caching,
        // so the claim is not trusted blindly on repeat, and log the
        // posture loudly for operators.
        crate::log::warn(
            module_path!(),
            &format!(
                "chain longer than {AUDIT_MAX_WINDOWS} windows; not cached: {}",
                peer.node_id
            ),
        );
        return Ok(true);
    }
    if verified_head != expected_head {
        ctx.counters.audits_failed.fetch_add(1, Ordering::Relaxed);
        return Ok(false);
    }
    ctx.audited_heads
        .lock()
        .await
        .insert(peer.node_id.clone(), expected_head);
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
mod tests {
    use super::*;
    use crate::node::identity::Identity;
    use crate::node::state::ReceiptLog;
    use crate::testutil::scratch_dir;
    use crate::trust::now_unix;

    fn signed_receipt(task_id: &str, provider: &Identity) -> Message {
        let unix_ts = now_unix();
        Message::Receipt {
            task_id: task_id.to_string(),
            provider_node: provider.node_id(),
            billed_secs: 12,
            charge: 24,
            outcome_hash: [7; 32],
            unix_ts,
            pubkey: provider.pubkey(),
            signature: provider
                .sign(&Message::receipt_signing_payload(
                    task_id,
                    &provider.node_id(),
                    12,
                    24,
                    &[7; 32],
                    unix_ts,
                ))
                .to_vec(),
        }
    }

    #[test]
    fn multi_window_walk_recomputes_the_full_chain_head() {
        // Simulate the walker's math against a real journal: two
        // bounded windows must chain from the genesis anchor to the
        // live head, each internally consistent.
        let dir = scratch_dir("audit-walk");
        let provider = Identity::generate();
        let mut log = ReceiptLog::load(&dir).unwrap();
        for n in 1..=5 {
            log.append(signed_receipt(&format!("t{n}"), &provider))
                .unwrap();
        }
        let window_cap = 3usize;
        let mut anchor = genesis_head();
        let mut final_head = genesis_head();
        let mut complete = false;
        let mut windows = 0;
        while !complete && windows < 16 {
            windows += 1;
            let (receipts, head_after, done) = log.window(anchor, window_cap).unwrap();
            assert!(verify_window(anchor, &receipts, head_after));
            final_head = head_after;
            complete = done;
            anchor = head_after;
        }
        assert!(complete, "five receipts must fit the simulated budget");
        assert_eq!(windows, 2);
        assert_eq!(final_head, log.head());
        // The walk must never accept a head that skips middle receipts.
        let (first, head_after_first, done_first) = log.window(genesis_head(), 1).unwrap();
        assert!(!done_first);
        assert!(verify_window(genesis_head(), &first, head_after_first));
        let (second, head_after_second, _) = log.window(head_after_first, 1).unwrap();
        assert!(verify_window(head_after_first, &second, head_after_second));
        assert_ne!(
            head_after_second,
            log.head(),
            "two of five cannot reach the head"
        );
    }
}
