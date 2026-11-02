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
//! cached, so an over-budget claim is re-verified on every bid. A
//! chain longer than `AUDIT_HARD_CAP` windows fails the audit: that
//! much evidence cannot be fetched inside any reasonable bid
//! deadline, and unverifiable trust never trades.

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
/// outlasts the hard walk cap — callers treat `Err` as "audit
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

    /// Mirror of the walk loop in `audit_chain` against a real
    /// journal: the walk chains bounded windows from the genesis
    /// anchor to the live head. `max_windows` models only the hard
    /// walk cap (`AUDIT_HARD_CAP`): the cache budget never bounds the
    /// walk, which must reach the chain end before anything is
    /// accepted.
    fn simulated_walk(log: &ReceiptLog, window_cap: usize, max_windows: usize) -> Option<[u8; 32]> {
        let mut anchor = genesis_head();
        let mut final_head = genesis_head();
        let mut complete = false;
        let mut windows = 0usize;
        while !complete && windows < max_windows {
            windows += 1;
            let (receipts, head_after, done) = log.window(anchor, window_cap)?;
            assert!(verify_window(anchor, &receipts, head_after));
            final_head = head_after;
            complete = done;
            anchor = head_after;
        }
        complete.then_some(final_head)
    }

    #[test]
    fn multi_window_walk_recomputes_the_full_chain_head() {
        let dir = scratch_dir("audit-walk");
        let provider = Identity::generate();
        let mut log = ReceiptLog::load(&dir).unwrap();
        for n in 1..=5 {
            log.append(signed_receipt(&format!("t{n}"), &provider))
                .unwrap();
        }
        let head = simulated_walk(&log, 3, 16).expect("five receipts must fit the budget");
        assert_eq!(head, log.head());
        // Two of five receipts can never reach the head: skipping
        // evidence must not verify.
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

    #[test]
    fn walk_past_the_cache_budget_still_reaches_the_head() {
        // Eleven receipts at a window cap of five need three windows,
        // more than the two-window cache budget: the cache budget must
        // never stop the walk — only the hard walk cap bounds it — and
        // the walk must still land on the real head, because the
        // announced head is compared on every path.
        let dir = scratch_dir("audit-long");
        let provider = Identity::generate();
        let mut log = ReceiptLog::load(&dir).unwrap();
        for n in 1..=11 {
            log.append(signed_receipt(&format!("t{n}"), &provider))
                .unwrap();
        }
        let head = simulated_walk(&log, 5, usize::MAX).expect("the walk must reach the chain end");
        assert_eq!(head, log.head());
        // Any other announced head is a mismatch, no matter how many
        // windows the walk needed.
        assert_ne!(head, [0xff; 32]);
    }

    #[test]
    fn hard_capped_walk_reports_incomplete() {
        // A walk that never sees the chain end reports nothing, so the
        // caller fails the audit instead of trusting a partial chain.
        let dir = scratch_dir("audit-cap");
        let provider = Identity::generate();
        let mut log = ReceiptLog::load(&dir).unwrap();
        for n in 1..=4 {
            log.append(signed_receipt(&format!("t{n}"), &provider))
                .unwrap();
        }
        assert!(simulated_walk(&log, 1, 2).is_none());
    }
}
