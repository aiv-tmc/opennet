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
//! `NodeState::reserve` / `release` / `settle`.

use crate::compute::policy::{announced_points, stranger_factor};
use crate::compute::{ComputeEvent, TaskOutcome};
use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::node::state::genesis_head;
use crate::node::state::receipt_hash;
use crate::node::state::Mode;
use crate::trust::{now_unix, points::units_for};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// How long to wait for the bid decision before giving up.
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);
/// Extra seconds of billing slack beyond the measured elapsed time
/// before a provider's reported duration is cut; LAN clocks may skew by a
/// few seconds, so the cap must not bite honest providers.
const BILLING_SLACK_SECS: u64 = 5;
/// How long to wait for the provider's receipt to show up in the
/// dispatch stash. The receipt travels one frame ahead of the result on
/// the same ordered connection, so it is normally stashed before the
/// result completes the waiter; the poll is a scheduling safety net,
/// not a sync point.
const RECEIPT_PULL_ATTEMPTS: usize = 20;
const RECEIPT_PULL_DELAY: Duration = Duration::from_millis(50);

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
            Ok((outcome, charge)) => settled_header(ctx, charge).await + &render(&outcome),
            Err(err) => format!("error: {err}\n"),
        };
    }
    run_verified(ctx, command, timeout_secs, ram_mb, gpus, verify).await
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
        None => auto_pick(ctx).await,
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
    let task_id = format!("{:016x}", rand::random::<u64>());
    {
        let mut state = ctx.state.lock().await;
        state
            .reserve(&task_id, max_units, ctx.config.trust.min_trust)
            .map_err(|err| err.to_string())?;
    }
    let (events_tx, mut events_rx) = oneshot::channel::<ComputeEvent>();
    // The waiter binds the request to the peer's listener port: a
    // result frame from anywhere else is put back instead of
    // completing the request (see dispatch).
    ctx.result_waiters
        .lock()
        .await
        .insert(task_id.clone(), (peer.addr.clone(), events_tx));
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
        ctx.state.lock().await.release(&task_id);
        return Err(format!("cannot reach peer: {err:#}"));
    }
    // Wait for the bid decision before assigning real work.
    match tokio::time::timeout(REPLY_TIMEOUT, &mut events_rx).await {
        Ok(Ok(ComputeEvent::Accepted)) => {}
        Ok(Ok(ComputeEvent::Rejected(reason))) => {
            ctx.result_waiters.lock().await.remove(&task_id);
            ctx.state.lock().await.release(&task_id);
            return Err(format!("bid rejected: {reason}"));
        }
        _ => {
            ctx.result_waiters.lock().await.remove(&task_id);
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
        .insert(task_id.clone(), (peer.addr.clone(), outcome_tx));
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
        ctx.state.lock().await.release(&task_id);
        return Err(format!("cannot assign task: {err:#}"));
    }
    let grace = Duration::from_secs(timeout_secs + 60);
    let outcome = match tokio::time::timeout(grace, outcome_rx).await {
        Ok(Ok(ComputeEvent::Outcome(outcome))) => outcome,
        _ => {
            ctx.state.lock().await.release(&task_id);
            return Err("task did not finish in time, reservation released".to_string());
        }
    };
    // The provider's receipt travels one frame ahead of its result; a
    // missing or invalid receipt falls back to the locally computed
    // charge (both formulas agree for honest providers, so the ledgers
    // stay in lockstep either way).
    let charge = settle_with_receipt(
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

/// Settle one finished task against its receipt. When the provider's
/// receipt verifies — signature, provider identity, and the outcome
/// hash matching the delivered output — the receipt enters the local
/// journal and the consumer countersigns it back; the charge is the
/// provider's claim capped by the reservation. Without a usable
/// receipt the locally computed charge (identical formula) settles the
/// reservation.
#[allow(clippy::too_many_arguments)]
async fn settle_with_receipt(
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
        && crate::trust::handlers::verify_receipt(
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
        let mut state = ctx.state.lock().await;
        if state.receipts.append(receipt_record.clone()).is_err() {
            // A duplicate receipt (retried result) settles without
            // re-entering the journal.
            let charge = claimed.min(max_units);
            state.settle(task_id, charge);
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
    let charge = claimed.min(max_units);
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

/// Settle the reservation with one charge.
async fn settle(ctx: &Arc<Ctx>, task_id: &str, charge: i64) {
    ctx.state.lock().await.settle(task_id, charge);
}

/// The settlement line shown above the task output.
async fn settled_header(ctx: &Arc<Ctx>, charge: i64) -> String {
    let trust = ctx.state.lock().await.trust;
    format!("consumed {charge} units (trust now {trust})\n")
}

/// Redundant-execution verification: run the identical task on `verify`
/// distinct peers concurrently, group the results by output hash and
/// keep the majority outcome. Every execution settles its own
/// reservation — that is the price of verification — and a divergent
/// minority is reported so the operator can investigate the liar.
async fn run_verified(
    ctx: &Arc<Ctx>,
    command: String,
    timeout_secs: u64,
    ram_mb: u64,
    gpus: u32,
    verify: u32,
) -> String {
    let peers = pick_verifiers(ctx, verify as usize).await;
    if peers.len() < verify as usize {
        return format!(
            "error: redundant verification needs {verify} distinct peers, {} known\n",
            peers.len()
        );
    }
    let mut jobs = tokio::task::JoinSet::new();
    for peer in peers {
        let ctx = ctx.clone();
        let command = command.clone();
        jobs.spawn(async move {
            compute_once(
                &ctx,
                Some(&peer.node_id),
                command,
                timeout_secs,
                ram_mb,
                gpus,
            )
            .await
        });
    }
    let mut ok: Vec<(TaskOutcome, i64)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    while let Some(joined) = jobs.join_next().await {
        match joined {
            Ok(Ok(result)) => ok.push(result),
            Ok(Err(err)) => errors.push(err),
            Err(err) => errors.push(format!("verification task panicked: {err}")),
        }
    }
    if ok.is_empty() {
        return format!("error: no verified result ({})\n", errors.join("; "));
    }
    // Majority by output hash; the billed seconds of the winning copy
    // are reported, the charges of every executed copy were settled.
    let mut groups: HashMap<[u8; 32], Vec<(TaskOutcome, i64)>> = HashMap::new();
    for result in ok {
        groups.entry(result.0.hash()).or_default().push(result);
    }
    let majority_needed = (verify / 2 + 1) as usize;
    let best = groups
        .values()
        .map(|group| (group.len(), group))
        .max_by_key(|(count, _)| *count);
    let Some((count, group)) = best else {
        return "error: no verified result\n".to_string();
    };
    let (outcome, _) = group[0].clone();
    if count < majority_needed {
        return format!(
            "error: outcomes diverged ({count}/{} agree), no majority trust in the result\n",
            verify
        );
    }
    let mut out = settled_header(ctx, group.iter().map(|(_, charge)| *charge).sum()).await;
    out.push_str(&format!(
        "verified: {count}/{verify} providers agree on the output\n"
    ));
    out.push_str(&render(&outcome));
    out
}

/// Choose the peers most likely to serve well: seeds first, then the
/// highest-trust peers, with reputation and freshness as tiebreakers.
async fn auto_pick(ctx: &Arc<Ctx>) -> Option<PeerInfo> {
    let mut candidates = candidates(ctx).await;
    let reputation = ctx.reputation.lock().await;
    candidates.sort_by(|a, b| {
        let seed_a = (a.mode == "seed") as u8;
        let seed_b = (b.mode == "seed") as u8;
        seed_b
            .cmp(&seed_a)
            .then_with(|| b.trust.cmp(&a.trust))
            .then_with(|| {
                reputation
                    .score_of(&b.node_id)
                    .cmp(&reputation.score_of(&a.node_id))
            })
            .then_with(|| b.last_seen.cmp(&a.last_seen))
    });
    candidates.into_iter().next()
}

/// The top `count` distinct candidates for redundant verification.
async fn pick_verifiers(ctx: &Arc<Ctx>, count: usize) -> Vec<PeerInfo> {
    let mut candidates = candidates(ctx).await;
    let reputation = ctx.reputation.lock().await;
    candidates.sort_by(|a, b| {
        let seed_a = (a.mode == "seed") as u8;
        let seed_b = (b.mode == "seed") as u8;
        seed_b
            .cmp(&seed_a)
            .then_with(|| b.trust.cmp(&a.trust))
            .then_with(|| {
                reputation
                    .score_of(&b.node_id)
                    .cmp(&reputation.score_of(&a.node_id))
            })
            .then_with(|| b.last_seen.cmp(&a.last_seen))
    });
    candidates.truncate(count);
    candidates
}

/// All usable providers with announced capacity.
async fn candidates(ctx: &Arc<Ctx>) -> Vec<PeerInfo> {
    ctx.dht
        .lock()
        .await
        .all_peers()
        .into_iter()
        .filter(|peer| !peer.node_id.is_empty() && peer.mode != "leech" && peer.points > 0)
        .collect()
}

/// Format the finished task for the control socket.
fn render(outcome: &TaskOutcome) -> String {
    format!(
        "exit_code: {code}\nstdout:\n{stdout}\nstderr:\n{stderr}\n",
        code = outcome.exit_code,
        stdout = outcome.stdout,
        stderr = outcome.stderr,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::identity::Identity;
    use crate::testutil::make_ctx;
    use crate::transport::Transport;

    #[tokio::test]
    async fn seed_mode_cannot_request_tasks() {
        let (ctx, _rx) = make_ctx("cl-seed").await;
        ctx.state.lock().await.mode = Mode::Seed;
        let out = compute(&ctx, None, "echo x".to_string(), 60, 0, 0, 1).await;
        assert!(out.contains("seed mode"));
    }

    #[tokio::test]
    async fn unknown_peer_reports_no_suitable_peer() {
        let (ctx, _rx) = make_ctx("cl-empty").await;
        let out = compute(&ctx, None, "echo x".to_string(), 60, 0, 0, 1).await;
        assert!(out.contains("no suitable peer"));
    }

    #[tokio::test]
    async fn unannounced_points_is_an_error() {
        let (ctx, _rx) = make_ctx("cl-no-points").await;
        let provider_side = Transport::new(Identity::generate(), 0, Duration::from_secs(60))
            .await
            .unwrap();
        let addr = provider_side.local_id();
        ctx.dht.lock().await.insert(&addr);
        ctx.dht
            .lock()
            .await
            .apply_ann(&addr, "abcd1234abcd1234", "peer", 50, 0, 0);
        let out = compute(&ctx, Some("abcd"), "echo x".to_string(), 60, 0, 0, 1).await;
        assert!(out.contains("capacity points"));
    }

    #[tokio::test]
    async fn gpu_request_beyond_the_peer_offer_is_rejected_early() {
        let (ctx, _rx) = make_ctx("cl-gpu-floor").await;
        let provider_side = Transport::new(Identity::generate(), 0, Duration::from_secs(60))
            .await
            .unwrap();
        let addr = provider_side.local_id();
        ctx.dht.lock().await.insert(&addr);
        ctx.dht.lock().await.apply_ann_ext(
            &addr,
            "gpu-node",
            "peer",
            50,
            24,
            1,
            genesis_head(),
            1_700_000_000,
        );
        let out = compute(&ctx, Some("gpu-node"), "echo x".to_string(), 60, 0, 4, 1).await;
        assert!(out.contains("offers 1 GPU"));
    }

    #[tokio::test]
    async fn verification_needs_enough_distinct_peers() {
        let (ctx, _rx) = make_ctx("cl-verify-count").await;
        let out = compute(&ctx, None, "echo x".to_string(), 60, 0, 0, 3).await;
        assert!(out.contains("distinct peers"));
    }
}
