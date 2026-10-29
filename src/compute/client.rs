//! Consumer side of the compute market: reserve trust units, bid with a
//! signed trust snapshot, assign the signed command, settle the reservation
//! by actual billed time and return the rendered result.
//!
//! All trust accounting happens under the single state lock through
//! `NodeState::reserve` / `release` / `settle`, so no secondary lock is
//! ever taken while holding it.

use crate::compute::policy::announced_points;
use crate::compute::{ComputeEvent, TaskOutcome};
use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::node::state::Mode;
use crate::trust::{now_unix, points::units_for};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// How long to wait for the bid decision before giving up.
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// Run `command` on a peer and charge trust units for it. `prefix` selects
/// a peer by node id; `None` lets the client pick the most suitable known
/// peer automatically. The result is returned as control-socket text.
pub async fn compute(
    ctx: &Arc<Ctx>,
    prefix: Option<&str>,
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
    // Both sides price the reservation from the provider's announced points
    // and the agreed limit; the final charge follows the billed seconds
    // reported in the outcome.
    let points = {
        let dht = ctx.dht.lock().await;
        announced_points(&dht, &peer.node_id)
    };
    let Some(points) = points else {
        return format!(
            "error: peer {} has not announced its capacity points yet\n",
            peer.addr
        );
    };
    let max_units = units_for(points, timeout_secs);

    let task_id = format!("{:016x}", rand::random::<u64>());
    let floor = ctx.config.trust.min_trust;
    {
        let mut state = ctx.state.lock().await;
        if let Err(err) = state.reserve(&task_id, max_units, floor) {
            return format!("error: {err}\n");
        }
    }
    let (events_tx, mut events_rx) = oneshot::channel::<ComputeEvent>();
    ctx.result_waiters
        .lock()
        .await
        .insert(task_id.clone(), events_tx);

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
        return format!("error: cannot reach peer: {err:#}\n");
    }

    // Wait for the bid decision before assigning real work.
    match tokio::time::timeout(REPLY_TIMEOUT, &mut events_rx).await {
        Ok(Ok(ComputeEvent::Accepted)) => {}
        Ok(Ok(ComputeEvent::Rejected(reason))) => {
            ctx.result_waiters.lock().await.remove(&task_id);
            ctx.state.lock().await.release(&task_id);
            return format!("error: bid rejected: {reason}\n");
        }
        _ => {
            ctx.result_waiters.lock().await.remove(&task_id);
            ctx.state.lock().await.release(&task_id);
            return "error: peer did not answer the bid, reservation released\n".to_string();
        }
    }

    // The bid reply consumed the first one-shot waiter; arm a fresh one
    // for the outcome phase before handing the work to the provider, so a
    // result arriving during the handover can never be lost.
    let (outcome_tx, outcome_rx) = oneshot::channel::<ComputeEvent>();
    ctx.result_waiters
        .lock()
        .await
        .insert(task_id.clone(), outcome_tx);

    // The assignment is signed by the same key that made the bid; the
    // provider launches only assignments that match an accepted bid.
    let assign = {
        let payload = Message::assign_signing_payload(&task_id, &command, timeout_secs);
        Message::TaskAssign {
            task_id: task_id.clone(),
            command,
            timeout_secs,
            pubkey: ctx.identity.pubkey(),
            signature: ctx.identity.sign(&payload).to_vec(),
        }
    };
    if let Err(err) = send_msg(ctx, &peer.addr, &assign).await {
        ctx.result_waiters.lock().await.remove(&task_id);
        ctx.state.lock().await.release(&task_id);
        return format!("error: cannot assign task: {err:#}\n");
    }

    let grace = Duration::from_secs(timeout_secs + 60);
    let outcome = match tokio::time::timeout(grace, outcome_rx).await {
        Ok(Ok(ComputeEvent::Outcome(outcome))) => outcome,
        _ => {
            ctx.state.lock().await.release(&task_id);
            return "error: task did not finish in time, reservation released\n".to_string();
        }
    };
    ctx.result_waiters.lock().await.remove(&task_id);

    // The task consumed real capacity: charge the actual billed time and
    // return the unused part of the reservation to the coefficient.
    let charge = units_for(points, outcome.billed_secs).min(max_units);
    let header = {
        let mut state = ctx.state.lock().await;
        state.settle(&task_id, charge);
        format!(
            "consumed {charge} units on {} (trust now {})\n",
            peer.node_id, state.trust
        )
    };
    render(&header, &outcome)
}

/// Choose the peer most likely to serve well: seeds first, then the
/// highest-trust peers, with the reputation score and freshness as
/// tiebreakers.
async fn auto_pick(ctx: &Arc<Ctx>) -> Option<PeerInfo> {
    let mut candidates: Vec<PeerInfo> = ctx
        .dht
        .lock()
        .await
        .all_peers()
        .into_iter()
        .filter(|peer| !peer.node_id.is_empty() && peer.mode != "leech" && peer.points > 0)
        .collect();
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

/// Format the finished task for the control socket, keeping the settlement
/// header that the settlement step produced.
fn render(header: &str, outcome: &TaskOutcome) -> String {
    format!(
        "{header}exit_code: {code}\nstdout:\n{stdout}\nstderr:\n{stderr}\n",
        code = outcome.exit_code,
        stdout = outcome.stdout,
        stderr = outcome.stderr,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::make_ctx;
    use crate::transport::Transport;

    #[tokio::test]
    async fn seed_mode_cannot_request_tasks() {
        let (ctx, _rx) = make_ctx("cl-seed").await;
        ctx.state.lock().await.mode = Mode::Seed;
        let out = compute(&ctx, None, "echo x".to_string(), 60).await;
        assert!(out.contains("seed mode"));
    }

    #[tokio::test]
    async fn unknown_peer_reports_no_suitable_peer() {
        let (ctx, _rx) = make_ctx("cl-empty").await;
        let out = compute(&ctx, None, "echo x".to_string(), 60).await;
        assert!(out.contains("no suitable peer"));
    }

    #[tokio::test]
    async fn unannounced_points_is_an_error() {
        let (ctx, _rx) = make_ctx("cl-no-points").await;
        let provider_side = Transport::new(0, Duration::from_secs(60)).await.unwrap();
        let addr = provider_side.local_id();
        ctx.dht.lock().await.insert(&addr);
        ctx.dht
            .lock()
            .await
            .apply_ann(&addr, "abcd1234abcd1234", "peer", 50, 0, 0);
        let out = compute(&ctx, Some("abcd"), "echo x".to_string(), 60).await;
        assert!(out.contains("capacity points"));
    }
}
