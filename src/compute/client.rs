//! Consumer side of the compute market: reserve trust units, bid with a
//! signed trust snapshot, assign the command and settle the reservation
//! when the result arrives.

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

/// Run `command` on a peer and charge `units` trust units for it. `prefix`
/// selects a peer by node id; `None` lets the client pick the most suitable
/// known peer automatically. The result is returned as control-socket text.
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
    if peer.points == 0 {
        return format!(
            "error: peer {} has not announced its capacity points yet\n",
            peer.addr
        );
    }
    // Both sides price the task from the provider's announced points and
    // the configured default timeout, so they always agree on the charge.
    let units = units_for(peer.points, timeout_secs);

    let task_id = format!("{:016x}", rand::random::<u64>());
    if let Err(text) = reserve(ctx, &task_id, units).await {
        return text;
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
        release(ctx, &task_id).await;
        return format!("error: cannot reach peer: {err:#}\n");
    }

    // Wait for the bid decision before assigning real work.
    match tokio::time::timeout(REPLY_TIMEOUT, &mut events_rx).await {
        Ok(Ok(ComputeEvent::Accepted)) => {}
        Ok(Ok(ComputeEvent::Rejected(reason))) => {
            ctx.result_waiters.lock().await.remove(&task_id);
            release(ctx, &task_id).await;
            return format!("error: bid rejected: {reason}\n");
        }
        _ => {
            ctx.result_waiters.lock().await.remove(&task_id);
            release(ctx, &task_id).await;
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
        release(ctx, &task_id).await;
        return format!("error: cannot assign task: {err:#}\n");
    }

    let grace = Duration::from_secs(timeout_secs + 60);
    let outcome = match tokio::time::timeout(grace, outcome_rx).await {
        Ok(Ok(ComputeEvent::Outcome(outcome))) => outcome,
        _ => {
            release(ctx, &task_id).await;
            return "error: task did not finish in time, reservation released\n".to_string();
        }
    };
    ctx.result_waiters.lock().await.remove(&task_id);

    // The task consumed real capacity: make the charge permanent by moving
    // the reserved units into the consumption counter. The trust deduction
    // already happened at reservation time.
    let header = {
        let mut state = ctx.state.lock().await;
        state.consumed = state.consumed.saturating_add(units.max(0) as u64);
        if state.save().is_ok() {
            format!(
                "consumed {units} units on {} (trust now {})\n",
                peer.node_id, state.trust
            )
        } else {
            format!("consumed {units} units on {}\n", peer.node_id)
        }
    };
    render(&header, &outcome)
}

/// Deduct the task price from the local trust coefficient and remember the
/// reservation so concurrent local tasks cannot overspend. Fails when the
/// remaining trust would drop below the configured floor.
async fn reserve(ctx: &Arc<Ctx>, task_id: &str, units: i64) -> Result<(), String> {
    let mut reservations = ctx.reservations.lock().await;
    let reserved: i128 = reservations.values().map(|units| *units as i128).sum();
    let mut state = ctx.state.lock().await;
    let available = state.trust as i128 - reserved - units as i128;
    if available < ctx.config.trust.min_trust as i128 {
        return Err(format!(
            "error: insufficient trust (have {}, reserved {}, need {})\n",
            state.trust, reserved, units
        ));
    }
    state.trust -= units;
    let _ = state.save();
    reservations.insert(task_id.to_string(), units);
    Ok(())
}

/// Return the reserved units to the local trust coefficient after a failed
/// or rejected task and forget the reservation.
async fn release(ctx: &Arc<Ctx>, task_id: &str) {
    let Some(units) = ctx.reservations.lock().await.remove(task_id) else {
        return;
    };
    let mut state = ctx.state.lock().await;
    state.trust += units;
    let _ = state.save();
}

/// Choose the peer most likely to serve well: seeds first, then the
/// highest-trust peers, freshest as the tiebreaker.
async fn auto_pick(ctx: &Arc<Ctx>) -> Option<PeerInfo> {
    let mut candidates: Vec<PeerInfo> = ctx
        .dht
        .lock()
        .await
        .all_peers()
        .into_iter()
        .filter(|peer| !peer.node_id.is_empty() && peer.mode != "leech" && peer.points > 0)
        .collect();
    candidates.sort_by(|a, b| {
        let seed_a = (a.mode == "seed") as u8;
        let seed_b = (b.mode == "seed") as u8;
        seed_b
            .cmp(&seed_a)
            .then_with(|| b.trust.cmp(&a.trust))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
    });
    candidates.into_iter().next()
}

/// Format the finished task for the control socket, keeping the consumption
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
    use crate::trust::now_unix;

    #[tokio::test]
    async fn seed_mode_cannot_request_tasks() {
        let (ctx, _rx) = make_ctx("cl-seed").await;
        ctx.state.lock().await.mode = Mode::Seed;
        let out = compute(&ctx, None, "echo x".to_string(), 60).await;
        assert!(out.contains("seed mode"), "unexpected output: {out}");
    }

    #[tokio::test]
    async fn unknown_prefix_reports_no_peer() {
        let (ctx, _rx) = make_ctx("cl-nopeer").await;
        let out = compute(&ctx, Some("ffff"), "echo x".to_string(), 60).await;
        assert!(out.contains("no suitable peer"), "unexpected output: {out}");
    }

    #[tokio::test]
    async fn peer_without_points_is_reported() {
        let (ctx, _rx) = make_ctx("cl-nopoints").await;
        let addr = "tcp:10.2.2.2:5000";
        ctx.dht.lock().await.insert(addr);
        ctx.dht
            .lock()
            .await
            .apply_ann(addr, "aa11bb22", "peer", 100, 0, now_unix());
        let out = compute(&ctx, Some("aa11bb22"), "echo x".to_string(), 60).await;
        assert!(out.contains("capacity points"), "unexpected output: {out}");
    }

    #[tokio::test]
    async fn insufficient_trust_blocks_reservation() {
        let (ctx, _rx) = make_ctx("cl-poor").await;
        let addr = "tcp:10.4.4.4:7000";
        ctx.dht.lock().await.insert(addr);
        ctx.dht
            .lock()
            .await
            .apply_ann(addr, "bb33cc44", "peer", 100, 100, now_unix());
        let timeout = ctx.config.network.task_timeout_secs;
        let out = compute(&ctx, Some("bb33cc44"), "echo x".to_string(), timeout).await;
        assert!(
            out.contains("insufficient trust"),
            "unexpected output: {out}"
        );
        let state = ctx.state.lock().await;
        assert_eq!(state.trust, 100);
        assert_eq!(state.consumed, 0);
        assert!(ctx.reservations.lock().await.is_empty());
    }
}
