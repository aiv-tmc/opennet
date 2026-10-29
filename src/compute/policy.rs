//! Accept policy for incoming task bids and verification helpers for task
//! assignments.
//!
//! A bid is accepted only when the provider donates capacity (not a leech),
//! the bid has not expired, the consumer is a verified peer and its signed
//! arithmetic (`trust - consumed - in_flight`) stays at or above the
//! configured floor. An assignment is honored only when it carries a valid
//! signature from the same node whose bid was accepted for the task id.

use crate::daemon::Ctx;
use crate::dht::Dht;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::node::state::Mode;
use crate::trust::handlers::bid_units;
use std::sync::Arc;

/// Outcome of evaluating one bid.
pub enum Decision {
    /// Accept the bid and reserve `units` trust units for it.
    Accept { units: i64 },
    /// Refuse the bid with a human-readable explanation.
    Reject(&'static str),
}

/// Evaluate one authenticated bid against the local policy.
///
/// `in_flight` is the sum of units currently running or pending launch
/// for this consumer; it is subtracted from the signed snapshot exactly
/// like the consumption counter.
pub async fn evaluate_bid(
    ctx: &Arc<Ctx>,
    from_node: &str,
    trust: i64,
    consumed: u64,
    expires_unix: u64,
    in_flight: i64,
) -> Decision {
    if ctx.state.lock().await.mode == Mode::Leech {
        return Decision::Reject("leech mode donates no capacity");
    }
    if expires_unix <= crate::trust::now_unix() {
        return Decision::Reject("bid expired");
    }
    let announced = match ctx.dht.lock().await.find_by_exact_node_id(from_node) {
        Some(peer) => peer.trust,
        None => return Decision::Reject("unknown consumer"),
    };
    // The signed post-reservation snapshot must not claim more trust than
    // the consumer last announced; an inflated coefficient is rejected.
    if trust > announced {
        return Decision::Reject("claimed trust exceeds the announced coefficient");
    }
    let floor = ctx.config.trust.min_trust as i128;
    let effective = trust as i128 - consumed as i128 - in_flight as i128;
    if effective < floor {
        return Decision::Reject("insufficient trust for this task");
    }
    let points = ctx.state.lock().await.points;
    Decision::Accept {
        units: bid_units(&ctx.config, points),
    }
}

/// Authenticate a task assignment: the signature must cover the exact
/// fields and the signer must be the node that made the accepted bid.
pub fn verify_assign(
    task_id: &str,
    command: &str,
    timeout_secs: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
    accepted_from: &str,
) -> bool {
    let payload = Message::assign_signing_payload(task_id, command, timeout_secs);
    let Ok(sig) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    Identity::verify(pubkey, &payload, sig)
        && Identity::node_id_from_pubkey(pubkey) == accepted_from
}

/// Look up the announced capacity points of one verified peer; providers
/// and consumers derive the reservation from this value so both sides
/// agree on the price of a task.
pub fn announced_points(dht: &Dht, node_id: &str) -> Option<u32> {
    let peer = dht.find_by_exact_node_id(node_id)?;
    (peer.points > 0).then_some(peer.points)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_rejects_wrong_signer_and_bad_signature() {
        let a = Identity::load_or_create(&crate::testutil::scratch_dir("pol-a")).unwrap();
        let b = Identity::load_or_create(&crate::testutil::scratch_dir("pol-b")).unwrap();
        let payload = Message::assign_signing_payload("t1", "echo hi", 60);
        let sig = a.sign(&payload);
        assert!(verify_assign(
            "t1",
            "echo hi",
            60,
            &a.pubkey(),
            &sig,
            &a.node_id()
        ));
        assert!(!verify_assign(
            "t1",
            "echo hi",
            60,
            &b.pubkey(),
            &sig,
            &b.node_id()
        ));
        assert!(!verify_assign(
            "t1",
            "echo hi",
            60,
            &a.pubkey(),
            &sig[..32],
            &a.node_id()
        ));
    }
}
