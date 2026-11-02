//! Provider-side bid policy: given the bidder's signed trust snapshot
//! and the local configuration, decide whether to accept and how many
//! units to reserve. The inequality enforced here is
//! `trust - consumed - in_flight >= min_trust`, evaluated in `i128`
//! against the announced (signed) values, so a consumer cannot inflate
//! its effective trust by racing announcements and no operator-set
//! combination of values can overflow the check.
//!
//! Trust above the genesis endowment is evidence-gated: the bidder's
//! announced receipt head must verify against a chain it can produce
//! on demand. A peer whose chain does not match its announcement, or
//! that cannot answer an audit at all, is refused — unverifiable trust
//! claims never enter the market at face value.

use crate::config::{Config, Limits};
use crate::daemon::Ctx;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::node::state::genesis_head;
use crate::trust::{now_unix, points::units_for};
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// Scheduling decision for one bid.
pub enum Decision {
    Accept { units: i64 },
    Reject(&'static str),
}

/// Local concurrency gate checked before the trust economy: a full
/// node refuses work regardless of how much trust the bidder offers.
pub fn check_capacity(limits: &Limits, running: usize) -> Decision {
    if running >= limits.max_tasks as usize {
        return Decision::Reject("at capacity");
    }
    Decision::Accept { units: 0 }
}

/// Pricing multiplier for one consumer: nodes with a countersigned
/// receipt history (a non-genesis announced head) pay the base price;
/// strangers — including every freshly wiped identity — pay the
/// configured surcharge. Both sides derive the identical factor from
/// the consumer's announced head, so the reservation and the
/// settlement stay in lockstep.
pub fn stranger_factor(config: &Config, consumer_known: bool) -> i64 {
    if consumer_known {
        1
    } else {
        config.trust.new_node_units_factor as i64
    }
}

/// Evaluate one verified bid: capacity first against the real number
/// of running tasks, then the trust floor against the announced
/// snapshot, then the receipt-chain audit for consumers claiming more
/// trust than the genesis endowment — their announced head must verify
/// against the receipts they can produce, and a peer that cannot be
/// audited is refused outright. The reservation is priced from this
/// provider's own announced capacity points, the GPU offer and the
/// stranger surcharge, so consumer and provider compute the identical
/// number. Every balance comparison runs in `i128`; the final
/// reservation saturates at `i64::MAX` so the widest announceable
/// values still produce a usable decision.
pub async fn evaluate_bid(
    ctx: &Arc<Ctx>,
    from_node: &str,
    trust: i64,
    consumed: u64,
    expires_unix: u64,
    running: usize,
    in_flight: i64,
) -> Decision {
    {
        let state = ctx.state.lock().await;
        let capacity = check_capacity(&state.limits, running);
        if let Decision::Reject(reason) = capacity {
            return Decision::Reject(reason);
        }
    }
    if expires_unix <= now_unix() {
        return Decision::Reject("bid expired");
    }
    let Some(peer) = ctx.dht.lock().await.find_by_exact_node_id(from_node) else {
        return Decision::Reject("unknown consumer");
    };
    if trust > peer.trust {
        return Decision::Reject("trust claim exceeds announced value");
    }
    let effective = i128::from(trust) - i128::from(consumed) - i128::from(in_flight);
    if effective < i128::from(ctx.config.trust.min_trust) {
        return Decision::Reject("insufficient trust");
    }
    // Receipt-chain audit: earned trust must be backed by a chain whose
    // recomputed head matches the announcement. A mismatched chain and
    // an unreachable auditor are both refusals: unverifiable trust
    // claims must not trade at face value.
    if trust > ctx.config.trust.genesis_trust && peer.receipt_head != genesis_head() {
        match crate::trust::audit::audit_chain(ctx, &peer, peer.receipt_head).await {
            Ok(true) => {}
            Ok(false) => return Decision::Reject("receipt chain audit failed"),
            Err(err) => {
                crate::log::warn(
                    module_path!(),
                    &format!("[audit] {} unavailable: {err:#}", peer.node_id),
                );
                return Decision::Reject("receipt chain audit unavailable");
            }
        }
    }
    let points = ctx.state.lock().await.points;
    let factor = stranger_factor(&ctx.config, peer.receipt_head != genesis_head());
    Decision::Accept {
        units: bid_units(&ctx.config, points).saturating_mul(factor),
    }
}

/// Verify an assignment signature and bind it to the node whose bid was
/// accepted. The payload covers the command, the wall-clock limit and
/// the resource request (`ram_mb`, `gpus`), so none of them can be
/// altered in flight; the scheduler separately re-checks the request
/// against what this node actually offers. The arity mirrors the signed
/// assignment field set.
#[allow(clippy::too_many_arguments)]
pub fn verify_assign(
    task_id: &str,
    command: &str,
    timeout_secs: u64,
    ram_mb: u64,
    gpus: u32,
    pubkey: &[u8; 32],
    signature: &[u8],
    accepted_from: &str,
) -> bool {
    if Identity::node_id_from_pubkey(pubkey) != accepted_from {
        return false;
    }
    let payload = Message::assign_signing_payload(task_id, command, timeout_secs, ram_mb, gpus);
    let Ok(sig) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    Identity::verify(pubkey, &payload, sig)
}

/// Announced points of one node id, the market price of its capacity.
pub fn announced_points(dht: &crate::dht::Dht, node_id: &str) -> Option<u32> {
    dht.announced_points(node_id)
}

/// Base trust units one bid reserves, priced from the provider's
/// points, before the stranger surcharge.
pub fn bid_units(config: &Config, points: u32) -> i64 {
    units_for(points, config.network.task_timeout_secs)
}
