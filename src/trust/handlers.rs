//! Verification of signed announcements, swarm offers and task bids.
//!
//! Announcements establish a peer's identity, mode, trust coefficient and
//! capacity points; bids carry a signed trust snapshot so providers can
//! enforce the consumption policy without trusting bare wire claims. Every
//! failed verification is penalized against the connection address, never
//! against a claimed node id: a replayed or forged message proves nothing
//! about the node it tries to borrow, and penalizing the victim would let
//! an attacker destroy an innocent peer's reputation.

use crate::config::Config;
use crate::daemon::Ctx;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::node::state::Mode;
use std::sync::Arc;

/// Convert a wire signature to the fixed-size array verification expects;
/// malformed lengths are treated as invalid signatures.
fn sig_array(signature: &[u8]) -> Option<&[u8; 64]> {
    signature.try_into().ok()
}

/// Check that an announcement timestamp is recent: neither older than
/// `max_age_secs` nor further than `future_skew_secs` in the future. This
/// stops replay of captured high-trust announcements from earlier rounds.
fn timestamp_fresh(unix_ts: u64, now: u64, max_age_secs: u64, future_skew_secs: u64) -> bool {
    unix_ts <= now + future_skew_secs && now.saturating_sub(unix_ts) <= max_age_secs
}

/// Verify a signed announcement and apply it to the routing table.
///
/// The node id must match the signer's public key, the signature must cover
/// the exact signed payload, the timestamp must be fresh and the mode must
/// be a known operating mode. Valid updates refresh the peer record and the
/// reputation table; anything else penalizes the sender's connection
/// address so a replayed announcement can never hurt the real owner's score.
pub async fn handle_ann(ctx: &Arc<Ctx>, src: &str, ann: Message) {
    let Message::Ann {
        node_id,
        mode,
        trust,
        points,
        unix_ts,
        pubkey,
        signature,
    } = ann
    else {
        return; // the dispatcher only routes announcements here
    };
    let payload = Message::ann_signing_payload(&node_id, &mode, trust, points, unix_ts);
    let id_matches = node_id == Identity::node_id_from_pubkey(&pubkey);
    let mode_valid = Mode::parse(&mode).is_ok();
    let fresh = timestamp_fresh(
        unix_ts,
        crate::trust::now_unix(),
        ctx.config.network.ann_max_age_secs,
        ctx.config.network.ann_future_skew_secs,
    );
    let signature_valid =
        sig_array(&signature).is_some_and(|sig| Identity::verify(&pubkey, &payload, sig));
    if id_matches && mode_valid && fresh && signature_valid {
        ctx.reputation.lock().await.record_valid(&node_id);
        ctx.dht
            .lock()
            .await
            .apply_ann(src, &node_id, &mode, trust, points, unix_ts);
    } else {
        ctx.reputation.lock().await.record_invalid(src);
        eprintln!("[opennetd] invalid announcement from {src}");
    }
}

/// Verify a signed task bid and return the authenticated consumer node id.
///
/// The signature covers the claimed trust and consumed counters, binding
/// them to the signer's identity so the provider can check the claim
/// against the consumer's last signed announcement. Returns `None` for any
/// signature or identity mismatch.
pub fn verify_bid(
    task_id: &str,
    trust: i64,
    consumed: u64,
    expires_unix: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::bid_signing_payload(task_id, trust, consumed, expires_unix);
    let sig = sig_array(signature)?;
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

/// Verify a signed swarm offer and return the authenticated node id, or
/// `None` when the signature does not match the claimed identity.
pub fn verify_swarm_join(
    program: &str,
    max_shard_ram_mb: u64,
    cpu_cores: u32,
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::swarm_signing_payload(program, max_shard_ram_mb, cpu_cores, unix_ts);
    let sig = sig_array(signature)?;
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

/// Recompute the trust units a task on this provider costs from the
/// provider's own capacity points and the configured default task timeout.
pub fn bid_units(config: &Config, points: u32) -> i64 {
    crate::trust::points::units_for(points, config.network.task_timeout_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn timestamp_accepted_within_age_and_skew() {
        assert!(timestamp_fresh(1000, 1000, 10, 5));
        assert!(timestamp_fresh(990, 1000, 10, 5));
        assert!(timestamp_fresh(1005, 1000, 10, 5));
    }

    #[test]
    fn timestamp_rejected_when_stale_or_from_future() {
        assert!(!timestamp_fresh(989, 1000, 10, 5));
        assert!(!timestamp_fresh(1006, 1000, 10, 5));
        assert!(!timestamp_fresh(0, 10_000, 10, 5));
    }

    #[test]
    fn valid_bid_authenticates_signer_node_id() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let payload = Message::bid_signing_payload("t1", 90, 10, 12345);
        let signature = key.sign(&payload).to_vec();
        let claimed = verify_bid("t1", 90, 10, 12345, &pubkey, &signature);
        assert_eq!(
            claimed.as_deref(),
            Some(Identity::node_id_from_pubkey(&pubkey).as_str())
        );
    }

    #[test]
    fn tampered_claim_breaks_bid_signature() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let payload = Message::bid_signing_payload("t1", 90, 10, 12345);
        let signature = key.sign(&payload).to_vec();
        assert!(verify_bid("t1", 91, 10, 12345, &pubkey, &signature).is_none());
        assert!(verify_bid("t1", 90, 11, 12345, &pubkey, &signature).is_none());
        assert!(verify_bid("t2", 90, 10, 12345, &pubkey, &signature).is_none());
    }

    #[test]
    fn valid_swarm_join_authenticates_signer_node_id() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let payload = Message::swarm_signing_payload("demo", 4096, 8, 12345);
        let signature = key.sign(&payload).to_vec();
        let claimed = verify_swarm_join("demo", 4096, 8, 12345, &pubkey, &signature);
        assert_eq!(
            claimed.as_deref(),
            Some(Identity::node_id_from_pubkey(&pubkey).as_str())
        );
        assert!(verify_swarm_join("other", 4096, 8, 12345, &pubkey, &signature).is_none());
    }

    #[test]
    fn bid_units_follow_configured_task_timeout() {
        let mut config = Config::default();
        config.network.task_timeout_secs = 300;
        assert_eq!(bid_units(&config, 2), 10);
        config.network.task_timeout_secs = 30;
        assert_eq!(bid_units(&config, 2), 2);
        config.network.task_timeout_secs = 0;
        assert_eq!(bid_units(&config, 7), 7);
    }
}
