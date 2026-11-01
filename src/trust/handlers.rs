//! Verification of signed announcements, swarm offers, task bids,
//! billing receipts and WAN gossip.

use crate::config::Config;
use crate::daemon::Ctx;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::node::state::Mode;
use std::sync::Arc;

fn sig_array(signature: &[u8]) -> Option<&[u8; 64]> {
    signature.try_into().ok()
}

fn timestamp_fresh(unix_ts: u64, now: u64, max_age_secs: u64, future_skew_secs: u64) -> bool {
    unix_ts <= now + future_skew_secs && now.saturating_sub(unix_ts) <= max_age_secs
}

/// Verify a signed announcement and apply it to the routing table.
pub async fn handle_ann(ctx: &Arc<Ctx>, src: &str, ann: Message) {
    let Message::Ann {
        node_id,
        mode,
        trust,
        points,
        gpus,
        receipt_head,
        unix_ts,
        pubkey,
        signature,
    } = ann
    else {
        return;
    };
    let payload =
        Message::ann_signing_payload(&node_id, &mode, trust, points, gpus, &receipt_head, unix_ts);
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
        ctx.dht.lock().await.apply_ann_ext(
            src,
            &node_id,
            &mode,
            trust,
            points,
            gpus,
            receipt_head,
            unix_ts,
        );
    } else {
        ctx.reputation.lock().await.record_invalid(src);
        eprintln!("[opennetd] invalid announcement from {src}");
    }
}

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

pub fn verify_swarm_join(
    program: &str,
    max_shard_ram_mb: u64,
    cpu_cores: u32,
    gpus: u32,
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload =
        Message::swarm_signing_payload(program, max_shard_ram_mb, cpu_cores, gpus, unix_ts);
    let sig = sig_array(signature)?;
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_receipt(
    task_id: &str,
    provider_node: &str,
    billed_secs: u64,
    charge: i64,
    outcome_hash: &[u8; 32],
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::receipt_signing_payload(
        task_id,
        provider_node,
        billed_secs,
        charge,
        outcome_hash,
        unix_ts,
    );
    let sig = sig_array(signature)?;
    if provider_node != Identity::node_id_from_pubkey(pubkey) {
        return None;
    }
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

pub fn verify_receipt_ack(
    task_id: &str,
    receipt_hash: &[u8; 32],
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::receipt_ack_signing_payload(task_id, receipt_hash, unix_ts);
    let sig = sig_array(signature)?;
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

/// Verify a signed WAN gossip snapshot and return the authenticated
/// sender node id. The snapshot itself carries no identity claims —
/// the signature only proves who relayed it.
pub fn verify_gossip(
    addrs: &[String],
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::gossip_signing_payload(addrs, unix_ts);
    let sig = sig_array(signature)?;
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

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
        let payload = Message::swarm_signing_payload("demo", 4096, 8, 2, 12345);
        let signature = key.sign(&payload).to_vec();
        let claimed = verify_swarm_join("demo", 4096, 8, 2, 12345, &pubkey, &signature);
        assert_eq!(
            claimed.as_deref(),
            Some(Identity::node_id_from_pubkey(&pubkey).as_str())
        );
        assert!(verify_swarm_join("demo", 4096, 8, 3, 12345, &pubkey, &signature).is_none());
    }

    #[test]
    fn valid_receipt_authenticates_provider_and_covers_every_field() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let node = Identity::node_id_from_pubkey(&pubkey);
        let payload = Message::receipt_signing_payload("t1", &node, 12, 24, &[5; 32], 12345);
        let signature = key.sign(&payload).to_vec();
        assert!(
            verify_receipt("t1", &node, 12, 24, &[5; 32], 12345, &pubkey, &signature).is_some()
        );
        assert!(
            verify_receipt("t1", &node, 13, 24, &[5; 32], 12345, &pubkey, &signature).is_none()
        );
        assert!(
            verify_receipt("t1", &node, 12, 25, &[5; 32], 12345, &pubkey, &signature).is_none()
        );
        assert!(
            verify_receipt("t1", &node, 12, 24, &[6; 32], 12345, &pubkey, &signature).is_none()
        );
    }

    #[test]
    fn receipt_signed_for_a_claimed_node_id_is_rejected() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let payload =
            Message::receipt_signing_payload("t1", "someone-else", 12, 24, &[5; 32], 12345);
        let signature = key.sign(&payload).to_vec();
        assert!(verify_receipt(
            "t1",
            "someone-else",
            12,
            24,
            &[5; 32],
            12345,
            &pubkey,
            &signature
        )
        .is_none());
    }

    #[test]
    fn valid_gossip_authenticates_the_relayer() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let addrs = vec!["tcp:203.0.113.7:7000".to_string()];
        let payload = Message::gossip_signing_payload(&addrs, 12345);
        let signature = key.sign(&payload).to_vec();
        assert!(verify_gossip(&addrs, 12345, &pubkey, &signature).is_some());
        let other = vec!["tcp:203.0.113.8:7000".to_string()];
        assert!(verify_gossip(&other, 12345, &pubkey, &signature).is_none());
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
