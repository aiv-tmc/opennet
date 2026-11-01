//! Pure signature verification for every signed wire message.
//!
//! Each function recomputes the exact domain-tagged signing payload
//! from the decoded fields and returns the signer node id on success.
//! Every payload covers the message type tag, the protocol version and
//! the complete field set, so no signature verifies against a
//! different message type, version or field set. Callers punish failed
//! verifications against the connection address, never against a
//! claimed node id.

use crate::message::Message;
use crate::node::identity::Identity;

fn sig_array(signature: &[u8]) -> Option<&[u8; 64]> {
    signature.try_into().ok()
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

/// Verify one signed TaskAccept and return the accepting provider's
/// node id; the payload binds the task id and the timestamp.
pub fn verify_accept(
    task_id: &str,
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::accept_signing_payload(task_id, unix_ts);
    let sig = sig_array(signature)?;
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

/// Verify one signed TaskReject and return the rejecting provider's
/// node id; the payload binds the task id, the reason and the
/// timestamp.
pub fn verify_reject(
    task_id: &str,
    reason: &str,
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::reject_signing_payload(task_id, reason, unix_ts);
    let sig = sig_array(signature)?;
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

/// Verify one signed TaskResult and return the reporting provider's
/// node id; the payload binds the task id and the outcome hash, which
/// commits to the exit code and both captured output streams.
pub fn verify_result(
    task_id: &str,
    outcome_hash: &[u8; 32],
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::result_signing_payload(task_id, outcome_hash, unix_ts);
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

pub fn verify_receipt_request(
    request_id: &[u8; 32],
    head_before: &[u8; 32],
    limit: u32,
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::receipt_request_signing_payload(request_id, head_before, limit, unix_ts);
    let sig = sig_array(signature)?;
    Identity::verify(pubkey, &payload, sig).then(|| Identity::node_id_from_pubkey(pubkey))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_receipt_response(
    request_id: &[u8; 32],
    head_before: &[u8; 32],
    receipts: &[Message],
    head_after: &[u8; 32],
    complete: bool,
    unix_ts: u64,
    pubkey: &[u8; 32],
    signature: &[u8],
) -> Option<String> {
    let payload = Message::receipt_response_signing_payload(
        request_id,
        head_before,
        receipts,
        head_after,
        complete,
        unix_ts,
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
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
    fn valid_accept_authenticates_the_provider() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let payload = Message::accept_signing_payload("t1", 12345);
        let signature = key.sign(&payload).to_vec();
        assert!(verify_accept("t1", 12345, &pubkey, &signature).is_some());
        assert!(verify_accept("t2", 12345, &pubkey, &signature).is_none());
    }

    #[test]
    fn valid_reject_authenticates_the_provider_and_reason() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let payload = Message::reject_signing_payload("t1", "busy", 12345);
        let signature = key.sign(&payload).to_vec();
        assert!(verify_reject("t1", "busy", 12345, &pubkey, &signature).is_some());
        assert!(verify_reject("t1", "free", 12345, &pubkey, &signature).is_none());
    }

    #[test]
    fn valid_result_authenticates_the_provider_and_outcome_hash() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let payload = Message::result_signing_payload("t1", &[9; 32], 12345);
        let signature = key.sign(&payload).to_vec();
        assert!(verify_result("t1", &[9; 32], 12345, &pubkey, &signature).is_some());
        assert!(verify_result("t1", &[8; 32], 12345, &pubkey, &signature).is_none());
    }

    #[test]
    fn valid_swarm_join_authenticates_signer_node_id() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let payload = Message::swarm_signing_payload("demo", 4096, 8, 2, 12345);
        let signature = key.sign(&payload).to_vec();
        assert!(verify_swarm_join("demo", 4096, 8, 2, 12345, &pubkey, &signature).is_some());
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
            verify_receipt("t1", &node, 12, 24, &[6; 32], 12345, &pubkey, &signature).is_none()
        );
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
    fn receipt_response_roundtrip_verifies() {
        let key = test_key();
        let pubkey = key.verifying_key().to_bytes();
        let receipts = Vec::new();
        let payload = Message::receipt_response_signing_payload(
            &[1; 32], &[2; 32], &receipts, &[3; 32], true, 12345,
        );
        let signature = key.sign(&payload).to_vec();
        assert!(verify_receipt_response(
            &[1; 32], &[2; 32], &receipts, &[3; 32], true, 12345, &pubkey, &signature
        )
        .is_some());
        assert!(verify_receipt_response(
            &[9; 32], &[2; 32], &receipts, &[3; 32], true, 12345, &pubkey, &signature
        )
        .is_none());
    }
}
