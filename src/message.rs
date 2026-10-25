//! Wire protocol messages exchanged between nodes over persistent TCP
//! connections.
//!
//! Announcements and task bids carry ed25519 signatures so every node can
//! verify the claimed identity, trust coefficient and consumption counter.
//! Signatures travel as `Vec<u8>` because serde supports fixed arrays only
//! up to 32 elements; verification converts them back to `[u8; 64]`.
//! Multicast discovery datagrams stay outside this protocol and unsigned.

use crate::compute::TaskOutcome;
use serde::{Deserialize, Serialize};

/// Messages carried inside length-prefixed TCP frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Liveness probe; the receiver must answer with `Pong`.
    Ping,
    /// Answer to a `Ping` probe.
    Pong,
    /// First frame on every connection; tells the receiver which address
    /// (`tcp:<ip>:<port>`) the sender wants to be known as, so the inbound
    /// socket can be registered under the peer's listen address and replies
    /// can reuse the same connection.
    ConnHello {
        /// Listen address of the sender in `tcp:<ip>:<port>` form.
        listen_addr: String,
    },
    /// Periodic signed announcement of identity, mode, trust coefficient
    /// and capacity points, timestamped so captured copies cannot be
    /// replayed in later heartbeat rounds.
    Ann {
        /// Public node identifier: first 8 bytes of blake3 of `pubkey`.
        node_id: String,
        /// Operating mode of the sender: peer, seed or leech.
        mode: String,
        /// Current trust coefficient of the sender.
        trust: i64,
        /// Capacity points of the sender's hardware.
        points: u32,
        /// Unix time the announcement was signed.
        unix_ts: u64,
        /// ed25519 public key of the sender.
        pubkey: [u8; 32],
        /// ed25519 signature over `ann_signing_payload`.
        signature: Vec<u8>,
    },
    /// Signed request to run one task; the signature binds the consumer's
    /// claimed trust and consumed counters to its identity.
    TaskBid {
        /// Unique identifier of the task.
        task_id: String,
        /// Trust coefficient of the consumer after reserving this task.
        trust: i64,
        /// Cumulative trust units the consumer had already consumed before
        /// this task.
        consumed: u64,
        /// Unix time after which the bid may be discarded.
        expires_unix: u64,
        /// ed25519 public key of the consumer.
        pubkey: [u8; 32],
        /// ed25519 signature over `bid_signing_payload`.
        signature: Vec<u8>,
    },
    /// Provider accepts the bid and reserves an execution slot for it.
    TaskAccept {
        /// Identifier of the accepted task.
        task_id: String,
    },
    /// Provider refuses the bid.
    TaskReject {
        /// Identifier of the refused task.
        task_id: String,
        /// Human-readable explanation for the refusal.
        reason: String,
    },
    /// Consumer hands the actual work to the provider.
    TaskAssign {
        /// Identifier of the task being assigned.
        task_id: String,
        /// Shell command executed in a fresh working directory.
        command: String,
        /// Hard wall-clock limit for the execution, in seconds.
        timeout_secs: u64,
    },
    /// Provider reports the finished task so the consumer can charge the
    /// reserved trust units to itself and the provider can credit itself.
    TaskResult {
        /// Identifier of the finished task.
        task_id: String,
        /// Exit status and captured output of the command.
        outcome: TaskOutcome,
    },
}

impl Message {
    /// Serialize the message to bincode bytes; serialization of this enum is infallible.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("message serialization failed")
    }

    /// Deserialize a message; returns `None` for malformed input.
    pub fn decode(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Build the exact byte sequence signed inside an `Ann` message.
    pub fn ann_signing_payload(
        node_id: &str,
        mode: &str,
        trust: i64,
        points: u32,
        unix_ts: u64,
    ) -> Vec<u8> {
        bincode::serialize(&("ann", node_id, mode, trust, points, unix_ts))
            .expect("payload serialization failed")
    }

    /// Build the exact byte sequence signed inside a `TaskBid` message.
    pub fn bid_signing_payload(
        task_id: &str,
        trust: i64,
        consumed: u64,
        expires_unix: u64,
    ) -> Vec<u8> {
        bincode::serialize(&("bid", task_id, trust, consumed, expires_unix))
            .expect("payload serialization failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_conn_hello() {
        let msg = Message::ConnHello {
            listen_addr: "tcp:10.0.0.1:4000".into(),
        };
        match Message::decode(&msg.encode()) {
            Some(Message::ConnHello { listen_addr }) => {
                assert_eq!(listen_addr, "tcp:10.0.0.1:4000");
            }
            _ => panic!("decode failed"),
        }
    }

    #[test]
    fn roundtrip_signed_variants() {
        let ann = Message::Ann {
            node_id: "nid".into(),
            mode: "peer".into(),
            trust: 80,
            points: 44,
            unix_ts: 1_700_000_000,
            pubkey: [7u8; 32],
            signature: vec![9u8; 64],
        };
        match Message::decode(&ann.encode()) {
            Some(Message::Ann { trust, points, .. }) => {
                assert_eq!(trust, 80);
                assert_eq!(points, 44);
            }
            _ => panic!("decode failed"),
        }
        let bid = Message::TaskBid {
            task_id: "t1".into(),
            trust: 50,
            consumed: 20,
            expires_unix: 9_999_999_999,
            pubkey: [7u8; 32],
            signature: vec![9u8; 64],
        };
        match Message::decode(&bid.encode()) {
            Some(Message::TaskBid {
                trust, consumed, ..
            }) => {
                assert_eq!(trust, 50);
                assert_eq!(consumed, 20);
            }
            _ => panic!("decode failed"),
        }
    }

    #[test]
    fn signing_payloads_are_stable() {
        let a = Message::ann_signing_payload("nid", "peer", 100, 44, 1_700_000_000);
        let b = Message::ann_signing_payload("nid", "peer", 100, 44, 1_700_000_000);
        assert_eq!(a, b);
        let c = Message::bid_signing_payload("t1", 50, 20, 9_999_999_999);
        let d = Message::bid_signing_payload("t1", 50, 20, 9_999_999_999);
        assert_eq!(c, d);
        assert_ne!(a, c);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Message::decode(&[0xff, 0x00, 0x01]).is_none());
    }
}
