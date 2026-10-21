//! Wire protocol messages exchanged between nodes over TCP.
//!
//! Announcements and credit transfers carry ed25519 signatures so every
//! node can verify the claimed identity and balance movements. Signatures
//! travel as `Vec<u8>` because serde supports fixed arrays only up to 32
//! elements; the daemon converts them to `[u8; 64]` before verification.

use crate::compute::TaskOutcome;
use serde::{Deserialize, Serialize};

/// Messages carried inside length-prefixed TCP frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Liveness probe; the receiver must answer with `Pong`.
    Ping,
    /// Answer to a `Ping` probe.
    Pong,
    /// Periodic signed node announcement of identity, mode and credit balance.
    Ann {
        /// Public node identifier: first 8 bytes of blake3 of `pubkey`.
        node_id: String,
        /// Operating mode of the sender: peer, seed or leech.
        mode: String,
        /// Credit balance of the sender.
        credits: u64,
        /// ed25519 public key of the sender.
        pubkey: [u8; 32],
        /// ed25519 signature over `ann_signing_payload`.
        signature: Vec<u8>,
    },
    /// Signed credit transfer from one node to another.
    Credit {
        /// Unique identifier of the transfer, echoed in the acknowledgement.
        task_id: String,
        /// Node id of the payer.
        from_node: String,
        /// Node id of the payee.
        to_node: String,
        /// Number of credits moved.
        amount: u64,
        /// ed25519 public key of the payer.
        pubkey: [u8; 32],
        /// ed25519 signature over `credit_signing_payload`.
        signature: Vec<u8>,
    },
    /// Reply confirming or rejecting a received credit transfer.
    CreditAck {
        /// Identifier of the transfer being acknowledged.
        task_id: String,
        /// True when the transfer was applied to the local balance.
        accepted: bool,
    },
    /// Offer to pay `offer` credits for one task execution on the receiver.
    TaskBid {
        /// Unique identifier of the task.
        task_id: String,
        /// Payment promised to the executor on completion.
        offer: u64,
        /// Unix time after which the bid may be discarded.
        expires_unix: u64,
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
    /// Provider reports the finished task so the consumer can pay.
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
    pub fn ann_signing_payload(node_id: &str, mode: &str, credits: u64) -> Vec<u8> {
        bincode::serialize(&("ann", node_id, mode, credits))
            .expect("payload serialization failed")
    }

    /// Build the exact byte sequence signed inside a `Credit` message.
    pub fn credit_signing_payload(
        task_id: &str,
        from_node: &str,
        to_node: &str,
        amount: u64,
    ) -> Vec<u8> {
        bincode::serialize(&("credit", task_id, from_node, to_node, amount))
            .expect("payload serialization failed")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ping() {
        let msg = Message::Ping;
        let bytes = msg.encode();
        assert!(matches!(Message::decode(&bytes), Some(Message::Ping)));
    }

    #[test]
    fn roundtrip_task_bid() {
        let msg = Message::TaskBid {
            task_id: "abc".into(),
            offer: 42,
            expires_unix: 1000,
        };
        let bytes = msg.encode();
        match Message::decode(&bytes) {
            Some(Message::TaskBid {
                task_id,
                offer,
                expires_unix,
            }) => {
                assert_eq!(task_id, "abc");
                assert_eq!(offer, 42);
                assert_eq!(expires_unix, 1000);
            }
            _ => panic!("decode failed"),
        }
    }

    #[test]
    fn signing_payloads_are_stable() {
        let a = Message::ann_signing_payload("nid", "peer", 100);
        let b = Message::ann_signing_payload("nid", "peer", 100);
        assert_eq!(a, b);
        let c = Message::credit_signing_payload("t1", "from", "to", 5);
        let d = Message::credit_signing_payload("t1", "from", "to", 5);
        assert_eq!(c, d);
        assert_ne!(a, c);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Message::decode(&[0xff, 0x00, 0x01]).is_none());
    }
}