//! Wire protocol messages exchanged between nodes over persistent TCP
//! connections.
//!
//! Announcements, swarm offers, task bids and task assignments carry ed25519
//! signatures so every node can verify the claimed identity and counters.
//! Signatures travel as `Vec<u8>` because serde supports fixed arrays only
//! up to 32 elements; verification converts them back to `[u8; 64]`.
//! Messages and signing payloads are encoded with postcard; the encoding
//! is part of the wire format, so all nodes must run a matching
//! `PROTOCOL_VERSION`. Multicast discovery datagrams stay outside this
//! protocol and unsigned.

use crate::compute::TaskOutcome;
use serde::{Deserialize, Serialize};

/// Wire protocol version negotiated in every `ConnHello`; connections whose
/// version differs are dropped before any frame is exchanged.
pub const PROTOCOL_VERSION: u16 = 2;

/// Messages carried inside length-prefixed TCP frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// First frame on every connection; carries the protocol version and
    /// the address (`tcp:<ip>:<port>`) the sender wants to be known as, so
    /// the inbound socket can be registered under the peer's listen address
    /// and replies can reuse the same connection.
    ConnHello {
        /// Wire protocol version of the sender.
        version: u16,
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
    /// Signed offer to host one shard of a shared program; sent only by
    /// nodes whose user explicitly opted in through the swarm consent.
    SwarmJoin {
        /// Name of the program the sender agreed to host.
        program: String,
        /// RAM in megabytes the sender offers to one shard.
        max_shard_ram_mb: u64,
        /// CPU cores the sender offers to shard processes.
        cpu_cores: u32,
        /// Unix time the offer was signed.
        unix_ts: u64,
        /// ed25519 public key of the sender.
        pubkey: [u8; 32],
        /// ed25519 signature over `swarm_signing_payload`.
        signature: Vec<u8>,
    },
    /// Signed retraction of a previously announced swarm offer.
    SwarmLeave {
        /// Unix time the retraction was signed.
        unix_ts: u64,
        /// ed25519 public key of the sender.
        pubkey: [u8; 32],
        /// ed25519 signature over `leave_signing_payload`.
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
    /// Consumer hands the actual work to the provider; signed by the same
    /// key that made the accepted bid, so only the authenticated consumer
    /// can trigger execution of a task id.
    TaskAssign {
        /// Identifier of the task being assigned.
        task_id: String,
        /// Shell command executed in a fresh working directory.
        command: String,
        /// Hard wall-clock limit for the execution, in seconds.
        timeout_secs: u64,
        /// ed25519 public key of the consumer.
        pubkey: [u8; 32],
        /// ed25519 signature over `assign_signing_payload`.
        signature: Vec<u8>,
    },
    /// Provider reports the finished task so the consumer can charge the
    /// reserved trust units to itself and the provider can credit itself.
    TaskResult {
        /// Identifier of the finished task.
        task_id: String,
        /// Exit status, captured output and billed duration.
        outcome: TaskOutcome,
    },
    /// Coordinator instruction to launch one shard of a placement plan.
    ShardLaunch {
        /// Identifier of the placement plan.
        plan_id: String,
        /// Zero-based index of the shard in the pipeline.
        shard_index: u32,
        /// Name of the shared program being launched.
        program: String,
        /// Expected blake3 hex digest of the artifact.
        artifact_hash: String,
        /// First layer (inclusive) owned by this shard.
        layer_from: u32,
        /// Last layer (exclusive) owned by this shard.
        layer_to: u32,
        /// RAM budget for the shard process, in megabytes.
        ram_mb: u64,
        /// Listen address of the next shard in the pipeline in
        /// `tcp:<ip>:<port>` form; empty for the last shard.
        next_addr: String,
        /// Unix time the launch was signed.
        unix_ts: u64,
        /// ed25519 public key of the coordinator.
        pubkey: [u8; 32],
        /// ed25519 signature over `launch_signing_payload`.
        signature: Vec<u8>,
    },
    /// Shard process is up and ready to receive traffic.
    ShardReady {
        /// Identifier of the placement plan.
        plan_id: String,
        /// Index of the reporting shard.
        shard_index: u32,
    },
    /// Pipeline payload relayed between shards (activation tensors for an
    /// LLM, work chunks for any other sharded program).
    ShardFwd {
        /// Identifier of the placement plan.
        plan_id: String,
        /// Monotonic sequence number within the plan.
        seq: u64,
        /// Index of the shard that produced the payload.
        src: u32,
        /// Index of the shard that must receive the payload.
        dst: u32,
        /// Opaque payload interpreted by the shard runner.
        payload: Vec<u8>,
    },
    /// Final shard delivers output tokens (or any other result payload)
    /// to the coordinator.
    ShardOut {
        /// Identifier of the placement plan.
        plan_id: String,
        /// Monotonic sequence number within the plan.
        seq: u64,
        /// Opaque result payload produced by the last shard.
        payload: Vec<u8>,
    },
    /// Coordinator or shard terminates the plan; every node holding state
    /// for the plan releases it and kills local shard processes.
    SwarmDone {
        /// Identifier of the placement plan.
        plan_id: String,
        /// Human-readable termination reason.
        reason: String,
    },
}

impl Message {
    /// Serialize the message to postcard bytes; serialization of this enum
    /// is infallible for every representable value.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("message serialization failed")
    }

    /// Deserialize a message; returns `None` for malformed input.
    pub fn decode(data: &[u8]) -> Option<Self> {
        postcard::from_bytes(data).ok()
    }

    /// Build the exact byte sequence signed inside an `Ann` message.
    pub fn ann_signing_payload(
        node_id: &str,
        mode: &str,
        trust: i64,
        points: u32,
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&("ann", node_id, mode, trust, points, unix_ts))
            .expect("payload serialization failed")
    }

    /// Build the exact byte sequence signed inside a `SwarmJoin` message.
    pub fn swarm_signing_payload(
        program: &str,
        max_shard_ram_mb: u64,
        cpu_cores: u32,
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&("swarm", program, max_shard_ram_mb, cpu_cores, unix_ts))
            .expect("payload serialization failed")
    }

    /// Build the exact byte sequence signed inside a `SwarmLeave` message.
    pub fn leave_signing_payload(unix_ts: u64) -> Vec<u8> {
        postcard::to_allocvec(&("leave", unix_ts)).expect("payload serialization failed")
    }

    /// Build the exact byte sequence signed inside a `TaskBid` message.
    pub fn bid_signing_payload(
        task_id: &str,
        trust: i64,
        consumed: u64,
        expires_unix: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&("bid", task_id, trust, consumed, expires_unix))
            .expect("payload serialization failed")
    }

    /// Build the exact byte sequence signed inside a `TaskAssign` message.
    pub fn assign_signing_payload(task_id: &str, command: &str, timeout_secs: u64) -> Vec<u8> {
        postcard::to_allocvec(&("assign", task_id, command, timeout_secs))
            .expect("payload serialization failed")
    }

    /// Build the exact byte sequence signed inside a `ShardLaunch` message.
    #[allow(clippy::too_many_arguments)]
    pub fn launch_signing_payload(
        plan_id: &str,
        shard_index: u32,
        program: &str,
        artifact_hash: &str,
        layer_from: u32,
        layer_to: u32,
        next_addr: &str,
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "launch",
            plan_id,
            shard_index,
            program,
            artifact_hash,
            layer_from,
            layer_to,
            next_addr,
            unix_ts,
        ))
        .expect("payload serialization failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_conn_hello_with_version() {
        let msg = Message::ConnHello {
            version: PROTOCOL_VERSION,
            listen_addr: "tcp:10.0.0.1:4000".into(),
        };
        match Message::decode(&msg.encode()) {
            Some(Message::ConnHello {
                version,
                listen_addr,
            }) => {
                assert_eq!(version, PROTOCOL_VERSION);
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
        let assign = Message::TaskAssign {
            task_id: "t1".into(),
            command: "echo hi".into(),
            timeout_secs: 60,
            pubkey: [7u8; 32],
            signature: vec![9u8; 64],
        };
        match Message::decode(&assign.encode()) {
            Some(Message::TaskAssign { command, .. }) => assert_eq!(command, "echo hi"),
            _ => panic!("decode failed"),
        }
        let launch = Message::ShardLaunch {
            plan_id: "p1".into(),
            shard_index: 2,
            program: "demo".into(),
            artifact_hash: "abc".into(),
            layer_from: 10,
            layer_to: 20,
            ram_mb: 4096,
            next_addr: "tcp:10.0.0.9:5000".into(),
            unix_ts: 1_700_000_000,
            pubkey: [7u8; 32],
            signature: vec![9u8; 64],
        };
        match Message::decode(&launch.encode()) {
            Some(Message::ShardLaunch {
                layer_to,
                next_addr,
                ..
            }) => {
                assert_eq!(layer_to, 20);
                assert_eq!(next_addr, "tcp:10.0.0.9:5000");
            }
            _ => panic!("decode failed"),
        }
    }

    #[test]
    fn signing_payloads_are_stable_and_distinct() {
        let a = Message::ann_signing_payload("nid", "peer", 100, 44, 1_700_000_000);
        let b = Message::ann_signing_payload("nid", "peer", 100, 44, 1_700_000_000);
        assert_eq!(a, b);
        let c = Message::bid_signing_payload("t1", 50, 20, 9_999_999_999);
        let d = Message::bid_signing_payload("t1", 50, 20, 9_999_999_999);
        assert_eq!(c, d);
        assert_ne!(a, c);
        let e = Message::assign_signing_payload("t1", "echo hi", 60);
        let f = Message::assign_signing_payload("t1", "echo hi", 60);
        assert_eq!(e, f);
        assert_ne!(c, e);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Message::decode(&[0xff, 0x00, 0x01]).is_none());
    }
}
