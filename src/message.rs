//! Wire protocol: one `Message` enum postcard-encoded onto the
//! transport. Signed variants carry the ed25519 public key and
//! signature inline; verification always recomputes the domain-tagged
//! signing payload (see `signing.rs`) from the decoded fields, so a
//! signature never covers bytes the receiver cannot reconstruct.
//!
//! Protocol version 9 hardens the compute market by signing every
//! bid-decision and result frame: TaskAccept, TaskReject and TaskResult
//! all carry the provider's public key, a timestamp and a signature
//! over the task id (and the outcome hash for results), so a frame
//! injected from a connection sharing the same listener port cannot
//! complete a consumer's waiter.

use serde::{Deserialize, Serialize};

/// Bump on every wire-incompatible change; the transport refuses to
/// establish sessions with a different version.
pub const PROTOCOL_VERSION: u16 = 9;

/// One frame on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    ConnHello {
        version: u16,
        listen_addr: String,
        eph_pubkey: [u8; 32],
        nonce: [u8; 32],
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    ConnAccept {
        version: u16,
        eph_pubkey: [u8; 32],
        nonce: [u8; 32],
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    Ann {
        node_id: String,
        mode: String,
        trust: i64,
        points: u32,
        gpus: u32,
        receipt_head: [u8; 32],
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    TaskBid {
        task_id: String,
        trust: i64,
        consumed: u64,
        expires_unix: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    TaskAssign {
        task_id: String,
        command: String,
        timeout_secs: u64,
        ram_mb: u64,
        gpus: u32,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    TaskAccept {
        task_id: String,
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    TaskReject {
        task_id: String,
        reason: String,
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    TaskResult {
        task_id: String,
        outcome: crate::compute::TaskOutcome,
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    Receipt {
        task_id: String,
        provider_node: String,
        billed_secs: u64,
        charge: i64,
        outcome_hash: [u8; 32],
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    ReceiptAck {
        task_id: String,
        receipt_hash: [u8; 32],
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    /// Signed request for one window of the peer's receipt journal,
    /// starting after `head_before` (use the genesis head for a
    /// full-chain audit). The response echoes `request_id`.
    ReceiptRequest {
        request_id: [u8; 32],
        head_before: [u8; 32],
        limit: u32,
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    /// Signed window of the journal: the receipts after `head_before`,
    /// the chain head after the last returned receipt, and `complete`
    /// when the window reached the chain end. The requestor recomputes
    /// the chaining hash over the window and compares `head_after`.
    ReceiptResponse {
        request_id: [u8; 32],
        head_before: [u8; 32],
        receipts: Vec<Message>,
        head_after: [u8; 32],
        complete: bool,
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    SwarmJoin {
        program: String,
        max_shard_ram_mb: u64,
        cpu_cores: u32,
        gpus: u32,
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    SwarmLeave {
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    ShardLaunch {
        plan_id: String,
        shard_index: u32,
        program: String,
        artifact_hash: String,
        layer_from: u32,
        layer_to: u32,
        ram_mb: u64,
        gpus: u32,
        next_addr: String,
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
    ShardReady {
        plan_id: String,
        shard_index: u32,
    },
    ShardFwd {
        plan_id: String,
        seq: u64,
        src: u32,
        dst: u32,
        payload: Vec<u8>,
    },
    ShardOut {
        plan_id: String,
        seq: u64,
        payload: Vec<u8>,
    },
    SwarmDone {
        plan_id: String,
        reason: String,
    },
    PeerGossip {
        addrs: Vec<String>,
        unix_ts: u64,
        pubkey: [u8; 32],
        signature: Vec<u8>,
    },
}

impl Message {
    /// Canonical postcard encoding; the signing payloads are built from
    /// the same field order, so signatures stay valid across processes.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("message serialization failed")
    }

    /// Decode one frame; garbage maps to `None` and is counted as a
    /// wire failure by the dispatcher.
    pub fn decode(data: &[u8]) -> Option<Message> {
        postcard::from_bytes(data).ok()
    }
}

mod signing;
#[cfg(test)]
mod tests;
