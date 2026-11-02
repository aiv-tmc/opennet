//! Domain-tagged signing payloads for every signed wire message.
//!
//! Every signature covers the exact postcard-serialized tuple produced
//! here — the domain tag, the protocol version and the complete field
//! set — so no signature verifies against a different message type,
//! version or field set. Callers punish failed verifications against
//! the connection address, never against a claimed node id.

use super::Message;
use super::PROTOCOL_VERSION;

impl Message {
    #[allow(clippy::too_many_arguments)]
    pub fn ann_signing_payload(
        node_id: &str,
        mode: &str,
        trust: i64,
        points: u32,
        gpus: u32,
        receipt_head: &[u8; 32],
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "ann",
            PROTOCOL_VERSION,
            node_id,
            mode,
            trust,
            points,
            gpus,
            receipt_head,
            unix_ts,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn bid_signing_payload(
        task_id: &str,
        trust: i64,
        consumed: u64,
        expires_unix: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "bid",
            PROTOCOL_VERSION,
            task_id,
            trust,
            consumed,
            expires_unix,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn assign_signing_payload(
        task_id: &str,
        command: &str,
        timeout_secs: u64,
        ram_mb: u64,
        gpus: u32,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "assign",
            PROTOCOL_VERSION,
            task_id,
            command,
            timeout_secs,
            ram_mb,
            gpus,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn accept_signing_payload(task_id: &str, unix_ts: u64) -> Vec<u8> {
        postcard::to_allocvec(&("accept", PROTOCOL_VERSION, task_id, unix_ts))
            .expect("signing payload serialization failed")
    }

    pub fn reject_signing_payload(task_id: &str, reason: &str, unix_ts: u64) -> Vec<u8> {
        postcard::to_allocvec(&("reject", PROTOCOL_VERSION, task_id, reason, unix_ts))
            .expect("signing payload serialization failed")
    }

    pub fn result_signing_payload(task_id: &str, outcome_hash: &[u8; 32], unix_ts: u64) -> Vec<u8> {
        postcard::to_allocvec(&("result", PROTOCOL_VERSION, task_id, outcome_hash, unix_ts))
            .expect("signing payload serialization failed")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receipt_signing_payload(
        task_id: &str,
        provider_node: &str,
        billed_secs: u64,
        charge: i64,
        outcome_hash: &[u8; 32],
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "receipt",
            PROTOCOL_VERSION,
            task_id,
            provider_node,
            billed_secs,
            charge,
            outcome_hash,
            unix_ts,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn receipt_ack_signing_payload(
        task_id: &str,
        receipt_hash: &[u8; 32],
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "receipt_ack",
            PROTOCOL_VERSION,
            task_id,
            receipt_hash,
            unix_ts,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn receipt_request_signing_payload(
        request_id: &[u8; 32],
        head_before: &[u8; 32],
        limit: u32,
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "receipt_request",
            PROTOCOL_VERSION,
            request_id,
            head_before,
            limit,
            unix_ts,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn receipt_response_signing_payload(
        request_id: &[u8; 32],
        head_before: &[u8; 32],
        receipts: &[Message],
        head_after: &[u8; 32],
        complete: bool,
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "receipt_response",
            PROTOCOL_VERSION,
            request_id,
            head_before,
            receipts,
            head_after,
            complete,
            unix_ts,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn swarm_signing_payload(
        program: &str,
        max_shard_ram_mb: u64,
        cpu_cores: u32,
        gpus: u32,
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "swarm_join",
            PROTOCOL_VERSION,
            program,
            max_shard_ram_mb,
            cpu_cores,
            gpus,
            unix_ts,
        ))
        .expect("signing payload serialization failed")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn launch_signing_payload(
        plan_id: &str,
        shard_index: u32,
        program: &str,
        artifact_hash: &str,
        layer_from: u32,
        layer_to: u32,
        ram_mb: u64,
        gpus: u32,
        next_addr: &str,
        unix_ts: u64,
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "shard_launch",
            PROTOCOL_VERSION,
            plan_id,
            shard_index,
            program,
            artifact_hash,
            layer_from,
            layer_to,
            ram_mb,
            gpus,
            next_addr,
            unix_ts,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn leave_signing_payload(unix_ts: u64) -> Vec<u8> {
        postcard::to_allocvec(&("swarm_leave", PROTOCOL_VERSION, unix_ts))
            .expect("signing payload serialization failed")
    }

    pub fn conn_hello_signing_payload(
        listen_addr: &str,
        eph_pubkey: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "conn_hello",
            PROTOCOL_VERSION,
            listen_addr,
            eph_pubkey,
            nonce,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn conn_accept_signing_payload(
        dialer_nonce: &[u8; 32],
        acceptor_nonce: &[u8; 32],
        dialer_eph_pubkey: &[u8; 32],
        acceptor_eph_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        postcard::to_allocvec(&(
            "conn_accept",
            PROTOCOL_VERSION,
            dialer_nonce,
            acceptor_nonce,
            dialer_eph_pubkey,
            acceptor_eph_pubkey,
        ))
        .expect("signing payload serialization failed")
    }

    pub fn gossip_signing_payload(addrs: &[String], unix_ts: u64) -> Vec<u8> {
        postcard::to_allocvec(&("peer_gossip", PROTOCOL_VERSION, addrs, unix_ts))
            .expect("signing payload serialization failed")
    }
}
