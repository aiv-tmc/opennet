//! Wire roundtrip and signing-payload tests.

use super::*;
use crate::compute::TaskOutcome;
use crate::node::identity::Identity;

#[test]
fn every_message_variant_roundtrips_through_postcard() {
    let cases = vec![
        Message::ConnHello {
            version: 7,
            listen_addr: "tcp:127.0.0.1:4000".into(),
            eph_pubkey: [1; 32],
            nonce: [2; 32],
            pubkey: [3; 32],
            signature: vec![4; 64],
        },
        Message::ConnAccept {
            version: 7,
            eph_pubkey: [5; 32],
            nonce: [6; 32],
            pubkey: [7; 32],
            signature: vec![8; 64],
        },
        Message::Ann {
            node_id: "abcd1234".into(),
            mode: "seed".into(),
            trust: -40,
            points: 24,
            gpus: 2,
            receipt_head: [9; 32],
            unix_ts: 1_700_000_000,
            pubkey: [10; 32],
            signature: vec![11; 64],
        },
        Message::TaskBid {
            task_id: "t1".into(),
            trust: 88,
            consumed: 12,
            expires_unix: 9_999_999_999,
            pubkey: [12; 32],
            signature: vec![13; 64],
        },
        Message::TaskAssign {
            task_id: "t2".into(),
            command: "uname -a".into(),
            timeout_secs: 300,
            ram_mb: 4096,
            gpus: 1,
            pubkey: [14; 32],
            signature: vec![15; 64],
        },
        Message::TaskAccept {
            task_id: "t3".into(),
        },
        Message::TaskReject {
            task_id: "t4".into(),
            reason: "busy".into(),
        },
        Message::TaskResult {
            task_id: "t5".into(),
            outcome: TaskOutcome {
                exit_code: 0,
                stdout: "ok".into(),
                stderr: String::new(),
                billed_secs: 12,
            },
        },
        Message::Receipt {
            task_id: "t5".into(),
            provider_node: "node-b".into(),
            billed_secs: 12,
            charge: 24,
            outcome_hash: [16; 32],
            unix_ts: 1_700_000_000,
            pubkey: [17; 32],
            signature: vec![18; 64],
        },
        Message::ReceiptAck {
            task_id: "t5".into(),
            receipt_hash: [19; 32],
            unix_ts: 1_700_000_000,
            pubkey: [20; 32],
            signature: vec![21; 64],
        },
        Message::SwarmJoin {
            program: "demo".into(),
            max_shard_ram_mb: 4096,
            cpu_cores: 8,
            gpus: 2,
            unix_ts: 1_700_000_000,
            pubkey: [22; 32],
            signature: vec![23; 64],
        },
        Message::SwarmLeave {
            unix_ts: 1_700_000_000,
            pubkey: [24; 32],
            signature: vec![25; 64],
        },
        Message::ShardLaunch {
            plan_id: "plan-1".into(),
            shard_index: 2,
            program: "demo".into(),
            artifact_hash: "b3-demo".into(),
            layer_from: 10,
            layer_to: 19,
            ram_mb: 2048,
            gpus: 1,
            next_addr: "tcp:127.0.0.1:5001".into(),
            unix_ts: 1_700_000_000,
            pubkey: [26; 32],
            signature: vec![27; 64],
        },
        Message::ShardReady {
            plan_id: "plan-1".into(),
            shard_index: 2,
        },
        Message::ShardFwd {
            plan_id: "plan-1".into(),
            seq: 7,
            src: 2,
            dst: 3,
            payload: vec![1, 2, 3],
        },
        Message::ShardOut {
            plan_id: "plan-1".into(),
            seq: 1,
            payload: vec![4, 5, 6],
        },
        Message::SwarmDone {
            plan_id: "plan-1".into(),
            reason: String::new(),
        },
        Message::PeerGossip {
            addrs: vec!["tcp:203.0.113.7:7000".into(), "tcp:203.0.113.8:7000".into()],
            unix_ts: 1_700_000_000,
            pubkey: [28; 32],
            signature: vec![29; 64],
        },
    ];
    for message in cases {
        let decoded = Message::decode(&message.encode()).expect("roundtrip");
        let reencoded = decoded.encode();
        assert_eq!(reencoded, message.encode(), "encoding must be canonical");
    }
}

#[test]
fn signing_payloads_are_deterministic_and_domain_separated() {
    let ann = Message::ann_signing_payload("node-1", "peer", 100, 44, 2, &[1; 32], 1_700_000_000);
    let bid = Message::bid_signing_payload("node-1", 100, 0, 1_700_000_000);
    let assign = Message::assign_signing_payload("t1", "echo hi", 60, 0, 0);
    let receipt = Message::receipt_signing_payload("t1", "node-1", 12, 24, &[2; 32], 1_700_000_000);
    let ack = Message::receipt_ack_signing_payload("t1", &[3; 32], 1_700_000_000);
    let launch = Message::launch_signing_payload(
        "plan-1",
        0,
        "demo",
        "b3-demo",
        0,
        10,
        2048,
        1,
        "tcp:127.0.0.1:1",
        1_700_000_000,
    );
    let swarm = Message::swarm_signing_payload("demo", 4096, 8, 2, 1_700_000_000);
    let leave = Message::leave_signing_payload(44);
    let hello = Message::conn_hello_signing_payload("tcp:127.0.0.1:4000", &[1; 32], &[2; 32]);
    let accept = Message::conn_accept_signing_payload(&[1; 32], &[2; 32], &[3; 32], &[4; 32]);
    let gossip =
        Message::gossip_signing_payload(&["tcp:203.0.113.7:7000".to_string()], 1_700_000_000);
    let payloads = [
        &ann, &bid, &assign, &receipt, &ack, &launch, &swarm, &leave, &hello, &accept, &gossip,
    ];
    assert_eq!(
        Message::ann_signing_payload("node-1", "peer", 100, 44, 2, &[1; 32], 1_700_000_000),
        ann
    );
    for (index, payload) in payloads.iter().enumerate() {
        for (other_index, other) in payloads.iter().enumerate() {
            if index != other_index {
                assert_ne!(payload, other, "payloads {index} and {other_index} collide");
            }
        }
    }
    assert_ne!(
        Message::gossip_signing_payload(&["tcp:10.0.0.1:1".to_string()], 1),
        Message::gossip_signing_payload(&["tcp:10.0.0.2:1".to_string()], 1)
    );
}

#[test]
fn signing_payloads_are_sensitive_to_every_field() {
    let base = Message::ann_signing_payload("node-1", "peer", 100, 44, 2, &[1; 32], 1_700_000_000);
    assert_ne!(
        base,
        Message::ann_signing_payload("node-2", "peer", 100, 44, 2, &[1; 32], 1_700_000_000)
    );
    assert_ne!(
        base,
        Message::ann_signing_payload("node-1", "seed", 100, 44, 2, &[1; 32], 1_700_000_000)
    );
    assert_ne!(
        base,
        Message::ann_signing_payload("node-1", "peer", 101, 44, 2, &[1; 32], 1_700_000_000)
    );
    assert_ne!(
        base,
        Message::ann_signing_payload("node-1", "peer", 100, 45, 2, &[1; 32], 1_700_000_000)
    );
    assert_ne!(
        base,
        Message::ann_signing_payload("node-1", "peer", 100, 44, 3, &[1; 32], 1_700_000_000)
    );
    assert_ne!(
        base,
        Message::ann_signing_payload("node-1", "peer", 100, 44, 2, &[2; 32], 1_700_000_000)
    );
    assert_ne!(
        base,
        Message::ann_signing_payload("node-1", "peer", 100, 44, 2, &[1; 32], 1_700_000_001)
    );
}

#[test]
fn real_signatures_verify_against_their_payloads() {
    let identity = Identity::generate();
    let payload =
        Message::ann_signing_payload(&identity.node_id(), "peer", 100, 44, 0, &[0; 32], 42);
    let signature = identity.sign(&payload);
    assert!(Identity::verify(&identity.pubkey(), &payload, &signature));
    let foreign = Identity::generate();
    assert!(!Identity::verify(&foreign.pubkey(), &payload, &signature));
    assert!(!Identity::verify(
        &identity.pubkey(),
        &payload[..payload.len() - 1],
        &signature
    ));
}
