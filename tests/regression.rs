//! Regression proofs: the four confirmed exploits of the old code now
//! fail. Each test mirrors one attack and asserts the fixed behavior.

use opennet::config::{Limits, TrustCfg};
use opennet::dht::Dht;
use opennet::message::Message;
use opennet::node::state::NodeState;

fn limits() -> Limits {
    Limits {
        cpu_percent: 50,
        ram_mb: 2048,
        max_tasks: 4,
    }
}

fn trust_cfg() -> TrustCfg {
    TrustCfg {
        genesis_trust: 100,
        min_trust: 0,
        points_per_core: 10,
        points_per_gb: 2,
        new_node_units_factor: 2,
    }
}

/// FIX 1: a negative charge no longer mints trust; settlement clamps
/// every charge at zero.
#[test]
fn negative_charge_cannot_mint_trust() {
    let dir = std::env::temp_dir().join(format!("opennet-fix1-{}", std::process::id()));
    let mut state = NodeState::load(
        &dir,
        opennet::node::state::Mode::Peer,
        limits(),
        &trust_cfg(),
    )
    .unwrap();
    state.reserve("t1", 50, 0).unwrap();
    let before = state.trust;
    state.settle("t1", -1_000_000);
    assert_eq!(state.trust, before, "negative charge must not change trust");
}

/// FIX 2: the routing table is capped; a flood of fake addresses
/// evicts unverified seeds instead of growing without bound.
#[test]
fn dht_flood_is_bounded() {
    let mut dht = Dht::new();
    for i in 0..200_000u32 {
        dht.insert(&format!(
            "tcp:10.{}.{}.{}:7000",
            (i >> 16) & 255,
            (i >> 8) & 255,
            i & 255
        ));
    }
    assert!(dht.peer_count() <= 4096, "table must stay capped");
}

/// FIX 3: gossip garbage is refused at the table boundary.
#[test]
fn dht_refuses_garbage_addresses() {
    let mut dht = Dht::new();
    dht.insert("this is not an address");
    dht.insert("tcp:999.999.999.999:99999");
    assert_eq!(dht.peer_count(), 0, "garbage must not be stored");
}

/// FIX 4: an ack signed by a third party cannot countersign a receipt
/// issued for somebody else; the signer must be the recorded consumer.
#[tokio::test]
async fn foreign_ack_is_refused() {
    use opennet::node::identity::Identity;
    use opennet::node::state::ReceiptLog;
    let dir = std::env::temp_dir().join(format!("opennet-fix4-{}", std::process::id()));
    let provider = Identity::generate();
    let consumer = Identity::generate();
    let attacker = Identity::generate();
    let mut log = ReceiptLog::load(&dir).unwrap();
    let ts = 1_700_000_000u64;
    let receipt = Message::Receipt {
        task_id: "task-x".into(),
        provider_node: provider.node_id(),
        billed_secs: 10,
        charge: 50,
        outcome_hash: [1; 32],
        unix_ts: ts,
        pubkey: provider.pubkey(),
        signature: provider
            .sign(&Message::receipt_signing_payload(
                "task-x",
                &provider.node_id(),
                10,
                50,
                &[1; 32],
                ts,
            ))
            .to_vec(),
    };
    log.append(receipt.clone(), &consumer.node_id()).unwrap();
    let hash = opennet::node::state::receipt_hash(&receipt);
    let foreign_ack = Message::ReceiptAck {
        task_id: "task-x".into(),
        receipt_hash: hash,
        unix_ts: ts,
        pubkey: attacker.pubkey(),
        signature: attacker
            .sign(&Message::receipt_ack_signing_payload("task-x", &hash, ts))
            .to_vec(),
    };
    assert!(
        log.record_ack(foreign_ack).is_err(),
        "foreign ack must fail"
    );
    let own_ack = Message::ReceiptAck {
        task_id: "task-x".into(),
        receipt_hash: hash,
        unix_ts: ts,
        pubkey: consumer.pubkey(),
        signature: consumer
            .sign(&Message::receipt_ack_signing_payload("task-x", &hash, ts))
            .to_vec(),
    };
    assert!(
        log.record_ack(own_ack).is_ok(),
        "the true consumer countersigns"
    );
}
