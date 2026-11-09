//! Routing-table tests: address validation, capacity bounds with
//! unverified-first eviction, verified-peer protection and the
//! per-peer swarm offer cap.

use super::*;

/// Insert `n` distinct well-formed seed addresses.
fn seed_many(dht: &mut Dht, n: usize) {
    for i in 0..n {
        dht.insert(&format!("tcp:10.0.{}.{}:9000", i / 256, i % 256));
    }
}

#[test]
fn malformed_addresses_are_refused() {
    let mut dht = Dht::new();
    dht.insert("not-an-address");
    dht.insert("tcp:");
    dht.insert("tcp:999.999.999.999:1");
    dht.insert("udp:127.0.0.1:9000");
    assert_eq!(dht.peer_count(), 0);
    dht.insert("tcp:127.0.0.1:9000");
    assert_eq!(dht.peer_count(), 1);
}

#[test]
fn flood_evicts_unverified_but_never_verified_peers() {
    let mut dht = Dht::new();
    // One verified peer that must survive any flood.
    dht.apply_ann(
        "tcp:192.168.1.10:9000",
        "node-a",
        "peer",
        100,
        24,
        crate::trust::now_unix(),
    );
    seed_many(&mut dht, MAX_PEERS + 500);
    assert!(dht.peer_count() <= MAX_PEERS);
    assert!(dht.find_by_exact_node_id("node-a").is_some());
}

#[test]
fn table_of_only_verified_peers_refuses_new_seeds() {
    let mut dht = Dht::new();
    for i in 0..MAX_PEERS {
        let addr = format!("tcp:10.1.{}.{}:9000", i / 256, i % 256);
        dht.apply_ann(&addr, &format!("node-{i}"), "peer", 100, 24, crate::trust::now_unix());
    }
    assert_eq!(dht.peer_count(), MAX_PEERS);
    dht.insert("tcp:10.9.9.9:9000");
    assert_eq!(dht.peer_count(), MAX_PEERS);
    assert!(dht.find_by_addr("tcp:10.9.9.9:9000").is_none());
}

#[test]
fn prune_drops_silent_entries() {
    let mut dht = Dht::new();
    dht.insert("tcp:127.0.0.1:9000");
    dht.apply_ann(
        "tcp:127.0.0.1:9001",
        "node-b",
        "peer",
        100,
        24,
        crate::trust::now_unix(),
    );
    // Age the verified entry by hand: announcements always carry a
    // fresh last_seen, so the test moves the clock back directly.
    dht.peers
        .get_mut("tcp:127.0.0.1:9001")
        .expect("entry exists")
        .last_seen = 1;
    dht.prune(60);
    assert!(dht.find_by_addr("tcp:127.0.0.1:9001").is_none());
    assert_eq!(dht.peer_count(), 1);
}

#[test]
fn swarm_offers_are_capped_per_peer() {
    let mut dht = Dht::new();
    for i in 0..(MAX_SWARM_PROGRAMS_PER_PEER + 10) {
        dht.apply_swarm(
            "tcp:127.0.0.1:9000",
            "node-c",
            &format!("prog-{i}"),
            512,
            1,
            0,
        );
    }
    let peer = dht.find_by_addr("tcp:127.0.0.1:9000").unwrap();
    assert_eq!(peer.swarm.len(), MAX_SWARM_PROGRAMS_PER_PEER);
    // Re-announcing a known program still updates the offer.
    dht.apply_swarm("tcp:127.0.0.1:9000", "node-c", "prog-0", 1024, 2, 0);
    let peer = dht.find_by_addr("tcp:127.0.0.1:9000").unwrap();
    assert_eq!(peer.swarm.get("prog-0").unwrap().ram_mb, 1024);
}

#[test]
fn borrowed_swarm_announcement_cannot_rebind_an_entry() {
    let mut dht = Dht::new();
    dht.apply_swarm("tcp:127.0.0.1:9000", "node-c", "prog", 512, 1, 0);
    dht.apply_swarm("tcp:127.0.0.1:9000", "node-d", "prog2", 512, 1, 0);
    let peer = dht.find_by_addr("tcp:127.0.0.1:9000").unwrap();
    assert_eq!(peer.node_id, "node-c");
    assert!(!peer.swarm.contains_key("prog2"));
}
