//! Peer routing table indexed by network address, with freshness tracking
//! and the last verified announcement fields.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Information kept about one known peer.
#[derive(Clone)]
pub struct PeerInfo {
    /// Routing key: blake3 hash of the peer network address.
    pub id: [u8; 32],
    /// Network address in the form `tcp:<ip>:<port>`.
    pub addr: String,
    /// Public node id announced by the peer; empty until the first signed
    /// announcement arrives.
    pub node_id: String,
    /// Last announced operating mode of the peer.
    pub mode: String,
    /// Last announced trust coefficient of the peer.
    pub trust: i64,
    /// Last announced capacity points of the peer's hardware.
    pub points: u32,
    /// Unix timestamp of the last accepted announcement.
    pub ann_unix: u64,
    /// When the peer was last seen via discovery or an announcement.
    pub last_seen: Instant,
}

/// Table of known peers keyed by address hash.
pub struct Dht {
    routing_table: HashMap<[u8; 32], PeerInfo>,
}

impl Default for Dht {
    /// An empty routing table, identical to `Dht::new`.
    fn default() -> Self {
        Self::new()
    }
}

impl Dht {
    pub fn new() -> Self {
        Self {
            routing_table: HashMap::new(),
        }
    }

    /// Derive the routing key for a network address.
    pub fn key_for(addr: &str) -> [u8; 32] {
        let hash = blake3::hash(addr.as_bytes());
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_bytes());
        id
    }

    /// Insert a freshly discovered peer or refresh its timestamp.
    ///
    /// The announcement-derived fields stay empty because multicast
    /// announcements are unsigned; they are filled in once a verified signed
    /// announcement arrives.
    pub fn insert(&mut self, addr: &str) {
        let id = Self::key_for(addr);
        self.routing_table.insert(
            id,
            PeerInfo {
                id,
                addr: addr.to_string(),
                node_id: String::new(),
                mode: "peer".to_string(),
                trust: 0,
                points: 0,
                ann_unix: 0,
                last_seen: Instant::now(),
            },
        );
    }

    /// Apply fields from a verified announcement to an existing entry.
    pub fn apply_ann(
        &mut self,
        addr: &str,
        node_id: &str,
        mode: &str,
        trust: i64,
        points: u32,
        ann_unix: u64,
    ) {
        let id = Self::key_for(addr);
        if let Some(peer) = self.routing_table.get_mut(&id) {
            peer.node_id = node_id.to_string();
            peer.mode = mode.to_string();
            peer.trust = trust;
            peer.points = points;
            peer.ann_unix = ann_unix;
            peer.last_seen = Instant::now();
        }
    }

    /// Refresh the timestamp of a peer that answered a liveness probe.
    pub fn touch(&mut self, addr: &str) {
        let id = Self::key_for(addr);
        if let Some(peer) = self.routing_table.get_mut(&id) {
            peer.last_seen = Instant::now();
        }
    }

    /// Remove peers that have been silent longer than `max_age`.
    pub fn prune_stale(&mut self, max_age: Duration) {
        self.routing_table
            .retain(|_, peer| peer.last_seen.elapsed() <= max_age);
    }

    /// Find the freshest peer whose announced node id starts with `prefix`.
    /// An empty prefix matches every node id and is rejected so callers
    /// never accidentally target an arbitrary peer.
    pub fn find_by_node_id(&self, prefix: &str) -> Option<PeerInfo> {
        if prefix.is_empty() {
            return None;
        }
        self.routing_table
            .values()
            .filter(|peer| !peer.node_id.is_empty() && peer.node_id.starts_with(prefix))
            .max_by_key(|peer| peer.last_seen)
            .cloned()
    }

    /// Remove one peer from the table by its network address.
    pub fn remove(&mut self, addr: &str) {
        self.routing_table.remove(&Self::key_for(addr));
    }

    /// All known peers ordered by freshness, most recent first.
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        let mut peers: Vec<PeerInfo> = self.routing_table.values().cloned().collect();
        peers.sort_by_key(|peer| std::cmp::Reverse(peer.last_seen));
        peers
    }

    /// Number of peers currently in the table.
    pub fn peer_count(&self) -> usize {
        self.routing_table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "tcp:10.0.0.1:4001";
    const B: &str = "tcp:10.0.0.2:4002";

    #[test]
    fn key_for_is_stable_and_distinct() {
        assert_eq!(Dht::key_for(A), Dht::key_for(A));
        assert_ne!(Dht::key_for(A), Dht::key_for(B));
    }

    #[test]
    fn insert_creates_unverified_peer_record() {
        let mut dht = Dht::new();
        dht.insert(A);
        let peer = &dht.all_peers()[0];
        assert_eq!(peer.addr, A);
        assert!(peer.node_id.is_empty());
        assert_eq!(peer.mode, "peer");
        assert_eq!(peer.trust, 0);
        assert_eq!(peer.points, 0);
        assert_eq!(peer.ann_unix, 0);
        assert_eq!(dht.peer_count(), 1);
    }

    #[test]
    fn apply_ann_updates_verified_fields() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.apply_ann(A, "node-1", "seed", 88, 4, 1_700_000_000);
        let peer = dht.find_by_node_id("node-1").expect("peer vanished");
        assert_eq!(peer.node_id, "node-1");
        assert_eq!(peer.mode, "seed");
        assert_eq!(peer.trust, 88);
        assert_eq!(peer.points, 4);
        assert_eq!(peer.ann_unix, 1_700_000_000);
    }

    #[test]
    fn apply_ann_ignores_unknown_address() {
        let mut dht = Dht::new();
        dht.apply_ann(A, "node-1", "peer", 1, 1, 0);
        assert_eq!(dht.peer_count(), 0);
    }

    #[test]
    fn find_by_node_id_matches_prefixes() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert(B);
        dht.apply_ann(A, "abcd1234", "peer", 1, 1, 0);
        dht.apply_ann(B, "abcd5678", "peer", 2, 2, 0);
        let found = dht.find_by_node_id("abcd").expect("prefix lookup failed");
        assert!(found.node_id.starts_with("abcd"));
        assert!(dht.find_by_node_id("abcd1234").is_some());
        assert!(dht.find_by_node_id("zzzz").is_none());
        assert!(dht.find_by_node_id("").is_none());
    }

    #[test]
    fn freshest_peer_wins_prefix_lookup() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert(B);
        dht.apply_ann(A, "abcd1111", "peer", 1, 1, 0);
        dht.apply_ann(B, "abcd2222", "peer", 2, 2, 0);
        dht.touch(A);
        let found = dht.find_by_node_id("abcd").expect("prefix lookup failed");
        assert_eq!(found.node_id, "abcd1111");
    }

    #[test]
    fn remove_deletes_the_peer_record() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.remove(A);
        assert_eq!(dht.peer_count(), 0);
        dht.remove(A); // removing twice must not panic
    }

    #[test]
    fn all_peers_orders_most_recent_first() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert(B);
        dht.touch(A);
        let peers = dht.all_peers();
        assert_eq!(peers[0].addr, A);
        assert_eq!(peers[1].addr, B);
    }

    #[test]
    fn prune_stale_drops_everything_at_zero_age() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert(B);
        dht.prune_stale(Duration::ZERO);
        assert_eq!(dht.peer_count(), 0);
    }

    #[test]
    fn prune_stale_keeps_fresh_peers() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.prune_stale(Duration::from_secs(60));
        assert_eq!(dht.peer_count(), 1);
    }
}
