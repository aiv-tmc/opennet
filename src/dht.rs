//! Peer routing table indexed by network address, with freshness tracking,
//! the last verified announcement fields and swarm offer state.
//!
//! Multicast HELLO datagrams only refresh the freshness of an existing
//! entry: they never erase verified announcement data, because unsigned
//! datagrams must not be able to blank a peer's identity or trust.
//! Iterators return entries in hash order; callers that need recency
//! ordering use `all_peers_by_recency` instead of paying for a sort on
//! every call.

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
    /// announcement or swarm offer arrives.
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
    /// Program this peer offered to host as a swarm shard; empty when the
    /// peer announced no swarm offer or retracted it.
    pub swarm_program: String,
    /// RAM in megabytes the peer offers to one shard.
    pub swarm_ram_mb: u64,
    /// CPU cores the peer offers to shard processes.
    pub swarm_cores: u32,
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
    /// An existing entry keeps every verified field (node id, mode, trust,
    /// points, swarm offer): unsigned discovery datagrams must never reset
    /// them. A new entry starts unverified with empty announcement fields.
    pub fn insert(&mut self, addr: &str) {
        let id = Self::key_for(addr);
        self.routing_table
            .entry(id)
            .and_modify(|peer| peer.last_seen = Instant::now())
            .or_insert_with(|| PeerInfo {
                id,
                addr: addr.to_string(),
                node_id: String::new(),
                mode: "peer".to_string(),
                trust: 0,
                points: 0,
                ann_unix: 0,
                last_seen: Instant::now(),
                swarm_program: String::new(),
                swarm_ram_mb: 0,
                swarm_cores: 0,
            });
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

    /// Apply a verified, signature-authenticated swarm offer to an existing
    /// entry. The offer itself proves the node id through its signature, so
    /// the identity is recorded together with the offer even when no
    /// announcement has been seen yet.
    pub fn apply_swarm(
        &mut self,
        addr: &str,
        node_id: &str,
        program: &str,
        ram_mb: u64,
        cores: u32,
    ) {
        let id = Self::key_for(addr);
        if let Some(peer) = self.routing_table.get_mut(&id) {
            peer.node_id = node_id.to_string();
            peer.swarm_program = program.to_string();
            peer.swarm_ram_mb = ram_mb;
            peer.swarm_cores = cores;
            peer.last_seen = Instant::now();
        }
    }

    /// Clear the swarm offer of every entry whose verified node id matches.
    pub fn clear_swarm_by_node(&mut self, node_id: &str) {
        for peer in self.routing_table.values_mut() {
            if peer.node_id == node_id {
                peer.swarm_program = String::new();
                peer.swarm_ram_mb = 0;
                peer.swarm_cores = 0;
            }
        }
    }

    /// Refresh the timestamp of a peer that sent traffic our way.
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

    /// Find a verified peer by its exact node id.
    pub fn find_by_exact_node_id(&self, node_id: &str) -> Option<PeerInfo> {
        self.routing_table
            .values()
            .find(|peer| peer.node_id == node_id)
            .cloned()
    }

    /// All peers that offered to host `program` as a swarm shard, with the
    /// most recent offer first.
    pub fn swarm_candidates(&self, program: &str) -> Vec<PeerInfo> {
        let mut peers: Vec<PeerInfo> = self
            .routing_table
            .values()
            .filter(|peer| peer.swarm_program == program && !peer.node_id.is_empty())
            .cloned()
            .collect();
        peers.sort_by_key(|peer| std::cmp::Reverse(peer.last_seen));
        peers
    }

    /// Remove one peer from the table by its network address.
    pub fn remove(&mut self, addr: &str) {
        self.routing_table.remove(&Self::key_for(addr));
    }

    /// All known peers in hash order — cheap; no sorting on the hot path.
    /// Callers needing recency order use `all_peers_by_recency`.
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.routing_table.values().cloned().collect()
    }

    /// All known peers ordered by freshness, most recent first; pays one
    /// sort, so use only for display or selection purposes.
    pub fn all_peers_by_recency(&self) -> Vec<PeerInfo> {
        let mut peers = self.all_peers();
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
    fn rediscovery_keeps_verified_fields() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.apply_ann(A, "node-1", "seed", 88, 4, 1_700_000_000);
        dht.apply_swarm(A, "node-1", "demo", 4096, 8);
        // A repeated unsigned HELLO must not blank the verified data.
        dht.insert(A);
        let peer = dht.find_by_exact_node_id("node-1").expect("peer vanished");
        assert_eq!(peer.trust, 88);
        assert_eq!(peer.swarm_program, "demo");
        assert_eq!(peer.swarm_ram_mb, 4096);
    }

    #[test]
    fn insert_creates_unverified_peer_record() {
        let mut dht = Dht::new();
        dht.insert(A);
        let peer = &dht.all_peers()[0];
        assert_eq!(peer.addr, A);
        assert!(peer.node_id.is_empty());
        assert_eq!(peer.trust, 0);
        assert_eq!(dht.peer_count(), 1);
    }

    #[test]
    fn apply_ann_ignores_unknown_address() {
        let mut dht = Dht::new();
        dht.apply_ann(A, "node-1", "peer", 1, 1, 0);
        assert_eq!(dht.peer_count(), 0);
    }

    #[test]
    fn find_by_node_id_matches_prefixes_and_rejects_empty() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert(B);
        dht.apply_ann(A, "abcd1234", "peer", 1, 1, 0);
        dht.apply_ann(B, "abcd5678", "peer", 2, 2, 0);
        assert!(dht.find_by_node_id("abcd").is_some());
        assert!(dht.find_by_node_id("abcd1234").is_some());
        assert!(dht.find_by_node_id("zzzz").is_none());
        assert!(dht.find_by_node_id("").is_none());
    }

    #[test]
    fn swarm_candidates_filter_by_program() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert(B);
        dht.apply_ann(A, "node-a", "peer", 1, 1, 0);
        dht.apply_ann(B, "node-b", "peer", 2, 2, 0);
        dht.apply_swarm(A, "node-a", "demo", 4096, 8);
        dht.apply_swarm(B, "node-b", "other", 1024, 2);
        let candidates = dht.swarm_candidates("demo");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id, "node-a");
    }

    #[test]
    fn swarm_candidates_include_offers_without_announcement() {
        // A signed swarm offer proves the node id by itself, so a peer that
        // only sent an offer must already be placeable.
        let mut dht = Dht::new();
        dht.insert(A);
        dht.apply_swarm(A, "node-x", "demo", 2048, 4);
        let candidates = dht.swarm_candidates("demo");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id, "node-x");
    }

    #[test]
    fn clear_swarm_by_node_removes_only_matching_offers() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert(B);
        dht.apply_ann(A, "node-a", "peer", 1, 1, 0);
        dht.apply_ann(B, "node-b", "peer", 2, 2, 0);
        dht.apply_swarm(A, "node-a", "demo", 4096, 8);
        dht.apply_swarm(B, "node-b", "demo", 2048, 4);
        dht.clear_swarm_by_node("node-a");
        let remaining = dht.swarm_candidates("demo");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].node_id, "node-b");
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
    fn prune_stale_drops_everything_at_zero_age() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert(B);
        dht.prune_stale(Duration::ZERO);
        assert_eq!(dht.peer_count(), 0);
    }

    #[test]
    fn recency_ordering_puts_newest_first() {
        let mut dht = Dht::new();
        dht.insert(A);
        std::thread::sleep(Duration::from_millis(5));
        dht.insert(B);
        let peers = dht.all_peers_by_recency();
        assert_eq!(peers[0].addr, B);
        assert_eq!(peers[1].addr, A);
    }
}
