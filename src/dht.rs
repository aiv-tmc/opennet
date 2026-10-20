//! Peer routing table indexed by node id, with freshness tracking.

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
    /// Last announced credit balance of the peer.
    pub credits: u64,
    /// When the peer was last seen via discovery or an announcement.
    pub last_seen: Instant,
}

/// Table of known peers keyed by address hash.
pub struct Dht {
    routing_table: HashMap<[u8; 32], PeerInfo>,
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
    /// The node id stays empty because multicast announcements are unsigned;
    /// it is filled in once a verified signed announcement arrives.
    pub fn insert(&mut self, addr: &str) {
        let id = Self::key_for(addr);
        self.routing_table.insert(
            id,
            PeerInfo {
                id,
                addr: addr.to_string(),
                node_id: String::new(),
                mode: "peer".to_string(),
                credits: 0,
                last_seen: Instant::now(),
            },
        );
    }

    /// Apply fields from a verified announcement to an existing entry.
    pub fn apply_ann(&mut self, addr: &str, node_id: &str, mode: &str, credits: u64) {
        let id = Self::key_for(addr);
        if let Some(peer) = self.routing_table.get_mut(&id) {
            peer.node_id = node_id.to_string();
            peer.mode = mode.to_string();
            peer.credits = credits;
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
    pub fn find_by_node_id(&self, prefix: &str) -> Option<PeerInfo> {
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
        peers.sort_by_key(|peer| peer.last_seen);
        peers
    }

    /// Number of peers currently in the table.
    pub fn peer_count(&self) -> usize {
        self.routing_table.len()
    }
}
