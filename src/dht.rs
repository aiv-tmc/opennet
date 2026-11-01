//! Peer routing table. Entries are keyed by a hash of the dial address
//! and only ever updated from verified announcements or discovery
//! packets carrying the sender's real address, so the table cannot be
//! poisoned with fabricated routes. Swarm offers attach to existing
//! entries only — discovery seeds the address first, mirroring the
//! real HELLO-then-SwarmJoin order.

use crate::node::state::genesis_head;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: [u8; 32],
    pub addr: String,
    pub node_id: String,
    pub mode: String,
    pub trust: i64,
    pub points: u32,
    pub gpus: u32,
    pub receipt_head: [u8; 32],
    pub ann_unix: u64,
    pub last_seen: Instant,
    pub swarm_program: String,
    pub swarm_ram_mb: u64,
    pub swarm_cores: u32,
    pub swarm_gpus: u32,
}

pub struct Dht {
    routing_table: HashMap<[u8; 32], PeerInfo>,
}

impl Dht {
    pub fn new() -> Self {
        Self {
            routing_table: HashMap::new(),
        }
    }

    pub fn key_for(addr: &str) -> [u8; 32] {
        let hash = blake3::hash(addr.as_bytes());
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_bytes());
        id
    }

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
                gpus: 0,
                receipt_head: genesis_head(),
                ann_unix: 0,
                last_seen: Instant::now(),
                swarm_program: String::new(),
                swarm_ram_mb: 0,
                swarm_cores: 0,
                swarm_gpus: 0,
            });
    }

    pub fn apply_ann(
        &mut self,
        addr: &str,
        node_id: &str,
        mode: &str,
        trust: i64,
        points: u32,
        ann_unix: u64,
    ) {
        self.apply_ann_ext(
            addr,
            node_id,
            mode,
            trust,
            points,
            0,
            genesis_head(),
            ann_unix,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_ann_ext(
        &mut self,
        addr: &str,
        node_id: &str,
        mode: &str,
        trust: i64,
        points: u32,
        gpus: u32,
        receipt_head: [u8; 32],
        ann_unix: u64,
    ) {
        let id = Self::key_for(addr);
        if let Some(peer) = self.routing_table.get_mut(&id) {
            peer.node_id = node_id.to_string();
            peer.mode = mode.to_string();
            peer.trust = trust;
            peer.points = points;
            peer.gpus = gpus;
            peer.receipt_head = receipt_head;
            peer.ann_unix = ann_unix;
            peer.last_seen = Instant::now();
        }
    }

    pub fn apply_id(&mut self, addr: &str, id: [u8; 32]) {
        let key = Self::key_for(addr);
        if let Some(peer) = self.routing_table.get_mut(&key) {
            peer.id = id;
            peer.last_seen = Instant::now();
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_swarm(
        &mut self,
        addr: &str,
        node_id: &str,
        program: &str,
        ram_mb: u64,
        cores: u32,
        gpus: u32,
    ) {
        let id = Self::key_for(addr);
        if let Some(peer) = self.routing_table.get_mut(&id) {
            peer.node_id = node_id.to_string();
            peer.swarm_program = program.to_string();
            peer.swarm_ram_mb = ram_mb;
            peer.swarm_cores = cores;
            peer.swarm_gpus = gpus;
            peer.last_seen = Instant::now();
        }
    }

    pub fn clear_swarm_by_node(&mut self, node_id: &str) {
        for peer in self.routing_table.values_mut() {
            if peer.node_id == node_id {
                peer.swarm_program = String::new();
                peer.swarm_ram_mb = 0;
                peer.swarm_cores = 0;
                peer.swarm_gpus = 0;
            }
        }
    }

    pub fn touch(&mut self, addr: &str) {
        let id = Self::key_for(addr);
        if let Some(peer) = self.routing_table.get_mut(&id) {
            peer.last_seen = Instant::now();
        }
    }

    pub fn prune_stale(&mut self, max_age: Duration) {
        self.routing_table
            .retain(|_, peer| peer.last_seen.elapsed() < max_age);
    }

    pub fn remove(&mut self, addr: &str) {
        self.routing_table.remove(&Self::key_for(addr));
    }

    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.routing_table
            .values()
            .filter(|peer| !peer.node_id.is_empty())
            .cloned()
            .collect()
    }

    /// Every known dial address, verified or not — the WAN gossip
    /// snapshot source. Callers cap the result.
    pub fn all_addrs(&self) -> Vec<String> {
        self.routing_table
            .values()
            .map(|peer| peer.addr.clone())
            .collect()
    }

    pub fn all_peers_by_recency(&self) -> Vec<PeerInfo> {
        let mut peers: Vec<PeerInfo> = self.routing_table.values().cloned().collect();
        peers.sort_by_key(|a| std::cmp::Reverse(a.last_seen));
        peers
    }

    pub fn peer_count(&self) -> usize {
        self.routing_table.len()
    }

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

    pub fn find_by_exact_node_id(&self, node_id: &str) -> Option<PeerInfo> {
        self.routing_table
            .values()
            .find(|peer| peer.node_id == node_id)
            .cloned()
    }

    pub fn announced_points(&self, node_id: &str) -> Option<u32> {
        self.routing_table
            .values()
            .find(|peer| peer.node_id == node_id)
            .filter(|peer| peer.points > 0)
            .map(|peer| peer.points)
    }

    pub fn swarm_candidates(&self, program: &str) -> Vec<PeerInfo> {
        let mut candidates: Vec<PeerInfo> = self
            .routing_table
            .values()
            .filter(|peer| peer.swarm_program == program && !peer.node_id.is_empty())
            .cloned()
            .collect();
        candidates.sort_by_key(|a| std::cmp::Reverse(a.swarm_ram_mb));
        candidates
    }
}

impl Default for Dht {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "tcp:10.0.0.1:4000";
    const T: u64 = 1_700_000_000;

    #[test]
    fn apply_ann_ext_records_every_verified_field() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.apply_ann_ext(A, "node-1", "peer", 100, 44, 2, [9; 32], T);
        let peer = dht.find_by_exact_node_id("node-1").unwrap();
        assert_eq!(peer.gpus, 2);
        assert_eq!(peer.receipt_head, [9; 32]);
    }

    #[test]
    fn all_addrs_includes_unverified_seeds() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.insert("tcp:10.0.0.9:4000");
        let addrs = dht.all_addrs();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&A.to_string()));
    }

    #[test]
    fn swarm_offers_record_the_gpu_offer() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.apply_swarm(A, "node-a", "demo", 4096, 8, 2);
        assert_eq!(dht.swarm_candidates("demo")[0].swarm_gpus, 2);
    }

    #[test]
    fn stale_entries_are_pruned_and_touch_refreshes() {
        let mut dht = Dht::new();
        dht.insert(A);
        dht.apply_ann(A, "node-a", "peer", 1, 1, T);
        for peer in dht.routing_table.values_mut() {
            peer.last_seen = Instant::now() - Duration::from_secs(400);
        }
        dht.touch(A);
        dht.prune_stale(Duration::from_secs(300));
        assert_eq!(dht.peer_count(), 1);
    }
}
