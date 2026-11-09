//! Peer routing table: verified announcements applied to hash-keyed
//! entries, with one signed swarm offer per program merged into each
//! entry so a node can host several programs at once.
//!
//! Entries start unverified (a gossiped or statically seeded address):
//! only the address is known and every verified field stays empty
//! until a signed announcement arrives for that address. This module
//! owns no identity logic — callers verify signatures and freshness
//! before calling `apply_ann*`, so everything stored here is already
//! authenticated.
//!
//! The table is a bounded resource: `insert` refuses malformed
//! addresses outright and, at capacity, evicts the stalest unverified
//! entry before admitting a new seed — a gossip flood can never grow
//! the table without limit. Swarm offers are likewise capped per peer.

mod peer;

pub use peer::{valid_addr, PeerInfo, SwarmOffer};

use std::collections::HashMap;

/// Hard cap on routing-table entries. LAN tables are tens of entries;
/// the cap only bites an active flood, and admission then evicts the
/// stalest unverified seed rather than a verified peer.
const MAX_PEERS: usize = 4096;

/// Hard cap on swarm programs one peer may publish: a peer announcing
/// unlimited programs would otherwise grow its entry without limit.
const MAX_SWARM_PROGRAMS_PER_PEER: usize = 64;

/// The routing table: entries keyed by address, plus a recency ring
/// used for gossip and freshest-first listings.
pub struct Dht {
    /// All entries, verified and unverified, keyed by address.
    peers: HashMap<String, PeerInfo>,
    /// Addresses in touch order; the tail is the most recently seen.
    recency: Vec<String>,
}

impl Default for Dht {
    fn default() -> Self {
        Self::new()
    }
}

impl Dht {
    /// An empty table.
    pub fn new() -> Dht {
        Dht {
            peers: HashMap::new(),
            recency: Vec::new(),
        }
    }

    /// Seed an unverified entry (gossip or static seed): only the
    /// address is recorded; verified fields fill in from the first
    /// announcement. Malformed addresses are refused. At capacity the
    /// stalest unverified entry is evicted first; a table of verified
    /// peers refuses the seed.
    pub fn insert(&mut self, addr: &str) {
        if self.peers.contains_key(addr) {
            return;
        }
        if !valid_addr(addr) {
            return;
        }
        if self.peers.len() >= MAX_PEERS && !self.evict_stalest_unverified() {
            return;
        }
        let peer = PeerInfo {
            addr: addr.to_string(),
            node_id: String::new(),
            mode: String::new(),
            trust: 0,
            points: 0,
            gpus: 0,
            receipt_head: crate::node::state::genesis_head(),
            last_seen: crate::trust::now_unix(),
            swarm: Default::default(),
        };
        self.recency.push(addr.to_string());
        self.peers.insert(addr.to_string(), peer);
    }

    /// Evict the oldest unverified entry, if any.
    fn evict_stalest_unverified(&mut self) -> bool {
        let victim = self
            .recency
            .iter()
            .find(|addr| {
                self.peers
                    .get(*addr)
                    .is_some_and(|peer| peer.node_id.is_empty())
            })
            .cloned();
        let Some(victim) = victim else {
            return false;
        };
        self.peers.remove(&victim);
        self.recency.retain(|known| known != &victim);
        true
    }

    /// Apply one signed announcement (callers verified signature and
    /// freshness); the short form carries no GPU offer.
    pub fn apply_ann(
        &mut self,
        addr: &str,
        node_id: &str,
        mode: &str,
        trust: i64,
        points: u32,
        unix_ts: u64,
    ) {
        self.apply_ann_ext(
            addr,
            node_id,
            mode,
            trust,
            points,
            0,
            crate::node::state::genesis_head(),
            unix_ts,
        );
    }

    /// Apply one signed announcement carrying the GPU offer and the
    /// receipt journal head; the entry becomes verified and moves to
    /// the recency tail.
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
        unix_ts: u64,
    ) {
        if !self.peers.contains_key(addr) {
            self.insert(addr);
        }
        let Some(peer) = self.peers.get_mut(addr) else {
            return;
        };
        peer.node_id = node_id.to_string();
        peer.mode = mode.to_string();
        peer.trust = trust;
        peer.points = points;
        peer.gpus = gpus;
        peer.receipt_head = receipt_head;
        peer.last_seen = unix_ts.max(peer.last_seen);
        self.recency.retain(|known| known != addr);
        self.recency.push(addr.to_string());
    }

    /// Drop entries silent for longer than the given age.
    pub fn prune(&mut self, max_age_secs: u64) {
        let now = crate::trust::now_unix();
        let stale: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, peer)| now.saturating_sub(peer.last_seen) > max_age_secs)
            .map(|(addr, _)| addr.clone())
            .collect();
        for addr in stale {
            self.peers.remove(&addr);
            self.recency.retain(|known| known != &addr);
        }
    }

    /// Number of known entries, verified and unverified.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Find one peer by node-id prefix; ambiguous prefixes yield nothing.
    pub fn find_by_node_id(&self, prefix: &str) -> Option<PeerInfo> {
        let mut matches = self
            .peers
            .values()
            .filter(|peer| !peer.node_id.is_empty() && peer.node_id.starts_with(prefix));
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first.clone())
    }

    /// Find one peer by its exact node id.
    pub fn find_by_exact_node_id(&self, node_id: &str) -> Option<PeerInfo> {
        self.peers
            .values()
            .find(|peer| peer.node_id == node_id)
            .cloned()
    }

    /// Find one entry by its dial address.
    pub fn find_by_addr(&self, addr: &str) -> Option<PeerInfo> {
        self.peers.get(addr).cloned()
    }

    /// Every verified peer.
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .values()
            .filter(|peer| !peer.node_id.is_empty())
            .cloned()
            .collect()
    }

    /// Every verified peer ordered by announcement recency, oldest first.
    pub fn all_peers_by_recency(&self) -> Vec<PeerInfo> {
        self.recency
            .iter()
            .filter_map(|addr| self.peers.get(addr))
            .filter(|peer| !peer.node_id.is_empty())
            .cloned()
            .collect()
    }

    /// Every known address for gossip snapshots and leave broadcasts.
    pub fn all_addrs(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }

    /// Announced capacity points of one node id; `None` while the node
    /// is unverified or has not announced a positive price.
    pub fn announced_points(&self, node_id: &str) -> Option<u32> {
        self.peers
            .values()
            .find(|peer| peer.node_id == node_id)
            .filter(|peer| peer.points > 0)
            .map(|peer| peer.points)
    }

    /// Merge one signed swarm offer into the entry for `addr`, keyed
    /// by program: one node can publish several programs, and a
    /// re-announcement for one program never clobbers the others. A
    /// borrowed announcement never rebinds an entry that already
    /// belongs to a different verified node id.
    pub fn apply_swarm(
        &mut self,
        addr: &str,
        node_id: &str,
        program: &str,
        ram_mb: u64,
        cores: u32,
        gpus: u32,
    ) {
        if !self.peers.contains_key(addr) {
            self.insert(addr);
        }
        let Some(peer) = self.peers.get_mut(addr) else {
            return;
        };
        if !peer.node_id.is_empty() && peer.node_id != node_id {
            return;
        }
        if !peer.swarm.contains_key(program) && peer.swarm.len() >= MAX_SWARM_PROGRAMS_PER_PEER {
            return;
        }
        peer.node_id = node_id.to_string();
        peer.last_seen = crate::trust::now_unix();
        peer.swarm.insert(
            program.to_string(),
            SwarmOffer {
                ram_mb,
                cores,
                gpus,
            },
        );
        self.recency.retain(|known| known != addr);
        self.recency.push(addr.to_string());
    }

    /// Drop every swarm offer of one node (signed retraction received).
    pub fn clear_swarm_by_node(&mut self, node_id: &str) {
        for peer in self.peers.values_mut() {
            if peer.node_id == node_id {
                peer.swarm.clear();
            }
        }
    }

    /// Placement candidates: verified peers offering `program`, most
    /// recently announced first.
    pub fn swarm_candidates(&self, program: &str) -> Vec<PeerInfo> {
        self.all_peers_by_recency()
            .into_iter()
            .filter(|peer| peer.swarm.contains_key(program))
            .collect()
    }
}

#[cfg(test)]
mod tests;
