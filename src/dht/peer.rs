//! Data types of the routing table: the per-program swarm offer and
//! the per-address peer entry. Both are plain serializable records;
//! every rule about who may write them lives in `super::Dht`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One signed swarm offer for one program from one peer.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct SwarmOffer {
    /// RAM offered per shard of this program, MB.
    pub ram_mb: u64,
    /// CPU cores offered per shard of this program.
    pub cores: u32,
    /// GPU devices offered per shard of this program; 0 = CPU-only.
    pub gpus: u32,
}

/// One routing-table entry; verified fields come only from signed
/// announcements, gossiped seeds stay empty until one arrives.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Dial address of the peer, the table key.
    pub addr: String,
    /// Verified node id; empty while unverified.
    pub node_id: String,
    /// Verified operating mode name; empty while unverified.
    pub mode: String,
    /// Verified trust coefficient; 0 while unverified.
    pub trust: i64,
    /// Verified capacity points; 0 while unverified or not priced.
    pub points: u32,
    /// Verified GPU offer count; 0 while unverified or CPU-only.
    pub gpus: u32,
    /// Verified receipt journal head; genesis while unverified.
    pub receipt_head: [u8; 32],
    /// Unix time of the last announcement or touch.
    pub last_seen: u64,
    /// Swarm offers keyed by program; empty while none were announced.
    pub swarm: BTreeMap<String, SwarmOffer>,
}

/// Shape-check one dial address: the table only carries `tcp:` targets
/// with a real port and a host that is either an IP literal or a DNS
/// name, so a garbage string can never occupy an entry or be dialed
/// later.
pub fn valid_addr(addr: &str) -> bool {
    let Some(rest) = addr.strip_prefix("tcp:") else {
        return false;
    };
    if rest.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    // Hostname form: `name:port` with a DNS-safe name and a real port.
    let Some((host, port)) = rest.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u16>().is_err() || host.is_empty() || host.len() > 253 {
        return false;
    }
    // A dotted-quad that failed the IP parse above is not a DNS name:
    // all-numeric labels mean a malformed IP literal, not a hostname.
    if host.chars().all(|ch| ch.is_ascii_digit() || ch == '.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}
