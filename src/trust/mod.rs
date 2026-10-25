//! Trust coefficient economy powering the compute market.
//!
//! Every node carries a local trust coefficient: donating compute raises
//! it, consuming compute lowers it. Providers gate task acceptance on the
//! consumer's signed trust snapshot, so a node that only leeches exhausts
//! its trust and must serve the network to earn more capacity. This module
//! holds the shared clock helper; the pricing rules live in `points` and
//! the wire verification logic lives in `handlers`.

pub mod handlers;
pub mod points;

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in seconds; used to timestamp announcements, bids and
/// reputation records.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
