//! Priority queue entry for pending task bids.

use std::cmp::Ordering;

/// A queued task bid waiting for a free execution slot.
#[derive(PartialEq, Eq)]
pub struct BidEntry {
    pub task_id: String,
    pub from_addr: String,
    pub offer: u64,
    pub expires_unix: u64,
    pub seq: u64,
}

impl PartialOrd for BidEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BidEntry {
    /// BinaryHeap is a max-heap: the highest offer with the earliest arrival
    /// sorts to the top, giving priority to high bidders like in BitTorrent.
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .offer
            .cmp(&self.offer)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
