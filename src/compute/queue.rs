//! Priority queue entry for pending task bids.

use std::cmp::Ordering;

/// A queued task bid waiting for a free execution slot.
#[derive(PartialEq, Eq, Debug)]
pub struct BidEntry {
    pub task_id: String,
    pub from_node: String,
    pub from_addr: String,
    pub offer: u64,
    /// Trust coefficient claimed by the consumer when the bid was queued.
    pub trust: i64,
    pub expires_unix: u64,
    pub seq: u64,
}

impl PartialOrd for BidEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BidEntry {
    /// BinaryHeap is a max-heap: highest offer first; earlier seq wins ties.
    fn cmp(&self, other: &Self) -> Ordering {
        self.offer
            .cmp(&other.offer)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BinaryHeap;

    fn bid(offer: u64, seq: u64) -> BidEntry {
        BidEntry {
            task_id: format!("t{seq}"),
            from_node: "node".into(),
            from_addr: "1.2.3.4:9".into(),
            offer,
            trust: 100,
            expires_unix: 9_999_999_999,
            seq,
        }
    }

    #[test]
    fn highest_offer_wins() {
        let mut heap = BinaryHeap::new();
        heap.push(bid(5, 1));
        heap.push(bid(20, 2));
        heap.push(bid(10, 3));
        assert_eq!(heap.pop().unwrap().offer, 20);
        assert_eq!(heap.pop().unwrap().offer, 10);
        assert_eq!(heap.pop().unwrap().offer, 5);
    }

    #[test]
    fn earlier_seq_wins_on_tie() {
        let mut heap = BinaryHeap::new();
        heap.push(bid(10, 2));
        heap.push(bid(10, 1));
        assert_eq!(heap.pop().unwrap().seq, 1);
    }
}
