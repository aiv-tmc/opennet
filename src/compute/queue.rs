//! Expiring priority queue of accepted bids awaiting assignment.
//!
//! Bids are ordered by reservation size, highest first, with earlier
//! expiry as the tiebreaker so the most valuable and the most urgent
//! work is served first. Expired entries are skipped on pop and dropped
//! by periodic purges.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// One accepted bid waiting for its task assignment.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QueuedBid {
    /// Unique identifier of the task.
    pub task_id: String,
    /// Trust units reserved for this task.
    pub units: i64,
    /// Unix time after which the bid may be discarded.
    pub expires_unix: u64,
}

impl Ord for QueuedBid {
    /// BinaryHeap pops the greatest element: order by units descending and,
    /// for equal units, by expiry ascending so the soonest-expiring bid of
    /// the same price is served first.
    fn cmp(&self, other: &Self) -> Ordering {
        self.units
            .cmp(&other.units)
            .then_with(|| other.expires_unix.cmp(&self.expires_unix))
    }
}

impl PartialOrd for QueuedBid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority queue of accepted bids keyed by task id.
pub struct BidQueue {
    heap: BinaryHeap<QueuedBid>,
}

impl Default for BidQueue {
    /// An empty queue, identical to `BidQueue::new`.
    fn default() -> Self {
        Self::new()
    }
}

impl BidQueue {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
        }
    }

    /// Insert one accepted bid.
    pub fn push(&mut self, bid: QueuedBid) {
        self.heap.push(bid);
    }

    /// Remove the bid of one task id; used when an assignment supersedes
    /// the queue entry.
    pub fn remove(&mut self, task_id: &str) {
        self.heap.retain(|bid| bid.task_id != task_id);
    }

    /// Pop the highest-priority bid that has not expired at `now`.
    pub fn pop_fresh(&mut self, now: u64) -> Option<QueuedBid> {
        while let Some(bid) = self.heap.pop() {
            if bid.expires_unix > now {
                return Some(bid);
            }
        }
        None
    }

    /// Drop every bid whose expiry has passed at `now`.
    pub fn purge_expired(&mut self, now: u64) {
        self.heap.retain(|bid| bid.expires_unix > now);
    }

    /// Number of queued bids.
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Whether the queue holds no bids.
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_units_win_and_expired_entries_are_skipped() {
        let mut queue = BidQueue::new();
        queue.push(QueuedBid {
            task_id: "cheap".into(),
            units: 5,
            expires_unix: 1000,
        });
        queue.push(QueuedBid {
            task_id: "rich".into(),
            units: 50,
            expires_unix: 900,
        });
        queue.push(QueuedBid {
            task_id: "stale".into(),
            units: 99,
            expires_unix: 10,
        });
        let first = queue.pop_fresh(500).expect("queue empty");
        assert_eq!(first.task_id, "rich");
        let second = queue.pop_fresh(500).expect("queue empty");
        assert_eq!(second.task_id, "cheap");
        assert!(queue.pop_fresh(500).is_none());
    }

    #[test]
    fn equal_units_pop_the_soonest_expiry_first() {
        let mut queue = BidQueue::new();
        queue.push(QueuedBid {
            task_id: "later".into(),
            units: 10,
            expires_unix: 900,
        });
        queue.push(QueuedBid {
            task_id: "sooner".into(),
            units: 10,
            expires_unix: 800,
        });
        assert_eq!(queue.pop_fresh(500).unwrap().task_id, "sooner");
        assert_eq!(queue.pop_fresh(500).unwrap().task_id, "later");
    }

    #[test]
    fn remove_drops_only_the_matching_bid() {
        let mut queue = BidQueue::new();
        queue.push(QueuedBid {
            task_id: "a".into(),
            units: 1,
            expires_unix: 1000,
        });
        queue.push(QueuedBid {
            task_id: "b".into(),
            units: 2,
            expires_unix: 1000,
        });
        queue.remove("a");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop_fresh(0).unwrap().task_id, "b");
    }

    #[test]
    fn purge_expired_drops_stale_bids_only() {
        let mut queue = BidQueue::new();
        queue.push(QueuedBid {
            task_id: "old".into(),
            units: 1,
            expires_unix: 10,
        });
        queue.push(QueuedBid {
            task_id: "new".into(),
            units: 2,
            expires_unix: 1000,
        });
        queue.purge_expired(500);
        assert_eq!(queue.len(), 1);
    }
}
