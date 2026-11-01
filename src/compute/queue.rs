//! Scheduling queues: the accepted-bid priority queue (highest units
//! first, soonest expiry first on ties) and the pending-launch heap
//! (highest reservation first, FIFO on ties). All ordering happens
//! through `Ord` implementations, so the scheduler never re-sorts
//! explicitly.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use crate::compute::Launch;

/// One accepted bid in the priority queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedBid {
    pub task_id: String,
    pub units: i64,
    pub expires_unix: u64,
}

impl Ord for QueuedBid {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap by units: the most valuable bid pops first. Ties
        // break by expiry (sooner expiry first), then by task id so the
        // order stays total and deterministic.
        self.units
            .cmp(&other.units)
            .then_with(|| other.expires_unix.cmp(&self.expires_unix))
            .then_with(|| other.task_id.cmp(&self.task_id))
    }
}

impl PartialOrd for QueuedBid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority queue of accepted bids.
pub struct BidQueue {
    heap: BinaryHeap<QueuedBid>,
}

impl BidQueue {
    pub fn new() -> BidQueue {
        BidQueue {
            heap: BinaryHeap::new(),
        }
    }

    /// Queue one accepted bid.
    pub fn push(&mut self, bid: QueuedBid) {
        self.heap.push(bid);
    }

    /// Pop the most valuable bid that has not expired; expired entries
    /// are discarded silently.
    pub fn pop_fresh(&mut self, now_unix: u64) -> Option<QueuedBid> {
        while let Some(bid) = self.heap.pop() {
            if bid.expires_unix > now_unix {
                return Some(bid);
            }
        }
        None
    }

    /// Remove one task id (its assignment arrived or was rejected).
    pub fn remove(&mut self, task_id: &str) {
        let bids: Vec<QueuedBid> = self
            .heap
            .drain()
            .filter(|bid| bid.task_id != task_id)
            .collect();
        self.heap = bids.into();
    }

    /// Drop all expired entries.
    pub fn purge_expired(&mut self, now_unix: u64) {
        let bids: Vec<QueuedBid> = self
            .heap
            .drain()
            .filter(|bid| bid.expires_unix > now_unix)
            .collect();
        self.heap = bids.into();
    }

    /// Number of queued bids.
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// True when no bids are queued.
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

impl Default for BidQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// One launch parked in the pending heap, waiting for a free executor
/// slot. Ordered by reservation size descending; equal reservations pop
/// in insertion order (FIFO) via a monotonically increasing counter.
#[derive(Clone, Debug)]
pub struct PendingLaunch {
    pub units: i64,
    pub order: u64,
    pub from_node: String,
    pub launch: Launch,
}

impl PartialEq for PendingLaunch {
    fn eq(&self, other: &Self) -> bool {
        self.units == other.units && self.order == other.order
    }
}

impl Eq for PendingLaunch {}

impl Ord for PendingLaunch {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap by units, FIFO on ties: the counter is assigned at
        // insertion time, so a smaller counter means "inserted earlier"
        // and must pop first.
        self.units
            .cmp(&other.units)
            .then_with(|| other.order.cmp(&self.order))
    }
}

impl PartialOrd for PendingLaunch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_units_pop_first() {
        let mut queue = BidQueue::new();
        queue.push(QueuedBid {
            task_id: "small".into(),
            units: 5,
            expires_unix: 1000,
        });
        queue.push(QueuedBid {
            task_id: "big".into(),
            units: 50,
            expires_unix: 1000,
        });
        let first = queue.pop_fresh(0).expect("queue empty");
        assert_eq!(first.task_id, "big");
    }

    #[test]
    fn expired_bids_are_skipped() {
        let mut queue = BidQueue::new();
        queue.push(QueuedBid {
            task_id: "old".into(),
            units: 100,
            expires_unix: 10,
        });
        queue.push(QueuedBid {
            task_id: "fresh".into(),
            units: 1,
            expires_unix: 1000,
        });
        let first = queue.pop_fresh(50).expect("queue empty");
        assert_eq!(first.task_id, "fresh");
        assert!(queue.pop_fresh(50).is_none());
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
            expires_unix: 100,
        });
        let first = queue.pop_fresh(50).expect("queue empty");
        assert_eq!(first.task_id, "sooner");
    }

    #[test]
    fn remove_drops_only_the_named_bid() {
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
    fn pending_launches_pop_highest_units_first_and_fifo_on_ties() {
        let launch = |task_id: &str| Launch {
            task_id: task_id.to_string(),
            return_addr: "tcp:127.0.0.1:1".into(),
            from_node: "consumer".into(),
            units: 0,
            command: "echo".into(),
            timeout_secs: 60,
            ram_mb: 0,
            gpus: Vec::new(),
        };
        let mut heap = BinaryHeap::new();
        heap.push(PendingLaunch {
            units: 5,
            order: 1,
            from_node: "n1".into(),
            launch: launch("cheap-1"),
        });
        heap.push(PendingLaunch {
            units: 50,
            order: 2,
            from_node: "n2".into(),
            launch: launch("expensive"),
        });
        heap.push(PendingLaunch {
            units: 5,
            order: 3,
            from_node: "n3".into(),
            launch: launch("cheap-2"),
        });
        assert_eq!(heap.pop().unwrap().launch.task_id, "expensive");
        assert_eq!(heap.pop().unwrap().launch.task_id, "cheap-1");
        assert_eq!(heap.pop().unwrap().launch.task_id, "cheap-2");
    }
}
