//! GPU device pool of the compute scheduler: the offered device
//! indices minus the sets currently bound to running tasks. Allocation
//! is deterministic (lowest free indices first), and every allocation
//! is paired with exactly one `free` when the task finishes, so the
//! pool can never leak devices across task lifecycles.

use crate::daemon::Ctx;
use std::sync::Arc;

/// Offered GPU devices and the free subset.
#[derive(Default)]
pub(super) struct GpuPool {
    /// Currently unbound device indices, sorted ascending.
    free: Vec<u32>,
}

impl GpuPool {
    /// A pool over exactly the offered devices.
    pub(super) fn new(offered: Vec<u32>) -> GpuPool {
        let mut free = offered;
        free.sort_unstable();
        GpuPool { free }
    }

    /// Number of currently unbound devices.
    pub(super) fn len(&self) -> usize {
        self.free.len()
    }

    /// Bind up to `count` devices (lowest free indices first) and
    /// return them; the scheduler only calls this after checking
    /// `len() >= count`.
    pub(super) fn alloc(&mut self, count: usize) -> Vec<u32> {
        let take = count.min(self.free.len());
        self.free.drain(..take).collect()
    }

    /// Return one task's devices to the pool.
    pub(super) fn free(&mut self, mut devices: Vec<u32>) {
        self.free.append(&mut devices);
        self.free.sort_unstable();
        self.free.dedup();
    }
}

/// Device indices offered to remote tasks: the explicit configured
/// list, or the first `count` indices when no list is given. An
/// explicit list lets a node donate specific cards while keeping
/// others (e.g. the desktop's display GPU) out of the pool.
pub(super) async fn offered_gpus(ctx: &Arc<Ctx>) -> Vec<u32> {
    configured_devices(ctx.config.gpu.count, &ctx.config.gpu.devices)
}

/// Pure device-list resolution shared by the scheduler and its tests:
/// an explicit list wins, otherwise the first `count` indices.
fn configured_devices(count: u32, devices: &[u32]) -> Vec<u32> {
    if !devices.is_empty() {
        devices.to_vec()
    } else {
        (0..count).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_binds_lowest_free_indices_and_free_returns_them() {
        let mut pool = GpuPool::new(vec![3, 1, 2]);
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.alloc(2), vec![1, 2]);
        assert_eq!(pool.len(), 1);
        // Releasing a mid-set device and allocating again stays
        // deterministic.
        pool.free(vec![1]);
        assert_eq!(pool.alloc(2), vec![1, 3]);
        assert_eq!(pool.len(), 0);
        pool.free(vec![1, 2, 3]);
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.alloc(5), vec![1, 2, 3]);
    }

    #[test]
    fn configured_devices_follow_the_explicit_list_first() {
        assert_eq!(configured_devices(2, &[]), vec![0, 1]);
        assert_eq!(configured_devices(8, &[2, 4]), vec![2, 4]);
        assert_eq!(configured_devices(0, &[]), Vec::<u32>::new());
    }
}
