//! Execution sandbox applied to every spawned child process,
//! best-effort on Linux and a no-op elsewhere.
//!
//! Two isolation profiles are provided:
//!
//! * [`apply_to_command`] — full isolation for compute tasks: fresh
//!   mount, UTS, IPC, PID and network namespaces, a read-only root
//!   with a private tmpfs scratch space, and cgroup v2 limits. Tasks
//!   need no network access, so they get none; the loopback interface
//!   is brought up inside their private network namespace for
//!   programs that expect a working `lo`.
//! * [`apply_to_runner`] — swarm shard runners: the same namespaces
//!   and limits, but **without** a private network namespace. Runners
//!   must reach the worker's listener, which is bound on the daemon's
//!   loopback; isolating them into their own network namespace would
//!   put that listener behind a boundary they cannot cross.
//!
//! Every step degrades gracefully: capabilities the current user
//! lacks (namespace creation, cgroup writes) are skipped with a log
//! line, and the child still runs. On platforms without cgroup v2 the
//! guard is a no-op returning `None`, so callers can use one code
//! path everywhere.
//!
//! The functions take `tokio::process::Command` (the type the
//! executor and the shard worker build) and operate on its `std` half
//! via `as_std_mut()`, where `pre_exec` and friends live. The scratch
//! tmpfs is sized from the effective memory limit: a zero
//! `cfg.memory_mb` inherits `inherit_memory_mb` (the node's task RAM
//! limit), matching the cgroup policy where zero means "inherit".

use crate::config::SandboxCfg;
use std::path::Path;
use tokio::process::Command;

#[cfg(target_os = "linux")]
mod linux;
/// Linux implementation of the cgroup guard.
#[cfg(target_os = "linux")]
pub(crate) use linux::CgroupGuard;
/// No-op cgroup guard on platforms without cgroup v2: attaching always
/// reports "no limits applied", which the callers treat exactly like a
/// failed best-effort attach on Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) use stub::CgroupGuard;

/// Apply the full task isolation profile to `command`.
pub fn apply_to_command(
    command: &mut Command,
    workdir: &Path,
    cfg: &SandboxCfg,
    inherit_memory_mb: u64,
) {
    #[cfg(target_os = "linux")]
    linux::apply(
        command,
        workdir,
        cfg,
        inherit_memory_mb,
        linux::TASK_UNSHARE_FLAGS,
    );
    #[cfg(not(target_os = "linux"))]
    let _ = (command, workdir, cfg, inherit_memory_mb);
}

/// Apply the swarm runner isolation profile to `command`: everything
/// the task profile applies, except the private network namespace.
pub fn apply_to_runner(
    command: &mut Command,
    workdir: &Path,
    cfg: &SandboxCfg,
    inherit_memory_mb: u64,
) {
    #[cfg(target_os = "linux")]
    linux::apply(
        command,
        workdir,
        cfg,
        inherit_memory_mb,
        linux::RUNNER_UNSHARE_FLAGS,
    );
    #[cfg(not(target_os = "linux"))]
    let _ = (command, workdir, cfg, inherit_memory_mb);
}

/// Platform without cgroup v2: the guard never applies limits.
#[cfg(not(target_os = "linux"))]
mod stub {
    use crate::config::SandboxCfg;

    /// No-op cgroup guard; see the crate-level `CgroupGuard` re-export.
    pub struct CgroupGuard;

    impl CgroupGuard {
        /// Always returns `None`: there is no cgroup v2 to attach to.
        pub fn attach(
            _name: &str,
            _pid: u32,
            _cfg: &SandboxCfg,
            _inherit_memory_mb: u64,
            _inherit_cpu_percent: u32,
        ) -> Option<CgroupGuard> {
            None
        }

        /// No-op teardown.
        pub fn teardown(&self) {}
    }
}
