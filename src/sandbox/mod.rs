//! Task sandbox: OS-level isolation for executed commands, best-effort
//! on Linux and a no-op elsewhere. The Linux implementation unshares
//! namespaces per the profile (mount, UTS, IPC, PID, net for tasks),
//! mounts a fresh tmpfs at the workdir, makes the read-only root stick
//! and moves the child into a cgroup v2 subtree when one is writable;
//! anywhere else the sandbox degrades to running the command with the
//! working directory and environment isolation only.
//!
//! Every path is best-effort: failures degrade to the no-op profile
//! and are logged, so a task is never lost because the sandbox broke —
//! only because the task itself failed. When the daemon runs without
//! root, namespace creation first enters a user namespace and maps the
//! current uid/gid to namespace root, which grants the capabilities
//! the mount steps need on kernels that allow unprivileged user
//! namespaces; on kernels that forbid them the sandbox degrades
//! exactly like any other missing capability. The capability reported
//! by `opennetctl status` always reflects the effective profile.

use crate::config::{Config, SandboxCfg};
use std::path::Path;
use tokio::process::Command;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod linux {
    use super::SandboxCfg;
    use std::path::Path;
    use tokio::process::Command;

    /// Isolation is unavailable: the pre-exec hook is a no-op.
    pub fn apply(
        _command: &mut Command,
        _workdir: &Path,
        _cfg: &SandboxCfg,
        _inherit_memory_mb: u64,
        _flags: libc::c_int,
    ) {
    }

    /// No-op cgroup guard for platforms without cgroup v2.
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

pub(crate) use linux::CgroupGuard;

/// Namespace flags for compute tasks: the child cannot use the host
/// network, so a fresh private network namespace is included.
/// Linux-only: the constants do not exist anywhere else.
#[cfg(target_os = "linux")]
pub const TASK_UNSHARE_FLAGS: libc::c_int = libc::CLONE_NEWNS
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET;
/// Namespace flags for swarm runners: identical to the task profile
/// minus `CLONE_NEWNET`, so the runner can connect to the worker's
/// loopback listener in the daemon's network namespace. Linux-only.
#[cfg(target_os = "linux")]
pub const RUNNER_UNSHARE_FLAGS: libc::c_int =
    libc::CLONE_NEWNS | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC | libc::CLONE_NEWPID;

/// Apply the full task isolation profile to `command`: namespaces,
/// read-only root, private tmpfs scratch space and environment scrub.
pub fn apply_to_command(
    command: &mut Command,
    workdir: &Path,
    cfg: &SandboxCfg,
    inherit_memory_mb: u64,
) {
    #[cfg(target_os = "linux")]
    linux::apply(command, workdir, cfg, inherit_memory_mb, TASK_UNSHARE_FLAGS);
    #[cfg(not(target_os = "linux"))]
    let _ = (command, workdir, cfg, inherit_memory_mb);
}

/// Apply the swarm runner isolation profile to `command`: the same
/// namespaces and limits, but without the private network namespace.
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
        RUNNER_UNSHARE_FLAGS,
    );
    #[cfg(not(target_os = "linux"))]
    let _ = (command, workdir, cfg, inherit_memory_mb);
}

/// One human-readable sandbox capability line for `opennetctl status`:
/// what the config asks for and what the platform can honor.
pub fn capability_line(config: &Config) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        let namespaces = config.sandbox.namespaces;
        let cgroup = config.sandbox.cgroup;
        match (namespaces, cgroup) {
            (true, true) => "active (namespaces + cgroup)",
            (true, false) => "active (namespaces, cgroup disabled)",
            (false, true) => "degraded (cgroup limits only)",
            (false, false) => "disabled (no isolation)",
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if config.sandbox.namespaces || config.sandbox.cgroup {
            "degraded (no-op sandbox: no namespace support on this platform)"
        } else {
            "disabled (no isolation)"
        }
    }
}
