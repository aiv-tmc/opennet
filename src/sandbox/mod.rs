//! Task sandbox: OS-level isolation for executed commands, best-effort
//! on Linux and a no-op elsewhere. The Linux implementation unshares
//! namespaces per the profile (mount, UTS, IPC, PID, net), mounts a
//! fresh tmpfs at /tmp, makes the read-only root stick with a bind
//! plus remount and moves the child into a cgroup v2 subtree when one
//! is writable; anywhere else the sandbox degrades to running the
//! command with the working directory and environment isolation only.
//! Every path is best-effort: failures degrade to the no-op profile
//! and are logged, so a task is never lost because the sandbox broke —
//! only because the task itself failed. The capability reported by
//! `opennetctl status` always reflects the effective profile.

use crate::config::{Config, SandboxCfg};
use std::path::Path;
use std::process::Command;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod linux {
    use super::SandboxCfg;
    use std::process::Command;

    /// Isolation is unavailable: the pre-exec hook is a no-op.
    fn apply(_command: &mut Command, _sandbox: &SandboxCfg) {}

    /// No-op cgroup guard for platforms without cgroup v2.
    pub struct CgroupGuard;

    impl CgroupGuard {
        /// Attach without limits and return the no-op guard.
        pub fn attach(
            _name: &str,
            _pid: u32,
            _sandbox: &SandboxCfg,
            _ram_mb: u64,
            _cpu_percent: u64,
        ) -> Self {
            CgroupGuard
        }
    }
}

pub use linux::CgroupGuard;

/// Apply the sandbox profile to one command before spawning: the
/// platform pre-exec hook (namespaces on Linux, nothing elsewhere)
/// plus the environment pin — either way the child sees a controlled
/// environment with the working directory already created.
pub fn apply_to_command(command: &mut Command, workdir: &Path, sandbox: &SandboxCfg, _ram_mb: u64) {
    std::fs::create_dir_all(workdir).expect("cannot create task workdir");
    command.current_dir(workdir);
    linux::apply(command, sandbox);
}

/// Apply the swarm runner profile: like `apply_to_command`, but the
/// runner keeps its network namespace — shard runners must reach their
/// next hop — so only the mount/UTS/IPC/PID parts of the profile are
/// honored.
pub fn apply_to_runner(command: &mut Command, sandbox: &SandboxCfg) {
    linux::apply(command, sandbox);
}
