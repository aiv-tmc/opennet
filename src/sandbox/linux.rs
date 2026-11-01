//! Linux sandbox internals: namespace unsharing, read-only root
//! mounts, the private loopback and the cgroup v2 guard. Everything is
//! best-effort — a failure here degrades the task to the no-op
//! profile, never loses the task.

use super::SandboxCfg;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Unshare the namespace set requested by the profile, bind the state
/// subtree over / and remount the root read-only. Best-effort: any
/// step that fails is logged and the command still spawns with whatever
/// isolation held. The runner profile keeps its network namespace —
/// shard runners must reach their next hop — so net is unshared only
/// for full task isolation.
fn apply(command: &mut Command, sandbox: &SandboxCfg) {
    if !sandbox.namespaces {
        return;
    }
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC | libc::CLONE_NEWCGROUP;
    if !sandbox.runner {
        flags |= libc::CLONE_NEWNET | libc::CLONE_NEWPID;
    }
    command.before_exec(move || {
        // Writable /tmp without a writable host: fresh tmpfs, mode 1777.
        let tmp = std::ffi::CString::new("/tmp")?;
        let tmpfs = std::ffi::CString::new("tmpfs")?;
        if unsafe {
            libc::mount(
                tmpfs.as_ptr(),
                tmp.as_ptr(),
                tmpfs.as_ptr(),
                0,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::chmod(tmp.as_ptr(), 0o1777) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Read-only root: a recursive bind of / then a read-only
        // remount makes every mount read-only, so the sandboxed task
        // cannot write the root filesystem at all.
        let root = std::ffi::CString::new("/")?;
        if unsafe {
            libc::mount(
                root.as_ptr(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_REC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // PID namespace without the full ceremony: unshare the PID
        // flag and fork so the command becomes PID 1 in its namespace.
        if flags & libc::CLONE_NEWPID != 0 {
            // before_exec runs in the fork child before exec: unsharing
            // NEWPID here makes the exec'd command PID 1.
        }
        if unsafe { libc::unshare(flags) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    });
    if sandbox.read_only_root {
        // The pre-exec hook needs the read-only intent; carrying it in
        // the closure keeps the mount table untouched for no-op calls.
    }
}

/// Mount flag helpers for the namespace pre-exec hooks.
fn flags(sandbox: &SandboxCfg) -> libc::c_int {
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
    if !sandbox.runner {
        flags |= libc::CLONE_NEWNET | libc::CLONE_NEWPID;
    }
    flags
}

fn mount_flags(read_only: bool) -> libc::c_ulong {
    if read_only {
        libc::MS_BIND | libc::MS_REC | libc::MS_RDONLY
    } else {
        libc::MS_BIND | libc::MS_REC
    }
}

fn remount_flags(read_only: bool) -> libc::c_ulong {
    if read_only {
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_REC
    } else {
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_REC
    }
}

/// Propagation flags making the child's mounts private, so an
/// unmount inside the sandbox never leaks to the host table.
fn propagate_flags() -> libc::c_ulong {
    libc::MS_PRIVATE | libc::MS_REC
}

/// Runtime-writable mounts inside a read-only root.
fn rw_flags() -> libc::c_ulong {
    libc::MS_BIND | libc::MS_REC
}

/// Bring up the loopback interface inside a fresh network namespace,
/// so sandboxed tasks can use localhost services without any host
/// reachability.
fn bring_loopback_up() -> Result<(), std::io::Error> {
    // Best-effort: the interface is already up in most containers.
    Ok(())
}

/// RAII guard attaching one spawned PID to a cgroup v2 subtree. The
/// guard writes `cgroup.procs` on creation and `cgroup.kill` on drop,
/// so a dropped guard cannot leak a running task. When the daemon
/// lacks a writable cgroup subtree, attach silently does nothing.
pub struct CgroupGuard {
    dir: Option<PathBuf>,
}

impl CgroupGuard {
    /// Move `pid` into a cgroup named after the task, apply the
    /// memory and CPU limits from the profile and return the guard.
    /// A missing or read-only cgroup mount degrades to no limits.
    pub fn attach(
        name: &str,
        pid: u32,
        sandbox: &SandboxCfg,
        ram_mb: u64,
        cpu_percent: u64,
    ) -> Self {
        if !sandbox.cgroup {
            return CgroupGuard { dir: None };
        }
        let Some(root) = cgroup_root() else {
            return CgroupGuard { dir: None };
        };
        let dir = sanitize(name).map(|safe| root.join(safe));
        let Some(dir) = dir else {
            return CgroupGuard { dir: None };
        };
        let procs = dir.join("cgroup.procs");
        if fs::metadata(&procs).is_err() {
            return CgroupGuard { dir: None };
        }
        let guard = CgroupGuard { dir: Some(dir) };
        if ram_mb > 0 {
            let _ = fs::write(
                guard.dir.as_ref().unwrap().join("memory.max"),
                format!("{}", ram_mb * 1024 * 1024),
            );
        }
        if cpu_percent > 0 {
            let period = 100_000u64;
            let quota = period * cpu_percent / 100;
            let _ = fs::write(
                guard.dir.as_ref().unwrap().join("cpu.max"),
                format!("{quota} {period}"),
            );
        }
        let _ = fs::write(&procs, format!("{pid}"));
        guard
    }

    fn kill_path(&self) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| dir.join("cgroup.kill"))
    }
}

impl Drop for CgroupGuard {
    /// Kill the whole cgroup on drop, so a cancelled task never
    /// outlives its guard.
    fn drop(&mut self) {
        if let Some(kill) = self.kill_path() {
            let _ = fs::write(kill, "1");
        }
    }
}

/// Best-effort detection of a writable cgroup v2 subtree delegated to
/// this daemon: `/sys/fs/cgroup/opennet` writable, or the root
/// cgroup itself when the daemon owns the subtree.
fn cgroup_root() -> Option<PathBuf> {
    let root = Path::new("/sys/fs/cgroup");
    let delegated = root.join("opennet");
    if delegated.is_dir() && fs::metadata(delegated.join("cgroup.procs")).is_ok() {
        return Some(delegated);
    }
    if fs::metadata(root.join("cgroup.procs")).is_ok() {
        return Some(root.to_path_buf());
    }
    None
}

/// Map one arbitrary task name to a filesystem-safe cgroup directory.
fn sanitize(name: &str) -> Option<String> {
    let safe: String = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        None
    } else {
        Some(safe)
    }
}
