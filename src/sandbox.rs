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

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;

    /// Namespace flags for compute tasks: the child cannot use the
    /// host network, so a fresh private network namespace is included.
    pub const TASK_UNSHARE_FLAGS: libc::c_int = libc::CLONE_NEWNS
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET;
    /// Namespace flags for swarm runners: identical to the task
    /// profile minus `CLONE_NEWNET`, so the runner can connect to the
    /// worker's loopback listener in the daemon's network namespace.
    pub const RUNNER_UNSHARE_FLAGS: libc::c_int =
        libc::CLONE_NEWNS | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC | libc::CLONE_NEWPID;

    /// Shared implementation for both profiles. `pre_exec` runs in the
    /// child after fork and before exec, while it is still
    /// single-threaded; the environment scrub happens in the parent.
    pub fn apply(
        command: &mut Command,
        workdir: &Path,
        cfg: &SandboxCfg,
        inherit_memory_mb: u64,
        flags: libc::c_int,
    ) {
        if !cfg.namespaces {
            return;
        }
        let work = workdir.to_path_buf();
        let read_only_root = cfg.read_only_root;
        // Zero config memory means "inherit the node's task RAM limit",
        // exactly like the cgroup policy; the tmpfs covering the
        // child's scratch space is sized at half of that.
        let memory_mb = if cfg.memory_mb > 0 {
            cfg.memory_mb
        } else {
            inherit_memory_mb
        };
        let std_command = command.as_std_mut();
        // SAFETY: `pre_exec` runs in the forked child between fork and
        // exec; the closure must be async-signal-safe, and the libc
        // calls used here (unshare, mount, socket, ioctl, close) are.
        unsafe {
            std_command.pre_exec(move || {
                if libc::unshare(flags) != 0 {
                    // Missing privileges (unprivileged daemon): degrade
                    // to no namespace isolation rather than failing the
                    // task.
                    eprintln!(
                        "[sandbox] unshare failed: {}",
                        std::io::Error::last_os_error()
                    );
                    return Ok(());
                }
                let work_c = std::ffi::CString::new(work.as_os_str().as_bytes())?;
                // Detach the new mount tree from peer groups: nothing
                // the child mounts propagates anywhere else.
                if libc::mount(
                    c"".as_ptr(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
                {
                    eprintln!(
                        "[sandbox] mount(private) failed: {}",
                        std::io::Error::last_os_error()
                    );
                    return Ok(());
                }
                if read_only_root {
                    // Remount the root read-only; separate mounts stay
                    // as-is, and the tmpfs below still covers the
                    // workdir.
                    if libc::mount(
                        c"".as_ptr(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
                        std::ptr::null(),
                    ) != 0
                    {
                        eprintln!(
                            "[sandbox] remount(ro) failed: {}",
                            std::io::Error::last_os_error()
                        );
                        return Ok(());
                    }
                }
                // Fresh tmpfs over the child's scratch space: the only
                // writable place the child can see, capped at half the
                // effective memory limit.
                let size_k = memory_mb.saturating_mul(1024) / 2;
                let size_opt = format!("size={size_k}k");
                let size_c = std::ffi::CString::new(size_opt)?;
                if libc::mount(
                    c"tmpfs".as_ptr(),
                    work_c.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    size_c.as_ptr() as *const libc::c_void,
                ) != 0
                {
                    eprintln!(
                        "[sandbox] tmpfs failed: {}",
                        std::io::Error::last_os_error()
                    );
                    return Ok(());
                }
                if flags & libc::CLONE_NEWNET != 0 {
                    bring_loopback_up();
                }
                Ok(())
            });
        }
        std_command.env_clear();
        std_command.env("PATH", "/usr/local/bin:/usr/bin:/bin");
        std_command.env("HOME", workdir);
        std_command.env("TMPDIR", workdir);
    }

    /// Bring `lo` up inside the current (new) network namespace so
    /// sandboxed tasks see a functional loopback.
    fn bring_loopback_up() {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if fd < 0 {
                eprintln!("[sandbox] socket: {}", std::io::Error::last_os_error());
                return;
            }
            let mut req: libc::ifreq = std::mem::zeroed();
            let name = c"lo";
            std::ptr::copy_nonoverlapping(
                name.as_ptr() as *const libc::c_char,
                req.ifr_name.as_mut_ptr(),
                2,
            );
            // SIOCGIFFLAGS / SIOCSIFFLAGS: read the flags, set
            // UP|RUNNING, write them back. The constants are already
            // `i32` on this platform, so they combine directly with
            // the `ifr_flags` field.
            if libc::ioctl(fd, 0x8913, &mut req) == 0 {
                let flags = req.ifr_ifru.ifru_flags as i32 | libc::IFF_UP | libc::IFF_RUNNING;
                req.ifr_ifru.ifru_flags = flags as libc::c_short;
                if libc::ioctl(fd, 0x8914, &req) != 0 {
                    eprintln!("[sandbox] lo up: {}", std::io::Error::last_os_error());
                }
            }
            libc::close(fd);
        }
    }

    /// RAII handle to one task cgroup: removes the directory (and
    /// kills any stragglers) on drop.
    pub struct CgroupGuard {
        dir: PathBuf,
    }

    impl CgroupGuard {
        /// Move `pid` into a fresh cgroup under the delegated subtree
        /// and apply `memory.max`, `cpu.max` and `pids.max`. Zero
        /// memory or CPU config values inherit the given task
        /// defaults. Returns `None` when the subtree is not writable:
        /// the child then runs without cgroup limits, matching the
        /// best-effort policy of the rest of the sandbox.
        pub fn attach(
            name: &str,
            pid: u32,
            cfg: &SandboxCfg,
            inherit_memory_mb: u64,
            inherit_cpu_percent: u32,
        ) -> Option<CgroupGuard> {
            if !cfg.cgroup {
                return None;
            }
            let root = delegated_cgroup_root()?;
            let dir = root.join(sanitize(name));
            fs::create_dir(&dir).ok()?;
            let guard = CgroupGuard { dir: dir.clone() };
            let memory_mb = if cfg.memory_mb > 0 {
                cfg.memory_mb
            } else {
                inherit_memory_mb
            };
            let cpu_percent = if cfg.cpu_percent > 0 {
                cfg.cpu_percent
            } else {
                inherit_cpu_percent
            };
            let memory_bytes = memory_mb.saturating_mul(1024 * 1024);
            let cpu_quota = (cpu_percent as u64).saturating_mul(1000).min(100_000);
            let pids = cfg.pids_max.max(1);
            // Each control file is written independently so one
            // failing write cannot unbalance the whole setup
            // expression.
            let memory_ok = fs::write(dir.join("memory.max"), format!("{memory_bytes}")).is_ok();
            let cpu_ok = fs::write(dir.join("cpu.max"), format!("{cpu_quota} 100000")).is_ok();
            let pids_ok = fs::write(dir.join("pids.max"), format!("{pids}")).is_ok();
            let attach_ok = fs::write(dir.join("cgroup.procs"), format!("{pid}")).is_ok();
            if !(memory_ok && cpu_ok && pids_ok && attach_ok) {
                // Leave the empty cgroup for the guard to remove.
                eprintln!("[sandbox] cgroup setup failed, running without limits");
                drop(guard);
                return None;
            }
            Some(guard)
        }

        /// Remove the task cgroup: best-effort `cgroup.kill` first to
        /// reap stragglers, then the directory. Failing both is fine —
        /// systemd reclaims the subtree when the unit stops.
        pub fn teardown(&self) {
            let _ = fs::write(self.dir.join("cgroup.kill"), "1");
            let _ = fs::remove_dir(&self.dir);
        }
    }

    impl Drop for CgroupGuard {
        fn drop(&mut self) {
            self.teardown();
        }
    }

    /// Cgroup directory names allow a restricted alphabet; map
    /// anything else to `-` so arbitrary task ids cannot escape the
    /// subtree.
    fn sanitize(name: &str) -> String {
        name.chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '-'
                }
            })
            .collect()
    }

    /// Locate the nearest cgroup v2 ancestor this process may manage:
    /// the daemon's own cgroup (the systemd unit sets `Delegate=yes`)
    /// or an explicitly delegated subtree. Probes write access by
    /// creating and removing a scratch directory; walks upward until a
    /// delegated ancestor is found. Returns `None` outside a writable
    /// subtree.
    fn delegated_cgroup_root() -> Option<PathBuf> {
        let own = fs::read_to_string("/proc/self/cgroup").ok()?;
        let rel = own
            .lines()
            .find(|line| line.starts_with("0::"))
            .map(|line| line.trim_start_matches("0::").trim_start_matches('/'))?;
        let start = Path::new("/sys/fs/cgroup").join(rel);
        let mut candidate = start.as_path();
        loop {
            if candidate.join("cgroup.procs").exists() {
                let probe = candidate.join(format!(".probe-{}", std::process::id()));
                if fs::create_dir(&probe).is_ok() {
                    let _ = fs::remove_dir(&probe);
                    return Some(candidate.to_path_buf());
                }
            }
            // Move one level up; the filter stops the walk at the
            // filesystem root, which has no parent.
            let parent = candidate.parent().filter(|parent| *parent != candidate)?;
            candidate = parent;
        }
    }
}
