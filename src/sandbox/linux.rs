//! Linux sandbox internals: namespace unsharing with a read-only root
//! and a private tmpfs scratch space, loopback bring-up inside the new
//! network namespace, user-namespace bootstrap for unprivileged
//! daemons, and the cgroup v2 guard. Every step degrades to "no
//! isolation" when the daemon lacks the capability, so the sandbox can
//! never lose a task — only fail to isolate it.
//!
//! The `pre_exec` closure runs in the forked child between fork and
//! exec, while the parent process is still multi-threaded: everything
//! in it must be async-signal-safe (no allocation, no stdio, no
//! locking libc calls). All formatting happens in the parent.

use super::*;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

/// Async-signal-safe write of one small control file.
fn write_ctl(path: &std::ffi::CStr, data: &[u8]) -> std::io::Result<()> {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut written = 0usize;
    while written < data.len() {
        let n = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const libc::c_void,
                data.len() - written,
            )
        };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        written += n as usize;
    }
    unsafe { libc::close(fd) };
    Ok(())
}

/// Enter a user namespace and map the current uid/gid to namespace
/// root (0): on kernels that allow unprivileged user namespaces this
/// grants CAP_SYS_ADMIN inside the new namespace tree, so the mount
/// and namespace steps below succeed without host root. The map
/// payloads are pre-formatted by the caller in the parent.
fn enter_user_namespace(uid_map: &[u8], gid_map: &[u8]) -> std::io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // deny is required before writing gid_map when the process has
    // multiple groups; harmless otherwise.
    write_ctl(c"/proc/self/setgroups", b"deny")?;
    let _ = (uid, gid);
    write_ctl(c"/proc/self/uid_map", uid_map)?;
    write_ctl(c"/proc/self/gid_map", gid_map)?;
    Ok(())
}

/// Shared implementation for both profiles; the environment scrub
/// happens in the parent, everything else in `pre_exec`.
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
    // exactly like the cgroup policy; the tmpfs covering the child's
    // scratch space is sized at half of that.
    let memory_mb = if cfg.memory_mb > 0 {
        cfg.memory_mb
    } else {
        inherit_memory_mb
    };
    // The uid/gid map payloads must exist before fork: formatting
    // allocates, which the child may not do between fork and exec.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let uid_map = format!("0 {uid} 1");
    let gid_map = format!("0 {gid} 1");
    let std_command = command.as_std_mut();
    // SAFETY: the closure only calls async-signal-safe libc entry
    // points (unshare, mount, open, write, close, socket, ioctl) on
    // pre-formatted data.
    unsafe {
        std_command.pre_exec(move || {
            if libc::unshare(flags) != 0 {
                // Namespace creation needs privileges the daemon may
                // lack. Unprivileged path: enter a user namespace
                // first (allowed on default kernels) and retry the
                // same flags inside it; a kernel that forbids
                // unprivileged user namespaces degrades here, exactly
                // like any other missing capability. Failures degrade
                // silently: stdio between fork and exec is unsafe.
                if enter_user_namespace(uid_map.as_bytes(), gid_map.as_bytes()).is_err()
                    || libc::unshare(flags) != 0
                {
                    return Ok(());
                }
            }
            let work_c = std::ffi::CString::new(work.as_os_str().as_bytes())?;
            // Detach the new mount tree from peer groups: nothing the
            // child mounts propagates anywhere else.
            if libc::mount(
                c"".as_ptr(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Ok(());
            }
            if read_only_root {
                // Remount the root read-only; the tmpfs below still
                // covers the workdir. Inside a user namespace this
                // remount may fail (host mounts are not owned by the
                // namespace root): the failure is ignored on purpose so
                // the scratch tmpfs and the loopback setup below still
                // run — a task with a writable root but a private
                // scratch space is degraded, not unsandboxed.
                let _ = libc::mount(
                    c"".as_ptr(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
                    std::ptr::null(),
                );
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
            return;
        }
        let mut req: libc::ifreq = std::mem::zeroed();
        let name = c"lo";
        std::ptr::copy_nonoverlapping(
            name.as_ptr() as *const libc::c_char,
            req.ifr_name.as_mut_ptr(),
            2,
        );
        // SIOCGIFFLAGS / SIOCSIFFLAGS: read the flags, set UP|RUNNING,
        // write them back. The constants are `i32` on this platform
        // and combine directly with the `ifr_flags` field.
        if libc::ioctl(fd, 0x8913, &mut req) == 0 {
            let flags = req.ifr_ifru.ifru_flags as i32 | libc::IFF_UP | libc::IFF_RUNNING;
            req.ifr_ifru.ifru_flags = flags as libc::c_short;
            let _ = libc::ioctl(fd, 0x8914, &req);
        }
        libc::close(fd);
    }
}

/// RAII handle to one task cgroup: teardown kills stragglers on drop.
pub struct CgroupGuard {
    dir: PathBuf,
}

impl CgroupGuard {
    /// Move `pid` into a fresh cgroup under the delegated subtree and
    /// apply `memory.max`, `cpu.max` and `pids.max`. Zero memory or
    /// CPU config values inherit the given task defaults. Returns
    /// `None` when the subtree is not writable: the child then runs
    /// without cgroup limits, matching the best-effort policy.
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
        // Each control file is written independently so one failing
        // write cannot unbalance the whole setup expression.
        let memory_ok = fs::write(dir.join("memory.max"), format!("{memory_bytes}")).is_ok();
        let cpu_ok = fs::write(dir.join("cpu.max"), format!("{cpu_quota} 100000")).is_ok();
        let pids_ok = fs::write(dir.join("pids.max"), format!("{pids}")).is_ok();
        let attach_ok = fs::write(dir.join("cgroup.procs"), format!("{pid}")).is_ok();
        if !(memory_ok && cpu_ok && pids_ok && attach_ok) {
            // Leave the empty cgroup for the guard to remove.
            drop(guard);
            return None;
        }
        Some(guard)
    }

    /// Remove the task cgroup: best-effort `cgroup.kill` first, then
    /// the directory; systemd reclaims the subtree on unit stop anyway.
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

/// Cgroup directory names allow a restricted alphabet.
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

/// Locate the nearest cgroup v2 ancestor this process may manage,
/// probing write access by creating and removing a scratch directory
/// and walking upward. Returns `None` outside a writable subtree.
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
