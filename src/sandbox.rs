//! Execution sandbox for compute tasks and swarm shard runners.
//!
//! Two layers, both applied best-effort on Linux:
//!
//! * Namespaces: the task unshares the mount, UTS, IPC, PID and network
//!   namespaces before exec. The mount tree is made private, the root is
//!   remounted read-only, and a private tmpfs is mounted over the task's
//!   working directory — the only writable place the task can see. The
//!   loopback interface is brought up inside the fresh network namespace
//!   because swarm runners talk to their worker over 127.0.0.1.
//! * cgroups v2: every task lives in its own cgroup under the daemon's
//!   subtree (writable through systemd `Delegate=yes` or as root) with
//!   `memory.max`, `cpu.max` and `pids.max` set. Dropping the guard kills
//!   every remaining process and removes the directory.
//!
//! Every step degrades gracefully: an unshare failure (for example a
//! daemon running without the needed capabilities) skips the namespace
//! layer entirely so the task still starts; an unavailable cgroup
//! hierarchy simply means no resource limits for that task.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use tokio::process::Command;

use crate::config::SandboxCfg;

/// Namespace flags applied to sandboxed processes: isolated mounts, hostname,
/// IPC, PID view and networking.
const UNSHARE_FLAGS: libc::c_int = libc::CLONE_NEWNS
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET;

/// Wire namespace isolation into a command before it is spawned.
///
/// The hook runs in the child between fork and exec. An error there aborts
/// the exec, so the namespace setup tolerates every failure internally —
/// nothing here returns an error, an unprivileged daemon just gets no
/// namespaces instead of failed tasks.
pub fn apply_to_command(command: &mut Command, workdir: &std::path::Path, cfg: &SandboxCfg) {
    if !cfg.namespaces {
        return;
    }
    let Ok(workdir) = CString::new(workdir.as_os_str().as_bytes()) else {
        return; // path with an interior nul: run without namespace mounts
    };
    let read_only_root = cfg.read_only_root;
    // SAFETY: `pre_exec` runs once in the child before exec in the
    // single-threaded post-fork window; the closure only performs
    // syscalls. tokio's Command provides the inherent `pre_exec` hook.
    unsafe {
        command.pre_exec(move || enter_namespaces(&workdir, read_only_root));
    }
}

/// Child-side namespace setup executed after fork and before exec.
fn enter_namespaces(workdir: &CString, read_only_root: bool) -> io::Result<()> {
    // SAFETY: pure syscalls with constant arguments on freshly created
    // per-process namespaces; nothing here touches shared memory.
    unsafe {
        if libc::unshare(UNSHARE_FLAGS) != 0 {
            // Without the namespaces the mount steps below would leak into
            // the host mount tree, so skip the whole sandbox layer and let
            // the task run unsandboxed instead of failing to start.
            return Ok(());
        }
        // Make the mount tree private so none of our mounts propagate back
        // to the host.
        let root = cstring("/");
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        );
        if read_only_root {
            libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
                std::ptr::null(),
            );
        }
        // A private scratch filesystem over the working directory: the one
        // writable place the task can see, bounded in size by the cgroup
        // memory limit.
        let tmpfs = cstring("tmpfs");
        libc::mount(
            tmpfs.as_ptr(),
            workdir.as_ptr(),
            tmpfs.as_ptr(),
            0,
            std::ptr::null(),
        );
        bring_loopback_up();
    }
    Ok(())
}

/// Wrap a constant string as a C string.
fn cstring(text: &str) -> CString {
    CString::new(text).expect("constant without interior nul")
}

/// Bring the loopback interface up inside the fresh network namespace so
/// sandboxed runners can reach their local worker socket.
fn bring_loopback_up() {
    // SAFETY: standard socket/ioctl dance on a freshly created socket fd.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(c"lo".as_ptr(), ifr.ifr_name.as_mut_ptr(), 3);
        if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) == 0 {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            let _ = libc::ioctl(fd, libc::SIOCSIFFLAGS, &mut ifr);
        }
        libc::close(fd);
    }
}

/// Handle to one task's cgroup; kills its processes and removes the
/// directory when dropped.
pub struct CgroupGuard {
    dir: PathBuf,
}

impl CgroupGuard {
    /// Create a cgroup for `name`, write the limits and move `pid` into it.
    /// Returns `None` when cgroups v2 are unavailable — the caller simply
    /// has no resource limits for this task.
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
        std::fs::create_dir_all(&root).ok()?;
        let dir = root.join(sanitize(name));
        std::fs::create_dir(&dir).ok()?;
        // Write the limits individually: a missing controller must not
        // strip the remaining ones.
        let memory_mb = if cfg.memory_mb > 0 {
            cfg.memory_mb
        } else {
            inherit_memory_mb
        };
        if memory_mb > 0 {
            let bytes = memory_mb.saturating_mul(1024 * 1024);
            let _ = std::fs::write(dir.join("memory.max"), bytes.to_string());
        }
        let cpu_percent = if cfg.cpu_percent > 0 {
            cfg.cpu_percent
        } else {
            inherit_cpu_percent
        };
        if (1..=100).contains(&cpu_percent) {
            // cpu.max: quota in microseconds per 100 ms period.
            let quota = cpu_percent as u64 * 1000;
            let _ = std::fs::write(dir.join("cpu.max"), format!("{quota} 100000"));
        }
        if cfg.pids_max > 0 {
            let _ = std::fs::write(dir.join("pids.max"), cfg.pids_max.to_string());
        }
        std::fs::write(dir.join("cgroup.procs"), pid.to_string()).ok()?;
        Some(CgroupGuard { dir })
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // cgroup.kill exists since kernel 5.14; fall back to signaling
        // every listed pid when the file is missing.
        if std::fs::write(self.dir.join("cgroup.kill"), "1").is_err() {
            if let Ok(procs) = std::fs::read_to_string(self.dir.join("cgroup.procs")) {
                for line in procs.lines() {
                    if let Ok(pid) = line.trim().parse::<libc::pid_t>() {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                }
            }
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Locate the daemon's cgroup v2 subtree: `/proc/self/cgroup` holds the
/// cgroup-relative path of the current process, which is writable when
/// systemd delegates it (`Delegate=yes`) or when the daemon runs as root
/// with write access to /sys/fs/cgroup.
fn delegated_cgroup_root() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let line = text.lines().find(|line| line.starts_with("0::"))?;
    let rel = line.trim_start_matches("0::").trim_start_matches('/');
    let base = PathBuf::from("/sys/fs/cgroup").join(rel);
    if base.join("cgroup.controllers").exists() {
        Some(base.join("opennet"))
    } else {
        None
    }
}

/// Reduce an arbitrary task name to a filesystem-safe cgroup directory name.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
