//! systemd integration: notify the service manager about startup
//! completion through the `sd_notify` socket when one is provided.
//!
//! Best-effort by design: the daemon also runs under dinit, OpenRC and
//! runit, which never set `NOTIFY_SOCKET`, and any failure here must not
//! affect the daemon.

use std::mem::offset_of;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;

/// Send the readiness notification marking the service active.
pub fn notify_ready() {
    notify("READY=1");
}

/// Deliver one state line to the `NOTIFY_SOCKET`; filesystem and abstract
/// socket forms are both supported, failures are ignored.
fn notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let bytes = path.as_os_str().as_bytes();
    let Ok(socket) = std::os::unix::net::UnixDatagram::unbound() else {
        return;
    };
    if bytes.first() == Some(&b'@') {
        // Abstract socket: the '@' maps to a leading nul byte in sun_path,
        // so copy the name without its prefix into the raw sockaddr.
        let name = &bytes[1..];
        if name.is_empty() || name.len() >= 108 {
            return;
        }
        let mut storage: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        storage.sun_family = libc::AF_UNIX as libc::sa_family_t;
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                storage.sun_path.as_mut_ptr() as *mut u8,
                name.len(),
            );
        }
        let addr_len = offset_of!(libc::sockaddr_un, sun_path) + name.len();
        unsafe {
            let addr = &storage as *const libc::sockaddr_un as *const libc::sockaddr;
            libc::sendto(
                socket.as_raw_fd(),
                state.as_ptr() as *const libc::c_void,
                state.len(),
                0,
                addr,
                addr_len as libc::socklen_t,
            );
        }
    } else {
        // Filesystem socket: std's UnixDatagram takes the path directly.
        let _ = socket.send_to(state.as_bytes(), std::path::Path::new(&path));
    }
}
