//! Integration with the systemd readiness protocol (sd_notify).

use std::env;
use std::os::unix::net::UnixDatagram;

/// Send a state string to systemd via the NOTIFY_SOCKET datagram.
///
/// Does nothing when the daemon runs outside systemd (no NOTIFY_SOCKET).
fn notify(state: &str) {
    let Ok(path) = env::var("NOTIFY_SOCKET") else {
        return;
    };
    // Abstract socket addresses are encoded with a leading '@'.
    let path = path
        .strip_prefix('@')
        .map(|name| format!("\0{name}"))
        .unwrap_or(path);
    let Ok(socket) = UnixDatagram::unbound() else {
        return;
    };
    let _ = socket.send_to(state.as_bytes(), path);
}

/// Tell systemd the daemon finished startup (READY=1).
pub fn notify_ready() {
    notify("READY=1");
}

/// Tell systemd the daemon is about to exit (STOPPING=1).
pub fn notify_stopping() {
    notify("STOPPING=1");
}
