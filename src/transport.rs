//! Persistent TCP transport with authenticated, encrypted connections.
//!
//! Every connection begins with a signed key exchange (`handshake`)
//! producing directional ChaCha20-Poly1305 session keys; afterwards every
//! frame is encrypted with a strictly increasing counter nonce, so a
//! man-in-the-middle can neither read nor alter frames, and tampering or
//! desynchronization kills the connection. The advertised listen address
//! must match the peer's real socket IP; a wildcard advertisement is
//! accepted but rewritten to the real IP at registration time, because
//! the wildcard is not a usable dial target.
//!
//! Resource guards: a bounded connection budget owned and released by
//! each socket's own reader, idle recycling with on-demand
//! re-establishing, a hard frame-size cap, a bounded write deadline so a
//! silent peer cannot park a sender forever, and one
//! reconnect-and-rewrite retry per send.

use crate::node::identity::Identity;
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

mod frame;
mod handshake;
mod reader;
#[cfg(test)]
mod tests;

use reader::ConnMap;

/// Hard cap on one frame's payload; larger frames are rejected before
/// allocation so a length prefix cannot exhaust memory.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Upper bound on concurrently claimed connections; the shared counter
/// is incremented on registration and decremented by the socket's own
/// reader, so a reconnecting daemon never exhausts the budget.
const MAX_CONNECTIONS: usize = 256;

/// Deadline for the greeting exchange and for establishing a TCP connection.
pub(super) const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Deadline for one frame write; a peer that never drains its receive
/// buffer can stall a write for at most this long, never indefinitely.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct Conn {
    pub(super) stream: TcpStream,
    pub(super) write_lock: Mutex<()>,
    pub(super) crypto: Mutex<handshake::CryptoSession>,
}

/// Shared persistent transport.
pub struct Transport {
    local_addr: SocketAddr,
    identity: Identity,
    streams: ConnMap,
    frame_tx: mpsc::Sender<(String, Bytes)>,
    frame_rx: Mutex<mpsc::Receiver<(String, Bytes)>>,
    connect_lock: Mutex<()>,
    connections: Arc<AtomicUsize>,
    idle_timeout: Duration,
}

impl Transport {
    /// Bind an ephemeral or fixed port on all interfaces and start the
    /// accept loop; each accepted socket is claimed against the budget
    /// before its greeting is read.
    pub async fn new(identity: Identity, port: u16, idle_timeout: Duration) -> Result<Transport> {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await?;
        let local_addr = listener.local_addr()?;
        let (frame_tx, frame_rx) = mpsc::channel::<(String, Bytes)>(256);
        let transport = Transport {
            local_addr,
            identity: identity.clone(),
            streams: Arc::new(Mutex::new(HashMap::new())),
            frame_tx,
            frame_rx: Mutex::new(frame_rx),
            connect_lock: Mutex::new(()),
            connections: Arc::new(AtomicUsize::new(0)),
            idle_timeout,
        };
        tokio::spawn(reader::accept_loop(
            identity,
            listener,
            transport.streams.clone(),
            transport.frame_tx.clone(),
            transport.connections.clone(),
            transport.idle_timeout,
        ));
        Ok(transport)
    }

    /// Advertised local address in `tcp:<ip>:<port>` form.
    pub fn local_id(&self) -> String {
        format!("tcp:{}", self.local_addr)
    }

    /// Local address advertised to peers over discovery and stored in
    /// their routing tables: when bound to the wildcard (the default),
    /// the wildcard is not a usable dial target, so the primary
    /// interface address is probed with a best-effort UDP route lookup
    /// (no packet ever leaves the host; the call only asks the routing
    /// table for the egress address). Falls back to the wildcard when
    /// no route exists, in which case the accept side rewrites it to
    /// the real socket IP anyway.
    pub fn advertise_id(&self) -> String {
        if !self.local_addr.ip().is_unspecified() {
            return self.local_id();
        }
        let probed = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .and_then(|socket| {
                socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
                socket.local_addr()
            })
            .map(|addr| addr.ip());
        match probed {
            Ok(ip) => format!("tcp:{ip}:{}", self.local_addr.port()),
            Err(_) => self.local_id(),
        }
    }

    /// Send one encoded frame to `dest` (`tcp:<ip>:<port>`), dialing and
    /// handshaking on demand. A failed write on a stale socket triggers
    /// exactly one reconnect-and-rewrite attempt so the frame is never
    /// lost to a torn-down connection.
    pub async fn send(&self, dest: &str, data: Bytes) -> Result<()> {
        let addr = dest.strip_prefix("tcp:").unwrap_or(dest);
        let mut reconnected_after_failure = false;
        loop {
            let conn = { self.streams.lock().await.get(dest).cloned() };
            let Some(conn) = conn else {
                self.ensure_connected(dest, addr).await?;
                continue;
            };
            if write_frame(&conn, &data).await.is_ok() {
                return Ok(());
            }
            self.remove_if_current(dest, &conn).await;
            if reconnected_after_failure {
                bail!("cannot deliver frame to {dest}");
            }
            reconnected_after_failure = true;
        }
    }

    /// Dial and register a connection unless another task already did.
    /// The new socket gets its own reader so inbound frames on the
    /// dialed connection are pumped into the shared receive queue.
    async fn ensure_connected(&self, dest: &str, addr: &str) -> Result<()> {
        let _guard = self.connect_lock.lock().await;
        if self.streams.lock().await.contains_key(dest) {
            return Ok(());
        }
        let socket_addr: SocketAddr = addr
            .parse()
            .with_context(|| format!("cannot parse peer address {addr}"))?;
        let conn = self.connect(socket_addr).await?;
        self.streams
            .lock()
            .await
            .insert(dest.to_string(), conn.clone());
        self.connections.fetch_add(1, Ordering::SeqCst);
        reader::spawn_conn_reader(
            dest.to_string(),
            conn,
            self.frame_tx.clone(),
            self.connections.clone(),
            self.idle_timeout,
            self.streams.clone(),
        );
        Ok(())
    }

    /// Dial one peer and run the initiator side of the handshake.
    async fn connect(&self, addr: SocketAddr) -> Result<Arc<Conn>> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("connect timed out")??;
        let _ = stream.set_nodelay(true);
        let session = tokio::time::timeout(
            HELLO_TIMEOUT,
            handshake::initiate(&self.identity, &stream, &self.local_id()),
        )
        .await
        .context("handshake timed out")??;
        Ok(Arc::new(Conn {
            stream,
            write_lock: Mutex::new(()),
            crypto: Mutex::new(session),
        }))
    }

    /// Drop the cached connection for `dest` if it still is `conn`.
    async fn remove_if_current(&self, dest: &str, conn: &Arc<Conn>) {
        let mut streams = self.streams.lock().await;
        if streams
            .get(dest)
            .is_some_and(|current| Arc::ptr_eq(current, conn))
        {
            streams.remove(dest);
        }
    }

    /// Receive the next inbound frame with the address of the
    /// connection it arrived on; `None` when every sender is gone.
    pub async fn recv(&self) -> Option<(String, Bytes)> {
        self.frame_rx.lock().await.recv().await
    }
}

/// Encrypt and write one frame; the write lock keeps ciphertext
/// contiguous, the counter nonce lives inside the session, and the
/// bounded write deadline keeps a stalled peer from parking the lock.
async fn write_frame(conn: &Conn, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME {
        bail!(
            "frame length {} exceeds the {}-byte cap",
            data.len(),
            MAX_FRAME
        );
    }
    let _guard = conn.write_lock.lock().await;
    let ciphertext = { conn.crypto.lock().await.seal(data)? };
    match tokio::time::timeout(
        WRITE_TIMEOUT,
        frame::write_frame_raw(&conn.stream, &ciphertext),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => bail!("frame write timed out after {WRITE_TIMEOUT:?}"),
    }
}
