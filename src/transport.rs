//! TCP transport with persistent per-peer connections.
//!
//! Every connection starts with a versioned `ConnHello` frame carrying
//! the sender's listen address. The greeting is validated against the
//! real socket address of the peer before the socket is registered:
//! an advertised address whose IP is neither unspecified (the wildcard
//! bind address daemons advertise by default) nor equal to the peer's
//! socket IP is dropped, so a connection can never be attributed to an
//! address it does not own. Every socket, in both directions, is
//! drained by its own reader task feeding a shared channel; replies
//! travel on whichever connection the peer chose.
//!
//! Hardening invariants: one serialized buffer per frame (written with
//! `write_vectored` so the fast path performs a single syscall), a hard
//! connection limit, a greeting deadline, an idle read deadline so dead
//! persistent connections are re-established on demand, no panicking
//! lookups in the send path, and a connection budget that is released
//! exactly once per registered socket by the task that owns it.

use crate::message::{Message, PROTOCOL_VERSION};
use anyhow::{bail, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// Reject frames larger than 1 MiB to bound memory usage per
/// connection. Shared with the swarm modules so local runner frames and
/// prompt injection never exceed what the wire accepts.
pub const MAX_FRAME: usize = 1024 * 1024;
/// Upper bound on concurrently open sockets, inbound and outbound
/// combined.
const MAX_CONNECTIONS: usize = 256;
/// Time allowed for the greeting frame on an accepted socket.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for one outbound connect attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Length of the frame size prefix on the wire, in bytes.
const LEN_PREFIX: usize = 4;

/// One registered socket plus the mutex that serializes writes to it,
/// so concurrent senders can never interleave two frames on the same
/// wire.
struct Conn {
    stream: TcpStream,
    write_lock: Mutex<()>,
}

/// Shared TCP transport used by the daemon for all peer traffic.
pub struct Transport {
    /// Address of the local listener, advertised to peers as
    /// `tcp:<addr>`.
    local_addr: SocketAddr,
    /// Sockets used for writing, keyed by peer listen address.
    streams: Arc<Mutex<HashMap<String, Arc<Conn>>>>,
    /// Sender half shared with every socket reader task.
    frame_tx: mpsc::Sender<(String, Bytes)>,
    /// Frames delivered by per-connection reader tasks; the accept loop
    /// holds a sender clone forever, so this channel never closes. The
    /// mutex allows receiving through a shared reference from any task.
    inbound: Arc<Mutex<mpsc::Receiver<(String, Bytes)>>>,
    /// Serializes connection establishment so concurrent sends to the
    /// same destination open exactly one socket.
    connect_lock: Arc<Mutex<()>>,
    /// Live connection count shared with accept and reader tasks; every
    /// registered socket increments it once and its reader decrements it
    /// exactly once on exit.
    connections: Arc<AtomicUsize>,
    /// Idle deadline applied to every frame read on a persistent
    /// socket.
    idle: Duration,
}

impl Transport {
    /// Bind a listener on all interfaces at the given port (0 =
    /// ephemeral) and start the accept loop; `idle_timeout` bounds how
    /// long a persistent connection may sit silent before its reader
    /// drops it.
    pub async fn new(port: u16, idle_timeout: Duration) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        let local_addr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel::<(String, Bytes)>(256);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        tokio::spawn(accept_loop(
            listener,
            tx.clone(),
            streams.clone(),
            connections.clone(),
            idle_timeout,
        ));
        Ok(Self {
            local_addr,
            streams,
            frame_tx: tx,
            inbound: Arc::new(Mutex::new(rx)),
            connect_lock: Arc::new(Mutex::new(())),
            connections,
            idle: idle_timeout,
        })
    }

    /// Address identifying this node on the LAN: `tcp:<ip>:<port>`.
    /// Daemons bind the wildcard address, so this is `tcp:0.0.0.0:<port>`
    /// unless configured otherwise.
    pub fn local_id(&self) -> String {
        format!("tcp:{}", self.local_addr)
    }

    /// Send one length-prefixed frame to `dest`, opening (and greeting)
    /// the connection on first use. A failed write drops the cached
    /// socket and the loop reconnects and writes again; if that second
    /// write also fails the frame is undeliverable and the call returns
    /// an error, so a torn frame is never reused: the desynced socket
    /// dies with the failed write.
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

    /// Open a fresh connection to `addr`, greet the peer with this
    /// node's versioned listen address, register the socket under `dest`
    /// and start draining it: replies from the peer arrive on this same
    /// socket and must be read locally.
    async fn ensure_connected(&self, dest: &str, addr: &str) -> Result<()> {
        if self.streams.lock().await.contains_key(dest) {
            return Ok(());
        }
        let _guard = self.connect_lock.lock().await;
        if self.streams.lock().await.contains_key(dest) {
            return Ok(());
        }
        self.connect(dest, addr).await
    }

    /// Connect, greet and register a fresh outbound socket. The
    /// connection budget is incremented here and released by the reader
    /// task when the socket dies, so a long-running daemon cannot
    /// exhaust the limit through reconnect churn.
    async fn connect(&self, dest: &str, addr: &str) -> Result<()> {
        if self.connections.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            bail!("connection limit ({MAX_CONNECTIONS}) reached");
        }
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await??;
        stream.set_nodelay(true).ok();
        let hello = Message::ConnHello {
            version: PROTOCOL_VERSION,
            listen_addr: self.local_id(),
        };
        write_frame_raw(&stream, &hello.encode()).await?;
        let conn = Arc::new(Conn {
            stream,
            write_lock: Mutex::new(()),
        });
        self.streams
            .lock()
            .await
            .insert(dest.to_string(), conn.clone());
        self.connections.fetch_add(1, Ordering::Relaxed);
        spawn_reader(
            conn,
            dest.to_string(),
            self.frame_tx.clone(),
            self.streams.clone(),
            self.connections.clone(),
            self.idle,
        );
        Ok(())
    }

    /// Remove a cached socket only when it is still the registered one,
    /// so an erroring reader task cannot delete a replacement
    /// connection.
    async fn remove_if_current(&self, dest: &str, conn: &Arc<Conn>) {
        let mut streams = self.streams.lock().await;
        if streams
            .get(dest)
            .is_some_and(|current| Arc::ptr_eq(current, conn))
        {
            streams.remove(dest);
        }
    }

    /// Wait for the next inbound frame from any connection.
    pub async fn recv(&self) -> Option<(String, Bytes)> {
        self.inbound.lock().await.recv().await
    }
}

/// Accept loop: reject sockets beyond the connection budget, then hand
/// every accepted socket to its own greeting handler.
async fn accept_loop(
    listener: TcpListener,
    tx: mpsc::Sender<(String, Bytes)>,
    streams: Arc<Mutex<HashMap<String, Arc<Conn>>>>,
    connections: Arc<AtomicUsize>,
    idle: Duration,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if connections.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    eprintln!("[transport] connection limit reached, dropping inbound socket");
                    continue;
                }
                let tx = tx.clone();
                let streams = streams.clone();
                let connections = connections.clone();
                tokio::spawn(async move {
                    handle_inbound(stream, peer_addr, tx, streams, connections, idle).await;
                });
            }
            Err(err) => eprintln!("[transport] accept failed: {err:#}"),
        }
    }
}

/// Handle one inbound connection: claim a budget unit, read the
/// versioned `ConnHello` greeting under a deadline, refuse foreign
/// protocol versions and greetings whose advertised listen address
/// cannot belong to this connection, then register the socket under the
/// advertised listen address and drain it. An advertised IP matches
/// when it is the unspecified address (the wildcard bind daemons
/// advertise by default) or when it equals the peer's real socket IP;
/// any other address would let a greeting borrow somebody else's
/// identity in the routing and reputation tables. When the peer already
/// has a registered socket (simultaneous connect from both sides), the
/// newcomer replaces it for writing; the replaced reader keeps draining
/// its socket until EOF, so in-flight frames are still delivered. A
/// socket that is registered hands its budget unit to the reader task;
/// every other exit path releases the unit here.
async fn handle_inbound(
    stream: TcpStream,
    peer_addr: SocketAddr,
    tx: mpsc::Sender<(String, Bytes)>,
    streams: Arc<Mutex<HashMap<String, Arc<Conn>>>>,
    connections: Arc<AtomicUsize>,
    idle: Duration,
) {
    connections.fetch_add(1, Ordering::Relaxed);
    let conn = Arc::new(Conn {
        stream,
        write_lock: Mutex::new(()),
    });
    let Ok(Ok(frame)) =
        tokio::time::timeout(HELLO_TIMEOUT, read_frame(&conn.stream, MAX_FRAME)).await
    else {
        release_budget(&connections);
        return;
    };
    let Some(Message::ConnHello {
        version,
        listen_addr,
    }) = Message::decode(&frame)
    else {
        release_budget(&connections);
        return;
    };
    if version != PROTOCOL_VERSION {
        eprintln!("[transport] peer {peer_addr} speaks protocol v{version}, dropping");
        release_budget(&connections);
        return;
    }
    let Some(advertised) = listen_addr
        .strip_prefix("tcp:")
        .and_then(|raw| raw.parse::<SocketAddr>().ok())
    else {
        eprintln!("[transport] peer {peer_addr} sent a malformed listen address, dropping");
        release_budget(&connections);
        return;
    };
    let ip_matches = advertised.ip().is_unspecified() || advertised.ip() == peer_addr.ip();
    if !ip_matches {
        eprintln!(
            "[transport] peer {peer_addr} advertised foreign address {listen_addr}, dropping"
        );
        release_budget(&connections);
        return;
    }
    streams
        .lock()
        .await
        .insert(listen_addr.clone(), conn.clone());
    spawn_reader(conn, listen_addr, tx, streams, connections, idle);
}

/// Release one unit of the connection budget; called once per socket
/// that will never be drained by a reader task (refused greetings).
fn release_budget(connections: &AtomicUsize) {
    connections.fetch_sub(1, Ordering::Relaxed);
}

/// Drain one socket until EOF, error, idle deadline or an oversized
/// frame, forwarding every frame under the peer identifier it was
/// registered with. Delivery uses `try_send` first so the reader never
/// parks on the channel in the common uncontended case; only a full
/// channel falls back to an awaited send. On exit the connection
/// budget is released exactly once and the socket is removed only when
/// it is still the registered one, so a replacement connection
/// survives the death of its predecessor.
fn spawn_reader(
    conn: Arc<Conn>,
    id: String,
    tx: mpsc::Sender<(String, Bytes)>,
    streams: Arc<Mutex<HashMap<String, Arc<Conn>>>>,
    connections: Arc<AtomicUsize>,
    idle: Duration,
) {
    tokio::spawn(async move {
        loop {
            let next = tokio::time::timeout(idle, read_frame(&conn.stream, MAX_FRAME)).await;
            match next {
                Ok(Ok(data)) => {
                    let frame = (id.clone(), data);
                    if tx.try_send(frame.clone()).is_err() && tx.send(frame).await.is_err() {
                        break;
                    }
                }
                // Idle deadline, socket error or oversized frame: drop
                // the connection; the next send re-establishes it on
                // demand.
                _ => break,
            }
        }
        connections.fetch_sub(1, Ordering::Relaxed);
        let mut map = streams.lock().await;
        if map
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &conn))
        {
            map.remove(&id);
        }
    });
}

/// Read exactly `buf.len()` bytes from a shared socket reference,
/// waiting for readability between `try_read` attempts; `try_read`
/// takes `&self`, so sockets held behind `Arc` need no mutable access.
async fn read_exact(stream: &TcpStream, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        stream.readable().await?;
        match stream.try_read(&mut buf[filled..]) {
            Ok(0) => bail!("connection closed by peer"),
            Ok(read) => filled += read,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

/// Read one length-prefixed frame, rejecting oversized lengths before
/// allocating the payload buffer.
async fn read_frame(stream: &TcpStream, max: usize) -> Result<Bytes> {
    let mut len_buf = [0u8; LEN_PREFIX];
    read_exact(stream, &mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        bail!("frame exceeds size limit ({len} > {max})");
    }
    let mut data = vec![0u8; len];
    read_exact(stream, &mut data).await?;
    Ok(Bytes::from(data))
}

/// Write one length-prefixed frame; the per-connection write lock
/// serializes frames from concurrent senders.
async fn write_frame(conn: &Conn, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME {
        bail!("frame exceeds size limit ({} > {MAX_FRAME})", data.len());
    }
    let _guard = conn.write_lock.lock().await;
    write_frame_raw(&conn.stream, data).await
}

/// Write header and body as one vectored syscall so the fast path
/// needs no heap buffer at all; a partial write flushes the remaining
/// bytes through the allocation-based fallback.
async fn write_frame_raw(stream: &TcpStream, data: &[u8]) -> Result<()> {
    let header = (data.len() as u32).to_be_bytes();
    let slices = [IoSlice::new(&header), IoSlice::new(data)];
    let total = data.len() + LEN_PREFIX;
    stream.writable().await?;
    match stream.try_write_vectored(&slices) {
        Ok(n) if n == total => Ok(()),
        Ok(n) => write_all(stream, &remainder(&slices, n)).await,
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
            write_all(stream, &remainder(&slices, 0)).await
        }
        Err(err) => Err(err.into()),
    }
}

/// Collect the bytes of `slices` that come after `skip` bytes into one
/// buffer; only used on the rare partial-write path.
fn remainder(slices: &[IoSlice<'_>], skip: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut left = skip;
    for slice in slices {
        if left >= slice.len() {
            left -= slice.len();
        } else {
            out.extend_from_slice(&slice[left..]);
            left = 0;
        }
    }
    out
}

/// Write all of `data` to a shared socket reference, waiting for
/// writability between `try_write` attempts.
async fn write_all(stream: &TcpStream, data: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < data.len() {
        stream.writable().await?;
        match stream.try_write(&data[written..]) {
            Ok(0) => bail!("connection closed by peer"),
            Ok(sent) => written += sent,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
