//! TCP transport with persistent per-peer connections.
//!
//! Every connection starts with a `ConnHello` frame carrying the sender's
//! listen address, so both outgoing and incoming sockets are registered
//! under the same `tcp:<ip>:<port>` identifier the peer advertises through
//! multicast discovery. Every socket, in both directions, is drained by its
//! own reader task feeding a shared channel; replies travel on whichever
//! connection the peer chose, and the daemon never blocks in `accept` while
//! a reply is waiting on an already-open connection.

use crate::message::Message;
use anyhow::{bail, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// Reject frames larger than 1 MiB to bound memory usage per connection.
const MAX_FRAME: usize = 1024 * 1024;

/// Length of the frame size prefix on the wire, in bytes.
const LEN_PREFIX: usize = 4;

/// Shared TCP transport used by the daemon for all peer traffic.
pub struct Transport {
    /// Address of the local listener, advertised to peers as `tcp:<addr>`.
    local_addr: std::net::SocketAddr,
    /// Sockets used for writing, keyed by peer listen address.
    streams: Arc<Mutex<HashMap<String, Arc<TcpStream>>>>,
    /// Sender half shared with every socket reader task.
    frame_tx: mpsc::Sender<(String, Bytes)>,
    /// Frames delivered by per-connection reader tasks; the accept loop
    /// holds a sender clone forever, so this channel never closes. The
    /// mutex allows receiving through a shared reference from any task.
    inbound: Arc<Mutex<mpsc::Receiver<(String, Bytes)>>>,
}

impl Transport {
    /// Bind a listener on all interfaces at the given port (0 = ephemeral)
    /// and start the accept loop.
    pub async fn new(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        let local_addr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel::<(String, Bytes)>(256);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(accept_loop(listener, tx.clone(), streams.clone()));
        Ok(Self {
            local_addr,
            streams,
            frame_tx: tx,
            inbound: Arc::new(Mutex::new(rx)),
        })
    }

    /// Address identifying this node on the LAN: `tcp:<ip>:<port>`.
    pub fn local_id(&self) -> String {
        format!("tcp:{}", self.local_addr)
    }

    /// Send one length-prefixed frame to `dest`, opening (and greeting) the
    /// connection on first use. A failed write drops the cached socket and
    /// retries once on a freshly opened connection.
    pub async fn send(&self, dest: &str, data: Bytes) -> Result<()> {
        let addr = dest.strip_prefix("tcp:").unwrap_or(dest);
        if !self.streams.lock().await.contains_key(dest) {
            self.connect(dest, addr).await?;
        }
        let stream = self
            .streams
            .lock()
            .await
            .get(dest)
            .expect("registered by connect")
            .clone();
        if write_frame(&stream, &data).await.is_ok() {
            return Ok(());
        }
        // The cached connection died: drop it and retry exactly once. If
        // the first write partially succeeded the peer sees a duplicate
        // frame, which the protocol tolerates because every task message
        // carries its unique task id.
        self.remove_if_current(dest, &stream).await;
        self.connect(dest, addr).await?;
        let stream = self
            .streams
            .lock()
            .await
            .get(dest)
            .expect("registered by connect")
            .clone();
        write_frame(&stream, &data).await
    }

    /// Open a fresh connection to `addr`, greet the peer with this node's
    /// listen address, register the socket under `dest` and start draining
    /// it: replies from the peer arrive on this same socket and must be
    /// read locally.
    async fn connect(&self, dest: &str, addr: &str) -> Result<()> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        let stream = Arc::new(stream);
        let hello = Message::ConnHello {
            listen_addr: self.local_id(),
        };
        write_frame(&stream, &hello.encode()).await?;
        self.streams
            .lock()
            .await
            .insert(dest.to_string(), stream.clone());
        spawn_reader(
            stream,
            dest.to_string(),
            self.frame_tx.clone(),
            self.streams.clone(),
        );
        Ok(())
    }

    /// Remove a cached socket only when it is still the registered one, so
    /// an erroring reader task cannot delete a replacement connection.
    async fn remove_if_current(&self, dest: &str, stream: &Arc<TcpStream>) {
        let mut streams = self.streams.lock().await;
        if streams
            .get(dest)
            .is_some_and(|current| Arc::ptr_eq(current, stream))
        {
            streams.remove(dest);
        }
    }

    /// Wait for the next inbound frame from any connection.
    pub async fn recv(&self) -> Option<(String, Bytes)> {
        self.inbound.lock().await.recv().await
    }
}

/// Accept loop: every incoming socket gets its own greeting handler.
async fn accept_loop(
    listener: TcpListener,
    tx: mpsc::Sender<(String, Bytes)>,
    streams: Arc<Mutex<HashMap<String, Arc<TcpStream>>>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(handle_inbound(stream, tx.clone(), streams.clone()));
            }
            Err(err) => eprintln!("[transport] accept failed: {err:#}"),
        }
    }
}

/// Handle one inbound connection: expect the `ConnHello` greeting, register
/// the socket under the peer's listen address and drain it. When the peer
/// already has a registered socket (simultaneous connect from both sides),
/// the newcomer replaces it for writing; the replaced reader keeps draining
/// its socket until EOF, so in-flight frames are still delivered.
async fn handle_inbound(
    stream: TcpStream,
    tx: mpsc::Sender<(String, Bytes)>,
    streams: Arc<Mutex<HashMap<String, Arc<TcpStream>>>>,
) {
    let stream = Arc::new(stream);
    let Ok(frame) = read_frame(&stream).await else {
        return;
    };
    let Some(Message::ConnHello { listen_addr }) = Message::decode(&frame) else {
        return;
    };
    streams
        .lock()
        .await
        .insert(listen_addr.clone(), stream.clone());
    spawn_reader(stream, listen_addr, tx, streams);
}

/// Drain one socket until EOF or error, forwarding every frame under the
/// peer identifier it was registered with; on exit the socket is removed
/// only when it is still the registered one, so a replacement connection
/// survives the death of its predecessor.
fn spawn_reader(
    stream: Arc<TcpStream>,
    id: String,
    tx: mpsc::Sender<(String, Bytes)>,
    streams: Arc<Mutex<HashMap<String, Arc<TcpStream>>>>,
) {
    tokio::spawn(async move {
        while let Ok(data) = read_frame(&stream).await {
            if tx.send((id.clone(), data)).await.is_err() {
                break;
            }
        }
        let mut map = streams.lock().await;
        if map
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &stream))
        {
            map.remove(&id);
        }
    });
}

/// Read exactly `buf.len()` bytes from a shared socket reference, waiting
/// for readability between `try_read` attempts; `try_read` takes `&self`,
/// so sockets held behind `Arc` need no mutable access.
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

/// Read one length-prefixed frame, rejecting oversized lengths before
/// allocating the payload buffer.
async fn read_frame(stream: &TcpStream) -> Result<Bytes> {
    let mut len_buf = [0u8; LEN_PREFIX];
    read_exact(stream, &mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        bail!("frame exceeds size limit ({len} > {MAX_FRAME})");
    }
    let mut data = vec![0u8; len];
    read_exact(stream, &mut data).await?;
    Ok(Bytes::from(data))
}

/// Write one length-prefixed frame.
async fn write_frame(stream: &TcpStream, data: &[u8]) -> Result<()> {
    write_all(stream, &(data.len() as u32).to_be_bytes()).await?;
    write_all(stream, data).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
