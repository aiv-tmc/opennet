//! Connection lifecycle workers: the accept loop, inbound greeting
//! handling, and the per-socket reader that pumps frames into the
//! shared receive queue and owns the connection budget claim.
//!
//! The reader is the single owner of the budget slot taken at accept
//! (or dial) time: whatever the reason for its exit — EOF, socket
//! error, idle timeout, tampered ciphertext, a closed dispatch queue —
//! it always drops the cached registration, closes the socket so the
//! peer's reader observes the shutdown, and decrements the shared
//! counter exactly once.

use super::frame;
use super::handshake;
use super::{Conn, HELLO_TIMEOUT};
use crate::node::identity::Identity;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// Cached connections keyed by their dial address, shared between the
/// transport, the accept loop and every reader task. This is the single
/// definition; `transport.rs` imports it from here.
pub(super) type ConnMap = Arc<Mutex<HashMap<String, Arc<Conn>>>>;

/// Accept loop: refuse connections once the shared budget is exhausted,
/// then claim the budget for each accepted socket and greet. Claims of
/// refused or failed greetings are released here; claims of established
/// connections are owned (and released) by the reader task.
pub(super) async fn accept_loop(
    identity: Identity,
    listener: TcpListener,
    streams: ConnMap,
    frame_tx: mpsc::Sender<(String, Bytes)>,
    connections: Arc<AtomicUsize>,
    idle: Duration,
) {
    loop {
        let Ok((socket, peer_addr)) = listener.accept().await else {
            break;
        };
        if connections.load(Ordering::SeqCst) >= super::MAX_CONNECTIONS {
            // Connection budget exhausted: drop the socket without
            // claiming anything, so slowloris-style floods cannot pin
            // the daemon at the connection ceiling.
            drop(socket);
            continue;
        }
        connections.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(handle_inbound(
            identity.clone(),
            socket,
            peer_addr,
            streams.clone(),
            frame_tx.clone(),
            connections.clone(),
            idle,
        ));
    }
}

/// Inbound greeting: run the responder side of the handshake, validate
/// the advertised listen address against the real socket IP, rewrite a
/// wildcard advertisement to the peer's real socket IP (the wildcard is
/// not a usable dial target), and register the connection.
async fn handle_inbound(
    identity: Identity,
    socket: TcpStream,
    peer_addr: SocketAddr,
    streams: ConnMap,
    frame_tx: mpsc::Sender<(String, Bytes)>,
    connections: Arc<AtomicUsize>,
    idle: Duration,
) {
    let accepted = tokio::time::timeout(
        HELLO_TIMEOUT,
        handshake::accept(&identity, &socket, peer_addr),
    )
    .await;
    let Ok(Ok((mut listen_addr, session))) = accepted else {
        if let Ok(Err(err)) = accepted {
            eprintln!("[transport] dropping connection from {peer_addr}: {err:#}");
        }
        connections.fetch_sub(1, Ordering::SeqCst);
        return;
    };
    if let Some(raw) = listen_addr.strip_prefix("tcp:") {
        if let Ok(advertised) = raw.parse::<SocketAddr>() {
            if advertised.ip().is_unspecified() {
                listen_addr = format!("tcp:{}:{}", peer_addr.ip(), advertised.port());
            }
        }
    }
    let conn = Arc::new(Conn {
        stream: socket,
        write_lock: Mutex::new(()),
        crypto: Mutex::new(session),
    });
    if let Some(old) = streams
        .lock()
        .await
        .insert(listen_addr.clone(), conn.clone())
    {
        // A simultaneous connection won the registration race; retire
        // the loser so its reader observes the shutdown and releases
        // the connection budget.
        frame::close_stream(&old.stream).await;
    }
    spawn_conn_reader(listen_addr, conn, frame_tx, connections, idle, streams);
}

/// Read frames until EOF, error or idle timeout, decrypt each frame and
/// forward it with the connection's address; an authentication failure
/// kills the connection. On exit the cached registration is dropped (so
/// the next send re-establishes the connection), the socket is closed
/// (so the peer's reader observes EOF) and the budget claim is released.
pub(super) fn spawn_conn_reader(
    id: String,
    conn: Arc<Conn>,
    frame_tx: mpsc::Sender<(String, Bytes)>,
    connections: Arc<AtomicUsize>,
    idle: Duration,
    streams: ConnMap,
) {
    tokio::spawn(async move {
        loop {
            let read = tokio::time::timeout(idle, frame::read_frame(&conn.stream)).await;
            match read {
                Err(_) => break,       // idle timeout
                Ok(Err(_)) => break,   // socket error
                Ok(Ok(None)) => break, // clean EOF
                Ok(Ok(Some(data))) => {
                    let plain = { conn.crypto.lock().await.open(&data) };
                    let Ok(plain) = plain else {
                        eprintln!(
                            "[transport] frame failed to decrypt on {id}: dropping connection"
                        );
                        break;
                    };
                    if frame_tx
                        .send((id.clone(), Bytes::from(plain)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        {
            let mut streams = streams.lock().await;
            if streams
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &conn))
            {
                streams.remove(&id);
            }
        }
        frame::close_stream(&conn.stream).await;
        connections.fetch_sub(1, Ordering::SeqCst);
    });
}
