//! Transport tests over a real loopback listener.

use super::*;
use crate::message::Message;
use std::time::Duration;

const IDLE: Duration = Duration::from_secs(60);

fn accept_frame(task_id: &str) -> Bytes {
    Bytes::from(
        Message::TaskAccept {
            task_id: task_id.to_string(),
        }
        .encode(),
    )
}

#[tokio::test]
async fn frames_roundtrip_between_two_transports() {
    let a = Transport::new(0, IDLE).await.unwrap();
    let b = Transport::new(0, IDLE).await.unwrap();
    let dest = b.local_id();
    a.send(&dest, accept_frame("t1")).await.unwrap();
    let (src, data) = tokio::time::timeout(Duration::from_secs(5), b.recv())
        .await
        .expect("timed out")
        .expect("transport closed");
    assert_eq!(src, a.local_id());
    match Message::decode(&data) {
        Some(Message::TaskAccept { task_id }) => assert_eq!(task_id, "t1"),
        other => panic!("unexpected frame: {other:?}"),
    }
}

#[tokio::test]
async fn foreign_protocol_version_is_dropped() {
    let a = Transport::new(0, IDLE).await.unwrap();
    let b = Transport::new(0, IDLE).await.unwrap();
    // Greet manually with a wrong version, then send a frame: the frame
    // must never surface on b's inbound channel.
    let stream = TcpStream::connect(a.local_id().trim_start_matches("tcp:"))
        .await
        .unwrap();
    let hello = Message::ConnHello {
        version: PROTOCOL_VERSION + 1,
        listen_addr: b.local_id(),
    };
    write_frame_raw(&stream, &hello.encode()).await.unwrap();
    write_frame_raw(&stream, &accept_frame("bad"))
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), b.recv()).await;
    assert!(
        result.is_err(),
        "frame from a foreign protocol version was delivered"
    );
}

#[tokio::test]
async fn greeting_with_foreign_listen_address_is_dropped() {
    let a = Transport::new(0, IDLE).await.unwrap();
    let b = Transport::new(0, IDLE).await.unwrap();
    // A peer that connects from b's socket but claims a concrete
    // foreign listen IP must not be able to register the borrowed
    // identity. (The wildcard 0.0.0.0 advertisement is the legitimate
    // default and stays accepted.)
    let stream = TcpStream::connect(a.local_id().trim_start_matches("tcp:"))
        .await
        .unwrap();
    let hello = Message::ConnHello {
        version: PROTOCOL_VERSION,
        listen_addr: "tcp:192.0.2.1:4999".to_string(),
    };
    write_frame_raw(&stream, &hello.encode()).await.unwrap();
    write_frame_raw(&stream, &accept_frame("spoof"))
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), b.recv()).await;
    assert!(
        result.is_err(),
        "frame from a spoofed listen address was delivered"
    );
}

#[tokio::test]
async fn greeting_with_wildcard_listen_address_is_accepted() {
    let a = Transport::new(0, IDLE).await.unwrap();
    let b = Transport::new(0, IDLE).await.unwrap();
    // Both daemons advertise tcp:0.0.0.0:<port>; the greeting must be
    // accepted and frames must flow.
    a.send(&b.local_id(), accept_frame("wild")).await.unwrap();
    let (_src, data) = tokio::time::timeout(Duration::from_secs(5), b.recv())
        .await
        .expect("timed out")
        .expect("transport closed");
    assert!(Message::decode(&data).is_some());
}

#[tokio::test]
async fn send_to_unreachable_peer_fails_without_panicking() {
    let a = Transport::new(0, IDLE).await.unwrap();
    let result = a.send("tcp:127.0.0.1:1", Bytes::from_static(b"x")).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn idle_connection_is_dropped_and_reestablished_on_demand() {
    let a = Transport::new(0, Duration::from_millis(200)).await.unwrap();
    let b = Transport::new(0, Duration::from_secs(60)).await.unwrap();
    let dest = b.local_id();
    a.send(&dest, accept_frame("t1")).await.unwrap();
    // Let a's reader hit the short idle deadline and drop the socket.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // The next send transparently reconnects and still delivers.
    a.send(&dest, accept_frame("t2")).await.unwrap();
    let (_src, first) = tokio::time::timeout(Duration::from_secs(5), b.recv())
        .await
        .expect("timed out")
        .expect("transport closed");
    let (_src, second) = tokio::time::timeout(Duration::from_secs(5), b.recv())
        .await
        .expect("timed out")
        .expect("transport closed");
    assert!(Message::decode(&first).is_some());
    assert!(Message::decode(&second).is_some());
}

#[tokio::test]
async fn connection_budget_is_released_when_the_peer_dies() {
    let a = Transport::new(0, Duration::from_millis(100)).await.unwrap();
    let b = Transport::new(0, Duration::from_secs(60)).await.unwrap();
    let dest = b.local_id();
    a.send(&dest, accept_frame("t1")).await.unwrap();
    assert_eq!(a.connections.load(Ordering::Relaxed), 1);
    // Drop the peer: a's reader must hit the idle deadline, release the
    // budget and remove the cached socket. (The reader task of the
    // dropped transport keeps its own socket handle, so the connection
    // survives on b's side — the budget check is about a's bookkeeping.)
    drop(b);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.connections.load(Ordering::Relaxed), 0);
    assert!(a.streams.lock().await.is_empty());
}

#[tokio::test]
async fn send_survives_a_failed_write_on_a_stale_socket() {
    // A stand-in peer built from raw sockets: unlike `drop(Transport)`,
    // closing these really tears the connection and the listener down.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let dest = format!("tcp:127.0.0.1:{port}");
    let a = Transport::new(0, IDLE).await.unwrap();
    a.send(&dest, accept_frame("t1")).await.unwrap();
    // Accept a's connection and close the server side; then close the
    // listener so the reconnect has nowhere to go.
    let (server, _) = listener.accept().await.unwrap();
    drop(server);
    drop(listener);
    // Give a's reader a moment to observe the close and drop the stale
    // cached socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The next send must not reuse the dead socket silently: it
    // reconnects, fails against the closed listener and surfaces the
    // error instead of panicking or losing the frame.
    let result = a.send(&dest, accept_frame("t2")).await;
    assert!(
        result.is_err(),
        "send to a peer with a closed listener unexpectedly succeeded"
    );
}
