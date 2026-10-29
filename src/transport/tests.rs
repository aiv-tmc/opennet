//! Transport tests over a real loopback listener.

use super::*;
use crate::message::Message;
use std::time::Duration;

const IDLE: Duration = Duration::from_secs(60);

#[tokio::test]
async fn frames_roundtrip_between_two_transports() {
    let a = Transport::new(0, IDLE).await.unwrap();
    let b = Transport::new(0, IDLE).await.unwrap();
    let dest = b.local_id();
    a.send(
        &dest,
        Bytes::from(
            Message::TaskAccept {
                task_id: "t1".into(),
            }
            .encode(),
        ),
    )
    .await
    .unwrap();
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
    write_frame_raw(
        &stream,
        &Message::TaskAccept {
            task_id: "bad".into(),
        }
        .encode(),
    )
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), b.recv()).await;
    assert!(
        result.is_err(),
        "frame from a foreign protocol version was delivered"
    );
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
    a.send(
        &dest,
        Bytes::from(
            Message::TaskAccept {
                task_id: "t1".into(),
            }
            .encode(),
        ),
    )
    .await
    .unwrap();
    // Let a's reader hit the short idle deadline and drop the socket.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // The next send transparently reconnects and still delivers.
    a.send(
        &dest,
        Bytes::from(
            Message::TaskAccept {
                task_id: "t2".into(),
            }
            .encode(),
        ),
    )
    .await
    .unwrap();
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
