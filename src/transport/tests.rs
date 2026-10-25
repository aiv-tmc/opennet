//! Tests for the TCP transport: frame framing, size limits and end-to-end
//! exchange between two transport instances.

use super::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Open a connected loopback socket pair for frame-level tests.
async fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[tokio::test]
async fn frame_roundtrip_over_socket() {
    let (mut client, server) = socket_pair().await;
    client.write_all(&(5u32).to_be_bytes()).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let frame = read_frame(&server).await.unwrap();
    assert_eq!(&frame[..], b"hello");
}

#[tokio::test]
async fn write_frame_matches_read_frame() {
    let (client, server) = socket_pair().await;
    write_frame(&client, b"payload").await.unwrap();
    let frame = read_frame(&server).await.unwrap();
    assert_eq!(&frame[..], b"payload");
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_allocation() {
    let (mut client, server) = socket_pair().await;
    client
        .write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
        .await
        .unwrap();
    client.write_all(&[0u8; 64]).await.unwrap();
    assert!(read_frame(&server).await.is_err());
}

#[tokio::test]
async fn truncated_frame_is_an_error() {
    let (mut client, server) = socket_pair().await;
    client.write_all(&(10u32).to_be_bytes()).await.unwrap();
    client.write_all(b"short").await.unwrap();
    drop(client);
    assert!(read_frame(&server).await.is_err());
}

#[tokio::test]
async fn two_transports_exchange_frames_both_ways() {
    let a = Transport::new(0).await.unwrap();
    let b = Transport::new(0).await.unwrap();
    let payload = Bytes::from_static(b"ping-bytes");
    a.send(&b.local_id(), payload.clone()).await.unwrap();
    let (src, data) = tokio::time::timeout(Duration::from_secs(5), b.recv())
        .await
        .expect("timed out waiting for frame")
        .expect("transport closed");
    // The greeting registered the connection under the sender's listen
    // address, so replies can be addressed to it directly.
    assert_eq!(src, a.local_id());
    assert_eq!(data, payload);

    b.send(&src, Bytes::from_static(b"pong")).await.unwrap();
    let (src, data) = tokio::time::timeout(Duration::from_secs(5), a.recv())
        .await
        .expect("timed out waiting for reply")
        .expect("transport closed");
    assert_eq!(src, b.local_id());
    assert_eq!(&data[..], b"pong");
}

#[tokio::test]
async fn unreachable_destination_is_an_error() {
    let a = Transport::new(0).await.unwrap();
    // Bind and immediately release a port so connecting there is
    // guaranteed to be refused.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = probe.local_addr().unwrap().port();
    drop(probe);
    let result = a
        .send(
            &format!("tcp:127.0.0.1:{dead_port}"),
            Bytes::from_static(b"x"),
        )
        .await;
    assert!(result.is_err());
}
