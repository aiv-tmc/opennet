//! Transport regression tests over real loopback sockets.

use super::frame;
use super::Transport;
use crate::message::{Message, PROTOCOL_VERSION};
use crate::node::identity::Identity;
use bytes::Bytes;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

const IDLE: Duration = Duration::from_secs(60);

async fn make_test_transport() -> Arc<Transport> {
    Arc::new(Transport::new(Identity::generate(), 0, IDLE).await.unwrap())
}

/// The bound port of one transport, for src-port assertions.
fn port_of(transport: &Transport) -> u16 {
    transport
        .local_id()
        .strip_prefix("tcp:")
        .unwrap()
        .rsplit_once(':')
        .unwrap()
        .1
        .parse()
        .unwrap()
}

/// Assert one reported connection source is a concrete, rewritten
/// address (never the wildcard bind address) carrying the expected
/// port. The exact IP is environment-dependent (it is the address the
/// peer actually dialed from, which may differ from what the peer
/// probes as its egress address), so only its shape is pinned here.
fn assert_concrete_src(src: &str, expected_port: u16) {
    let raw = src.strip_prefix("tcp:").expect("tcp: address");
    let (ip, port) = raw.rsplit_once(':').expect("ip:port");
    let ip: std::net::IpAddr = ip.parse().expect("valid ip");
    assert!(
        !ip.is_unspecified(),
        "the wildcard bind address must be rewritten to the real peer ip, got {src}"
    );
    assert_eq!(port.parse::<u16>().unwrap(), expected_port);
}

/// A fully signed hello; `version` is a parameter so tests can
/// exercise the version gate.
fn signed_hello(listen_addr: &str, version: u16, identity: &Identity) -> Message {
    let eph_pubkey = [7u8; 32];
    let nonce = [9u8; 32];
    Message::ConnHello {
        version,
        listen_addr: listen_addr.to_string(),
        eph_pubkey,
        nonce,
        pubkey: identity.pubkey(),
        signature: identity
            .sign(&Message::conn_hello_signing_payload(
                listen_addr,
                &eph_pubkey,
                &nonce,
            ))
            .to_vec(),
    }
}

async fn raw_connect(transport: &Transport) -> TcpStream {
    let dest = transport.local_id();
    let addr: std::net::SocketAddr = dest.strip_prefix("tcp:").unwrap().parse().unwrap();
    TcpStream::connect(addr).await.unwrap()
}

async fn poll_until(mut check: impl FnMut() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition did not become true in time");
}

#[tokio::test]
async fn frames_roundtrip_between_two_transports() {
    let a = make_test_transport().await;
    let b = make_test_transport().await;
    let frame = Bytes::from_static(b"hello over the encrypted channel");
    a.send(&b.local_id(), frame.clone()).await.unwrap();
    let (src, data) = b.recv().await.expect("transport closed");
    // The source is the rewritten (real-IP) registration address of
    // the connection, never the wildcard bind address.
    assert_concrete_src(&src, port_of(&a));
    assert_eq!(data, frame);
    // The reverse direction rides the same connection, re-keyed per
    // direction by the session.
    b.send(&a.local_id(), frame.clone()).await.unwrap();
    let (src, data) = a.recv().await.expect("transport closed");
    assert_concrete_src(&src, port_of(&b));
    assert_eq!(data, frame);
}

#[tokio::test]
async fn send_to_unreachable_peer_fails_without_panicking() {
    let a = make_test_transport().await;
    // 192.0.2.1 is TEST-NET-1 (RFC 5737) and guaranteed unroutable.
    let result = a.send("tcp:192.0.2.1:9", Bytes::from_static(b"x")).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn send_survives_a_failed_write_on_a_stale_socket() {
    let a = make_test_transport().await;
    let b = make_test_transport().await;
    let first = Bytes::from_static(b"before the break");
    a.send(&b.local_id(), first.clone()).await.unwrap();
    let (src, data) = b.recv().await.expect("transport closed");
    assert_concrete_src(&src, port_of(&a));
    assert_eq!(data, first);
    // Tear down b's side of the connection; a keeps the stale socket
    // cached. The registration key under which b holds the connection
    // is the source address b observed — use the reported src itself
    // rather than guessing the environment-dependent ip.
    let conn = b.streams.lock().await.get(&src).cloned().unwrap();
    frame::close_stream(&conn.stream).await;
    drop(conn);
    // Give the FIN a moment to propagate so the stale write
    // deterministically fails and the retry path engages.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = Bytes::from_static(b"after the break");
    a.send(&b.local_id(), second.clone()).await.unwrap();
    let (_src, data) = b.recv().await.expect("transport closed");
    assert_eq!(data, second, "the retry must deliver the frame");
}

#[tokio::test]
async fn connection_budget_is_released_when_the_peer_dies() {
    let a = make_test_transport().await;
    let b = make_test_transport().await;
    a.send(&b.local_id(), Bytes::from_static(b"ping"))
        .await
        .unwrap();
    let _ = b.recv().await;
    // Kill every socket b holds; a's readers observe the deaths and
    // must return the shared budget to zero.
    let keys: Vec<String> = b.streams.lock().await.keys().cloned().collect();
    for key in keys {
        let conn = b.streams.lock().await.get(&key).cloned().unwrap();
        frame::close_stream(&conn.stream).await;
    }
    poll_until(|| a.connections.load(Ordering::SeqCst) == 0).await;
}

#[tokio::test]
async fn greeting_with_foreign_listen_address_is_dropped() {
    let a = make_test_transport().await;
    let raw = raw_connect(&a).await;
    let identity = Identity::generate();
    let hello = signed_hello("tcp:10.0.0.1:7000", PROTOCOL_VERSION, &identity);
    frame::write_frame_raw(&raw, &hello.encode()).await.unwrap();
    // The greeting is refused before the signature matters; the socket
    // is closed with no accept and nothing is registered.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!a.streams.lock().await.contains_key("tcp:10.0.0.1:7000"));
    let mut byte = [0u8; 1];
    raw.readable().await.unwrap();
    let n = raw.try_read(&mut byte).unwrap_or(0);
    assert_eq!(n, 0, "the refused greeting must close the socket");
}

#[tokio::test]
async fn wildcard_greeting_is_registered_under_the_real_peer_ip() {
    let a = make_test_transport().await;
    let raw = raw_connect(&a).await;
    let real_ip = raw.local_addr().unwrap().ip().to_string();
    let identity = Identity::generate();
    let hello = signed_hello("tcp:0.0.0.0:7000", PROTOCOL_VERSION, &identity);
    frame::write_frame_raw(&raw, &hello.encode()).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), frame::read_frame(&raw))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Some(Message::ConnAccept { version, .. }) = Message::decode(&reply) else {
        panic!("expected a connection accept");
    };
    assert_eq!(version, PROTOCOL_VERSION);
    // The wildcard is not a usable dial target; the connection must be
    // registered under the peer's real socket IP so the advertised
    // port stays reachable through the routing table.
    let expected = format!("tcp:{real_ip}:7000");
    let mut registered = false;
    for _ in 0..100 {
        if a.streams.lock().await.contains_key(&expected) {
            registered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        registered,
        "wildcard greeting was not registered as {expected}"
    );
}

#[tokio::test]
async fn idle_connection_is_dropped_and_reestablished_on_demand() {
    let a = Arc::new(
        Transport::new(Identity::generate(), 0, Duration::from_secs(1))
            .await
            .unwrap(),
    );
    let b = make_test_transport().await;
    let b_id = b.local_id();
    let frame = Bytes::from_static(b"establish");
    a.send(&b_id, frame.clone()).await.unwrap();
    let (_src, data) = b.recv().await.expect("transport closed");
    assert_eq!(data, frame);
    // Both directions of the connection go silent; the readers drop
    // the sockets after the idle deadline and release the budget.
    poll_until(|| a.connections.load(Ordering::SeqCst) == 0).await;
    // The reader must also drop its cached registration, otherwise the
    // next send would write into a socket nobody reads and the reply
    // would be lost.
    for _ in 0..100 {
        if !a.streams.lock().await.contains_key(&b_id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !a.streams.lock().await.contains_key(&b_id),
        "the idle reader must drop its cached registration"
    );
    // The next send transparently re-establishes the connection.
    let again = Bytes::from_static(b"reestablished");
    a.send(&b_id, again.clone()).await.unwrap();
    let (_src, data) = b.recv().await.expect("transport closed");
    assert_eq!(data, again);
}

#[tokio::test]
async fn foreign_protocol_version_is_dropped() {
    let a = make_test_transport().await;
    let raw = raw_connect(&a).await;
    let identity = Identity::generate();
    let hello = signed_hello("tcp:127.0.0.1:9", PROTOCOL_VERSION - 1, &identity);
    frame::write_frame_raw(&raw, &hello.encode()).await.unwrap();
    // A version mismatch is never answered: the peer either stays
    // silent until the deadline or closes the socket without a frame.
    let reply = tokio::time::timeout(Duration::from_secs(2), frame::read_frame(&raw)).await;
    match reply {
        Err(_) => {}
        Ok(Ok(None)) => {}
        Ok(Ok(Some(_))) => panic!("a version mismatch must never be answered"),
        Ok(Err(_)) => {}
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(a.streams.lock().await.is_empty());
}

#[tokio::test]
async fn handshake_rejects_a_forged_accept() {
    let a = make_test_transport().await;
    // A raw listener stands in for a peer answering with a forged
    // signature: the dialer must refuse to establish the session, so
    // the send fails instead of trusting a man-in-the-middle.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest = format!("tcp:{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _hello = frame::read_frame(&stream).await.unwrap();
        let forged = Message::ConnAccept {
            version: PROTOCOL_VERSION,
            eph_pubkey: [1u8; 32],
            nonce: [2u8; 32],
            pubkey: [3u8; 32],
            signature: vec![9u8; 64],
        };
        frame::write_frame_raw(&stream, &forged.encode())
            .await
            .unwrap();
        // Keep the socket open so the failure is attributable to the
        // signature, not to a closed connection.
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    let result = a.send(&dest, Bytes::from_static(b"payload")).await;
    assert!(
        result.is_err(),
        "a forged accept must fail the send instead of trusting it"
    );
    server.await.unwrap();
}
