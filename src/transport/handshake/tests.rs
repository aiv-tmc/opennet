//! Crypto session and handshake regression tests.

use super::*;
use tokio::net::TcpListener;

/// Two sessions derived from the same transcript with the opposite
/// directional roles.
fn session_pair() -> (CryptoSession, CryptoSession) {
    let initiator_sk = StaticSecret::from([1u8; 32]);
    let responder_sk = StaticSecret::from([2u8; 32]);
    let initiator_pk = PublicKey::from(&initiator_sk).to_bytes();
    let responder_pk = PublicKey::from(&responder_sk).to_bytes();
    let initiator_nonce = [3u8; 32];
    let responder_nonce = [4u8; 32];
    let initiator = CryptoSession::pair(
        &initiator_sk,
        &PublicKey::from(responder_pk),
        &initiator_nonce,
        &responder_nonce,
        &initiator_pk,
        &responder_pk,
        true,
    );
    let responder = CryptoSession::pair(
        &responder_sk,
        &PublicKey::from(initiator_pk),
        &initiator_nonce,
        &responder_nonce,
        &initiator_pk,
        &responder_pk,
        false,
    );
    (initiator, responder)
}

#[test]
fn session_roundtrip_tamper_eviction_and_ordering() {
    let (mut initiator, mut responder) = session_pair();
    let first = initiator.seal(b"frame one").unwrap();
    assert_ne!(first, b"frame one", "ciphertext must not equal plaintext");
    assert_eq!(responder.open(&first).unwrap(), b"frame one");
    // Tampering is detected; the receive counter only advances on
    // success, so the genuine frame sealed for the failed slot no
    // longer fits its slot either, and the connection owner treats
    // the authentication failure as fatal.
    let mut tampered = initiator.seal(b"frame two").unwrap();
    tampered[0] ^= 1;
    assert!(responder.open(&tampered).is_err());
    let third = initiator.seal(b"three").unwrap();
    assert!(responder.open(&third).is_err());
    // The reverse direction is an independent key/counter space and
    // stays fully usable after the forward direction died.
    let back = responder.seal(b"pong").unwrap();
    assert_eq!(initiator.open(&back).unwrap(), b"pong");
}

#[test]
fn frames_must_arrive_in_exactly_send_order() {
    let (mut initiator, mut responder) = session_pair();
    let third = initiator.seal(b"three").unwrap();
    let fourth = initiator.seal(b"four").unwrap();
    assert_ne!(third, fourth, "equal-length frames still differ");
    // Delivering the newer frame first fails; the counter has not
    // advanced, so the older frame still opens afterwards.
    assert!(responder.open(&fourth).is_err());
    assert_eq!(responder.open(&third).unwrap(), b"three");
    // A replayed frame from an already-consumed slot never passes.
    assert!(responder.open(&third).is_err());
}

#[tokio::test]
async fn full_handshake_over_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor_identity = Identity::generate();
    let server = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let (listen_addr, session) = accept(&acceptor_identity, &stream, peer_addr)
            .await
            .expect("accept must succeed");
        (listen_addr, session)
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut dialer_session = initiate(&Identity::generate(), &stream, "tcp:127.0.0.1:9")
        .await
        .expect("initiate must succeed");
    let (listen_addr, mut acceptor_session) = server.await.unwrap();
    assert_eq!(listen_addr, "tcp:127.0.0.1:9");
    let ping = dialer_session.seal(b"ping").unwrap();
    assert_eq!(acceptor_session.open(&ping).unwrap(), b"ping");
    let pong = acceptor_session.seal(b"pong").unwrap();
    assert_eq!(dialer_session.open(&pong).unwrap(), b"pong");
}
