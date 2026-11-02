//! Authenticated key exchange for protocol v3.
//!
//! Both sides generate an ephemeral X25519 keypair and a fresh nonce.
//! The dialer's `ConnHello` and the acceptor's `ConnAccept` are signed
//! by the nodes' ed25519 identity keys, which binds the ephemeral keys
//! to persistent identities: an active man-in-the-middle cannot
//! substitute its own key material without a valid signature, and an
//! accept recorded from an older session fails because it covers the
//! dialer's fresh nonce. The shared secret and the full transcript
//! (both nonces, both ephemeral keys) feed two domain-separated KDF
//! invocations, yielding one directional key per flow. Every data frame
//! is then a ChaCha20-Poly1305 ciphertext whose nonce is a strictly
//! increasing counter; TCP provides the ordering, the counter provides
//! uniqueness, and a single authentication failure kills the
//! connection: the receive counter only advances on success, so the
//! session never resynchronizes after tampering.

use super::frame;
use crate::message::{Message, PROTOCOL_VERSION};
use crate::node::identity::Identity;
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

/// KDF context separating the two directions of one session.
const CONTEXT_INITIATOR_TO_RESPONDER: &str = "opennet transport v3 initiator to responder";
const CONTEXT_RESPONDER_TO_INITIATOR: &str = "opennet transport v3 responder to initiator";

/// Counter headroom; a session is closed long before the nonce space
/// can wrap.
const COUNTER_LIMIT: u64 = u64::MAX - 1024;

/// One directional cipher state: the key and its frame counter.
struct Direction {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Direction {
    fn new(key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("a 32-byte key is always valid");
        Self { cipher, counter: 0 }
    }

    /// The counter as a 96-bit nonce: the low 8 little-endian bytes are
    /// the counter, the high 4 bytes stay zero.
    fn nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}

/// An established encrypted session with independent send and receive
/// directions.
pub struct CryptoSession {
    seal: Direction,
    open: Direction,
}

impl CryptoSession {
    /// Encrypt one outgoing frame with the next counter nonce.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.seal.counter >= COUNTER_LIMIT {
            bail!("session send counter exhausted");
        }
        let nonce = Direction::nonce(self.seal.counter);
        let out = self
            .seal
            .cipher
            .encrypt((&nonce).into(), plaintext)
            .map_err(|_| anyhow!("frame encryption failed"))?;
        self.seal.counter += 1;
        Ok(out)
    }

    /// Decrypt one incoming frame against the exact expected counter
    /// slot. A frame that fails authentication leaves the counter
    /// untouched, but the connection owner closes the socket on this
    /// error, so a tampered or reordered frame never gets a second
    /// chance: TCP ordering guarantees the genuine frame for this slot
    /// was already delivered or never will be, and any later frame was
    /// sealed against a different nonce. A replayed frame from an
    /// already-consumed slot can never pass: its nonce is behind the
    /// counter.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if self.open.counter >= COUNTER_LIMIT {
            bail!("session receive counter exhausted");
        }
        let nonce = Direction::nonce(self.open.counter);
        let out = self
            .open
            .cipher
            .decrypt((&nonce).into(), ciphertext)
            .map_err(|_| anyhow!("frame failed authentication"))?;
        self.open.counter += 1;
        Ok(out)
    }

    /// Derive both session directions from the local ephemeral secret,
    /// the peer's ephemeral key and the full handshake transcript. Both
    /// sides feed the identical transcript; `we_initiated` only picks
    /// which derived key seals and which opens.
    fn pair(
        eph_sk: &StaticSecret,
        peer_eph_pk: &PublicKey,
        initiator_nonce: &[u8; 32],
        responder_nonce: &[u8; 32],
        initiator_eph_pk: &[u8; 32],
        responder_eph_pk: &[u8; 32],
        we_initiated: bool,
    ) -> Self {
        let shared = eph_sk.diffie_hellman(peer_eph_pk);
        let mut material = Vec::with_capacity(32 * 5);
        material.extend_from_slice(shared.as_bytes());
        material.extend_from_slice(initiator_nonce);
        material.extend_from_slice(responder_nonce);
        material.extend_from_slice(initiator_eph_pk);
        material.extend_from_slice(responder_eph_pk);
        let i2r = blake3::derive_key(CONTEXT_INITIATOR_TO_RESPONDER, &material);
        let r2i = blake3::derive_key(CONTEXT_RESPONDER_TO_INITIATOR, &material);
        let (seal_key, open_key) = if we_initiated { (i2r, r2i) } else { (r2i, i2r) };
        CryptoSession {
            seal: Direction::new(seal_key),
            open: Direction::new(open_key),
        }
    }
}

/// Dialer side: send a signed `ConnHello` and verify the signed
/// `ConnAccept`; any deviation fails the connection attempt.
pub async fn initiate(
    identity: &Identity,
    stream: &TcpStream,
    local_id: &str,
) -> Result<CryptoSession> {
    let eph_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pk = PublicKey::from(&eph_sk);
    let eph_arr = eph_pk.to_bytes();
    let mut hello_nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut hello_nonce);
    let hello = Message::ConnHello {
        version: PROTOCOL_VERSION,
        listen_addr: local_id.to_string(),
        eph_pubkey: eph_arr,
        nonce: hello_nonce,
        pubkey: identity.pubkey(),
        signature: identity
            .sign(&Message::conn_hello_signing_payload(
                local_id,
                &eph_arr,
                &hello_nonce,
            ))
            .to_vec(),
    };
    frame::write_frame_raw(stream, &hello.encode()).await?;
    let reply = frame::read_frame(stream)
        .await?
        .ok_or_else(|| anyhow!("peer closed the connection during the handshake"))?;
    let Some(Message::ConnAccept {
        version,
        eph_pubkey,
        nonce: accept_nonce,
        pubkey,
        signature,
    }) = Message::decode(&reply)
    else {
        bail!("peer did not answer with a connection accept");
    };
    if version != PROTOCOL_VERSION {
        bail!("peer speaks protocol v{version}");
    }
    let Ok(signature) = <&[u8; 64]>::try_from(signature.as_slice()) else {
        bail!("malformed accept signature");
    };
    // The accept signature covers the dialer nonce (binding this
    // answer to exactly this handshake attempt) and the acceptor
    // nonce, plus both ephemeral keys — identical byte order on both
    // sides of the exchange.
    if !Identity::verify(
        &pubkey,
        &Message::conn_accept_signing_payload(&hello_nonce, &accept_nonce, &eph_arr, &eph_pubkey),
        signature,
    ) {
        bail!("accept signature invalid: peer identity does not match the key exchange");
    }
    Ok(CryptoSession::pair(
        &eph_sk,
        &PublicKey::from(eph_pubkey),
        &hello_nonce,
        &accept_nonce,
        &eph_arr,
        &eph_pubkey,
        true,
    ))
}

/// Acceptor side: validate the `ConnHello` (version, advertised listen
/// address against the real socket IP, identity signature), answer
/// with a signed `ConnAccept`, and return the advertised listen address
/// (the registration key) with the session.
pub async fn accept(
    identity: &Identity,
    stream: &TcpStream,
    peer_addr: SocketAddr,
) -> Result<(String, CryptoSession)> {
    let frame = frame::read_frame(stream)
        .await?
        .ok_or_else(|| anyhow!("peer closed the connection before the handshake"))?;
    let Some(Message::ConnHello {
        version,
        listen_addr,
        eph_pubkey,
        nonce: hello_nonce,
        pubkey,
        signature,
    }) = Message::decode(&frame)
    else {
        bail!("first frame is not a connection hello");
    };
    if version != PROTOCOL_VERSION {
        bail!("peer {peer_addr} speaks protocol v{version}");
    }
    let advertised = listen_addr
        .strip_prefix("tcp:")
        .and_then(|raw| raw.parse::<SocketAddr>().ok())
        .ok_or_else(|| anyhow!("malformed listen address {listen_addr}"))?;
    if !(advertised.ip().is_unspecified() || advertised.ip() == peer_addr.ip()) {
        bail!("advertised foreign listen address {listen_addr}");
    }
    let Ok(signature) = <&[u8; 64]>::try_from(signature.as_slice()) else {
        bail!("malformed hello signature");
    };
    if !Identity::verify(
        &pubkey,
        &Message::conn_hello_signing_payload(&listen_addr, &eph_pubkey, &hello_nonce),
        signature,
    ) {
        bail!("hello signature invalid");
    }
    let eph_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pk = PublicKey::from(&eph_sk);
    let eph_arr = eph_pk.to_bytes();
    let mut accept_nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut accept_nonce);
    let accept = Message::ConnAccept {
        version: PROTOCOL_VERSION,
        eph_pubkey: eph_arr,
        nonce: accept_nonce,
        pubkey: identity.pubkey(),
        // Same payload bytes the dialer reconstructs in `initiate`:
        // dialer nonce, acceptor nonce, dialer ephemeral key, acceptor
        // ephemeral key.
        signature: identity
            .sign(&Message::conn_accept_signing_payload(
                &hello_nonce,
                &accept_nonce,
                &eph_pubkey,
                &eph_arr,
            ))
            .to_vec(),
    };
    frame::write_frame_raw(stream, &accept.encode()).await?;
    Ok((
        listen_addr,
        CryptoSession::pair(
            &eph_sk,
            &PublicKey::from(eph_pubkey),
            &hello_nonce,
            &accept_nonce,
            &eph_pubkey,
            &eph_arr,
            false,
        ),
    ))
}

#[cfg(test)]
mod tests;
