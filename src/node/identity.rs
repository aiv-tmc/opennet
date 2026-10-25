//! Persistent node identity backed by an ed25519 keypair.
//!
//! The public node id is derived from the public key, so any signed message
//! can be checked against its claimed node id without extra bookkeeping.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Node identity able to sign wire messages and derive the public node id.
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Load the 32-byte secret key from `<state_dir>/node.key` or generate a
    /// fresh ed25519 keypair and store it with mode 0600.
    ///
    /// The state directory is created when missing so the identity can be
    /// the first component to touch a fresh state location. A key file of
    /// unexpected length is reported as an error instead of being silently
    /// replaced.
    pub fn load_or_create(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join("node.key");
        if let Ok(bytes) = std::fs::read(&path) {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("node key file {} has invalid length", path.display()))?;
            let signing_key = SigningKey::from_bytes(&bytes);
            return Ok(Self { signing_key });
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create state dir {}", parent.display()))?;
        }
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(&signing_key.to_bytes()))
            .with_context(|| format!("cannot write node key file {}", path.display()))?;
        Ok(Self { signing_key })
    }

    /// ed25519 public key of this node.
    pub fn pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Short public node identifier: first 8 bytes of blake3 of the public key.
    pub fn node_id(&self) -> String {
        Self::node_id_from_pubkey(&self.pubkey())
    }

    /// Derive the node id for an arbitrary public key.
    pub fn node_id_from_pubkey(pubkey: &[u8; 32]) -> String {
        hex::encode(&blake3::hash(pubkey).as_bytes()[..8])
    }

    /// Sign a protocol payload; the resulting signature travels on the wire.
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.signing_key.sign(payload).to_bytes()
    }

    /// Verify an ed25519 signature against the given public key and payload.
    pub fn verify(pubkey: &[u8; 32], payload: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        key.verify(payload, &Signature::from_bytes(signature))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch_dir;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn creates_key_with_mode_0600_in_missing_directory() {
        let dir = scratch_dir("id-create");
        let identity = Identity::load_or_create(&dir).unwrap();
        let metadata = std::fs::metadata(dir.join("node.key")).unwrap();
        #[cfg(unix)]
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(identity.node_id().len(), 16);
    }

    #[test]
    fn reload_returns_the_same_identity() {
        let dir = scratch_dir("id-reload");
        let first = Identity::load_or_create(&dir).unwrap();
        let second = Identity::load_or_create(&dir).unwrap();
        assert_eq!(first.node_id(), second.node_id());
        assert_eq!(first.pubkey(), second.pubkey());
    }

    #[test]
    fn malformed_key_file_is_an_error() {
        let dir = scratch_dir("id-bad");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("node.key"), [1u8; 16]).unwrap();
        assert!(Identity::load_or_create(&dir).is_err());
    }

    #[test]
    fn sign_verify_roundtrip_and_foreign_key_rejection() {
        let dir = scratch_dir("id-sign");
        let identity = Identity::load_or_create(&dir).unwrap();
        let payload = b"announcement payload";
        let signature = identity.sign(payload);
        assert!(Identity::verify(&identity.pubkey(), payload, &signature));
        assert!(!Identity::verify(
            &identity.pubkey(),
            b"other payload",
            &signature
        ));
        let foreign = Identity::load_or_create(&scratch_dir("id-foreign")).unwrap();
        assert!(!Identity::verify(&foreign.pubkey(), payload, &signature));
    }
}
