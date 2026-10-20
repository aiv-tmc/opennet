use blake3::Hasher;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::Result;

#[allow(dead_code)]
pub async fn perform_handshake(stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin), is_initiator: bool) -> Result<[u8; 32]> {
    let mut rng = rand::thread_rng();
    let challenge: u64 = rng.gen();
    let mut hasher = Hasher::new();
    hasher.update(&challenge.to_le_bytes());
    let my_hash = *hasher.finalize().as_bytes();
    
    if is_initiator {
        stream.write_all(&challenge.to_le_bytes()).await?;
        let mut peer_hash = [0u8; 32];
        stream.read_exact(&mut peer_hash).await?;
        let mut hasher2 = Hasher::new();
        hasher2.update(&(challenge + 1).to_le_bytes());
        let expected = *hasher2.finalize().as_bytes();
        if peer_hash != expected {
            anyhow::bail!("Handshake hash mismatch");
        }
        Ok(my_hash)
    } else {
        let mut peer_challenge = [0u8; 8];
        stream.read_exact(&mut peer_challenge).await?;
        let peer_challenge_val = u64::from_le_bytes(peer_challenge);
        let mut hasher2 = Hasher::new();
        hasher2.update(&(peer_challenge_val + 1).to_le_bytes());
        let response = *hasher2.finalize().as_bytes();
        stream.write_all(&response).await?;
        Ok(my_hash)
    }
}
