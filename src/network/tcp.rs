//! TCP transport with persistent per-peer connections.

use super::NetworkAdapter;
use anyhow::{bail, Result};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Reject frames larger than 1 MiB to bound memory usage per connection.
const MAX_FRAME: usize = 1024 * 1024;

pub struct TcpAdapter {
    listener: TcpListener,
    streams: Arc<Mutex<HashMap<String, TcpStream>>>,
    local_addr: std::net::SocketAddr,
}

impl TcpAdapter {
    /// Bind a listener on all interfaces at the given port (0 = ephemeral).
    pub async fn new(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            streams: Arc::new(Mutex::new(HashMap::new())),
            local_addr,
        })
    }

    /// Open and register a new outbound connection to `addr`.
    async fn connect(&self, addr: &str) -> Result<()> {
        let stream = TcpStream::connect(addr).await?;
        let id = format!("tcp:{}", stream.peer_addr()?);
        self.streams.lock().await.insert(id, stream);
        Ok(())
    }
}

#[async_trait]
impl NetworkAdapter for TcpAdapter {
    async fn send(&self, dest: &str, data: Bytes) -> Result<()> {
        // Open the connection on first use, then reuse the stored stream.
        if !self.streams.lock().await.contains_key(dest) {
            self.connect(dest).await?;
        }
        let mut streams = self.streams.lock().await;
        let stream = streams
            .get_mut(dest)
            .expect("stream registered by connect");
        stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
        stream.write_all(&data).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<(String, Bytes)> {
        let (mut stream, addr) = self.listener.accept().await?;
        let id = format!("tcp:{}", addr);
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME {
            bail!("frame from {id} exceeds size limit ({len} > {MAX_FRAME})");
        }
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;
        // Keep the connection open so replies can reuse it.
        self.streams.lock().await.insert(id.clone(), stream);
        Ok((id, Bytes::from(data)))
    }

    fn local_id(&self) -> String {
        format!("tcp:{}", self.local_addr)
    }

    fn priority(&self) -> u8 {
        1
    }
}
