//! Network transport layer.

mod manager;
mod tcp;

pub use manager::Manager;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

/// A network transport able to exchange frames with remote nodes.
#[async_trait]
pub trait NetworkAdapter: Send + Sync {
    /// Send one frame to the peer identified by `dest`.
    async fn send(&self, dest: &str, data: Bytes) -> Result<()>;
    /// Receive the next inbound frame, returning its source id and payload.
    async fn recv(&mut self) -> Result<(String, Bytes)>;
    /// Network address identifying the local node on this adapter.
    fn local_id(&self) -> String;
    /// Lower value means preferred adapter.
    fn priority(&self) -> u8;
}
