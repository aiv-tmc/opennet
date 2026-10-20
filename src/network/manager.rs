//! Network adapter manager: routes frames across available transports.

use super::tcp::TcpAdapter;
use super::NetworkAdapter;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::future::select_all;

/// Sends and receives frames through the best available transport adapter.
pub struct Manager {
    adapters: Vec<Box<dyn NetworkAdapter>>,
}

impl Manager {
    /// Build a manager with all transports that initialized successfully.
    ///
    /// Fails if no adapter could be initialized at all.
    pub async fn new(port: u16) -> Result<Self> {
        let mut adapters: Vec<Box<dyn NetworkAdapter>> = Vec::new();
        if let Ok(tcp) = TcpAdapter::new(port).await {
            adapters.push(Box::new(tcp));
        }
        adapters.sort_by_key(|adapter| adapter.priority());
        if adapters.is_empty() {
            return Err(anyhow!("no network adapter available"));
        }
        Ok(Self { adapters })
    }

    /// Send a frame to `dest`, trying adapters from most to least preferred.
    pub async fn send(&mut self, dest: &str, data: Bytes) -> Result<()> {
        let mut last_err = None;
        for adapter in &mut self.adapters {
            match adapter.send(dest, data.clone()).await {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.expect("at least one adapter exists"))
    }

    /// Wait for the next inbound frame on any adapter.
    pub async fn recv(&mut self) -> Result<(String, Bytes)> {
        let futures: Vec<_> = self.adapters.iter_mut().map(|a| a.recv()).collect();
        let (result, _, _) = select_all(futures).await;
        result
    }

    /// Address identifying the local node on the preferred adapter.
    pub fn local_id(&self) -> String {
        self.adapters[0].local_id()
    }
}
