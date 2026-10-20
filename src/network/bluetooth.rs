// Bluetooth adapter временно отключён – требует доработки под API bluer 0.15
// Для включения раскомментируйте и исправьте импорты согласно документации bluer.

#![cfg(feature = "bluetooth")]

use super::*;
use anyhow::Result;
use bytes::Bytes;

pub struct BluetoothAdapter;

impl BluetoothAdapter {
    pub async fn new() -> Result<Self> {
        anyhow::bail!("Bluetooth adapter disabled in this build")
    }
}

#[async_trait]
impl NetworkAdapter for BluetoothAdapter {
    async fn send(&self, _dest: &str, _data: Bytes) -> Result<()> {
        anyhow::bail!("Bluetooth not available")
    }
    async fn recv(&mut self) -> Result<(String, Bytes)> {
        anyhow::bail!("Bluetooth not available")
    }
    fn local_id(&self) -> String { "bt:disabled".to_string() }
    fn priority(&self) -> u8 { 2 }
}
