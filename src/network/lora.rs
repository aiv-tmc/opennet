use super::*;
use tokio::net::UdpSocket;
use anyhow::Result;

const MULTICAST_ADDR: &str = "224.0.2.60:6000";
const PACKET_SIZE: usize = 256;

pub struct LoraAdapter {
    socket: UdpSocket,
}

impl LoraAdapter {
    pub async fn new() -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = MULTICAST_ADDR.split(':').next().unwrap().parse()?;
        socket.join_multicast_v4(addr, "0.0.0.0".parse()?)?;
        Ok(Self { socket })
    }
    
    async fn fragment_send(data: &Bytes, dest: &str) -> Result<()> {
        for chunk in data.chunks(PACKET_SIZE) {
            let mut packet = vec![0u8; PACKET_SIZE];
            packet[..chunk.len()].copy_from_slice(chunk);
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.send_to(&packet, dest).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl NetworkAdapter for LoraAdapter {
    async fn send(&self, dest: &str, data: Bytes) -> Result<()> {
        let addr = dest.strip_prefix("udp:").unwrap_or(dest);
        Self::fragment_send(&data, addr).await
    }
    
    async fn recv(&mut self) -> Result<(String, Bytes)> {
        let mut buf = [0u8; PACKET_SIZE];
        let (len, src) = self.socket.recv_from(&mut buf).await?;
        Ok((format!("lora:{}", src), Bytes::copy_from_slice(&buf[..len])))
    }
    
    fn local_id(&self) -> String {
        format!("lora:{}", self.socket.local_addr().unwrap())
    }
    
    fn priority(&self) -> u8 { 3 }
}
