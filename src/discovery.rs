//! LAN peer discovery via UDP multicast announcements.

use crate::config::NetworkCfg;
use crate::dht::Dht;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Spawn the discovery loop in the background.
///
/// The task sends a `HELLO <addr>` datagram to the multicast group every
/// `hello_interval_secs` and registers every foreign HELLO it receives in
/// the peer routing table.
pub fn spawn(dht: Arc<Mutex<Dht>>, cfg: NetworkCfg, local_id: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = run(dht, cfg, local_id).await {
            eprintln!("[discovery] task terminated: {err:#}");
        }
    })
}

async fn run(dht: Arc<Mutex<Dht>>, cfg: NetworkCfg, local_id: String) -> Result<()> {
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", cfg.multicast_port)
        .parse()
        .context("invalid multicast bind address")?;
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // Allow several nodes on the same host to bind the discovery port.
    socket.set_reuse_address(true)?;
    socket.bind(&bind_addr.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = tokio::net::UdpSocket::from_std(std_socket)?;
    let group: std::net::Ipv4Addr = cfg
        .multicast_addr
        .parse()
        .context("invalid multicast group address")?;
    socket.join_multicast_v4(group, std::net::Ipv4Addr::UNSPECIFIED)?;

    let mut interval = tokio::time::interval(Duration::from_secs(cfg.hello_interval_secs));
    let announce_addr = format!("{}:{}", cfg.multicast_addr, cfg.multicast_port);
    let mut buf = [0u8; 1024];

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let hello = format!("HELLO {local_id}");
                socket.send_to(hello.as_bytes(), &announce_addr).await?;
            }
            result = socket.recv_from(&mut buf) => {
                let (len, _src) = result?;
                let Ok(text) = std::str::from_utf8(&buf[..len]) else { continue };
                let Some(peer_addr) = text.strip_prefix("HELLO ") else { continue };
                // Ignore our own announcements reflected by the multicast group.
                if peer_addr == local_id {
                    continue;
                }
                dht.lock().await.insert(peer_addr);
            }
        }
    }
}
