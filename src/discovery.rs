//! LAN peer discovery via UDP multicast announcements.
//!
//! HELLO datagrams are unsigned by design and only seed the routing table;
//! the payload is strictly validated (`HELLO tcp:<ip>:<port>` with a real
//! socket address) so a spoofed datagram cannot inject arbitrary addresses.
//! The multicast group is joined on every local IPv4 interface enumerated
//! through getifaddrs, so discovery works on multi-homed hosts.

use crate::config::NetworkCfg;
use crate::dht::Dht;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Spawn the discovery loop in the background.
///
/// The task sends a `HELLO <addr>` datagram to the multicast group every
/// `hello_interval_secs` and registers every foreign, well-formed HELLO it
/// receives in the peer routing table.
pub fn spawn(dht: Arc<Mutex<Dht>>, cfg: NetworkCfg, local_id: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = run(dht, cfg, local_id).await {
            eprintln!("[discovery] task terminated: {err:#}");
        }
    })
}

/// Enumerate the addresses of all local IPv4 interfaces.
fn ipv4_interfaces() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cursor = ifap;
        while !cursor.is_null() {
            let ifa = &*cursor;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family == libc::AF_INET as u16 {
                let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                // sin_addr is stored in network byte order; from_be yields a
                // host-order u32 that Ipv4Addr::from renders as a.b.c.d.
                out.push(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)));
            }
            cursor = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// Extract the advertised listen address from one datagram payload; accepts
/// only `HELLO tcp:<ip>:<port>` with a parseable socket address.
fn parse_hello(text: &str) -> Option<String> {
    let addr = text.strip_prefix("HELLO ")?;
    let rest = addr.strip_prefix("tcp:")?;
    rest.parse::<SocketAddr>().ok()?;
    Some(addr.to_string())
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
    let group: Ipv4Addr = cfg
        .multicast_addr
        .parse()
        .context("invalid multicast group address")?;
    // Join the group on every local interface; down or ineligible interfaces
    // are skipped, but at least one successful join is required.
    let mut joined = false;
    for iface in ipv4_interfaces() {
        if socket.join_multicast_v4(group, iface).is_ok() {
            joined = true;
        }
    }
    if !joined
        && socket
            .join_multicast_v4(group, Ipv4Addr::UNSPECIFIED)
            .is_err()
    {
        anyhow::bail!("cannot join multicast group {group} on any interface");
    }

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
                let Some(peer_addr) = parse_hello(text) else { continue };
                // Ignore our own announcements reflected by the multicast group.
                if peer_addr == local_id {
                    continue;
                }
                dht.lock().await.insert(&peer_addr);
            }
        }
    }
}
