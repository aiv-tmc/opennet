//! OpenNet library crate: building blocks for the distributed computing daemon.
//!
//! The library exposes configuration loading, the peer routing table, LAN
//! discovery, the wire protocol, the TCP transport, node identity and runtime
//! state, the compute market, the credit ledger with reputation tracking,
//! plus the daemon event loop used by the `opennetd` binary.

pub mod compute;
pub mod config;
pub mod control;
pub mod credits;
pub mod daemon;
pub mod dht;
pub mod discovery;
pub mod heartbeat;
pub mod init;
pub mod message;
pub mod network;
pub mod node;
