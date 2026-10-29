//! OpenNet library crate: building blocks for the distributed computing daemon.
//!
//! The library exposes configuration loading, the TCP transport with
//! persistent per-peer connections, LAN multicast discovery, the signed wire
//! protocol, the peer routing table, node identity and runtime trust state,
//! capacity pricing in hardware points, the compute market driven by the
//! trust coefficient, the opt-in swarm mode for hosting shards of one
//! shared program across the LAN, the peer reputation table, the execution
//! sandbox for tasks and shard runners and the daemon event loop used by
//! the `opennetd` binary.

pub mod compute;
pub mod config;
pub mod control;
pub mod daemon;
pub mod dht;
pub mod discovery;
pub mod dispatch;
pub mod heartbeat;
pub mod init;
pub mod message;
pub mod node;
pub mod reputation;
pub mod sandbox;
pub mod swarm;
pub mod transport;
pub mod trust;

/// Test-only helpers shared by the unit tests of every module: scratch
/// directories and prebuilt daemon contexts wired to a real loopback
/// transport. Compiled only for test builds.
#[cfg(test)]
pub mod testutil;
