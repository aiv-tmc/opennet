//! OpenNet library crate: the daemon, the control surface, the wire
//! protocol and every subsystem hang off the modules listed here.
//! The two binaries (`opennetd`, `opennetctl`) are thin shells over
//! this library.

pub mod compute;
pub mod config;
pub mod control;
pub mod daemon;
pub mod dht;
pub mod discovery;
pub mod dispatch;
pub mod heartbeat;
pub mod hwperf;
pub mod init;
pub mod log;
pub mod message;
pub mod node;
pub mod reputation;
pub mod sandbox;
pub mod swarm;
pub mod transport;
pub mod trust;
pub mod wan;

/// Test-only helpers shared by the unit tests of every module: scratch
/// directories and prebuilt daemon contexts wired to a real loopback
/// transport. Compiled only for tests so the production library keeps
/// no test scaffolding.
#[cfg(test)]
pub mod testutil;
