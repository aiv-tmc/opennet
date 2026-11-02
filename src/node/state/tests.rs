//! Node state tests: persistence roundtrip, reservation floor,
//! settlement arithmetic and mode parsing.

use super::*;
use crate::node::state::Mode;
use crate::testutil::scratch_dir;

fn trust_cfg() -> TrustCfg {
    TrustCfg {
        genesis_trust: 100,
        min_trust: 0,
        points_per_core: 10,
        points_per_gb: 2,
        new_node_units_factor: 2,
    }
}

fn limits() -> Limits {
    Limits {
        cpu_percent: 50,
        ram_mb: 2048,
        max_tasks: 4,
    }
}

#[test]
fn state_roundtrips_through_disk() {
    let dir = scratch_dir("state-save");
    let mut state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
    assert_eq!(state.trust, 100);
    assert_eq!(state.mode, Mode::Peer);
    state.mode = Mode::Seed;
    state.trust = 42;
    state.consumed = 7;
    state.save().unwrap();
    let reloaded = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
    assert_eq!(reloaded.mode, Mode::Seed);
    assert_eq!(reloaded.trust, 42);
    assert_eq!(reloaded.consumed, 7);
}

#[test]
fn mode_names_parse_lowercase_and_reject_unknown() {
    assert_eq!(Mode::parse("peer").unwrap(), Mode::Peer);
    assert_eq!(Mode::parse("seed").unwrap(), Mode::Seed);
    assert_eq!(Mode::parse("leech").unwrap(), Mode::Leech);
    assert!(Mode::parse("bogus").is_err());
}

#[test]
fn reserve_enforces_the_floor_against_trust_consumed_and_held() {
    let dir = scratch_dir("state-reserve");
    let mut state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
    // Genesis 100: reserving 90 leaves 10 above the floor of zero.
    assert!(state.reserve("t1", 90, 0).is_ok());
    // A second reservation beyond the remaining 10 fails.
    assert!(state.reserve("t2", 20, 0).is_err());
    // Releasing the first reservation frees the balance.
    state.release("t1");
    assert!(state.reserve("t2", 20, 0).is_ok());
}

#[test]
fn settle_moves_charge_from_trust_to_consumed() {
    let dir = scratch_dir("state-settle");
    let mut state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
    state.reserve("t1", 50, 0).unwrap();
    state.settle("t1", 30);
    assert_eq!(state.trust, 70);
    assert_eq!(state.consumed, 30);
    assert!(state.reservations.is_empty());
}

#[test]
fn fresh_load_starts_a_genesis_receipt_chain() {
    let dir = scratch_dir("state-rcpt");
    let state = NodeState::load(&dir, Mode::Peer, limits(), &trust_cfg()).unwrap();
    assert_eq!(state.receipts.head(), genesis_head());
    assert!(state.receipts.is_empty());
}
