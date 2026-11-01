//! Fuzz target: signature verification must never panic on arbitrary
//! signature bytes against a fixed payload — verification runs on
//! every signed frame from every peer. Run with `cargo fuzz run
//! signing`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[..64]);
    let identity = opennet::node::identity::Identity::generate();
    let payload = opennet::message::Message::bid_signing_payload("t", 1, 2, 3);
    let _ = opennet::node::identity::Identity::verify(&identity.pubkey(), &payload, &signature);
});
