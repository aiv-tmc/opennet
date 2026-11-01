//! Fuzz target: the wire decoder must never panic, hang or allocate
//! unboundedly on arbitrary bytes — every frame from the network
//! reaches `Message::decode`, so this is the outermost robustness
//! boundary. Run with `cargo fuzz run decode`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = opennet::message::Message::decode(data);
});
