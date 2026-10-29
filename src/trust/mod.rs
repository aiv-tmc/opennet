//! Trust coefficient economy: capacity pricing, signed payload
//! verification and the shared wall-clock helper.

pub mod handlers;
pub mod points;

/// Current unix time in seconds; used for announcement timestamps, bid
/// expiry and freshness windows.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
