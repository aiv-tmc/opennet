//! Signed announcement handling: freshness checks, signature
//! verification and application to the routing table.

use crate::daemon::Ctx;
use crate::message::Message;
use crate::node::identity::Identity;
use std::sync::Arc;

fn timestamp_fresh(unix_ts: u64, now: u64, max_age_secs: u64, future_skew_secs: u64) -> bool {
    unix_ts <= now + future_skew_secs && now.saturating_sub(unix_ts) <= max_age_secs
}

/// Verify one signed announcement and apply it to the routing table.
/// The advertised node id must match the signing key, the mode must
/// parse, the timestamp must sit inside the configured freshness
/// window and the signature must verify; any failure is penalized
/// against the connection address.
pub async fn handle_ann(ctx: &Arc<Ctx>, src: &str, ann: Message) {
    let Message::Ann {
        node_id,
        mode,
        trust,
        points,
        gpus,
        receipt_head,
        unix_ts,
        pubkey,
        signature,
    } = ann
    else {
        return;
    };
    let payload =
        Message::ann_signing_payload(&node_id, &mode, trust, points, gpus, &receipt_head, unix_ts);
    let id_matches = node_id == Identity::node_id_from_pubkey(&pubkey);
    let mode_valid = crate::node::state::Mode::parse(&mode).is_ok();
    let fresh = timestamp_fresh(
        unix_ts,
        crate::trust::now_unix(),
        ctx.config.network.ann_max_age_secs,
        ctx.config.network.ann_future_skew_secs,
    );
    let signature_valid = signature
        .as_slice()
        .try_into()
        .ok()
        .is_some_and(|sig: &[u8; 64]| Identity::verify(&pubkey, &payload, sig));
    if id_matches && mode_valid && fresh && signature_valid {
        ctx.reputation.lock().await.record_valid(&node_id);
        ctx.dht.lock().await.apply_ann_ext(
            src,
            &node_id,
            &mode,
            trust,
            points,
            gpus,
            receipt_head,
            unix_ts,
        );
    } else {
        ctx.reputation.lock().await.record_invalid(src);
        crate::log::warn(
            module_path!(),
            &format!("[opennetd] invalid announcement from {src}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_accepted_within_age_and_skew() {
        assert!(timestamp_fresh(1000, 1000, 10, 5));
        assert!(timestamp_fresh(990, 1000, 10, 5));
        assert!(timestamp_fresh(1005, 1000, 10, 5));
    }

    #[test]
    fn timestamp_rejected_when_stale_or_from_future() {
        assert!(!timestamp_fresh(989, 1000, 10, 5));
        assert!(!timestamp_fresh(1006, 1000, 10, 5));
        assert!(!timestamp_fresh(0, 10_000, 10, 5));
    }
}
