//! WAN seed gossip: beyond the LAN multicast domain, nodes discover
//! each other through static seeds and signed address snapshots.
//!
//! Every heartbeat interval each node signs a capped snapshot of its
//! routing table (dial addresses only — no identity claims) and sends
//! it to every peer it knows, including the configured seeds. Seeds
//! relay their own snapshots the same way, so two nodes that share a
//! seed converge into one mesh: gossip widens the table, heartbeats
//! then verify every entry through the normal announcement path, and
//! the usual hello validation binds identity to address before any
//! verified field is applied.

use crate::daemon::Ctx;
use crate::message::Message;
use crate::trust::handlers::verify_gossip;
use crate::trust::now_unix;
use std::sync::Arc;
use std::time::Duration;

/// Cap on addresses per gossip snapshot: keeps the frame comfortably
/// inside the wire cap and bounds relay amplification.
const MAX_GOSSIP_ADDRS: usize = 64;

/// Spawn the gossip loop. Idle (returns immediately) when WAN mode is
/// off and no static seeds are configured.
pub fn spawn(ctx: Arc<Ctx>) {
    if !ctx.config.network.wan && ctx.config.network.seeds.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let interval = Duration::from_secs(ctx.config.network.heartbeat_interval_secs);
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            let unix_ts = now_unix();
            // One snapshot serves as both the signed payload and the
            // frame body, so the signature always covers exactly what
            // is relayed.
            let addrs: Vec<String> = {
                let mut addrs = ctx.dht.lock().await.all_addrs();
                addrs.sort();
                addrs.dedup();
                addrs.truncate(MAX_GOSSIP_ADDRS);
                addrs
            };
            if addrs.is_empty() {
                continue;
            }
            let gossip = Message::PeerGossip {
                signature: ctx
                    .identity
                    .sign(&Message::gossip_signing_payload(&addrs, unix_ts))
                    .to_vec(),
                addrs,
                unix_ts,
                pubkey: ctx.identity.pubkey(),
            };
            let recipients: Vec<String> = ctx
                .dht
                .lock()
                .await
                .all_peers()
                .into_iter()
                .map(|peer| peer.addr)
                .collect();
            for recipient in recipients {
                let _ = crate::daemon::send_msg(&ctx, &recipient, &gossip).await;
            }
        }
    });
}

/// Handle one inbound gossip snapshot: verify the relayer's signature,
/// freshness-check the timestamp, seed every address as unverified and
/// credit the relayer. Verified fields arrive later through the normal
/// signed announcement path.
pub async fn handle_gossip(ctx: &Arc<Ctx>, src: &str, gossip: Message) {
    let Message::PeerGossip {
        addrs,
        unix_ts,
        pubkey,
        signature,
        ..
    } = gossip
    else {
        return;
    };
    if addrs.len() > MAX_GOSSIP_ADDRS {
        ctx.reputation.lock().await.record_invalid(src);
        return;
    }
    let Some(node) = verify_gossip(&addrs, unix_ts, &pubkey, &signature) else {
        ctx.reputation.lock().await.record_invalid(src);
        return;
    };
    let now = now_unix();
    let fresh = now.saturating_sub(unix_ts) <= ctx.config.network.ann_max_age_secs
        && unix_ts.saturating_sub(now) <= ctx.config.network.ann_future_skew_secs;
    if !fresh {
        return;
    }
    {
        let mut dht = ctx.dht.lock().await;
        for addr in addrs {
            dht.insert(&addr);
        }
    }
    ctx.reputation.lock().await.record_valid(&node);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::make_ctx;

    #[tokio::test]
    async fn verified_gossip_seeds_unverified_entries() {
        let (ctx, _rx) = make_ctx("wan-gossip").await;
        let unix_ts = now_unix();
        let addrs = vec!["tcp:203.0.113.7:7000".to_string()];
        let gossip = Message::PeerGossip {
            addrs: addrs.clone(),
            unix_ts,
            pubkey: ctx.identity.pubkey(),
            signature: ctx
                .identity
                .sign(&Message::gossip_signing_payload(&addrs, unix_ts))
                .to_vec(),
        };
        handle_gossip(&ctx, "tcp:10.0.0.1:1", gossip).await;
        let dht = ctx.dht.lock().await;
        assert_eq!(dht.peer_count(), 1);
        // Seeded entries are unverified until an announcement arrives.
        assert!(dht.all_peers().is_empty());
        assert!(dht
            .all_addrs()
            .contains(&"tcp:203.0.113.7:7000".to_string()));
    }

    #[tokio::test]
    async fn forged_gossip_is_penalized() {
        let (ctx, _rx) = make_ctx("wan-forged").await;
        let unix_ts = now_unix();
        let addrs = vec!["tcp:203.0.113.7:7000".to_string()];
        let gossip = Message::PeerGossip {
            addrs,
            unix_ts,
            pubkey: [7; 32],
            signature: vec![8; 64],
        };
        handle_gossip(&ctx, "tcp:10.9.9.9:1", gossip).await;
        assert_eq!(ctx.reputation.lock().await.score_of("tcp:10.9.9.9:1"), -1);
        assert_eq!(ctx.dht.lock().await.peer_count(), 0);
    }
}
