//! Periodic signed announcements that keep peer records fresh.

use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::trust::now_unix;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// Spawn the heartbeat task in the background.
pub fn spawn(ctx: Arc<Ctx>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = run(ctx).await {
            eprintln!("[heartbeat] task terminated: {err:#}");
        }
    })
}

/// Every heartbeat interval: drop silent peers and announce this node to
/// all remaining peers so their routing tables stay up to date.
async fn run(ctx: Arc<Ctx>) -> Result<()> {
    let interval_secs = ctx.config.network.heartbeat_interval_secs.max(1);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    // Peers silent for two announcement cycles are dropped from the table.
    let stale_after = Duration::from_secs(interval_secs.saturating_mul(2));

    loop {
        interval.tick().await;
        ctx.dht.lock().await.prune_stale(stale_after);
        let peers = ctx.dht.lock().await.all_peers();
        if peers.is_empty() {
            continue;
        }
        // Sign a fresh, timestamped announcement for every round so peers
        // can verify the identity, liveness and recency of the sender.
        let announcement = {
            let state = ctx.state.lock().await;
            let node_id = ctx.identity.node_id();
            let mode = state.mode.as_str().to_string();
            let trust = state.trust;
            let points = state.points;
            let unix_ts = now_unix();
            let signature = ctx.identity.sign(&Message::ann_signing_payload(
                &node_id, &mode, trust, points, unix_ts,
            ));
            Message::Ann {
                node_id,
                mode,
                trust,
                points,
                unix_ts,
                pubkey: ctx.identity.pubkey(),
                signature: signature.to_vec(),
            }
        };
        for peer in peers {
            if let Err(err) = send_msg(&ctx, &peer.addr, &announcement).await {
                eprintln!("[heartbeat] announce to {} failed: {err:#}", peer.addr);
            }
        }
    }
}
