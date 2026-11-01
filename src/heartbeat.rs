//! Periodic signed announcements: every `heartbeat_interval_secs` the
//! node signs its identity, mode, trust coefficient, total capacity
//! price (CPU/RAM points plus the GPU offer), the offered GPU count and
//! the head of its billing receipt journal, then sends the
//! announcement to every known peer. The receipt head is what lets
//! peers price strangers as strangers: a fresh identity announces the
//! genesis head and is charged accordingly.

use crate::daemon::Ctx;
use crate::message::Message;
use crate::trust::{now_unix, points::gpu_points};
use std::sync::Arc;

/// Spawn the heartbeat loop; it runs until the daemon exits.
pub fn spawn(ctx: Arc<Ctx>) {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(ctx.config.network.heartbeat_interval_secs);
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            let (node_id, mode, trust, base_points, receipt_head) = {
                let state = ctx.state.lock().await;
                (
                    ctx.identity.node_id(),
                    state.mode.as_str().to_string(),
                    state.trust,
                    state.points,
                    state.receipts.head(),
                )
            };
            // The announced price includes the GPU offer so consumers
            // reserve against the same total this node will credit on
            // settlement; the offered device count travels separately
            // for GPU-aware scheduling.
            let points = base_points.saturating_add(gpu_points(&ctx.config.gpu));
            let unix_ts = now_unix();
            let payload = Message::ann_signing_payload(
                &node_id,
                &mode,
                trust,
                points,
                ctx.config.gpu.count,
                &receipt_head,
                unix_ts,
            );
            let ann = Message::Ann {
                node_id: node_id.clone(),
                mode: mode.clone(),
                trust,
                points,
                gpus: ctx.config.gpu.count,
                receipt_head,
                unix_ts,
                pubkey: ctx.identity.pubkey(),
                signature: ctx.identity.sign(&payload).to_vec(),
            };
            // Encode once for the whole round: every peer receives the
            // identical bytes, so per-peer re-serialization is pure
            // waste.
            let frame: bytes::Bytes = ann.encode().into();
            let addrs: Vec<String> = ctx
                .dht
                .lock()
                .await
                .all_peers()
                .iter()
                .map(|peer| peer.addr.clone())
                .collect();
            for addr in addrs {
                let _ = ctx.transport.send(&addr, frame.clone()).await;
                ctx.state.lock().await.msgs_sent += 1;
            }
        }
    });
}
