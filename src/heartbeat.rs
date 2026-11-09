//! Periodic signed announcements: every `heartbeat_interval_secs` the
//! node signs its identity, mode, trust coefficient, total capacity
//! price, the offered GPU count and the head of its billing receipt
//! journal, then sends the announcement to every known peer. The
//! receipt head is what lets peers price strangers as strangers: a
//! fresh identity announces the genesis head and is charged
//! accordingly.
//!
//! The announced price is the unified capacity total: components with
//! a demonstrated performance score (CPU throughput, RAM bandwidth,
//! GPU utilization observed under real load or certified by the guided
//! stress test) are priced from their measurements, unscored
//! components keep their static offer price. Consumers therefore
//! reserve against exactly the total this node credits on settlement.

use crate::daemon::Ctx;
use crate::message::Message;
use crate::trust::now_unix;
use std::sync::Arc;

/// Entries silent for longer than this are pruned from the routing
/// table on every heartbeat round, so dead peers cannot accumulate
/// forever even below the hard capacity.
const PRUNE_AGE_SECS: u64 = 86_400;

/// Spawn the heartbeat loop; it runs until the daemon exits.
pub fn spawn(ctx: Arc<Ctx>) {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(ctx.config.network.heartbeat_interval_secs);
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            ctx.dht.lock().await.prune(PRUNE_AGE_SECS);
            let (node_id, mode, trust, receipt_head) = {
                let state = ctx.state.lock().await;
                (
                    ctx.identity.node_id(),
                    state.mode.as_str().to_string(),
                    state.trust,
                    state.receipts.head(),
                )
            };
            // The unified total prices measured components at their
            // demonstrated performance and everything else at the
            // static offer; the effectively offered device count
            // travels separately for GPU-aware scheduling.
            let points = ctx
                .hwperf
                .lock()
                .await
                .total_points(&ctx.config, &ctx.config.limits);
            let gpus = ctx.config.gpu.effective_count();
            let unix_ts = now_unix();
            let payload = Message::ann_signing_payload(
                &node_id,
                &mode,
                trust,
                points,
                gpus,
                &receipt_head,
                unix_ts,
            );
            let ann = Message::Ann {
                node_id: node_id.clone(),
                mode: mode.clone(),
                trust,
                points,
                gpus,
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
