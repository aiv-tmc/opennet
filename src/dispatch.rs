//! Inbound frame dispatcher: routes decoded wire messages to the compute
//! market, the routing table or a direct reply, after authenticating every
//! signed payload.
//!
//! The dispatcher is transport-agnostic: it receives `(source address,
//! frame bytes)` pairs from any transport and replies through
//! `Ctx::transport`, so the daemon loop and the tests drive the exact same
//! code path.

use crate::compute::provider::Cmd;
use crate::compute::{self, ComputeEvent};
use crate::daemon::Ctx;
use crate::message::Message;
use crate::trust::handlers;
use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;

/// Handle one inbound wire frame by dispatching it to its subsystem.
pub(crate) async fn handle_frame(ctx: &Arc<Ctx>, src: &str, data: &[u8]) {
    ctx.state.lock().await.msgs_received += 1;
    match Message::decode(data) {
        Some(Message::Ping) => {
            if let Err(err) = send_msg(ctx, src, &Message::Pong).await {
                eprintln!("[opennetd] pong to {src} failed: {err:#}");
            }
        }
        Some(Message::Pong) => {
            ctx.dht.lock().await.touch(src);
        }
        // Connection greetings are consumed by the transport layer and must
        // never reach the protocol dispatcher.
        Some(Message::ConnHello { .. }) => {}
        Some(ann @ Message::Ann { .. }) => handlers::handle_ann(ctx, src, ann).await,
        Some(Message::TaskBid {
            task_id,
            trust,
            consumed,
            expires_unix,
            pubkey,
            signature,
        }) => {
            // Authenticate the bid before it ever reaches the scheduler; a
            // bad signature is answered with a reject so an honest consumer
            // releases its reservation.
            match handlers::verify_bid(&task_id, trust, consumed, expires_unix, &pubkey, &signature)
            {
                Some(from_node) => {
                    let _ = ctx
                        .compute
                        .send(Cmd::Bid {
                            task_id,
                            from_node,
                            from_addr: src.to_string(),
                            trust,
                            expires_unix,
                        })
                        .await;
                }
                None => {
                    // Penalize the connection address, never the claimed
                    // node id: an invalid signature proves nothing about
                    // the identity it tries to borrow.
                    ctx.reputation.lock().await.record_invalid(src);
                    let _ = send_msg(
                        ctx,
                        src,
                        &Message::TaskReject {
                            task_id,
                            reason: "invalid bid signature".to_string(),
                        },
                    )
                    .await;
                }
            }
        }
        Some(Message::TaskAssign {
            task_id,
            command,
            timeout_secs,
        }) => {
            let _ = ctx
                .compute
                .send(Cmd::Assign {
                    task_id,
                    command,
                    timeout_secs,
                })
                .await;
        }
        Some(Message::TaskAccept { task_id }) => {
            compute::deliver_event(ctx, &task_id, ComputeEvent::Accepted).await;
        }
        Some(Message::TaskReject { task_id, reason }) => {
            compute::deliver_event(ctx, &task_id, ComputeEvent::Rejected(reason)).await;
        }
        Some(Message::TaskResult { task_id, outcome }) => {
            compute::deliver_event(ctx, &task_id, ComputeEvent::Outcome(outcome)).await;
        }
        None => eprintln!("[opennetd] undecodable frame from {src}"),
    }
}

/// Encode a message and send it to a peer, counting it in node statistics.
pub async fn send_msg(ctx: &Arc<Ctx>, dest: &str, msg: &Message) -> Result<()> {
    let data = Bytes::from(msg.encode());
    ctx.transport.send(dest, data).await?;
    ctx.state.lock().await.msgs_sent += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::provider;
    use crate::node::state::Mode;
    use crate::testutil::make_ctx;
    use crate::transport::Transport;
    use crate::trust::now_unix;
    use std::time::Duration;

    /// Forward every inbound frame of a context into the dispatcher,
    /// mimicking the daemon's receive task.
    fn pump(ctx: &Arc<Ctx>) -> tokio::task::JoinHandle<()> {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            while let Some((src, data)) = ctx.transport.recv().await {
                handle_frame(&ctx, &src, &data).await;
            }
        })
    }

    /// Seed both routing tables so each side sees the other as a verified
    /// peer with the given trust and capacity points.
    async fn introduce(consumer: &Arc<Ctx>, provider: &Arc<Ctx>, trust: i64, points: u32) {
        let provider_addr = provider.transport.local_id();
        let provider_id = provider.identity.node_id();
        consumer.dht.lock().await.insert(&provider_addr);
        consumer.dht.lock().await.apply_ann(
            &provider_addr,
            &provider_id,
            "peer",
            trust,
            points,
            now_unix(),
        );
        let consumer_addr = consumer.transport.local_id();
        provider.dht.lock().await.insert(&consumer_addr);
        provider.dht.lock().await.apply_ann(
            &consumer_addr,
            &consumer.identity.node_id(),
            "peer",
            trust,
            points,
            now_unix(),
        );
    }

    #[tokio::test]
    async fn market_executes_task_and_moves_units() {
        let (consumer, _consumer_rx) = make_ctx("mkt-consumer").await;
        let (provider, provider_rx) = make_ctx("mkt-provider").await;
        // Pin the provider's capacity points so the charged units are
        // deterministic: units = points * started minutes of the timeout,
        // with any partial minute counting as a full one.
        provider.state.lock().await.points = 2;
        let consumer_pump = pump(&consumer);
        let provider_pump = pump(&provider);
        provider::run(provider.clone(), provider_rx);
        introduce(&consumer, &provider, 100, 2).await;

        let timeout = consumer.config.network.task_timeout_secs;
        let units = 2 * ((timeout + 59) / 60).max(1) as i64;
        let prefix = &provider.identity.node_id()[..8];
        let out = compute::client::compute(
            &consumer,
            Some(prefix),
            "echo hello-opennet".to_string(),
            timeout,
        )
        .await;
        assert!(out.contains("exit_code: 0"), "unexpected output: {out}");
        assert!(out.contains("hello-opennet"), "missing stdout: {out}");

        let consumer_state = consumer.state.lock().await;
        assert_eq!(consumer_state.trust, 100 - units);
        assert_eq!(consumer_state.consumed, units as u64);
        drop(consumer_state);
        let provider_state = provider.state.lock().await;
        assert_eq!(provider_state.trust, 100 + units);
        assert_eq!(provider_state.tasks_completed, 1);
        consumer_pump.abort();
        provider_pump.abort();
    }

    #[tokio::test]
    async fn leech_provider_rejects_and_refunds_reservation() {
        let (consumer, _consumer_rx) = make_ctx("leech-consumer").await;
        let (provider, provider_rx) = make_ctx("leech-provider").await;
        provider.state.lock().await.mode = Mode::Leech;
        let consumer_pump = pump(&consumer);
        let provider_pump = pump(&provider);
        provider::run(provider.clone(), provider_rx);
        introduce(&consumer, &provider, 100, 2).await;

        let timeout = consumer.config.network.task_timeout_secs;
        let prefix = &provider.identity.node_id()[..8];
        let out =
            compute::client::compute(&consumer, Some(prefix), "echo x".to_string(), timeout).await;
        assert!(out.contains("bid rejected"), "unexpected output: {out}");

        let consumer_state = consumer.state.lock().await;
        assert_eq!(consumer_state.trust, 100);
        assert_eq!(consumer_state.consumed, 0);
        assert!(consumer.reservations.lock().await.is_empty());
        consumer_pump.abort();
        provider_pump.abort();
    }

    #[tokio::test]
    async fn ping_gets_pong_over_the_same_connection() {
        let (ctx, _rx) = make_ctx("pingpong").await;
        let pump = pump(&ctx);
        let peer = Transport::new(0).await.unwrap();
        ctx.dht.lock().await.insert(&peer.local_id());

        peer.send(
            &ctx.transport.local_id(),
            Bytes::from(Message::Ping.encode()),
        )
        .await
        .unwrap();
        let (src, data) = tokio::time::timeout(Duration::from_secs(5), peer.recv())
            .await
            .expect("timed out waiting for pong")
            .expect("transport closed");
        assert_eq!(src, ctx.transport.local_id());
        assert!(matches!(Message::decode(&data), Some(Message::Pong)));
        pump.abort();
    }

    #[tokio::test]
    async fn invalid_announcement_penalizes_the_source_address() {
        let (ctx, _rx) = make_ctx("bad-ann").await;
        let pump = pump(&ctx);
        let peer = Transport::new(0).await.unwrap();
        let announcement = Message::Ann {
            node_id: "deadbeef".to_string(),
            mode: "peer".to_string(),
            trust: 999,
            points: 1,
            unix_ts: now_unix(),
            pubkey: [1u8; 32],
            // A zeroed signature cannot verify against any payload.
            signature: vec![0u8; 64],
        };
        peer.send(
            &ctx.transport.local_id(),
            Bytes::from(announcement.encode()),
        )
        .await
        .unwrap();
        // Give the pump a moment to process the frame.
        tokio::time::sleep(Duration::from_millis(100)).await;
        pump.abort();

        let reputation = ctx.reputation.lock().await;
        let entry = reputation
            .all()
            .into_iter()
            .find(|(key, _)| key == &peer.local_id());
        assert!(entry.is_some(), "source address was not penalized");
        assert_eq!(entry.unwrap().1.invalid_msgs, 1);
    }
}
