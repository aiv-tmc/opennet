//! Inbound frame dispatcher: routes decoded wire messages to the compute
//! market, the swarm subsystem or the routing table after authenticating
//! every signed payload.
//!
//! The dispatcher is transport-agnostic: it receives `(source address,
//! frame bytes)` pairs from any transport and replies through the shared
//! transport, so the daemon loop and the tests drive the exact same code
//! path. Every message that can trigger local action is authenticated
//! here, before it reaches a scheduler: bids and assignments against the
//! compute market, swarm offers and shard launches against the consent
//! gate.

use crate::compute::provider::Cmd;
use crate::compute::{self, ComputeEvent};
use crate::daemon::Ctx;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::swarm;
use crate::trust::handlers;
use std::sync::Arc;

/// Re-export of the shared send helper so callers can address it either
/// through the dispatcher or through the daemon module.
pub use crate::daemon::send_msg;

/// Convert a wire signature blob to the fixed array verification expects.
fn sig_array(signature: &[u8]) -> Option<&[u8; 64]> {
    signature.try_into().ok()
}

/// Handle one inbound wire frame by dispatching it to its subsystem.
pub(crate) async fn handle_frame(ctx: &Arc<Ctx>, src: &str, data: &[u8]) {
    ctx.state.lock().await.msgs_received += 1;
    match Message::decode(data) {
        // Connection greetings are consumed by the transport layer and
        // must never reach the protocol dispatcher.
        Some(Message::ConnHello { .. }) => {}
        Some(ann @ Message::Ann { .. }) => handlers::handle_ann(ctx, src, ann).await,
        Some(join @ Message::SwarmJoin { .. }) => swarm::handle_join(ctx, src, join).await,
        Some(Message::SwarmLeave {
            unix_ts,
            pubkey,
            signature,
        }) => swarm::handle_leave(ctx, unix_ts, &pubkey, &signature),
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
                            consumed,
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
            pubkey,
            signature,
        }) => {
            // Verify the signature here; the scheduler separately checks
            // that the signer is the node whose bid was accepted for this
            // task id, so no unauthenticated party can trigger execution.
            let payload = Message::assign_signing_payload(&task_id, &command, timeout_secs);
            let verified =
                sig_array(&signature).is_some_and(|sig| Identity::verify(&pubkey, &payload, sig));
            if verified {
                let from_node = Identity::node_id_from_pubkey(&pubkey);
                let _ = ctx
                    .compute
                    .send(Cmd::Assign {
                        task_id,
                        command,
                        timeout_secs,
                        from_node,
                    })
                    .await;
            } else {
                ctx.reputation.lock().await.record_invalid(src);
                eprintln!("[opennetd] invalid task assignment signature from {src}");
            }
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
        Some(launch @ Message::ShardLaunch { .. }) => {
            swarm::handle_launch(ctx, src, launch).await;
        }
        Some(Message::ShardFwd {
            plan_id,
            seq,
            src: from_shard,
            dst,
            payload,
        }) => {
            swarm::route_fwd(ctx, &plan_id, seq, from_shard, dst, payload).await;
        }
        Some(Message::ShardReady {
            plan_id,
            shard_index,
        }) => {
            swarm::deliver_plan_event(ctx, &plan_id, swarm::PlanEvent::Ready(shard_index)).await;
        }
        Some(Message::ShardOut {
            plan_id,
            seq,
            payload,
        }) => {
            swarm::deliver_plan_event(ctx, &plan_id, swarm::PlanEvent::Out { seq, payload }).await;
        }
        Some(Message::SwarmDone { plan_id, reason }) => {
            swarm::finish_plan(ctx, &plan_id, &reason).await;
        }
        None => eprintln!("[opennetd] undecodable frame from {src}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::state::Mode;
    use crate::testutil::make_ctx;
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
        let consumer_id = consumer.identity.node_id();
        provider.dht.lock().await.insert(&consumer_addr);
        provider.dht.lock().await.apply_ann(
            &consumer_addr,
            &consumer_id,
            "peer",
            trust,
            points,
            now_unix(),
        );
    }

    #[tokio::test]
    async fn bid_with_invalid_signature_is_rejected() {
        let (consumer, _rx1) = make_ctx("dp-consumer").await;
        let (provider, _rx2) = make_ctx("dp-provider").await;
        introduce(&consumer, &provider, 100, 20).await;
        let pump = pump(&provider);

        let bad_bid = Message::TaskBid {
            task_id: "t-bad".into(),
            trust: 100,
            consumed: 0,
            expires_unix: now_unix() + 300,
            pubkey: consumer.identity.pubkey(),
            signature: vec![0u8; 64],
        };
        consumer
            .transport
            .send(&provider.transport.local_id(), bad_bid.encode().into())
            .await
            .unwrap();
        let (_src, data) = tokio::time::timeout(Duration::from_secs(5), consumer.transport.recv())
            .await
            .expect("no reply to bad bid")
            .expect("transport closed");
        match Message::decode(&data) {
            Some(Message::TaskReject { task_id, .. }) => assert_eq!(task_id, "t-bad"),
            other => panic!("expected TaskReject, got {other:?}"),
        }
        pump.abort();
    }

    #[tokio::test]
    async fn signed_swarm_offer_updates_the_routing_table() {
        let (joiner, _rx1) = make_ctx("dp-joiner").await;
        let (host, _rx2) = make_ctx("dp-host").await;
        let pump = pump(&host);
        // Discovery seeds the joiner's address before the signed offer
        // arrives, mirroring the real HELLO-then-SwarmJoin order.
        let joiner_addr = joiner.transport.local_id();
        host.dht.lock().await.insert(&joiner_addr);
        let unix_ts = now_unix();
        let payload = Message::swarm_signing_payload("demo", 4096, 8, unix_ts);
        let join = Message::SwarmJoin {
            program: "demo".into(),
            max_shard_ram_mb: 4096,
            cpu_cores: 8,
            unix_ts,
            pubkey: joiner.identity.pubkey(),
            signature: joiner.identity.sign(&payload).to_vec(),
        };
        joiner
            .transport
            .send(&host.transport.local_id(), join.encode().into())
            .await
            .unwrap();
        // Give the dispatcher a moment, then verify the offer landed.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let candidates = host.dht.lock().await.swarm_candidates("demo");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id, joiner.identity.node_id());
        assert_eq!(candidates[0].swarm_ram_mb, 4096);
        pump.abort();
    }

    #[tokio::test]
    async fn undecodable_frame_is_counted_and_ignored() {
        let (ctx, _rx) = make_ctx("dp-garbage").await;
        handle_frame(&ctx, "tcp:10.9.9.9:5555", &[0xff, 0x00, 0x01]).await;
        assert_eq!(ctx.state.lock().await.msgs_received, 1);
    }

    #[tokio::test]
    async fn mode_parse_roundtrips_through_the_wire_names() {
        assert_eq!(Mode::parse("peer").unwrap(), Mode::Peer);
        assert_eq!(Mode::parse("seed").unwrap().as_str(), "seed");
        assert!(Mode::parse("bogus").is_err());
    }
}
