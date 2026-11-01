//! Frame dispatch: authenticates signed frames and routes them to the
//! owning subsystem, attributing verification failures to the connection
//! address so a replayed frame cannot damage the reputation of the
//! identity it borrows.

use crate::compute::policy::verify_assign;
use crate::compute::provider::Cmd;
use crate::compute::ComputeEvent;
use crate::message::Message;
use crate::node::identity::Identity;
use crate::swarm;
use crate::trust::handlers::{handle_ann, verify_bid, verify_receipt, verify_receipt_ack};
use crate::wan;
use std::sync::Arc;

/// Handle one inbound frame from `src` (the validated connection
/// address): decode, authenticate, route. The total message counter
/// moves on every frame so `opennetctl status` reflects wire health.
pub async fn handle_frame(ctx: &Arc<crate::daemon::Ctx>, src: &str, data: &[u8]) {
    ctx.state.lock().await.msgs_received += 1;
    match Message::decode(data) {
        // Connection greetings are consumed by the transport layer and
        // must never reach the protocol dispatcher.
        Some(Message::ConnHello { .. }) => {}
        Some(Message::ConnAccept { .. }) => {}
        Some(ann @ Message::Ann { .. }) => {
            // Verification, freshness checking, reputation accounting
            // and routing-table application all live in the trust
            // handlers; failures are penalized against the connection
            // address inside the handler.
            handle_ann(ctx, src, ann).await;
        }
        Some(Message::TaskBid {
            task_id,
            trust,
            consumed,
            expires_unix,
            pubkey,
            signature,
        }) => {
            let Some(bid_node) =
                verify_bid(&task_id, trust, consumed, expires_unix, &pubkey, &signature)
            else {
                ctx.reputation.lock().await.record_invalid(src);
                return;
            };
            if bid_node != Identity::node_id_from_pubkey(&pubkey) {
                ctx.reputation.lock().await.record_invalid(src);
                return;
            }
            let _ = ctx
                .compute
                .send(Cmd::Bid {
                    task_id,
                    from_node: bid_node,
                    from_addr: src.to_string(),
                    trust,
                    consumed,
                    expires_unix,
                })
                .await;
        }
        Some(Message::TaskAssign {
            task_id,
            command,
            timeout_secs,
            ram_mb,
            gpus,
            pubkey,
            signature,
        }) => {
            // Authenticate the assignment signature and attribute the
            // frame to its signer. The scheduler independently binds the
            // task id to the node whose bid it accepted and enforces the
            // requested RAM/GPU capacity, so a request this node cannot
            // serve is refused there with its reservation released.
            let signer = Identity::node_id_from_pubkey(&pubkey);
            if !verify_assign(
                &task_id,
                &command,
                timeout_secs,
                ram_mb,
                gpus,
                &pubkey,
                &signature,
                &signer,
            ) {
                ctx.reputation.lock().await.record_invalid(src);
                return;
            }
            let _ = ctx
                .compute
                .send(Cmd::Assign {
                    task_id,
                    command,
                    timeout_secs,
                    ram_mb,
                    gpus,
                    from_node: signer,
                })
                .await;
        }
        Some(Message::TaskAccept { task_id }) => {
            complete_waiter(ctx, src, &task_id, ComputeEvent::Accepted).await;
        }
        Some(Message::TaskReject { task_id, reason }) => {
            complete_waiter(ctx, src, &task_id, ComputeEvent::Rejected(reason)).await;
        }
        Some(Message::TaskResult { task_id, outcome }) => {
            complete_waiter(ctx, src, &task_id, ComputeEvent::Outcome(outcome)).await;
        }
        // A billing receipt travels one frame ahead of its task result;
        // verify the provider signature and stash it under the task id
        // so the consumer's settle path can countersign it.
        Some(receipt @ Message::Receipt { .. }) => {
            let Message::Receipt {
                task_id,
                provider_node,
                billed_secs,
                charge,
                outcome_hash,
                unix_ts,
                pubkey,
                signature,
                ..
            } = &receipt
            else {
                return;
            };
            let valid = verify_receipt(
                task_id,
                provider_node,
                *billed_secs,
                *charge,
                outcome_hash,
                *unix_ts,
                pubkey,
                signature,
            )
            .is_some_and(|signer| signer == *provider_node);
            if valid {
                ctx.pending_receipts
                    .lock()
                    .await
                    .insert(task_id.clone(), receipt);
            } else {
                ctx.reputation.lock().await.record_invalid(src);
            }
        }
        // A countersigned receipt ack: the consumer accepted our charge
        // and output — evidence of a completed settlement.
        Some(ack @ Message::ReceiptAck { .. }) => {
            let Message::ReceiptAck {
                task_id,
                receipt_hash,
                unix_ts,
                pubkey,
                signature,
                ..
            } = &ack
            else {
                return;
            };
            let valid =
                verify_receipt_ack(task_id, receipt_hash, *unix_ts, pubkey, signature).is_some();
            if valid {
                let mut state = ctx.state.lock().await;
                let _ = state.receipts.record_ack(ack);
            } else {
                ctx.reputation.lock().await.record_invalid(src);
            }
        }
        // Swarm frames keep their fully decoded fields: the handlers
        // re-verify every signed field, so nothing the peer sent may be
        // dropped before verification.
        Some(join @ Message::SwarmJoin { .. }) => {
            swarm::handle_join(ctx, src, join).await;
        }
        Some(Message::SwarmLeave {
            unix_ts,
            pubkey,
            signature,
        }) => {
            swarm::handle_leave(ctx, unix_ts, &pubkey, &signature).await;
        }
        Some(launch @ Message::ShardLaunch { .. }) => {
            if let Err(err) = swarm::handle_launch(ctx, src, launch).await {
                eprintln!("[dispatch] shard launch from {src} rejected: {err:#}");
            }
        }
        Some(Message::ShardReady {
            plan_id,
            shard_index,
        }) => {
            swarm::deliver_plan_event(ctx, &plan_id, swarm::PlanEvent::Ready(shard_index)).await;
        }
        Some(Message::ShardFwd {
            plan_id,
            seq,
            src,
            dst,
            payload,
        }) => {
            swarm::route_fwd(ctx, &plan_id, seq, src, dst, payload).await;
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
        Some(gossip @ Message::PeerGossip { .. }) => {
            wan::handle_gossip(ctx, src, gossip).await;
        }
        None => {
            eprintln!("[opennetd] undecodable frame from {src}");
        }
    }
}

/// Complete one consumer waiter, but only for the peer it was booked
/// with. The connection address we see is the peer's address from our
/// viewpoint (rewrites and multihoming may change the IP), so only the
/// listener port is compared — a stray result from a different listener
/// goes nowhere near the waiter, which is put back for the genuine
/// reply.
async fn complete_waiter(
    ctx: &Arc<crate::daemon::Ctx>,
    src: &str,
    task_id: &str,
    event: ComputeEvent,
) {
    let entry = ctx.result_waiters.lock().await.remove(task_id);
    if let Some((expected, waiter)) = entry {
        if same_listener(src, &expected) {
            let _ = waiter.send(event);
        } else {
            ctx.result_waiters
                .lock()
                .await
                .insert(task_id.to_string(), (expected, waiter));
        }
    }
}

/// Compare the listener ports of two `tcp:<ip>:<port>` addresses. The
/// port identifies the peer's listener; the IP legitimately differs
/// between the advertised address, the dial target and the observed
/// connection source.
fn same_listener(src: &str, expected: &str) -> bool {
    fn port(addr: &str) -> Option<u16> {
        addr.rsplit_once(':')
            .and_then(|(_, raw)| raw.parse::<u16>().ok())
    }
    match (port(src), port(expected)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::state::Mode;
    use crate::testutil::make_ctx;

    #[tokio::test]
    async fn bid_with_invalid_signature_is_rejected() {
        let (ctx, mut rx) = make_ctx("dp-bad-bid").await;
        let bid = Message::TaskBid {
            task_id: "t1".into(),
            trust: 50,
            consumed: 20,
            expires_unix: 9_999_999_999,
            pubkey: [7; 32],
            signature: vec![8; 64],
        };
        handle_frame(&ctx, "tcp:10.9.9.9:5555", &bid.encode()).await;
        assert_eq!(
            ctx.reputation.lock().await.score_of("tcp:10.9.9.9:5555"),
            -1
        );
        assert!(
            rx.try_recv().is_err(),
            "no scheduler command may be produced"
        );
    }

    #[tokio::test]
    async fn a_result_from_a_wrong_listener_cannot_complete_the_waiter() {
        let (ctx, _rx) = make_ctx("dp-waiter-bind").await;
        let (tx, mut rx) = tokio::sync::oneshot::channel::<ComputeEvent>();
        ctx.result_waiters
            .lock()
            .await
            .insert("t1".to_string(), ("tcp:10.1.1.1:7000".to_string(), tx));
        let result = Message::TaskResult {
            task_id: "t1".into(),
            outcome: crate::compute::TaskOutcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                billed_secs: 1,
            },
        };
        // A different listener port: the waiter must survive.
        handle_frame(&ctx, "tcp:10.9.9.9:7999", &result.encode()).await;
        assert!(rx.try_recv().is_err());
        assert!(ctx.result_waiters.lock().await.contains_key("t1"));
        // The booked listener completes it.
        handle_frame(&ctx, "tcp:172.16.0.5:7000", &result.encode()).await;
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn undecodable_frame_is_counted_and_ignored() {
        let (ctx, _rx) = make_ctx("dp-garbage").await;
        handle_frame(&ctx, "tcp:10.9.9.9:5555", &[0xff, 0x00, 0x01]).await;
        assert_eq!(ctx.state.lock().await.msgs_received, 1);
    }

    #[test]
    fn mode_parse_roundtrips_through_the_wire_names() {
        assert_eq!(Mode::parse("peer").unwrap(), Mode::Peer);
        assert_eq!(Mode::parse("seed").unwrap(), Mode::Seed);
        assert_eq!(Mode::parse("leech").unwrap(), Mode::Leech);
        assert!(Mode::parse("relay").is_err());
    }
}
