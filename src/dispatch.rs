//! Frame dispatch: authenticates signed frames and routes them to the
//! owning subsystem, attributing verification failures to the
//! connection address so a replayed frame cannot damage the reputation
//! of the identity it borrows. Market decision frames (accept, reject,
//! result) only complete a consumer waiter after their signature
//! verifies against the provider node id the waiter was booked with.

use crate::compute::policy::verify_assign;
use crate::compute::provider::Cmd;
use crate::compute::{self, ComputeEvent};
use crate::message::Message;
use crate::node::identity::Identity;
use crate::swarm;
use crate::trust::ann::handle_ann;
use crate::trust::handlers::{
    handle_receipt_ack_frame, handle_receipt_frame, handle_receipt_request_frame,
    handle_receipt_response_frame,
};
use crate::trust::verify::{verify_accept, verify_bid, verify_reject, verify_result};
use crate::wan;
use std::sync::Arc;

/// Handle one inbound frame from `src` (the validated connection
/// address): decode, authenticate, route. The total message counter
/// moves on every frame so `opennetctl status` reflects wire health.
pub async fn handle_frame(ctx: &Arc<crate::daemon::Ctx>, src: &str, data: &[u8]) {
    ctx.state.lock().await.msgs_received += 1;
    match Message::decode(data) {
        // Session establishment is handled by the transport accept
        // loop, never by the dispatch path.
        Some(Message::ConnHello { .. }) => {}
        Some(Message::ConnAccept { .. }) => {}
        Some(ann @ Message::Ann { .. }) => {
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
        // Signed market decisions complete the matching consumer waiter
        // only when the signature belongs to the provider the request
        // was booked with.
        Some(Message::TaskAccept {
            task_id,
            unix_ts,
            pubkey,
            signature,
        }) => {
            let Some(signer) = verify_accept(&task_id, unix_ts, &pubkey, &signature) else {
                ctx.reputation.lock().await.record_invalid(src);
                return;
            };
            compute::complete_waiter(ctx, &signer, &task_id, ComputeEvent::Accepted).await;
        }
        Some(Message::TaskReject {
            task_id,
            reason,
            unix_ts,
            pubkey,
            signature,
        }) => {
            let Some(signer) = verify_reject(&task_id, &reason, unix_ts, &pubkey, &signature)
            else {
                ctx.reputation.lock().await.record_invalid(src);
                return;
            };
            compute::complete_waiter(ctx, &signer, &task_id, ComputeEvent::Rejected(reason)).await;
        }
        Some(Message::TaskResult {
            task_id,
            outcome,
            unix_ts,
            pubkey,
            signature,
        }) => {
            let Some(signer) =
                verify_result(&task_id, &outcome.hash(), unix_ts, &pubkey, &signature)
            else {
                ctx.reputation.lock().await.record_invalid(src);
                return;
            };
            compute::complete_waiter(ctx, &signer, &task_id, ComputeEvent::Outcome(outcome)).await;
        }
        Some(receipt @ Message::Receipt { .. }) => {
            handle_receipt_frame(ctx, src, receipt).await;
        }
        Some(ack @ Message::ReceiptAck { .. }) => {
            handle_receipt_ack_frame(ctx, src, ack).await;
        }
        Some(request @ Message::ReceiptRequest { .. }) => {
            handle_receipt_request_frame(ctx, src, request).await;
        }
        Some(response @ Message::ReceiptResponse { .. }) => {
            handle_receipt_response_frame(ctx, src, response).await;
        }
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
                crate::log::warn(
                    module_path!(),
                    &format!("shard launch from {src} rejected: {err:#}"),
                );
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
        Some(Message::ShardCheckpoint {
            plan_id,
            shard_index,
            payload,
        }) => {
            swarm::handle_checkpoint(ctx, &plan_id, shard_index, payload).await;
        }
        Some(Message::SwarmDone { plan_id, reason }) => {
            swarm::finish_plan(ctx, &plan_id, &reason).await;
        }
        Some(gossip @ Message::PeerGossip { .. }) => {
            wan::handle_gossip(ctx, src, gossip).await;
        }
        None => {
            crate::log::warn(module_path!(), &format!("undecodable frame from {src}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::TaskOutcome;
    use crate::node::identity::Identity;
    use crate::node::state::Mode;
    use crate::testutil::make_ctx;
    use crate::transport::Transport;
    use std::time::Duration;

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
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_result_from_a_wrong_signer_cannot_complete_the_waiter() {
        let (ctx, _rx) = make_ctx("dp-waiter-bind").await;
        let (tx, mut rx) = tokio::sync::oneshot::channel::<ComputeEvent>();
        let provider = Identity::generate();
        ctx.result_waiters
            .lock()
            .await
            .insert("t1".to_string(), (provider.node_id(), tx));
        let outcome = TaskOutcome {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            billed_secs: 1,
        };
        let foreign = Identity::generate();
        let unix_ts = crate::trust::now_unix();
        let foreign_result = Message::TaskResult {
            task_id: "t1".into(),
            outcome: outcome.clone(),
            unix_ts,
            pubkey: foreign.pubkey(),
            signature: foreign
                .sign(&Message::result_signing_payload(
                    "t1",
                    &outcome.hash(),
                    unix_ts,
                ))
                .to_vec(),
        };
        handle_frame(&ctx, "tcp:10.9.9.9:7999", &foreign_result.encode()).await;
        assert!(rx.try_recv().is_err());
        assert!(ctx.result_waiters.lock().await.contains_key("t1"));
        let signed_result = Message::TaskResult {
            task_id: "t1".into(),
            outcome: outcome.clone(),
            unix_ts,
            pubkey: provider.pubkey(),
            signature: provider
                .sign(&Message::result_signing_payload(
                    "t1",
                    &outcome.hash(),
                    unix_ts,
                ))
                .to_vec(),
        };
        handle_frame(&ctx, "tcp:10.9.9.9:7000", &signed_result.encode()).await;
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn a_signed_audit_request_is_served_from_the_local_journal() {
        let (ctx, _rx) = make_ctx("dp-audit-serve").await;
        // The request arrives from a real loopback transport so the
        // response has a reachable address to return to.
        let requester = Transport::new(Identity::generate(), 0, Duration::from_secs(60))
            .await
            .unwrap();
        let src = requester.local_id();
        let request_id = [42; 32];
        let unix_ts = crate::trust::now_unix();
        let request = Message::ReceiptRequest {
            signature: ctx
                .identity
                .sign(&Message::receipt_request_signing_payload(
                    &request_id,
                    &crate::node::state::genesis_head(),
                    16,
                    unix_ts,
                ))
                .to_vec(),
            request_id,
            head_before: crate::node::state::genesis_head(),
            limit: 16,
            unix_ts,
            pubkey: ctx.identity.pubkey(),
        };
        handle_frame(&ctx, &src, &request.encode()).await;
        let Ok(Some((_from, data))) =
            tokio::time::timeout(Duration::from_secs(5), requester.recv()).await
        else {
            panic!("no audit response");
        };
        let Some(message @ Message::ReceiptResponse { .. }) = Message::decode(&data) else {
            panic!("not a response");
        };
        let Message::ReceiptResponse {
            request_id: echoed,
            complete,
            receipts,
            ..
        } = message
        else {
            panic!("not a response");
        };
        assert_eq!(echoed, request_id);
        assert!(complete);
        assert!(receipts.is_empty());
    }

    #[tokio::test]
    async fn a_runner_checkpoint_is_stored_for_its_shard() {
        let (ctx, _rx) = make_ctx("dp-checkpoint").await;
        // Register a minimal plan state so the checkpoint has a home.
        let (events_tx, _events_rx) = tokio::sync::mpsc::channel(swarm::PLAN_EVENT_CAP);
        ctx.swarm_plans.lock().await.insert(
            "plan-1".to_string(),
            swarm::PlanState {
                shards: Vec::new(),
                ready: Default::default(),
                seqs: Default::default(),
                out_seq: 0,
                checkpoints: Default::default(),
                events: events_tx,
            },
        );
        let frame = Message::ShardCheckpoint {
            plan_id: "plan-1".into(),
            shard_index: 2,
            payload: vec![1, 2, 3],
        };
        handle_frame(&ctx, "tcp:10.0.0.1:1", &frame.encode()).await;
        let plans = ctx.swarm_plans.lock().await;
        let plan = plans.get("plan-1").expect("plan registered");
        assert_eq!(plan.checkpoints.get(&2), Some(&vec![1, 2, 3]));
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
