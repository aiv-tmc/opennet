//! Frame dispatch: authenticates signed frames and routes them to the
//! owning subsystem, attributing verification failures to the
//! connection address so a replayed frame cannot damage the reputation
//! of the identity it borrows. Market decision frames (accept, reject,
//! result) only complete a consumer waiter after their signature
//! verifies against the provider node id the waiter was booked with.
//! Unsigned swarm frames are handed to the swarm admission functions
//! together with the validated connection address, which authorizes
//! them against plan membership before any state changes.

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
        // Unsigned swarm frames: the swarm admission functions
        // authorize the sender (the validated connection address)
        // against plan membership or the launch-time coordinator
        // before any state changes.
        Some(Message::ShardReady {
            plan_id,
            shard_index,
        }) => {
            swarm::handle_ready(ctx, src, &plan_id, shard_index).await;
        }
        Some(Message::ShardFwd {
            plan_id,
            seq,
            src: src_shard,
            dst,
            payload,
        }) => {
            // The `src` field of the frame is the pipeline source
            // shard index's host claim; it is renamed so it cannot
            // shadow the connection address used for authorization.
            swarm::route_fwd(ctx, src, &plan_id, seq, src_shard, dst, payload).await;
        }
        Some(Message::ShardOut {
            plan_id,
            seq,
            payload,
        }) => {
            swarm::handle_out(ctx, src, &plan_id, seq, payload).await;
        }
        Some(Message::ShardCheckpoint {
            plan_id,
            shard_index,
            payload,
        }) => {
            swarm::handle_checkpoint(ctx, src, &plan_id, shard_index, payload).await;
        }
        Some(Message::SwarmDone { plan_id, reason }) => {
            swarm::handle_done(ctx, src, &plan_id, &reason).await;
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
mod tests;
