//! Plan abort helpers shared by the coordinator's timeout and
//! overrun paths: reading the readiness set, extracting the failed
//! shard index from a host-side launch failure reason, ending the
//! plan everywhere and telling every shard host to tear down.

use crate::daemon::Ctx;
use crate::message::Message;
use crate::swarm::{self, ShardSlot};
use std::sync::Arc;

/// Extract the shard index from a host-side launch failure reason of
/// the form "shard <index> launch failed: ..."; any other reason
/// (completion, aborts, malformed strings) yields `None`, which the
/// coordinator treats as a plan-ending signal rather than a failover
/// trigger.
pub(super) fn failed_shard_index(reason: &str) -> Option<usize> {
    let rest = reason.strip_prefix("shard ")?;
    let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() || !rest[digits.len()..].starts_with(" launch failed") {
        return None;
    }
    digits.parse().ok()
}

/// Current number of ready shards recorded in the plan state.
pub(super) async fn plan_ready_count(ctx: &Arc<Ctx>, plan_id: &str) -> usize {
    ctx.swarm_plans
        .lock()
        .await
        .get(plan_id)
        .map(|plan| plan.ready.len())
        .unwrap_or(0)
}

/// End the plan locally and tell every shard host to tear down.
pub(super) async fn abort_plan(ctx: &Arc<Ctx>, plan_id: &str, slots: &[ShardSlot], reason: &str) {
    swarm::finish_plan(ctx, plan_id, reason).await;
    broadcast_done(ctx, plan_id, slots, reason).await;
}

/// Send `SwarmDone` to every shard host that is not this node; shard
/// hosts admit it only from the coordinator recorded at launch time,
/// so an abort reaches exactly the runners it owns and nothing else.
pub(super) async fn broadcast_done(
    ctx: &Arc<Ctx>,
    plan_id: &str,
    slots: &[ShardSlot],
    reason: &str,
) {
    let local = ctx.transport.local_id();
    for slot in slots {
        if slot.addr != local {
            let _ = crate::daemon::send_msg(
                ctx,
                &slot.addr,
                &Message::SwarmDone {
                    plan_id: plan_id.to_string(),
                    reason: reason.to_string(),
                },
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::failed_shard_index;

    #[test]
    fn failed_shard_index_parses_the_host_failure_reason() {
        assert_eq!(
            failed_shard_index("shard 3 launch failed: no consent for program demo"),
            Some(3)
        );
        assert_eq!(failed_shard_index("completed"), None);
        assert_eq!(failed_shard_index("shard x launch failed"), None);
        assert_eq!(failed_shard_index("plan ended"), None);
    }
}
