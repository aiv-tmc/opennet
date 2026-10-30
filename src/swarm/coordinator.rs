//! Coordinating one swarm run: placement, launch, prompt injection,
//! pipeline completion.
//!
//! The coordinator must itself hold consent for the program. It
//! collects verified offers from the routing table, splits the manifest
//! layer space across hosts proportional to offered RAM — hosts
//! offering nothing, or less than one layer's worth of proportional
//! share, are skipped; the last contributing host takes the remainder —
//! signs one `Message::ShardLaunch` per shard, and waits for every
//! shard's readiness before injecting the prompt. From then on it
//! relays pipeline frames between shard hosts, collects output (capped)
//! and finishes on completion, on failure, or on the wall-clock
//! deadline.

use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::swarm::{finish_plan, peer_offers, PlanEvent, PlanState, ShardSlot};
use crate::transport::MAX_FRAME;
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Overall wall-clock budget for one plan.
const RUN_TIMEOUT: Duration = Duration::from_secs(1800);
/// Patience for shard readiness during launch.
const READY_TIMEOUT: Duration = Duration::from_secs(120);
/// Total output a plan may produce before the coordinator aborts it; a
/// runaway or malicious last shard cannot exhaust coordinator memory.
const OUTPUT_CAP: usize = 64 * 1024 * 1024;

/// Run `program` over the swarm with the contents of `prompt_path` as
/// the first shard's pipeline input; returns the final output text.
pub async fn run_program(ctx: &Arc<Ctx>, program: &str, prompt_path: &str) -> Result<String> {
    // The prompt becomes one ShardFwd frame; read it and reject
    // oversized prompts before any launch leaves this node.
    let prompt = std::fs::read(prompt_path)
        .map_err(|err| anyhow::anyhow!("cannot read prompt file {prompt_path}: {err}"))?;
    if prompt.is_empty() {
        bail!("empty prompt");
    }
    if prompt.len() > MAX_FRAME {
        bail!("prompt exceeds the {}-byte frame limit", MAX_FRAME);
    }
    // The coordinator must itself hold consent for the program.
    let consent = ctx.swarm.lock().await.clone();
    if !consent.allows(program) {
        bail!("coordinator holds no consent for {program}");
    }
    let spec = consent.verified_spec()?;
    drop(consent);
    // Only peers that currently offer this program with nonzero
    // capacity; zero offers are dropped so placement never divides by
    // an empty pool.
    let candidates: Vec<PeerInfo> = ctx
        .dht
        .lock()
        .await
        .all_peers()
        .into_iter()
        .filter(|peer| peer_offers(peer, program) && peer.swarm_ram_mb > 0)
        .collect();
    if candidates.is_empty() {
        bail!("no swarm offers for {program}");
    }
    // Random plan id; also the key for plan state everywhere.
    let plan_id = format!("{:016x}", rand::random::<u64>());
    let (events_tx, mut events_rx) = mpsc::unbounded_channel::<PlanEvent>();
    let slots: Vec<ShardSlot> = candidates
        .iter()
        .map(|peer| ShardSlot {
            addr: peer.addr.clone(),
            node_id: peer.node_id.clone(),
        })
        .collect();
    ctx.swarm_plans.lock().await.insert(
        plan_id.clone(),
        PlanState {
            shards: slots.clone(),
            ready: HashSet::new(),
            events: events_tx,
        },
    );
    let caps: Vec<u64> = candidates.iter().map(|peer| peer.swarm_ram_mb).collect();
    let ranges = split_layers(spec.layers, &caps);
    if ranges.is_empty() {
        ctx.swarm_plans.lock().await.remove(&plan_id);
        bail!("no usable placement for {program}");
    }
    // Sign and send one launch per shard; a single unreachable host
    // aborts the plan before any shard starts executing.
    for (slot, (host, (from, to))) in slots.iter().zip(ranges.iter()).enumerate() {
        let shard_index = slot as u32;
        let next_addr = match slots.get(slot + 1) {
            Some(next) => next.addr.clone(),
            // The empty next address tells the last shard it owns the
            // plan output; its runner must deliver with tag 2, not
            // tag 1.
            None => String::new(),
        };
        let unix_ts = crate::trust::now_unix();
        let launch = Message::ShardLaunch {
            plan_id: plan_id.clone(),
            shard_index,
            program: program.to_string(),
            artifact_hash: spec.artifact_hash.clone(),
            layer_from: *from,
            layer_to: *to,
            ram_mb: spec.shard_ram_mb,
            next_addr: next_addr.clone(),
            unix_ts,
            pubkey: ctx.identity.pubkey(),
            signature: ctx
                .identity
                .sign(&Message::launch_signing_payload(
                    &plan_id,
                    shard_index,
                    program,
                    &spec.artifact_hash,
                    *from,
                    *to,
                    &next_addr,
                    unix_ts,
                ))
                .to_vec(),
        };
        if let Err(err) = send_msg(ctx, &host.addr, &launch).await {
            abort_plan(
                ctx,
                &plan_id,
                &slots,
                &format!("cannot reach shard host {}: {err:#}", host.addr),
            )
            .await;
            bail!("cannot launch plan {plan_id}");
        }
    }
    // Phase 1: readiness. The overall deadline bounds the whole phase;
    // each event waits up to READY_TIMEOUT.
    let started = Instant::now();
    while plan_ready_count(ctx, &plan_id).await < ranges.len() {
        let remaining = RUN_TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            abort_plan(
                ctx,
                &plan_id,
                &slots,
                "plan timed out waiting for readiness",
            )
            .await;
            bail!("plan {plan_id} timed out waiting for readiness");
        }
        let event = match tokio::time::timeout(READY_TIMEOUT.min(remaining), events_rx.recv()).await
        {
            Ok(Some(event)) => event,
            _ => {
                abort_plan(
                    ctx,
                    &plan_id,
                    &slots,
                    "plan timed out waiting for readiness",
                )
                .await;
                bail!("plan {plan_id} timed out waiting for readiness");
            }
        };
        match event {
            PlanEvent::Ready(shard_index) => {
                if let Some(plan) = ctx.swarm_plans.lock().await.get_mut(&plan_id) {
                    plan.ready.insert(shard_index);
                }
            }
            PlanEvent::Done(reason) => {
                abort_plan(
                    ctx,
                    &plan_id,
                    &slots,
                    &format!("plan ended early: {reason}"),
                )
                .await;
                bail!("plan {plan_id} ended early: {reason}");
            }
            // Output or stray frames during readiness are ignored.
            _ => {}
        }
    }
    // Phase 2: inject the prompt into shard 0 and relay/collect until
    // completion, failure, or the deadline.
    send_msg(
        ctx,
        &slots[0].addr,
        &Message::ShardFwd {
            plan_id: plan_id.clone(),
            seq: 1,
            src: u32::MAX,
            dst: 0,
            payload: prompt,
        },
    )
    .await?;
    let run_deadline = started + RUN_TIMEOUT;
    let mut output: Vec<u8> = Vec::new();
    loop {
        // `Instant` has no saturating subtraction: measure now and fall
        // back to a zero duration once the deadline has passed.
        let now = Instant::now();
        let remaining = match run_deadline.checked_duration_since(now) {
            Some(remaining) => remaining,
            None => {
                abort_plan(ctx, &plan_id, &slots, "plan exceeded its deadline").await;
                bail!("plan {plan_id} exceeded its deadline");
            }
        };
        let event = match tokio::time::timeout(remaining, events_rx.recv()).await {
            Ok(Some(event)) => event,
            _ => {
                abort_plan(ctx, &plan_id, &slots, "plan exceeded its deadline").await;
                bail!("plan {plan_id} exceeded its deadline");
            }
        };
        match event {
            PlanEvent::Fwd { dst, payload, .. } => {
                // Relay a pipeline frame to its shard host.
                match slots.get(dst as usize) {
                    Some(slot) => {
                        let _ = send_msg(
                            ctx,
                            &slot.addr,
                            &Message::ShardFwd {
                                plan_id: plan_id.clone(),
                                seq: 0,
                                src: u32::MAX,
                                dst,
                                payload,
                            },
                        )
                        .await;
                    }
                    None => eprintln!("[swarm] plan {plan_id}: stray frame for shard {dst}"),
                }
            }
            PlanEvent::Out { payload, .. } => {
                output.extend_from_slice(&payload);
                if output.len() > OUTPUT_CAP {
                    abort_plan(ctx, &plan_id, &slots, "plan exceeded the output cap").await;
                    bail!("plan {plan_id} exceeded the output cap");
                }
            }
            PlanEvent::Done(reason) => {
                finish_plan(ctx, &plan_id, &reason).await;
                if reason == "completed" {
                    return Ok(String::from_utf8_lossy(&output).into_owned());
                }
                bail!("plan {plan_id} ended: {reason}");
            }
            PlanEvent::Ready(_) => {}
        }
    }
}

/// Current number of ready shards recorded in the plan state.
async fn plan_ready_count(ctx: &Arc<Ctx>, plan_id: &str) -> usize {
    ctx.swarm_plans
        .lock()
        .await
        .get(plan_id)
        .map(|plan| plan.ready.len())
        .unwrap_or(0)
}

/// End the plan locally and tell every shard host to tear down.
async fn abort_plan(ctx: &Arc<Ctx>, plan_id: &str, slots: &[ShardSlot], reason: &str) {
    finish_plan(ctx, plan_id, reason).await;
    broadcast_done(ctx, plan_id, slots, reason).await;
}

/// Send `SwarmDone` to every shard host that is not this node.
async fn broadcast_done(ctx: &Arc<Ctx>, plan_id: &str, slots: &[ShardSlot], reason: &str) {
    let local = ctx.transport.local_id();
    for slot in slots {
        if slot.addr != local {
            let _ = send_msg(
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

/// Split `layers` across capacity slots proportionally to `caps`. Zero
/// slots and slots whose rounded share cannot hold a single layer are
/// skipped — they never absorb part of the layer space. The last
/// contributing slot takes the remainder so the union of ranges always
/// covers `[0, layers)` exactly.
pub(crate) fn split_layers(layers: u32, caps: &[u64]) -> Vec<(u32, u32)> {
    let total: u64 = caps.iter().sum();
    let last_contributing = caps.iter().rposition(|cap| *cap > 0);
    let mut out = Vec::new();
    let mut from = 0u32;
    for (index, cap) in caps.iter().enumerate() {
        if from >= layers || *cap == 0 {
            continue;
        }
        let to = if Some(index) == last_contributing {
            layers
        } else {
            let share = ((*cap as f64 / total.max(1) as f64) * layers as f64).round() as u32;
            if share == 0 {
                continue;
            }
            (from + share).clamp(from + 1, layers)
        };
        out.push((from, to));
        from = to;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::split_layers;

    #[test]
    fn proportional_split() {
        assert_eq!(split_layers(10, &[100, 50]), vec![(0, 7), (7, 10)]);
    }

    #[test]
    fn single_shard_takes_all() {
        assert_eq!(split_layers(5, &[7]), vec![(0, 5)]);
    }

    #[test]
    fn zero_capacity_slots_are_skipped() {
        assert_eq!(split_layers(4, &[0, 10, 0]), vec![(0, 4)]);
        assert_eq!(split_layers(10, &[50, 0, 50]), vec![(0, 5), (5, 10)]);
    }

    #[test]
    fn all_zero_pool_places_nothing() {
        // With no capacity anywhere there is no placement at all; the
        // coordinator rejects the plan before launching.
        assert!(split_layers(3, &[0, 0, 0]).is_empty());
    }

    #[test]
    fn ranges_cover_the_layer_space() {
        let ranges = split_layers(3, &[1, 1, 1]);
        assert_eq!(ranges.first().map(|range| range.0), Some(0));
        assert_eq!(ranges.last().map(|range| range.1), Some(3));
        for (from, to) in &ranges {
            assert!(from < to, "empty range in {ranges:?}");
        }
    }
}
