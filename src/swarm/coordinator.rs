//! Swarm coordinator: builds a signed placement plan from consenting
//! peers and drives the pipeline to completion.
//!
//! The coordinator must hold consent for the program itself. Layer space
//! is split across candidates in proportion to their offered shard RAM,
//! rounded to whole layers; a sequential chain of shards forms the
//! pipeline and each launch carries the next shard's address so every
//! runner knows where to forward. Payloads flow as `ShardFwd` frames along
//! the chain and `ShardOut` frames back; the run ends when the last shard
//! reports completion or a deadline expires, at which point every shard
//! receives `SwarmDone` and tears down.

use crate::daemon::{send_msg, Ctx};
use crate::dht::PeerInfo;
use crate::message::Message;
use crate::swarm::{PlanEvent, PlanState, ShardSlot};
use crate::trust::now_unix;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// How long to wait for all shards of a plan to report ready.
const READY_TIMEOUT: Duration = Duration::from_secs(120);
/// Hard deadline for one whole pipeline run.
const RUN_TIMEOUT: Duration = Duration::from_secs(1800);
/// Maximum prompt payload injected into the pipeline.
const MAX_PROMPT_BYTES: usize = 16 * 1024 * 1024;

/// Split `layers` into contiguous shard ranges proportional to `caps`,
/// rounded to whole layers, returning one `(from, to)` per cap and skipping
/// caps too small to hold a single layer. The ranges always cover
/// `[0, layers)` exactly.
pub(crate) fn split_layers(layers: u32, caps: &[u64]) -> Vec<(u32, u32)> {
    let total: u64 = caps.iter().sum();
    let mut out = Vec::with_capacity(caps.len());
    let mut from = 0u32;
    for (i, cap) in caps.iter().enumerate() {
        if from >= layers {
            break;
        }
        let to = if i == caps.len() - 1 || *cap == 0 {
            layers
        } else {
            let share = ((*cap as f64 / total.max(1) as f64) * layers as f64).round() as u32;
            (from + share).max(from + 1).min(layers)
        };
        if to > from {
            out.push((from, to));
            from = to;
        }
    }
    out
}

/// Run `program` across the swarm with the contents of `prompt_path` as
/// the first pipeline payload, returning the collected output text.
pub async fn run_program(ctx: &Arc<Ctx>, program: &str, prompt_path: &str) -> Result<String> {
    let consent = ctx.swarm.lock().await.clone();
    if !consent.allows(program) {
        bail!("this node has no swarm consent for '{program}'");
    }
    let spec = consent
        .verified_spec()
        .context("cannot verify program artifacts")?;
    let prompt = std::fs::read(prompt_path)
        .with_context(|| format!("cannot read prompt file {prompt_path}"))?;
    if prompt.len() > MAX_PROMPT_BYTES {
        bail!("prompt file exceeds {} bytes", MAX_PROMPT_BYTES);
    }

    // Placement: consenting peers for this exact program, offering enough
    // RAM to be useful, ordered by their offer.
    let mut candidates: Vec<PeerInfo> = ctx
        .dht
        .lock()
        .await
        .swarm_candidates(program)
        .into_iter()
        .filter(|peer| peer.swarm_ram_mb >= spec.shard_ram_mb / 2)
        .collect();
    candidates.sort_by_key(|peer| std::cmp::Reverse(peer.swarm_ram_mb));
    if candidates.is_empty() {
        bail!("no consenting peers offer '{program}'");
    }
    let caps: Vec<u64> = candidates.iter().map(|peer| peer.swarm_ram_mb).collect();
    let ranges = split_layers(spec.layers, &caps);
    let shards: Vec<ShardSlot> = candidates
        .iter()
        .take(ranges.len())
        .map(|peer| ShardSlot {
            addr: peer.addr.clone(),
            node_id: peer.node_id.clone(),
        })
        .collect();
    let plan_id = format!("{:016x}", rand::random::<u64>());

    // Register the plan before launching so dispatcher events have a home.
    let (events_tx, mut events_rx) = mpsc::unbounded_channel::<PlanEvent>();
    ctx.swarm_plans.lock().await.insert(
        plan_id.clone(),
        PlanState {
            shards: shards.clone(),
            ready: HashSet::new(),
            events: events_tx,
        },
    );

    // Sign and send one launch per shard; `next_addr` links the pipeline.
    for (index, slot) in shards.iter().enumerate() {
        let (layer_from, layer_to) = ranges[index];
        let next_addr = shards
            .get(index + 1)
            .map(|next| next.addr.clone())
            .unwrap_or_default();
        let unix_ts = now_unix();
        let signature = ctx.identity.sign(&Message::launch_signing_payload(
            &plan_id,
            index as u32,
            program,
            &spec.artifact_hash,
            layer_from,
            layer_to,
            &next_addr,
            unix_ts,
        ));
        let launch = Message::ShardLaunch {
            plan_id: plan_id.clone(),
            shard_index: index as u32,
            program: program.to_string(),
            artifact_hash: spec.artifact_hash.clone(),
            layer_from,
            layer_to,
            ram_mb: spec.shard_ram_mb,
            next_addr,
            unix_ts,
            pubkey: ctx.identity.pubkey(),
            signature: signature.to_vec(),
        };
        if let Err(err) = send_msg(ctx, &slot.addr, &launch).await {
            abort_plan(ctx, &plan_id, &shards, "launch failed").await;
            bail!("cannot reach shard {}: {err:#}", slot.addr);
        }
    }

    // Phase 1: wait for every shard to report ready.
    let mut ready = HashSet::new();
    let ready_deadline = tokio::time::sleep(READY_TIMEOUT);
    tokio::pin!(ready_deadline);
    while ready.len() < shards.len() {
        tokio::select! {
            event = events_rx.recv() => {
                match event {
                    Some(PlanEvent::Ready(index)) => { ready.insert(index); }
                    Some(PlanEvent::Done(reason)) => {
                        abort_plan(ctx, &plan_id, &shards, &reason).await;
                        bail!("plan terminated during startup: {reason}");
                    }
                    Some(_) => {} // stray pipeline frames before startup
                    None => {
                        abort_plan(ctx, &plan_id, &shards, "plan channel closed").await;
                        bail!("plan channel closed during startup");
                    }
                }
            }
            _ = &mut ready_deadline => {
                abort_plan(ctx, &plan_id, &shards, "startup timeout").await;
                bail!("shards did not report ready within {READY_TIMEOUT:?}");
            }
        }
    }

    // Phase 2: inject the prompt into shard 0 and relay frames until the
    // last shard reports completion.
    let mut output = Vec::new();
    let mut seq = 1u64;
    let first = Message::ShardFwd {
        plan_id: plan_id.clone(),
        seq,
        src: u32::MAX,
        dst: 0,
        payload: prompt,
    };
    seq += 1;
    if let Err(err) = send_msg(ctx, &shards[0].addr, &first).await {
        abort_plan(ctx, &plan_id, &shards, "pipeline start failed").await;
        bail!("cannot inject prompt: {err:#}");
    }
    let run_deadline = tokio::time::sleep(RUN_TIMEOUT);
    tokio::pin!(run_deadline);
    loop {
        tokio::select! {
            event = events_rx.recv() => match event {
                Some(PlanEvent::Fwd { dst, payload, .. }) => {
                    let frame = Message::ShardFwd {
                        plan_id: plan_id.clone(),
                        seq,
                        src: u32::MAX,
                        dst,
                        payload,
                    };
                    seq += 1;
                    match shards.get(dst as usize) {
                        Some(slot) => {
                            if let Err(err) = send_msg(ctx, &slot.addr, &frame).await {
                                abort_plan(ctx, &plan_id, &shards, "pipeline relay failed").await;
                                bail!("pipeline relay to shard {dst} failed: {err:#}");
                            }
                        }
                        None => eprintln!("[swarm] frame for unknown shard {dst} dropped"),
                    }
                }
                Some(PlanEvent::Out { payload, .. }) => output.extend_from_slice(&payload),
                Some(PlanEvent::Done(reason)) => {
                    broadcast_done(ctx, &plan_id, &shards, &reason).await;
                    ctx.swarm_plans.lock().await.remove(&plan_id);
                    break;
                }
                Some(PlanEvent::Ready(_)) => {}
                None => {
                    abort_plan(ctx, &plan_id, &shards, "plan channel closed").await;
                    bail!("plan channel closed mid-run");
                }
            },
            _ = &mut run_deadline => {
                abort_plan(ctx, &plan_id, &shards, "run deadline").await;
                bail!("plan exceeded {RUN_TIMEOUT:?}");
            }
        }
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

/// Send `SwarmDone` to every shard of the plan.
async fn broadcast_done(ctx: &Arc<Ctx>, plan_id: &str, shards: &[ShardSlot], reason: &str) {
    for slot in shards {
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

/// Abort helper: notify all shards and drop local plan state.
async fn abort_plan(ctx: &Arc<Ctx>, plan_id: &str, shards: &[ShardSlot], reason: &str) {
    broadcast_done(ctx, plan_id, shards, reason).await;
    ctx.swarm_plans.lock().await.remove(plan_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_layers_covers_the_whole_range() {
        let ranges = split_layers(10, &[100, 50]);
        assert_eq!(ranges, vec![(0, 7), (7, 10)]);
        let ranges = split_layers(3, &[1, 1, 1]);
        assert_eq!(ranges, vec![(0, 1), (1, 2), (2, 3)]);
    }

    #[test]
    fn split_layers_skips_zero_caps() {
        let ranges = split_layers(4, &[0, 10, 0]);
        assert_eq!(ranges, vec![(0, 4)]);
    }

    #[test]
    fn split_layers_handles_single_shard() {
        assert_eq!(split_layers(5, &[7]), vec![(0, 5)]);
    }
}
