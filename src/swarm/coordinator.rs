//! The swarm coordinator: capability-aware placement with a hot spare,
//! signed launches and the pipeline relay loop of one plan. The
//! coordinator must itself hold consent for the program; it splits the
//! manifest's layer space across eligible shard hosts proportionally to
//! their offered RAM, keeps the last slot as an unlaunched spare, signs
//! one launch per active shard, and relays pipeline frames until the
//! last shard reports completion. When a shard host reports a launch
//! failure (a member's done signal naming the shard), the same signed
//! launch is re-sent to the spare, the failed slot is rewritten in
//! place, and the pipeline continues; the replacement runner receives
//! the failed shard's stored checkpoint through the readiness path
//! before new input flows.

use crate::message::Message;
use crate::swarm::consent::ProgramSpec;
use crate::swarm::{self, PlanEvent, PlanState, ShardSlot, PLAN_EVENT_CAP};
use crate::trust::now_unix;
use crate::{daemon::Ctx, transport::MAX_FRAME};
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;

mod abort;
mod split;

pub(crate) use split::split_layers;

use abort::{abort_plan, failed_shard_index, plan_ready_count};

/// Upper bound on shards per plan; keeps the signed launch set and the
/// relay state small enough to reason about.
const MAX_SHARDS: usize = 32;

/// Hard cap on the aggregate output of one plan.
const OUTPUT_CAP: usize = 64 * 1024 * 1024;

/// Run one shared program across the swarm: place shards on consenting
/// peers (last slot = hot spare), sign and send one launch per active
/// shard, wait for readiness, relay the prompt through the pipeline and
/// return the last shard's output. The caller must hold consent for the
/// program.
pub async fn run_program(ctx: &Arc<Ctx>, program: &str, prompt_path: &str) -> Result<String> {
    {
        let consent = ctx.swarm.lock().await;
        if !consent.allows(program) {
            bail!(
                "no local consent for '{program}'; run `opennetctl swarm enable {program}` first"
            );
        }
    }
    let spec = ProgramSpec::load(&ctx.config.swarm.artifacts_dir, program)?;
    let prompt = std::fs::read(prompt_path)?;
    if prompt.len() > MAX_FRAME {
        bail!("prompt exceeds the {}-byte frame cap", MAX_FRAME);
    }
    // Capability-aware placement: only peers whose swarm offer covers
    // the manifest's per-shard GPU need are eligible. CPU-only
    // programs (gpus_per_shard == 0) see every consenting peer.
    let eligible = swarm::gpu_capable_candidates(ctx, program, spec.gpus_per_shard).await;
    if eligible.is_empty() {
        bail!(
            "no eligible peers for '{program}' ({} GPU(s) per shard needed)",
            spec.gpus_per_shard
        );
    }
    let mut slots = Vec::new();
    let mut caps = Vec::new();
    for candidate in eligible.iter().take(MAX_SHARDS) {
        slots.push(ShardSlot {
            addr: candidate.addr.clone(),
            node_id: candidate.node_id.clone(),
        });
        caps.push(
            candidate
                .swarm
                .get(program)
                .map(|offer| offer.ram_mb)
                .unwrap_or(0),
        );
    }
    // Hot spare: the last slot receives no launch and no layer range
    // until an active shard fails, then takes the failed slot's place
    // with the identical signed launch. A plan needs at least two
    // candidates to afford a spare; a single-node plan fails fast as
    // before.
    let mut spare = if slots.len() > 1 {
        Some(slots.pop().unwrap())
    } else {
        None
    };
    caps.truncate(slots.len());
    let ranges = split_layers(spec.layers, &caps);
    if ranges.len() < 2 {
        eprintln!("[swarm] warning: only one shard for {} layers", spec.layers);
    }
    let plan_id = format!("plan-{:016x}", rand::random::<u64>());
    let local_addr = ctx.transport.local_id();
    let (events_tx, mut events_rx) = mpsc::channel::<PlanEvent>(PLAN_EVENT_CAP);
    ctx.swarm_plans.lock().await.insert(
        plan_id.clone(),
        PlanState {
            shards: slots.clone(),
            ready: HashSet::new(),
            seqs: Default::default(),
            out_seq: 0,
            checkpoints: Default::default(),
            events: events_tx,
        },
    );
    let unix_ts = now_unix();
    // Sign one launch per active shard and keep the frames: failover
    // re-sends the identical signed launch to the spare. The signature
    // covers the GPU requirement together with every other field.
    let mut launches: Vec<Message> = Vec::new();
    for (shard_index, (from, to)) in ranges.iter().enumerate() {
        let slot = &slots[shard_index];
        let next_addr = slots
            .get(shard_index + 1)
            .map(|slot| slot.addr.clone())
            .unwrap_or_default();
        let payload = Message::launch_signing_payload(
            &plan_id,
            shard_index as u32,
            program,
            &spec.artifact_hash,
            *from,
            *to,
            spec.shard_ram_mb,
            spec.gpus_per_shard,
            &next_addr,
            unix_ts,
        );
        let launch = Message::ShardLaunch {
            plan_id: plan_id.clone(),
            shard_index: shard_index as u32,
            program: program.to_string(),
            artifact_hash: spec.artifact_hash.clone(),
            layer_from: *from,
            layer_to: *to,
            ram_mb: spec.shard_ram_mb,
            gpus: spec.gpus_per_shard,
            next_addr,
            unix_ts,
            pubkey: ctx.identity.pubkey(),
            signature: ctx.identity.sign(&payload).to_vec(),
        };
        launches.push(launch.clone());
        if slot.addr == local_addr {
            swarm::handle_launch(ctx, &local_addr, launch).await?;
        } else {
            crate::daemon::send_msg(ctx, &slot.addr, &launch).await?;
        }
    }
    // Wait for every active shard to report readiness; the readiness
    // set inside the plan state is filled by the admission path as
    // authorized ShardReady frames arrive.
    loop {
        let ready = plan_ready_count(ctx, &plan_id).await;
        if ready >= slots.len() {
            break;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(30), events_rx.recv()).await {
            Ok(Some(PlanEvent::Ready(_))) | Ok(Some(PlanEvent::Fwd { .. })) => {}
            Ok(Some(PlanEvent::Out { .. })) => {}
            Ok(Some(PlanEvent::Done(reason))) => {
                bail!("plan {plan_id} ended before ready: {reason}")
            }
            Ok(None) => bail!("plan {plan_id} event queue closed"),
            Err(_) => {
                abort_plan(ctx, &plan_id, &slots, "shard readiness timed out").await;
                bail!("plan {plan_id}: shard readiness timed out")
            }
        }
    }
    // Push the prompt into the pipeline: local shard 0 takes it
    // directly (this node is an authorized sender of its own plan), a
    // remote shard 0 receives it as the first frame.
    match slots.first() {
        Some(slot) if slot.addr == local_addr => {
            swarm::route_fwd(ctx, &local_addr, &plan_id, 1, 0, 0, prompt).await;
        }
        Some(slot) => {
            let frame = Message::ShardFwd {
                plan_id: plan_id.clone(),
                seq: 1,
                src: 0,
                dst: 0,
                payload: prompt.clone(),
            };
            crate::daemon::send_msg(ctx, &slot.addr, &frame).await?;
        }
        None => unreachable!("placement always yields at least one slot"),
    }
    // Relay until the last shard reports completion. A member's done
    // signal with a host-side launch failure reason triggers failover
    // onto the spare; frames in flight during the swap may be lost,
    // which the pipeline tolerates for stateless shards, while
    // stateful runners resume from the checkpoint the readiness path
    // delivers to the spare.
    let mut output = Vec::new();
    loop {
        let event =
            match tokio::time::timeout(std::time::Duration::from_secs(300), events_rx.recv()).await
            {
                Ok(Some(event)) => event,
                Ok(None) => bail!("plan {plan_id} event queue closed"),
                Err(_) => {
                    abort_plan(ctx, &plan_id, &slots, "plan timed out").await;
                    bail!("plan {plan_id} timed out")
                }
            };
        match event {
            PlanEvent::Fwd {
                seq,
                src,
                dst,
                payload,
            } => {
                let slot = slots
                    .get(dst as usize)
                    .ok_or_else(|| anyhow::anyhow!("plan {plan_id}: bad shard index {dst}"))?;
                if slot.addr == local_addr {
                    swarm::route_fwd(ctx, &local_addr, &plan_id, seq, src, dst, payload).await;
                } else {
                    let frame = Message::ShardFwd {
                        plan_id: plan_id.clone(),
                        seq,
                        src,
                        dst,
                        payload,
                    };
                    crate::daemon::send_msg(ctx, &slot.addr, &frame).await?;
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
                if let Some(index) = failed_shard_index(&reason) {
                    if let Some(spare_slot) = spare.take() {
                        eprintln!(
                            "[swarm] plan {plan_id}: relaunching shard {index} on spare {}",
                            spare_slot.addr
                        );
                        // Rewrite the failed slot in place (relays,
                        // readiness accounting and the membership
                        // checks all follow the replacement) and
                        // require the spare to report ready again; the
                        // readiness event re-delivers the shard's
                        // checkpoint to the replacement runner.
                        {
                            let mut plans = ctx.swarm_plans.lock().await;
                            if let Some(plan) = plans.get_mut(&plan_id) {
                                if let Some(slot) = plan.shards.get_mut(index) {
                                    *slot = spare_slot.clone();
                                }
                                plan.ready.remove(&(index as u32));
                            }
                        }
                        slots[index] = spare_slot.clone();
                        let relaunch = launches[index].clone();
                        if spare_slot.addr == local_addr {
                            swarm::handle_launch(ctx, &local_addr, relaunch).await?;
                        } else {
                            crate::daemon::send_msg(ctx, &spare_slot.addr, &relaunch).await?;
                        }
                        continue;
                    }
                }
                swarm::finish_plan(ctx, &plan_id, &reason).await;
                if reason == "completed" {
                    return Ok(String::from_utf8_lossy(&output).into_owned());
                }
                bail!("plan {plan_id} ended: {reason}");
            }
            PlanEvent::Ready(_) => {}
        }
    }
}
