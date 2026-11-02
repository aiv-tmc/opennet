//! Launching local shard runners for swarm placement plans.
//!
//! A `Message::ShardLaunch` arrives signed by the coordinator. Every
//! constraint is re-verified before any process exists: signature and
//! freshness, known verified peer, explicit local consent for exactly
//! this program, manifest digest match against the on-disk artifact,
//! the consent RAM cap, the GPU requirement against the devices this
//! node offers, a sane layer range, no duplicate shard index for the
//! plan, and a global cap on concurrently hosted shards. Only then
//! does the runner spawn — exec'd directly from the local manifest
//! argv (the runner command never travels on the wire) with the runner
//! sandbox profile, which keeps the host network namespace so the
//! runner can reach the worker's loopback listener. The spawn itself
//! lives in `spawn`; the bridge task in `runner`.

use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::node::identity::Identity;
use anyhow::{bail, Result};
use std::sync::Arc;

mod spawn;

/// Hard cap on concurrently hosted shard runners per node; one consent
/// cannot be turned into an unbounded process fleet.
const MAX_LOCAL_SHARDS: usize = 16;

/// Verify a coordinator's launch request and, when every check passes,
/// spawn the local shard runner and register its bridge. Failures are
/// reported back to the coordinator as a done signal whose reason
/// names the failed shard, so the coordinator can relaunch it on the
/// plan's spare slot.
pub async fn handle_launch(ctx: &Arc<Ctx>, src: &str, launch: Message) -> Result<()> {
    if let Err(err) = try_launch(ctx, src, &launch).await {
        let (plan_id, shard_index) = match &launch {
            Message::ShardLaunch {
                plan_id,
                shard_index,
                ..
            } => (plan_id.clone(), *shard_index),
            _ => (String::new(), 0),
        };
        let _ = send_msg(
            ctx,
            src,
            &Message::SwarmDone {
                plan_id,
                reason: format!("shard {shard_index} launch failed: {err:#}"),
            },
        )
        .await;
        return Err(err);
    }
    Ok(())
}

/// The full launch pipeline, separated so the caller can translate any
/// failure into a plan-wide failover signal.
async fn try_launch(ctx: &Arc<Ctx>, src: &str, launch: &Message) -> Result<()> {
    let Message::ShardLaunch {
        plan_id,
        shard_index,
        program,
        artifact_hash,
        layer_from,
        layer_to,
        ram_mb,
        gpus,
        next_addr,
        unix_ts,
        pubkey,
        signature,
    } = launch
    else {
        bail!("not a shard launch");
    };
    // The launch must be signed by the coordinator over the exact fields
    // it carries — including the GPU requirement; any tamper breaks the
    // binding.
    let sig: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed shard launch signature"))?;
    let payload = Message::launch_signing_payload(
        plan_id,
        *shard_index,
        program,
        artifact_hash,
        *layer_from,
        *layer_to,
        *ram_mb,
        *gpus,
        next_addr,
        *unix_ts,
    );
    if !Identity::verify(pubkey, &payload, &sig) {
        ctx.reputation.lock().await.record_invalid(src);
        bail!("bad shard launch signature");
    }
    let coordinator = Identity::node_id_from_pubkey(pubkey);
    if !crate::swarm::timestamp_fresh(ctx, *unix_ts) {
        bail!("stale shard launch");
    }
    // The coordinator must be a verified, previously announced peer.
    if ctx
        .dht
        .lock()
        .await
        .find_by_exact_node_id(&coordinator)
        .is_none()
    {
        bail!("launch from unknown coordinator");
    }
    // Explicit consent for exactly this program is required; without it
    // nothing is spawned, regardless of signature validity.
    let consent = ctx.swarm.lock().await.clone();
    if !consent.allows(program) {
        bail!("no consent for program {program}");
    }
    // The manifest must exist, parse and hash-match the on-disk
    // artifact; the launch's digest must equal the manifest's.
    let spec = consent.verified_program(program)?;
    if artifact_hash != &spec.artifact_hash {
        bail!("launch digest does not match the local manifest");
    }
    // The requested shard must fit the consent caps.
    if *ram_mb > consent.max_shard_ram_mb {
        bail!("launch exceeds local shard RAM cap");
    }
    // The GPU requirement must fit the devices this node offers;
    // operators partition cards between compute tasks and shard
    // runners with the `[gpu].devices` list.
    let offered = offered_devices(ctx);
    if *gpus as usize > offered.len() {
        bail!(
            "shard requires {gpus} GPU(s), this node offers {}",
            offered.len()
        );
    }
    if spec.runner_cmd.is_empty() {
        bail!("manifest declares no runner command");
    }
    // Sane layer range inside the manifest layer space.
    if layer_from >= layer_to || *layer_to > spec.layers {
        bail!("invalid layer range");
    }
    drop(consent);
    // One shard index per plan: a duplicate would silently orphan the
    // first runner, leaking it until the plan deadline.
    let key = crate::swarm::proc_key(plan_id, *shard_index);
    {
        let procs = ctx.swarm_procs.lock().await;
        if procs.contains_key(&key) {
            bail!("shard {key} already running");
        }
        if procs.len() >= MAX_LOCAL_SHARDS {
            bail!("local shard capacity reached");
        }
    }
    spawn::spawn_shard(
        ctx,
        src,
        plan_id,
        *shard_index,
        &spec,
        *layer_from,
        *layer_to,
        *ram_mb,
        consent_cpu(ctx).await,
        next_addr,
        &offered[..*gpus as usize],
    )
    .await
}

/// Device indices this node offers for shard hosting: the explicit
/// configured list, or the first `count` indices.
pub(crate) fn offered_devices(ctx: &Arc<Ctx>) -> Vec<u32> {
    let gpu = &ctx.config.gpu;
    if !gpu.devices.is_empty() {
        gpu.devices.clone()
    } else {
        (0..gpu.count).collect()
    }
}

/// Read the consent CPU cap without holding the lock across the spawn.
async fn consent_cpu(ctx: &Arc<Ctx>) -> u32 {
    ctx.swarm.lock().await.max_shard_cpu_percent
}
