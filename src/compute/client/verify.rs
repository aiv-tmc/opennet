//! Redundant-execution verification and peer selection for the
//! consumer: with `--verify N` the identical task runs on N distinct
//! peers concurrently and the majority outcome hash wins — the
//! standard defense against a provider returning fabricated output.
//! Peer selection for single and verified runs also lives here.

use super::settle::settled_header;
use super::{compute_once, TaskOutcome};
use crate::daemon::Ctx;
use crate::dht::PeerInfo;
use crate::node::state::Mode;
use rand::seq::SliceRandom;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

/// Run the identical task on `verify` distinct peers concurrently,
/// group the results by output hash and keep the majority outcome.
/// Every execution settles its own reservation — that is the price of
/// verification — and a divergent minority is reported so the operator
/// can investigate the liar.
pub(super) async fn run_verified(
    ctx: &Arc<Ctx>,
    command: String,
    timeout_secs: u64,
    ram_mb: u64,
    gpus: u32,
    verify: u32,
) -> String {
    let peers = pick_verifiers(ctx, verify as usize).await;
    if peers.len() < verify as usize {
        return format!(
            "error: redundant verification needs {verify} distinct peers, {} known\n",
            peers.len()
        );
    }
    let mut jobs = tokio::task::JoinSet::new();
    for peer in peers {
        let ctx = ctx.clone();
        let command = command.clone();
        jobs.spawn(async move {
            compute_once(
                &ctx,
                Some(&peer.node_id),
                command,
                timeout_secs,
                ram_mb,
                gpus,
            )
            .await
        });
    }
    let mut ok: Vec<(TaskOutcome, i64)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    while let Some(joined) = jobs.join_next().await {
        match joined {
            Ok(Ok(result)) => ok.push(result),
            Ok(Err(err)) => errors.push(err),
            Err(err) => errors.push(format!("verification task panicked: {err}")),
        }
    }
    if ok.is_empty() {
        return format!("error: no verified result ({})\n", errors.join("; "));
    }
    // Majority by output hash; the billed seconds of the winning copy
    // are reported, the charges of every executed copy were settled.
    let mut groups: HashMap<[u8; 32], Vec<(TaskOutcome, i64)>> = HashMap::new();
    for result in ok {
        groups.entry(result.0.hash()).or_default().push(result);
    }
    let majority_needed = (verify / 2 + 1) as usize;
    let best = groups
        .values()
        .map(|group| (group.len(), group))
        .max_by_key(|(count, _)| *count);
    let Some((count, group)) = best else {
        return "error: no verified result\n".to_string();
    };
    let (outcome, _) = group[0].clone();
    if count < majority_needed {
        return format!(
            "error: outcomes diverged ({count}/{} agree), no majority trust in the result\n",
            verify
        );
    }
    let total_charge: i64 = group.iter().map(|(_, charge)| *charge).sum();
    let mut out = settled_header(ctx, total_charge).await;
    if count < verify as usize {
        out.push_str(&format!(
            "warning: only {count}/{} copies agreed on the output\n",
            verify
        ));
    }
    out.push_str(&super::render(&outcome));
    if !errors.is_empty() {
        out.push_str(&format!("warning: {} copy(s) failed\n", errors.len()));
    }
    out
}

/// Pick the most suitable known peer automatically: every usable
/// candidate is equally announced, so the choice is uniformly random
/// to spread load without a central scheduler.
pub(super) async fn auto_pick(ctx: &Arc<Ctx>) -> Option<PeerInfo> {
    let peers = candidates(ctx).await;
    peers.choose(&mut rand::thread_rng()).cloned()
}

/// The `count` most trusted usable peers, highest trust first; the
/// caller re-checks the count because reputation data may be sparse.
async fn pick_verifiers(ctx: &Arc<Ctx>, count: usize) -> Vec<PeerInfo> {
    let mut peers = candidates(ctx).await;
    peers.sort_by_key(|peer| Reverse(peer.trust));
    peers.truncate(count.max(1));
    peers
}

/// Every usable peer: a verified node id, not a seed, and offering at
/// least the minimum trust the local policy requires.
async fn candidates(ctx: &Arc<Ctx>) -> Vec<PeerInfo> {
    let dht = ctx.dht.lock().await;
    dht.all_peers()
        .into_iter()
        .filter(|peer| {
            peer.trust >= ctx.config.trust.min_trust
                && peer.points > 0
                && peer.mode != Mode::Seed.as_str()
        })
        .collect()
}
