//! Shared swarm state types: plan slots and coordination state,
//! shard bridge handles and the sequence guards. Owned by the swarm
//! module and re-exported for the daemon context and the coordinator.

use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot};

/// One coordination event of a plan, consumed by the coordinator's
/// event loop and produced by inbound network frames.
#[derive(Clone, Debug)]
pub enum PlanEvent {
    /// One shard reported readiness.
    Ready(u32),
    /// A pipeline frame must be relayed to shard `dst`; carries the
    /// original source shard and frame number so the relay preserves
    /// both on the wire and the sequence guard keeps working.
    Fwd {
        /// Monotonic frame number assigned by the source shard.
        seq: u64,
        /// Index of the shard that produced the payload.
        src: u32,
        /// Index of the shard that must receive the payload.
        dst: u32,
        /// Opaque payload interpreted by the shard runner.
        payload: Vec<u8>,
    },
    /// A shard delivered output bytes to the coordinator.
    Out {
        /// Monotonic frame number within the output stream.
        seq: u64,
        /// Opaque result payload produced by the last shard.
        payload: Vec<u8>,
    },
    /// The plan ended, carrying the human-readable reason.
    Done(String),
}

/// Live coordination state for one plan, owned by the coordinator.
pub struct PlanState {
    /// Placement slots in shard order: where each shard runs. During
    /// failover the failed slot is rewritten in place to the spare's
    /// address, so relays follow the replacement transparently.
    pub shards: Vec<ShardSlot>,
    /// Shards that have reported readiness so far.
    pub ready: HashSet<u32>,
    /// Highest accepted pipeline frame number per source shard; a
    /// frame whose number does not strictly increase the stored value
    /// for its source is dropped as a replay or reordering.
    pub seqs: HashMap<u32, u64>,
    /// Highest accepted output frame number; the output stream of the
    /// last shard restarts its numbering, so it is validated against
    /// its own counter instead of the pipeline counters.
    pub out_seq: u64,
    /// Latest runner checkpoint per shard: at most one bounded blob
    /// per shard, replaced on every new checkpoint.
    pub checkpoints: HashMap<u32, Vec<u8>>,
    /// Bounded event queue feeding the coordinator's select loop;
    /// producers drop with a log line when it is full.
    pub events: mpsc::Sender<PlanEvent>,
}

/// One placement slot: which shard runs on which verified peer.
#[derive(Clone, Debug)]
pub struct ShardSlot {
    /// Address of the shard's host.
    pub addr: String,
    /// Node id of the shard's host.
    pub node_id: String,
}

/// One local shard bridge registration: the bounded queue feeding the
/// runner and the handle that ends it when the plan dies.
pub struct ShardProc {
    /// Index of this shard inside the plan.
    pub shard_index: u32,
    /// Bounded queue of pipeline frames destined for the runner; the
    /// bridge task drains it and writes frames on the runner socket.
    pub inbound: mpsc::Sender<Vec<u8>>,
    /// Fired when the plan ends so the bridge tears the runner down
    /// even mid-pipeline.
    pub shutdown: oneshot::Sender<()>,
}

/// Registry key for one bridge inside `Ctx::swarm_procs`.
pub fn proc_key(plan_id: &str, shard_index: u32) -> String {
    format!("{plan_id}:{shard_index}")
}

/// Admit one pipeline frame number: numbers must strictly increase per
/// source shard, so a replayed or reordered frame is rejected. Each
/// shard emits its frames over one ordered stream, which makes
/// per-source monotonicity the exact correctness condition.
pub(crate) fn accept_seq(seqs: &mut HashMap<u32, u64>, src: u32, seq: u64) -> bool {
    let last = seqs.entry(src).or_insert(0);
    if seq > *last {
        *last = seq;
        true
    } else {
        false
    }
}
