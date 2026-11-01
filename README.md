# OpenNet

Peer-to-peer network for distributed computing. OpenNet turns a group
of Linux machines into a shared compute pool governed by a **trust
coefficient**: every node earns trust by donating CPU/GPU time to the
network and spends trust to run its own work on other machines. The
more useful a machine is to the network, the more capacity it can pull
back. Since 0.6.0 the pool includes **GPU accelerators**; since 0.7.0
the economy rests on **countersigned billing receipts**, tasks can be
**verified by redundant execution**, and meshes extend beyond one LAN
through **WAN seed gossip**. Since 0.8.0 every market decision
(accept/reject/result) is **signed**, trust claims are **evidence-gated
at bid time** through the receipt-chain audit, and the daemon compiles
and runs on **Windows and macOS** with a degraded (no-op) sandbox.
Since 0.9.0 swarm consent is **per-program**, shard runners support
**checkpoints** for stateful failover (wire v10), the chain audit walks
**multi-window journals**, the sandbox works **without root** through
user namespaces, and the daemon speaks **leveled logging** with
**metrics counters** in `status`.

## How it works

* Every machine runs the `opennetd` background daemon.
* Daemons find each other automatically on the LAN via multicast; with
  `[network].wan = true` and a shared seed list they also discover each
  other across NAT segments through signed address gossip relayed by
  the seeds (gossiped addresses are unverified seeds — identity always
  comes from signed announcements).
* Each node periodically announces its identity, mode, trust
  coefficient, capacity price (CPU/RAM plus per-GPU points), its
  **receipt journal head** and a timestamp over signed frames on
  persistent TCP connections validated by a versioned greeting.
* Hardware is priced in **capacity points**; one task reserves
  `points × ceil(timeout/60)` trust units; the final charge follows the
  *actual* billed seconds, capped by the observed wall time plus slack
  and by the reservation. Consumer and provider compute identical
  numbers, and the provider signs a **receipt** committing to the charge
  and the output hash; the consumer countersigns it (`ReceiptAck`) and
  both journals chain the receipts into an auditable log. Journal
  entries are signature-verified on append and on every replay; acks
  bind to the receipts they countersign.
* A node that wants work done sends a **bid** with a signed trust
  snapshot. Providers serve the highest offer first and accept only
  while `trust − consumed − in_flight ≥ min_trust`. Bid accept, reject
  and task results are signed by the provider: a consumer only acts on
  decisions that verify against the provider's node id. Receipt-less
  consumers (a wiped identity announces the genesis head) pay the
  configured stranger surcharge — Sybil resistance by pricing.
* Trust claimed above the genesis endowment must prove itself: at bid
  time the provider requests signed windows of the consumer's receipt
  journal and recomputes the chain head across the whole chain (16 ×
  1024 receipts per audit). A mismatch — or a peer that cannot answer —
  refuses the bid; unverifiable trust never trades.
* Task assignments are signed by the same key that made the bid and
  carry a signed resource request (`--gpus N`, `--ram-mb M`); the
  provider re-checks the request against its advertised capacity before
  anything starts. With `--verify K` the identical task runs on K peers
  and the majority output hash wins.

## Operating modes

| Mode  | Donates capacity | Requests tasks | Typical use                |
|-------|------------------|----------------|----------------------------|
| peer  | yes              | yes            | workstations (default)     |
| seed  | yes              | no             | servers + WAN rendezvous   |
| leech | no               | yes            | small devices              |

## Quick start

```sh
$ git clone https://github.com/aiv-tmc/opennet.git && cd opennet
$ ./install.sh            # builds, installs, enables and starts the service
$ opennetctl status       # node overview incl. sandbox capability + receipts
```

Without installing: `cargo build --release && sudo ./target/release/opennetd &`.
On a second machine the daemons discover each other within seconds
(`opennetctl peers`). Run a command on another machine:

```sh
$ opennetctl compute - 'uname -a && nproc'
$ opennetctl compute - --gpus 1 --ram-mb 4096 'python3 train.py'
$ opennetctl compute - --verify 3 'make -j4 test'   # majority-verified
```

## GPU support

```toml
[gpu]
count = 2            # devices offered to the network (0 = CPU-only)
devices = [0, 1]     # optional explicit indices; empty = first `count`
points_per_gpu = 50
```

The scheduler allocates concrete device indices (lowest free first,
returned exactly once), the runner gets `CUDA_VISIBLE_DEVICES` and
`ROCR_VISIBLE_DEVICES` pinned, and its memory cap is the larger of the
sandbox default and the task's request. Swarm manifests declare
`gpus_per_shard`; placement only picks peers whose swarm offer covers
it, and shard runners receive the same pinned environment.

## Swarm mode

One shared program across consenting nodes, strictly opt-in **per
program** (a node can host several programs at once, each with its own
resource ceilings). Manifests live in the artifacts directory as
`{program}.manifest.json`:

```json
{
  "artifact": "model.gguf",
  "blake3": "<hex digest>",
  "layers": 80,
  "shard_ram_mb": 4096,
  "gpus_per_shard": 1,
  "runner": ["./run-shard.sh"]
}
```

The coordinator splits the layer space proportionally to offered RAM
(128-bit integer math, last slot takes the remainder), keeps the **last
slot as a hot spare** (a failed shard is relaunched on the spare with
the identical signed launch), and relays `[u32 len][u8 tag][payload]`
frames (tags: 0 input, 1 forward, 2 output, 3 ready, 4 done, **5
checkpoint**) capped at 1 MiB. Runners that emit checkpoint frames
(tag 5 upstream via `ShardCheckpoint`, wire v10) resume their state on
the spare after a failure; runners that ignore tag 5 simply restart
cold, which stays correct for stateless programs.
`scripts/runners/pipeline-echo.sh` is a complete reference runner;
(Inference)[https://github.com/aiv-tmc/opennet/wiki/Inference] describes
the llama.cpp integration recipe.

## WAN mode

```toml
[network]
wan = true
seeds = ["203.0.113.7:7000", "203.0.113.8:7000"]
```

Seeds are seeded as unverified entries and dialed on demand; every node
periodically signs a capped snapshot of its routing table and relays it
to all peers, so two nodes sharing a seed converge into one mesh. The
transport is encrypted end to end; gossip carries dial addresses only.

## Execution sandbox

Tasks run sandboxed (namespaces + cgroup v2), swarm runners with the
same profile minus the network namespace. `opennetctl status` always
reports the effective capability (`active` / `degraded` / `disabled`).
Tuning in `[sandbox]`; `memory_mb = 0` and `cpu_percent = 0` inherit
`[limits]`. Without root the daemon first enters a user namespace
(`CLONE_NEWUSER` + `uid_map`/`gid_map`) and then creates the mount,
PID and network namespaces inside it, so full isolation works on
default kernels without privileges; on kernels that forbid unprivileged
user namespaces the sandbox degrades with a log line. On Windows/macOS
the sandbox degrades to the no-op profile and the control endpoint is a
loopback TCP listener whose address is recorded where the socket path
would be — set `OPENNET_SOCKET` for `opennetctl` to find it.

## Logging and metrics

Logs go to stderr with a unix timestamp, the level and the module path
(`OPENNET_LOG=info` or `debug` for more; default `warn`).
`opennetctl status` additionally reports live counters: tasks started,
receipts settled and failed chain audits.

## Control interface

Socket `/run/opennet/control.sock` on Unix (connections from root or
the daemon's own uid only, `SO_PEERCRED`); a loopback TCP endpoint
recorded in the same path on other platforms.

| Command | Action |
|---|---|
| `status` | identity, trust, counters, metrics, sandbox capability, receipts |
| `mode [peer\|seed\|leech]` | show or set operating mode |
| `peers` / `limits` / `trust` / `reputation` | tables and economy |
| `compute <prefix\|-> [--gpus N] [--ram-mb M] [--verify K] <cmd...>` | run a task on a peer |
| `swarm status\|enable\|disable\|run` | per-program consent and plans |
| `shutdown` | graceful stop |

## Configuration

The daemon reads `--config` / `$OPENNET_CONFIG` / `/etc/opennet/config.toml`
(a missing file materializes the defaults). Startup validation aborts
boot naming the offending key. State in `state_dir`: `node.key`,
`state.json`, `receipts.jsonl` + `receipts-acks.jsonl` (append-only,
chained, signature-verified), `reputation.json`, `swarm.toml`.
Reservations are in-memory.

```toml
mode = "peer"
[limits]        # cpu_percent, ram_mb, max_tasks
[gpu]           # count, devices, points_per_gpu
[trust]         # genesis_trust, min_trust, points_per_core/gb, new_node_units_factor
[network]       # port, multicast_*, intervals, ann windows, wan, seeds
[paths]         # state_dir, socket_path
[swarm]         # consent defaults, artifacts_dir
[sandbox]       # namespaces, read_only_root, cgroup, memory_mb, cpu_percent, pids_max
```

## Security notes

* Wire protocol v10; version negotiation precedes signature checks,
  and every signed frame covers the version.
* Bid decisions and results are signed by the provider; consumer
  waiters bind by provider node id, so an injected decision from any
  other key — even on the same listener port — cannot satisfy or
  poison a request.
* Every failed verification is penalized against the connection
  address, never a claimed node id.
* Greetings bind the advertised address to the real socket IP
  (wildcard rewritten to the real IP); gossiped addresses stay
  unverified until an announcement verifies them.
* Providers reject trust claims above the announced value, bind
  assignments to accepted bids, re-check signed resource requests, and
  bill capped by observed wall time — with a signed receipt the
  consumer countersigns.
* Trust above genesis is evidence-gated: the window-walk receipt-chain
  audit refuses mismatched or unreachable claims at bid time.
* Receipt journals verify every entry's signature on append and on
  replay; acks bind to issued receipts by task id and hash.
* Control socket: root or daemon uid only (unix); loopback-only
  elsewhere.
* The trust economy is self-attested at the announcement level but
  receipt-chained: wiping state resets the journal to the genesis head
  and lands the new identity on stranger pricing, and receipt
  discrepancies are auditable evidence.
* The wire decoder and the signature verifier are fuzz targets; the
  regular suite runs a deterministic chaos decode test so the outermost
  robustness boundary is pinned without fuzzing infrastructure.

## Testing and fuzzing

```sh
cargo test --release
OPENNET_SANDBOX_TEST=1 cargo test --release   # real namespace sandbox test
cargo bench --bench bench                     # criterion suite
cargo install cargo-fuzz && cargo fuzz run decode    # libFuzzer: decoder
cargo fuzz run signing                               # libFuzzer: verifier
```

## Benchmarks

```sh
cargo bench --bench bench
cargo bench --bench bench -- --save-baseline main
```

## Roadmap

1.–4. Core daemon, trust economy, swarm, sandboxed execution — **done**.
5. GPU market + wire v4 — **done** (0.6.0).
6. Receipts + redundant verification + Sybil pricing + WAN gossip +
   GPU shards + spare shards + bounded queues (wire v5–v7) — **done** (0.7.0).
7. Receipt-chain audit enforcement, signed market decisions, journal
   hardening, Windows/macOS base (wire v8–v9) — **done** (0.8.0).
8. Multi-program consent, shard checkpoints, window-walk audits,
   user-namespace sandbox, logging/metrics, fuzzing (wire v10) —
   **done** (0.9.0).
9. seccomp-bpf, tracing + Prometheus export, committed bench baseline,
   two-node CI smoke, artifact marketplace — planned (1.0.0-candidate).
