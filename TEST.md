# Testing OpenNet

## Running

```
cargo test                 # full unit + integration suite
cargo test --release       # release-mode run (mirrors production arithmetic)
OPENNET_SANDBOX_TEST=1 cargo test --release  # also run the namespace-isolation test
cargo bench --bench bench  # criterion benchmarks (encode, sign, transport, trust)
```

Tests never touch `/var/lib/opennet` or `/etc/opennet`; the only
system-wide resource they use is the loopback interface.

## Sandbox in unit tests

Test contexts disable the namespace and cgroup sandbox by default:
creating nested namespaces depends on host privileges and outer
container runtimes, which may reap sandboxed children and made task
outcomes nondeterministic. All executor behavior (billing, timeouts,
output capture, failure accounting) is therefore tested without
isolation, which keeps the suite deterministic on any machine.

The real sandbox is verified explicitly by
`compute::executor::tests::sandboxed_task_has_private_loopback_and_no_host_files`,
which only runs when `OPENNET_SANDBOX_TEST=1` is set. Run it on a
bare-metal host (or any host where `unshare --mount --uts --ipc --pid
--net --fork true` succeeds).

## Layout

| Area | Location | Notes |
|------|----------|-------|
| Transport | `src/transport/tests.rs` | real loopback sockets, two `Transport` instances |
| Trust economy | `src/trust/tests.rs` | accounting invariants and market flow |
| Executor | `src/compute/executor/tests.rs` | spawning, output caps, timeouts, gated sandbox test |
| Control | `src/control.rs` (`mod tests`) | command formatting and validation |
| Node state | `src/node/state.rs` | persistence and settlement |
| Swarm consent/spec | `src/swarm/consent.rs` | manifest parsing, digest verification |

## Regression pins for the hardened transport

* `connection_budget_is_released_when_the_peer_dies` — the shared
  connection counter returns to zero after the peer disappears; a
  daemon that reconnects forever never exhausts the 256-connection
  budget.
* `send_survives_a_failed_write_on_a_stale_socket` — a send against a
  torn-down peer surfaces an error instead of losing the frame or
  panicking.
* `greeting_with_foreign_listen_address_is_dropped` — a `ConnHello`
  advertising a concrete foreign IP is refused; the wildcard
  advertisement (`0.0.0.0`, the default bind address) is accepted.
* `idle_connection_is_dropped_and_reestablished_on_demand` — silent
  sockets are recycled transparently.
* `foreign_protocol_version_is_dropped` — version mismatch never
  surfaces frames to the dispatch loop.
* `frames_must_arrive_in_exactly_send_order` — the receive counter
  accepts exactly the next sealed frame; an out-of-order delivery
  fails, the counter does not advance, and a replayed frame from a
  consumed slot never passes (strict counters, no resync window).
* `session_roundtrip_tamper_eviction_and_ordering` — one failed
  authentication ends the session; the reverse direction is an
  independent key/counter space.

## Regression pins for the hardened transport

## Regression pins for the receipt-chain audit

* `multi_window_walk_recomputes_the_full_chain_head` — chaining two
  of five receipts never reaches the announced head; the walk must
  cover every window.
* `walk_past_the_cache_budget_still_reaches_the_head` — a chain
  longer than the cache budget (here: three windows at a budget of
  two) still verifies against the announced head; the cache budget
  never bounds the walk.
* `hard_capped_walk_reports_incomplete` — a walk that never sees the
  chain end reports nothing, so the caller fails the audit instead of
  trusting a partial chain.

## Regression pins for the provider scheduler

* `expired_bids_are_skipped` — the priority queue never serves an
  expired bid.
* `pending_launches_pop_highest_units_first_and_fifo_on_ties` — the
  pending heap orders by reservation size, FIFO within a tie.
* (purge path) — a parked launch whose accepted bid expired is
  dropped from the heap and its in-flight units return to the
  consumer on the next tick, so the provider-side policy counter
  cannot inflate forever.

## Regression pins for the swarm pipeline

* `zero_capacity_slots_are_skipped` / `all_zero_pool_places_nothing` —
  placement never lets an empty offer swallow the layer space.
* `frame_roundtrip` — the runner bridge frame codec
  (`[u32 len][u8 tag][payload]`) roundtrips on loopback.
* `route_fwd_drops_replays_and_foreign_senders` — a non-member cannot
  inject pipeline frames, a member can only speak for its own shard
  index, and non-increasing per-source sequence numbers replay.
* `route_fwd_at_a_shard_host_accepts_only_its_coordinator` — the
  runner queue accepts frames only from the coordinator recorded at
  launch time.
* `readiness_is_recorded_and_authorized` — readiness enters the
  plan's readiness set only from the shard's own host, and the
  readiness event reaches the coordinator queue.
* `output_comes_only_from_the_last_shard_in_increasing_order` — only
  the last shard emits output, and only in strictly increasing
  sequence.
* `checkpoints_store_per_shard_and_redeliver_on_ready` — checkpoints
  are stored only from the shard's host and re-delivered to the
  replacement runner as one bridge frame after a spare relaunch.
* `done_signals_route_by_role_and_authorize_the_sender` — at the
  coordinator a member's launch-failure report enters the event queue
  (failover trigger) and foreign done signals are dropped; at a shard
  host only the launching coordinator tears local runners down.
* `finish_plan_shuts_every_local_bridge` — ending a plan removes its
  state and fires every local bridge shutdown.

## Integration scenarios (manual, two machines)

1. **Discovery.** Start two daemons on one LAN; within one heartbeat
   interval both `opennetctl peers` listings show the other node with
   a verified node id and matching trust/mode.
2. **Market.** On node A: `opennetctl compute - 'uname -a'`. Expect a
   `TaskAccept`, correct output, and `trust` on both sides moving by
   the same amount (`consumed` up on A, trust up on B by `points ×
   minutes`).
3. **Trust floor.** Drain a leech node to zero effective trust; further
   `compute` attempts are rejected and reservations are released.
4. **Swarm E2E.** On two consenting nodes with a verified manifest:
   `opennetctl swarm enable demo`, then `swarm run demo prompt.txt`
   from a third node. Expect readiness from every shard, relayed
   pipeline frames, and final output equal to the last shard's report.
5. **Consent revocation.** `swarm disable` on one host; the other
   hosts stop offering it immediately (signed `SwarmLeave`) and new
   placements exclude it.
6. **Unclean shutdown.** `kill -9` a daemon mid-task; after restart
   reservations are gone (in-memory by design) and no peer shows a
   stale in-flight task.

## Security test cases

* Replay an old signed `Ann` (timestamp outside the freshness window)
  — rejected, reputation of the *connection address* penalized.
* Send a `TaskResult` from a connection whose greeting claimed a
  foreign listen IP — dropped by `handle_inbound` validation.
* Flood `ShardFwd` at a shard host — the bounded inbound queue drops
  frames under backpressure; memory stays flat, and frames from any
  sender other than the launch coordinator are refused.
* Offer a manifest whose blake3 digest does not match the artifact —
  consent/launch refuses before spawning anything.
* Send `SwarmDone`/`ShardReady`/`ShardOut` from a peer that is not a
  member of the plan — dropped by the admission checks without any
  state change.
* Connect to the non-Unix control listener without the token (or with
  a wrong one) — the session ends silently, before any command is
  read.

## Release gates

`cargo test` green on stable, `cargo clippy -- -D warnings`,
`cargo fmt --check`, and `cargo bench` within 20% of the recorded
baseline for the transport roundtrip.
