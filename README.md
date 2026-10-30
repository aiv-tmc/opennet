# OpenNet

Peer-to-peer network for distributed computing. OpenNet turns a group of
Linux machines into a shared compute pool governed by a **trust
coefficient**: every node earns trust by donating CPU time to the network
and spends trust to run its own work on other machines. The more useful a
machine is to the network, the more capacity it can pull back.

## How it works

* Every machine runs the `opennetd` background daemon.
* Daemons find each other automatically on the LAN via multicast
  announcements; no central server and no configuration of peers is needed.
* Each node periodically announces its identity, operating mode, trust
  coefficient and hardware price over signed, timestamped frames;
  announcements travel on persistent TCP connections validated by a
  versioned greeting whose advertised listen address must match the
  peer's real socket IP.
* Hardware is priced in **capacity points**, computed from the capacity
  the node actually offers to the network (CPU share and RAM limit from the
  config), announced with the identity. One task reserves
  `points × ceil(timeout/60)` trust units on its provider; the final
  charge follows the *actual* billed seconds, capped by the wall time
  observed between accept and result plus a small clock-skew slack, and can
  never exceed the reservation.
* A node that wants work done sends a **bid** carrying a signed snapshot
  of its trust and consumption counters. The provider serves the highest
  offer first, never runs more than `max_tasks` tasks at once, and accepts
  only while `trust − consumed − in_flight ≥ min_trust`. On completion the
  consumer's `consumed` counter grows and its trust drops; the provider's
  trust rises by the same amount. Refused, failed or timed-out tasks
  release their reservation automatically.
* Task assignments are signed by the same key that made the bid and are
  executed only for task ids the provider accepted from that exact node;
  no third party can trigger execution by replaying frames.
* Fresh nodes start with a 100-unit genesis trust endowment so the market
  works out of the box; a pure leech exhausts it quickly and must donate
  compute to earn more.

## Operating modes

| Mode  | Donates capacity | Requests tasks | Typical use                |
|-------|------------------|----------------|----------------------------|
| peer  | yes              | yes            | workstations (default)     |
| seed  | yes              | no             | servers accumulating trust |
| leech | no               | yes            | small devices              |

Switch at runtime: `opennetctl mode seed` (persisted across restarts).

## Quick start (zero configuration)

```sh
$ git clone https://github.com/aiv-tmc/opennet.git && cd opennet
$ ./install.sh            # builds, installs, enables and starts the service
$ opennetctl status       # check the node
```

`install.sh` detects systemd, dinit, OpenRC or runit, installs the binaries
to `/usr/local/bin`, writes a default config only when none exists and
starts the daemon. To try it without installing:

```sh
$ cargo build --release
$ sudo ./target/release/opennetd &
$ sudo ./target/release/opennetctl status
```

On a second machine on the same LAN the two daemons discover each other
within seconds (`opennetctl peers`). Run a command on the other machine:

```sh
$ opennetctl compute - 'uname -a && nproc'
```

## Control interface

`opennetctl` sends one command to the daemon and prints the response.
Socket: `/run/opennet/control.sock` (override with `--socket` or
`OPENNET_SOCKET`).

| Command                              | Action                                       |
|--------------------------------------|----------------------------------------------|
| `status`                             | node id, mode, trust, task and peer counters |
| `mode [peer\|seed\|leech]`           | show or set operating mode                   |
| `peers`                              | known peers with node id, mode, trust, points, age |
| `limits`                             | resource limits and capacity pricing         |
| `compute <node_prefix\|-> <command...>` | run a command on a peer, priced from its capacity points |
| `trust`                              | trust coefficient, consumption counter, reservations |
| `reputation`                         | peer reputation table                        |
| `swarm status`                       | consent state, local shards, live plans      |
| `swarm enable <program>`             | grant consent to host a shared program     |
| `swarm disable`                      | revoke swarm consent (announced immediately) |
| `swarm run <program> <prompt-file>`  | run one shared program across the swarm    |
| `shutdown`                           | stop the daemon gracefully                   |

`compute` with `-` picks the best peer automatically (seeds first, then
the highest-trust and best-reputed peers). The command runs sandboxed (see
below) in a fresh temporary directory with a scrubbed environment and a
hard wall-clock limit; the final charge is based on the actual billed
seconds.

## Execution sandbox

Every compute task and every swarm shard runner runs inside a sandbox,
applied best-effort on Linux and degrading gracefully where the platform
does not allow a step. Two profiles exist:

* **Tasks** get full isolation: fresh mount, UTS, IPC, PID and network
  namespaces. The mount tree is made private, the root is remounted
  read-only, and the task gets a private tmpfs over its working directory —
  the only writable place it can see. Sandboxed processes have no network
  access; the loopback interface is brought up inside the namespace for
  programs that expect a working `lo`.
* **Swarm runners** get the same namespaces minus the network namespace:
  they must reach the worker's listener, which is bound on the daemon's
  loopback, and a private network namespace would put it behind a
  boundary they cannot cross. The runner's only network exposure is the
  loopback address the worker hands it.

Tuning lives in the `[sandbox]` section; `memory_mb = 0` and
`cpu_percent = 0` inherit the `[limits]` values. Setting `namespaces =
false` or `cgroup = false` disables the respective layer.

```toml
[sandbox]
namespaces = true        # fresh mount/UTS/IPC/PID namespaces (plus network for tasks)
read_only_root = true    # read-only filesystem + private tmpfs workdir
cgroup = true            # per-task cgroup v2 limits
memory_mb = 0            # 0 = inherit limits.ram_mb
cpu_percent = 0          # 0 = inherit limits.cpu_percent
pids_max = 512           # fork bomb protection per task
```

Note: with the stock systemd unit the daemon runs unprivileged, so
namespace creation degrades silently and the sandbox reduces to cgroup
limits. Run the daemon with sufficient privileges (or as root under
runit/OpenRC/dinit) for full isolation — keeping in mind that swarm runners
then still share the daemon's network namespace by design.

## Swarm mode: one big program across the LAN

Swarm mode runs **one shared program** — for example a large LLM split by
layer ranges — across all consenting nodes of the network. It is strictly
opt-in:

* **Default off.** Without consent a node never announces swarm capacity,
  never enters a placement plan and refuses every launch before spawning
  anything.
* **Explicit consent.** `opennetctl swarm enable <program>` (persisted in
  `/var/lib/opennet/swarm.toml`) grants hosting for one named program
  only; the artifact must live in the artifacts directory and its blake3
  digest must match the manifest. `swarm disable` announces a signed
  retraction to all peers immediately.
* **Hash-verified artifacts.** A shard process starts only from a
  manifest plus artifact pair whose digest verifies; manifests are JSON:

```json
{
  "artifact": "model.gguf",
  "blake3": "<hex digest>",
  "layers": 80,
  "shard_ram_mb": 4096,
  "runner": ["./run-shard.sh"]
}
```

The runner command is exec'd directly (no shell), with the sandbox applied
and a scrubbed environment exporting `PLAN_ID`, `SHARD_INDEX`, `LAYER_FROM`,
`LAYER_TO`, `ARTIFACT`, `PORT`, `NEXT_ADDR`, `COORD_ADDR` and `RAM_MB`. It
connects back to the worker's local listener and speaks one
length-prefixed frame protocol:

* worker → runner: `[u32 len][u8 tag = 0][payload]` — pipeline input
  (activation tensors for an LLM); the tag byte is always 0 from the
  worker;
* runner → worker: `[u32 len][u8 tag][payload]` — tag 1 forwards the
  payload to the next shard (the last shard has an empty `NEXT_ADDR` and
  must not forward), tag 2 delivers output to the coordinator, tag 3
  reports readiness, tag 4 reports completion.

Frames in both directions are capped at the wire frame limit (1 MiB), so
the local protocol can never produce frames the transport would reject.

Any program implementing these frames can serve as a shard runner. The
coordinator (`opennetctl swarm run <program> <prompt-file>`) must hold
consent itself, splits the layer space across peers proportionally to
their offered RAM, signs one launch per shard and relays pipeline frames
until the last shard reports completion.

## Configuration

The daemon reads TOML from `--config`, `$OPENNET_CONFIG` or
`/etc/opennet/config.toml`. Every field has a working default; the daemon
runs correctly with no config file at all. The `[sandbox]` section may be
omitted entirely.

```toml
mode = "peer"            # peer | seed | leech

[limits]
cpu_percent = 50         # advertised CPU share for remote tasks
ram_mb = 2048            # advertised RAM for remote tasks
max_tasks = 4            # enforced: max concurrent remote tasks

[trust]
genesis_trust = 100      # trust granted to a fresh node
min_trust = 0            # floor for effective trust when accepting a task
points_per_core = 10     # capacity points per offered CPU core
points_per_gb = 2        # capacity points per offered GiB of RAM

[network]
port = 0                 # TCP listen port (0 = ephemeral)
multicast_addr = "239.255.0.1"   # LAN discovery group
multicast_port = 9999
hello_interval_secs = 5          # discovery announcement interval
heartbeat_interval_secs = 30     # signed announcement interval
task_timeout_secs = 300          # default wall-clock limit per task
ann_max_age_secs = 120           # reject announcements older than this
ann_future_skew_secs = 120        # reject announcements from the far future

[paths]
state_dir = "/var/lib/opennet"   # identity key + state + reputation + consent
socket_path = "/run/opennet/control.sock"

[swarm]                  # defaults for swarm consent (off by default)
enabled = false          # user consent for hosting a shared program
program = ""             # program name this node agrees to host
max_shard_ram_mb = 4096  # RAM cap for one shard process
max_shard_cpu_percent = 50
artifacts_dir = "/var/lib/opennet/swarm"

[sandbox]                # optional; defaults shown
namespaces = true
read_only_root = true
cgroup = true
memory_mb = 0            # 0 = inherit limits.ram_mb
cpu_percent = 0          # 0 = inherit limits.cpu_percent
pids_max = 512
```

State files in `state_dir`: `node.key` (ed25519 secret, 0600),
`state.json` (mode, trust, consumed, counters; written atomically with
owner-only permissions), `reputation.json`, `swarm.toml` (consent).
Reservations are held in memory: an unclean shutdown discards them, and
reservations recorded by older versions are refunded at load time —
nothing is owed across restarts either way.

## Documentation

* `docs/architecture.md` — subsystems, trust economy, task market flow.
* `docs/protocol.md` — wire protocol, signing payloads, transport hardening.
* `docs/swarm.md` — consent, artifacts, placement protocol, runner contract.
* `docs/operations.md` — service management, state files, troubleshooting,
  benchmarks, security checklist.
* `TEST.md` — test layout, regression pins, integration scenarios.

## Benchmarks

```sh
cargo bench --bench bench                       # fast suite (~1 minute)
cargo bench --bench bench -- --save-baseline main
cargo bench --bench bench -- --baseline main    # compare against the baseline
```

Covers message encode/decode, ed25519 sign/verify, routing-table lookups,
trust accounting, the bid priority queue and a loopback transport
roundtrip. See `docs/operations.md` for details.

## Running as a system service

`install.sh` handles everything. Manually:

* **systemd**: `cp init/opennetd.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now opennetd`
* **dinit**: `cp init/opennetd.dinit /etc/dinit.d/opennetd && dinitctl enable opennetd && dinitctl start opennetd`
* **OpenRC**: `cp init/opennetd.openrc /etc/init.d/opennetd && chmod +x /etc/init.d/opennetd && rc-update add opennetd default && rc-service opennetd start`
* **runit**: `mkdir -p /etc/sv/opennetd && cp init/opennetd.run /etc/sv/opennetd/run && chmod +x /etc/sv/opennetd/run && ln -s /etc/sv/opennetd /var/service/`

The systemd unit uses `Type=notify` readiness plus sandboxing
(`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`,
`Delegate=yes`) with explicit write access only to the state, runtime
and cgroup directories. Under other init systems cgroup limits require
root write access to /sys/fs/cgroup; namespace sandboxing works as long
as the daemon runs with sufficient privileges.

## Security notes

* Announcements, swarm offers, bids, launches and assignments are
  ed25519-signed and timestamped; the node id is blake3 of the signer's
  public key, so a valid signature proves identity, and stale messages are
  rejected as replays. Every failed verification is penalized against
  the connection address, never against a claimed node id, so a replay
  cannot damage the reputation of the node it borrows.
* Connection greetings are validated: the advertised listen address must
  match the peer's real socket IP, so unsigned messages (`TaskResult`,
  `ShardFwd`, …) cannot be injected through a borrowed address.
* Providers verify the bid's signed trust against the last announced
  value and enforce `trust − consumed − in_flight ≥ min_trust`; assignments
  are executed only for task ids accepted from the exact signing node.
* Task billing is capped by the wall time observed between accept and
  result, so a misreporting provider cannot overcharge beyond the task's
  actual lifetime plus a small clock-skew slack.
* Tasks and shard runners execute sandboxed (see above). The sandbox is
  defense-in-depth for mutually trusting LAN peers, not a boundary against
  fully hostile code: the transport is unencrypted, and trust accounting is
  self-attested by each node. Review the `[sandbox]` knobs before exposing
  the control socket more widely.
* Swarm shards run only hash-verified artifacts from the local artifacts
  directory under an explicit per-program consent with RAM/CPU caps; the
  consent file is root-owned state and takes effect only after an
  explicit `swarm enable`.
* The control socket trusts everyone with write access — protect it via
  filesystem permissions (default: root-only `/run/opennet`).
* The transport enforces a connection limit (released by the socket's own
  reader on death), greeting deadlines, idle read deadlines and a hard
  frame-size cap so slow or flooding peers cannot exhaust daemon memory.

## Roadmap

1. Daemon skeleton: config, control socket, init system integration. **done**
2. Trust coefficient economy with capacity pricing and billed-by-actual-time
   settlement. **done**
3. Swarm mode: consent-gated hosting of one shared program with a
   pipeline protocol and signed placement plans. **done**
4. Sandboxed execution (namespaces + cgroups v2) for compute tasks and
   swarm shards. **done**
5. Result verification and stronger sandboxing (seccomp, per-task
   seccomp-bpf profiles, user namespaces without root). **planned**
6. Authenticated, encrypted transport (X25519 + AEAD handshake bound to
   node identity) so LAN MitM cannot read or alter frames. **planned**
