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
  coefficient and hardware price over signed, timestamped, persistent TCP
  connections.
* Hardware is priced in **capacity points** (CPU cores and RAM size,
  read from the real machine), announced with the identity. One task costs
  `points × minutes` trust units on its provider.
* A node that wants work done sends a **bid** carrying a signed snapshot of
  its trust and consumption counters. The provider serves the highest
  offer first, never running more than `max_tasks` tasks at once, and
  accepts only while `trust − consumed ≥ min_trust`. On completion the
  consumer's `consumed` counter grows and its trust drops; the provider's
  trust rises by the same amount. Refused, failed or timed-out tasks
  release their reservation automatically.
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
to `/usr/local/bin`, writes a default config only when none exists and starts
the daemon. To try it without installing:

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
| `compute &lt;node_prefix\|-&gt; &lt;command...&gt;` | run a command on a peer, price derived from its capacity points |
| `trust`                              | trust coefficient, consumption counter, reservations |
| `reputation`                         | peer reputation table                        |
| `shutdown`                           | stop the daemon gracefully                   |

`compute` with `-` picks the best peer automatically (seeds first, then the
highest-trust peers). The command runs in a fresh temporary directory with a
scrubbed environment (`PATH`, `HOME` only), in its own process group with a
hard wall-clock limit.

## Configuration

The daemon reads TOML from `--config`, `$OPENNET_CONFIG` or
`/etc/opennet/config.toml`. Every field has a working default; the daemon
runs correctly with no config file at all.

```toml
mode = "peer"            # peer | seed | leech

[limits]
cpu_percent = 50         # advertised CPU share for remote tasks
ram_mb = 2048            # advertised RAM for remote tasks
max_tasks = 4            # enforced: max concurrent remote tasks

[trust]
genesis_trust = 100      # trust granted to a fresh node
min_trust = 0            # floor for effective trust when accepting a task
points_per_core = 10     # capacity points per CPU core
points_per_gb = 2        # capacity points per GiB of RAM

[network]
port = 0                 # TCP listen port (0 = ephemeral)
multicast_addr = "239.255.0.1"   # LAN discovery group
multicast_port = 9999
hello_interval_secs = 5          # discovery announcement interval
heartbeat_interval_secs = 30     # signed announcement interval
task_timeout_secs = 300          # default wall-clock limit per task
ann_max_age_secs = 120           # reject announcements older than this
ann_future_skew_secs = 120       # reject announcements from the far future

[paths]
state_dir = "/var/lib/opennet"   # identity key + state + reputation
socket_path = "/run/opennet/control.sock"
```

State files in `state_dir`: `node.key` (ed25519 secret, 0600),
`state.json` (mode, trust, consumed, task stats), `reputation.json` (peer
scores).

## Running as a system service

`install.sh` handles everything. Manually:

* **systemd**: `cp init/opennetd.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now opennetd`
* **dinit**: `cp init/opennetd.dinit /etc/dinit.d/opennetd && dinitctl enable opennetd && dinitctl start opennetd`
* **OpenRC**: `cp init/opennetd.openrc /etc/init.d/opennetd && chmod +x /etc/init.d/opennetd && rc-update add opennetd default && rc-service opennetd start`
* **runit**: `mkdir -p /etc/sv/opennetd && cp init/opennetd.run /etc/sv/opennetd/run && chmod +x /etc/sv/opennetd/run && ln -s /etc/sv/opennetd /var/service/`

The systemd unit uses `Type=notify` readiness plus sandboxing
(`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`).

## Security notes

* Announcements and bids are ed25519-signed and timestamped; the node id is
  blake3 of the signer's public key, so a valid signature proves identity,
  and stale announcements are rejected as replays.
* Providers verify the bid's signed trust against the last announced value
  and enforce `trust − consumed − in_flight ≥ min_trust`, so a node cannot
  inflate its coefficient or leech indefinitely.
* Multicast discovery datagrams are unsigned by design and only seed the
  routing table until a verified announcement arrives.
* Task commands run with the daemon's privileges inside a temporary
  directory with a scrubbed environment, their own process group and a
  wall-clock limit. They are **not** a security sandbox yet: only peers you
  trust should be allowed to submit tasks. Real isolation
  (namespaces/cgroups) is planned.
* The control socket trusts everyone with write access - protect it via
  filesystem permissions (default: root-only `/run/opennet`).

## Roadmap

1. Daemon skeleton: config, control socket, init system integration. **done**
2. Trust coefficient economy with hardware capacity pricing. **done**
3. Sandboxed execution (namespaces + cgroups v2) and result verification.
   **planned**
