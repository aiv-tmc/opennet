# OpenNet

Peer-to-peer network for distributed computing. OpenNet turns a group of
Linux machines into a shared compute pool: every node can donate spare CPU
time to the network, earns credits for executed tasks, and spends those
credits to run its own work on other machines with priority.

## How it works

* Every machine runs the `opennetd` background daemon.
* Daemons find each other automatically on the LAN via multicast
  announcements; no central server and no configuration of peers is needed.
* Each node periodically announces its identity, operating mode and credit
  balance over signed, persistent TCP connections.
* A node that wants work done sends a **bid** (`offer` credits) to a peer.
  The provider queues bids and serves the highest offer first, never running
  more than `max_tasks` tasks at once (BitTorrent-style tit-for-tat).
* On completion the consumer pays the promised credits with a signed
  transfer; refused, failed or timed-out transfers are refunded
  automatically.
* Fresh nodes start with a 100-credit genesis endowment so the market works
  out of the box.

## Operating modes

| Mode  | Donates capacity | Requests tasks | Typical use                |
|-------|------------------|----------------|----------------------------|
| peer  | yes              | yes            | workstations (default)     |
| seed  | yes              | no             | servers accumulating credits |
| leech | no               | yes            | small devices              |

Switch at runtime: `opennetctl mode seed` (persisted across restarts).

## Quick start (zero configuration)

```sh
$ $ git clone https://github.com/aiv-tmc/opennet.git && cd opennet
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
$ opennetctl compute - 5 'uname -a && nproc'
```

## Control interface

`opennetctl` sends one command to the daemon and prints the response.
Socket: `/run/opennet/control.sock` (override with `--socket` or
`OPENNET_SOCKET`).

| Command                              | Action                                       |
|--------------------------------------|----------------------------------------------|
| `status`                             | node id, mode, credits, task and peer counters |
| `mode [peer\|seed\|leech]`           | show or set operating mode                   |
| `peers`                              | known peers with node id, mode, credits, age |
| `limits`                             | resource limits offered to the network       |
| `transfer <node_prefix> <amount>`    | send signed credits to a peer                |
| `compute <node_prefix\|-> <offer> <command...>` | run a command on a peer, pay `offer` credits |
| `ledger [count]`                     | recent credit transfers (default 10)         |
| `reputation`                         | peer reputation table                        |
| `shutdown`                           | stop the daemon gracefully                   |

`compute` with `-` picks the best peer automatically (seeds first, then the
highest-credit peers). The command runs in a fresh temporary directory with a
scrubbed environment (`PATH`, `HOME` only) and a hard wall-clock limit.

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

[network]
port = 0                 # TCP listen port (0 = ephemeral)
multicast_addr = "239.255.0.1"   # LAN discovery group
multicast_port = 9999
hello_interval_secs = 5          # discovery announcement interval
heartbeat_interval_secs = 30     # signed announcement interval
task_timeout_secs = 300          # default wall-clock limit per task

[paths]
state_dir = "/var/lib/opennet"   # identity key + state + ledgers
socket_path = "/run/opennet/control.sock"
```

State files in `state_dir`: `node.key` (ed25519 secret, 0600),
`state.json` (mode, balance, task stats), `transfers.log` (append-only
credit ledger), `reputation.json` (peer scores).

## Running as a system service

`install.sh` handles everything. Manually:

* **systemd**: `cp init/opennetd.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now opennetd`
* **dinit**: `cp init/opennetd.dinit /etc/dinit.d/opennetd && dinitctl enable opennetd && dinitctl start opennetd`
* **OpenRC**: `cp init/opennetd.openrc /etc/init.d/opennetd && chmod +x /etc/init.d/opennetd && rc-update add opennetd default && rc-service opennetd start`
* **runit**: `mkdir -p /etc/sv/opennetd && cp init/opennetd.run /etc/sv/opennetd/run && chmod +x /etc/sv/opennetd/run && ln -s /etc/sv/opennetd /var/service/`

The systemd unit uses `Type=notify` readiness plus sandboxing
(`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`).

## Documentation

* `docs/PROTOCOL.md` - wire protocol and message flows.
* `docs/DEVELOPMENT.md` - module map, invariants and maintenance guide.

## Security notes

* Announcements and credit transfers are ed25519-signed; the node id is
  blake3 of the signer's public key, so a valid signature proves identity.
* Multicast discovery datagrams are unsigned by design and only seed the
  routing table until a verified announcement arrives.
* Task commands run with the daemon's privileges inside a temporary
  directory with a scrubbed environment and a wall-clock limit. They are
  **not** a security sandbox yet: only peers you trust should be allowed to
  submit tasks. Real isolation (namespaces/cgroups) is planned.
* The control socket trusts everyone with write access - protect it via
  filesystem permissions (default: root-only `/run/opennet`).

## Roadmap

1. Daemon skeleton: config, control socket, init system integration. **done**
2. Credit ledger: signed transfers, reputation tracking. **done**
3. Capacity market: bids, priority scheduling, task execution. **done (hardening ongoing)**
4. Sandboxed execution (namespaces + cgroups v2) and result verification. **planned**

See `CHANGELOG.md` for recent fixes (TCP transport, task kill-on-timeout, docs).

