#!/bin/sh
# Installs OpenNet system-wide with zero configuration:
# builds the binaries, creates the unprivileged daemon user, installs the
# service files and account/tmpfiles definitions, writes a default config
# only when none exists and hooks the daemon into the detected init system.
# After installation the daemon starts fully functional on first boot.
set -eu

PREFIX="${PREFIX:-/usr/local}"
REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# System-wide installation writes to /etc, /var and /run; refuse to run
# as an unprivileged user instead of failing halfway through.
if [ "$(id -u)" -ne 0 ]; then
    echo "error: install.sh must run as root (system-wide install)" >&2
    exit 1
fi

# Build release binaries when they are missing and cargo is available.
if [ ! -x "$REPO_DIR/target/release/opennetd" ]; then
    if ! command -v cargo >/dev/null 2>&1; then
        echo "error: cargo not found and no prebuilt target/release/opennetd" >&2
        exit 1
    fi
    (cd "$REPO_DIR" && cargo build --release)
fi

install -Dm755 "$REPO_DIR/target/release/opennetd"  "$PREFIX/bin/opennetd"
install -Dm755 "$REPO_DIR/target/release/opennetctl" "$PREFIX/bin/opennetctl"

# Unprivileged daemon user: tasks and shard runners never run as root.
if ! id opennet >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/opennet --shell /usr/sbin/nologin \
        --comment "OpenNet P2P compute daemon" opennet
    echo "created system user 'opennet'"
fi

# Account and tmpfiles definitions consumed by systemd; harmless elsewhere.
install -Dm644 "$REPO_DIR/opennet.sysusers" /usr/lib/sysusers.d/opennet.conf
install -Dm644 "$REPO_DIR/opennet.tmpfiles" /usr/lib/tmpfiles.d/opennet.conf

# Config: keep an existing one, otherwise write the built-in defaults.
mkdir -p /etc/opennet
if [ ! -f /etc/opennet/config.toml ]; then
    "$PREFIX/bin/opennetd" --print-default-config > /etc/opennet/config.toml
    chmod 644 /etc/opennet/config.toml
    echo "installed default config at /etc/opennet/config.toml"
fi

# State: identity key, state file, reputation table, consent and the
# swarm artifacts directory; the daemon recreates anything missing, but
# fixing ownership here avoids first-run surprises.
mkdir -p /var/lib/opennet /var/lib/opennet/swarm /run/opennet
chown -R opennet:opennet /var/lib/opennet /run/opennet

# Detect the running init system and install the matching service file.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    install -Dm644 "$REPO_DIR/init/opennetd.service" /etc/systemd/system/opennetd.service
    systemd-sysusers 2>/dev/null || true
    systemd-tmpfiles --create 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable --now opennetd
    echo "opennetd enabled and started via systemd"
elif command -v dinitctl >/dev/null 2>&1; then
    install -Dm644 "$REPO_DIR/init/opennetd.dinit" /etc/dinit.d/opennetd
    dinitctl enable opennetd 2>/dev/null || true
    dinitctl start opennetd
    echo "opennetd enabled and started via dinit"
elif command -v rc-update >/dev/null 2>&1; then
    install -Dm755 "$REPO_DIR/init/opennetd.openrc" /etc/init.d/opennetd
    rc-update add opennetd default
    rc-service opennetd start
    echo "opennetd enabled and started via OpenRC"
elif command -v sv >/dev/null 2>&1; then
    mkdir -p /etc/sv/opennetd
    install -Dm755 "$REPO_DIR/init/opennetd.run" /etc/sv/opennetd/run
    ln -sfn /etc/sv/opennetd /var/service/opennetd
    echo "opennetd linked into runit"
else
    echo "warning: no supported init system detected;" \
         "start the daemon manually with: $PREFIX/bin/opennetd"
fi

echo
echo "opennetd is running. Useful commands:"
echo "  opennetctl status     - node overview"
echo "  opennetctl peers      - known peers"
echo "  opennetctl compute - 'uname -a'   - try the compute market"
echo
echo "Swarm mode is off by default. To host one shared program"
echo "(for example a sharded LLM) on the LAN:"
echo "  1. place <program>.manifest.json and the artifact into /var/lib/opennet/swarm"
echo "  2. opennetctl swarm enable <program>     (grants consent)"
echo "  3. opennetctl swarm run <program> <prompt-file>   (from any node)"
