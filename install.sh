#!/bin/sh
# Installs OpenNet system-wide with zero configuration:
# builds the binaries, installs them, writes a default config only when
# none exists and hooks the daemon into the detected init system.
set -eu

PREFIX="${PREFIX:-/usr/local}"
REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

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

# Config: keep an existing one, otherwise write the built-in defaults.
mkdir -p /etc/opennet
if [ ! -f /etc/opennet/config.toml ]; then
    "$PREFIX/bin/opennetd" --print-default-config > /etc/opennet/config.toml
    echo "installed default config at /etc/opennet/config.toml"
fi

mkdir -p /var/lib/opennet

# Detect the running init system and install the matching service file.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    install -Dm644 "$REPO_DIR/init/opennetd.service" /etc/systemd/system/opennetd.service
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
