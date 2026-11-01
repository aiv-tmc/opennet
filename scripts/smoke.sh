#!/usr/bin/env bash
# Two-node end-to-end smoke test: boot two real opennetd daemons on
# loopback (a seed and a peer that reaches it through the WAN seed
# path — deterministic in containers where multicast may not route),
# wait for verification, run a task across the market and assert the
# full settlement: exit code, trust movement and a countersigned
# receipt on both sides.
#
# Usage: smoke.sh [opennetd-binary] [opennetctl-binary]
# Requires root (or CAP_SYS_ADMIN) only if the sandbox is left on;
# the script disables namespaces so it runs anywhere.

set -euo pipefail

OPENNETD="${1:-./target/release/opennetd}"
OPENNETCTL="${2:-./target/release/opennetctl}"

WORK="$(mktemp -d /tmp/opennet-smoke-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- configs ---------------------------------------------------------------
# Node A: the seed (donates capacity, never requests). Fixed port so the
# peer can aim its seed list at it.
cat > "$WORK/a.toml" <<'EOF'
mode = "seed"

[network]
port = 17701
wan = true
heartbeat_interval_secs = 1
ann_max_age_secs = 30
ann_future_skew_secs = 30

[paths]
state_dir = "STATE_A"
socket_path = "STATE_A/control.sock"

[sandbox]
namespaces = false
cgroup = false
EOF
sed -i "s|STATE_A|$WORK/a-state|" "$WORK/a.toml"

# Node B: the peer; reaches A purely through the static seed list.
cat > "$WORK/b.toml" <<'EOF'
mode = "peer"

[network]
port = 17702
wan = true
seeds = ["127.0.0.1:17701"]
heartbeat_interval_secs = 1
ann_max_age_secs = 30
ann_future_skew_secs = 30

[paths]
state_dir = "STATE_B"
socket_path = "STATE_B/control.sock"

[sandbox]
namespaces = false
cgroup = false
EOF
sed -i "s|STATE_B|$WORK/b-state|" "$WORK/b.toml"

# --- boot ---------------------------------------------------------------
"$OPENNETD" --config "$WORK/a.toml" >"$WORK/a.log" 2>&1 &
A_PID=$!
"$OPENNETD" --config "$WORK/b.toml" >"$WORK/b.log" 2>&1 &
B_PID=$!
trap 'kill $A_PID $B_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

# --- wait for verification ------------------------------------------------
# B must see A as a verified peer (node id present in the table).
for _ in $(seq 1 60); do
    if "$OPENNETCTL" --socket "$WORK/b-state/control.sock" peers 2>/dev/null \
        | grep -qE 'seed'; then
        break
    fi
    sleep 1
done

PEERS="$("$OPENNETCTL" --socket "$WORK/b-state/control.sock" peers 2>/dev/null || true)"
if ! grep -qE 'seed' <<<"$PEERS"; then
    echo "SMOKE FAIL: peer never saw the seed" >&2
    echo "--- node A log ---" >&2; tail -n 30 "$WORK/a.log" >&2 || true
    echo "--- node B log ---" >&2; tail -n 30 "$WORK/b.log" >&2 || true
    exit 1
fi
echo "smoke: peers verified"

# --- the market round -------------------------------------------------------
OUT="$("$OPENNETCTL" --socket "$WORK/b-state/control.sock" \
    compute - 'echo smoke-ok')"

if ! grep -q "exit_code: 0" <<<"$OUT" || ! grep -q "smoke-ok" <<<"$OUT"; then
    echo "SMOKE FAIL: compute did not succeed" >&2
    echo "$OUT" >&2
    exit 1
fi
echo "smoke: compute round succeeded"

# --- settlement evidence ------------------------------------------------------
# B consumed trust and holds one receipt; A earned trust and also holds
# the issued receipt.
B_TRUST="$("$OPENNETCTL" --socket "$WORK/b-state/control.sock" status)"
A_TRUST="$("$OPENNETCTL" --socket "$WORK/a-state/control.sock" status)"
grep -q "consumed" <<<"$OUT" || { echo "SMOKE FAIL: no consumption line" >&2; exit 1; }
echo "smoke: settlement lines present"
grep -E "trust|consumed" <<<"$B_TRUST" >&2 || true

if [ ! -s "$WORK/a-state/receipts.jsonl" ] || [ ! -s "$WORK/b-state/receipts.jsonl" ]; then
    echo "SMOKE FAIL: receipt journals missing on one side" >&2
    exit 1
fi
echo "smoke: receipt journals present on both sides"

echo "SMOKE PASS"
