#!/usr/bin/env bash
# Reference shard runner for the OpenNet swarm pipeline: implements the
# full runner frame contract against a demo "model" so a plan can be
# validated end to end without any inference dependencies, and serves
# as a template for real model runners (llama.cpp, vLLM — see
# docs/inference.md).
#
# Contract (see README / docs/inference.md): the worker connects this
# process's stdin/stdout to the daemon's runner bridge and exports
# PLAN_ID, SHARD_INDEX, LAYER_FROM, LAYER_TO, ARTIFACT, PORT,
# NEXT_ADDR, COORD_ADDR and RAM_MB. Frames are [u32 len][u8 tag][payload]:
#   inbound  tag 0 = pipeline input; outbound tag 1 = forward to next
#   shard (empty NEXT_ADDR = terminal shard, must not forward),
#   tag 2 = output to the coordinator, tag 3 = ready, 4 = done.
# This runner "computes" sha256 over the artifact slice for the shard's
# layer range plus the input, which makes tampering with the payload
# visible in the plan output.

set -euo pipefail

: "${PLAN_ID:?PLAN_INDEX env missing}"
: "${SHARD_INDEX:?SHARD_INDEX env missing}"
: "${LAYER_FROM:?LAYER_FROM env missing}"
: "${LAYER_TO:?LAYER_TO env missing}"
: "${ARTIFACT:?ARTIFACT env missing}"
: "${PORT:?PORT env missing}"
: "${NEXT_ADDR:?NEXT_ADDR env missing}"
: "${COORD_ADDR:?COORD_ADDR env missing}"
: "${RAM_MB:?RAM_MB env missing}"

# Read one length-prefixed frame from stdin: 4-byte little-endian length
# followed by exactly that many bytes. Returns payload via stdout-safe
# temp file (binary-safe for activations).
read_frame() {
    local len
    len=$(head -c 4 | od -An -tu4 | tr -d ' ')
    [ -n "$len" ] || return 1
    head -c "$len"
}

# Send one frame: length, tag byte, payload.
send_frame() {
    local tag="$1"
    local payload="$2"
    local len=$(( ${#payload} + 1 ))
    printf '%04x' "$len" | xxd -r -p
    printf '%02x' "$tag" | xxd -r -p
    printf '%s' "$payload"
}

ready()  { send_frame 3 ""; }
done_()  { send_frame 4 ""; }
output() { send_frame 2 "$1"; }
forward() { send_frame 1 "$1"; }

ready

while input=$(read_frame); do
    # The demo computation: commit to the shard's layer slice of the
    # artifact and the pipeline input. A real runner replaces this with
    # its tensor pipeline; the frame handling stays identical.
    digest=$(printf '%s:%s:%s-%s:%s' "$ARTIFACT" "$SHARD_INDEX" "$LAYER_FROM" "$LAYER_TO" "$input" \
        | sha256sum | cut -d' ' -f1)
    if [ -n "$NEXT_ADDR" ]; then
        forward "$digest"
    else
        output "$digest"
        done_
        exit 0
    fi
done
