# OpenNet all-in-one image: builds the daemon and CLI from source in a
# toolchain stage, then ships a minimal runtime with an unprivileged
# user and a single state volume.
#
# Build:  docker build -t opennet .
# Run:    docker run -d --name opennet --privileged -p 9999:9999/udp \
#           -v opennet-state:/var/lib/opennet opennet
#
# --privileged (or the finer-grained caps below) is required for the
# execution sandbox: namespace creation needs CAP_SYS_ADMIN. Without
# it the daemon still runs, and `opennetctl status` reports the
# sandbox as degraded (cgroup limits only).

# ---------------------------------------------------------------------------
# Build stage: pinned toolchain, dependency layer cached separately from
# the application code so iterative rebuilds only recompile the crate.
# ---------------------------------------------------------------------------
FROM rust:1.77-bookworm AS builder
WORKDIR /src

# The lockfile is copied first: `cargo fetch` populates the registry
# cache in its own layer and only changes when dependencies change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo fetch --locked

# Application sources; the build is locked (--locked) so the image is
# reproducible from the committed lockfile.
COPY . .
RUN cargo build --release --locked && \
    strip target/release/opennetd && \
    strip target/release/opennetctl

# ---------------------------------------------------------------------------
# Runtime stage: debian slim, no toolchain, non-root user.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system opennet \
    && useradd --system --gid opennet \
        --home-dir /var/lib/opennet --create-home \
        --shell /usr/sbin/nologin opennet

COPY --from=builder /src/target/release/opennetd  /usr/local/bin/opennetd
COPY --from=builder /src/target/release/opennetctl /usr/local/bin/opennetctl

# State (identity key, state.json, receipts, swarm consent) persists in
# the named volume; the socket lives in an anonymous runtime dir and is
# reachable via `docker exec`.
VOLUME ["/var/lib/opennet"]

# 9999/udp   — LAN discovery multicast group (host networking preferred)
# 7000/tcp   — default fixed listen port inside the container; override
#              with OPENNET_CONFIG or --config for multi-node setups
EXPOSE 9999/udp 7000/tcp

USER opennet
ENTRYPOINT ["opennetd"]
