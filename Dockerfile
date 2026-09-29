# ULPF — air-gapped syslog pre-processing + Merkle integrity fabric.
#
# Portable multi-arch image (linux/amd64, linux/arm64). Build with:
#   docker buildx build --platform linux/amd64,linux/arm64 -t ulpf:0.1.0 .
# Or for the local machine only:
#   docker compose up --build -d
#
# RELEASE BINARY: 15.9 MB measured (15,889,672 B). Under the 35 MB target.
#
# IMAGE: NOT measured, and NOT under 35 MB. Be precise about these two
# numbers -- they are unrelated and conflating them is how the 18.6 MB claim
# went stale. The budget for this Dockerfile as written is roughly:
#
#   debian:bookworm-slim base   ~74 MB   <- the whole problem
#   ulpf                       15.9 MB
#   ulpf-generator              1.2 MB
#   ca-certificates            ~0.4 MB
#   simulate_tamper.py          <0.1 MB
#                              --------
#                               ~92 MB
#
# Removing python3 and procps above saves roughly 20-25 MB of that, which is
# real but does not change the verdict: the base image alone is more than
# double the 35 MB target. Reaching the target requires a fully static musl
# build on distroless/static (or scratch) and dropping ulpf-generator from the
# runtime image -- a different build pipeline, not a trim of this one.
# Tracked in #45. Do not mark requirement k `yes` without measuring it.
#
# The python3/procps removal below is still worth doing on its own merits: it
# is dead weight in a runtime image, and a leaner image is easier to audit.

ARG RUST_VERSION=1.96

# ---------- Stage 1: build ----------
FROM rust:${RUST_VERSION}-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependency layer first for better caching.
COPY rust-toolchain.toml Cargo.toml Cargo.lock* ./
COPY crates ./crates

RUN cargo build --release -p ulpf-cli -p ulpf-generator \
    && strip target/release/ulpf target/release/ulpf-generator || true

# ---------- Stage 2: runtime ----------
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="ULPF" \
      org.opencontainers.image.description="Universal Log Pre-processing Framework: OCSF 1.3 normalization + RFC 6962 Merkle integrity" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /opt/ulpf

# ca-certificates only, for a TLS-ready base.
#
# python3 and procps are both removed as size measures:
#   * python3 shipped only so scripts/simulate_tamper.py could run inside the
#     container. That is a dev-time drill script, not runtime, and the demo
#     runs it from a checkout. python3 alone pulled in roughly 20 MB.
#   * procps existed only to provide `pidof` for the HEALTHCHECK. The check is
#     now a /proc scan, so the package is not needed at all.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin ulpf
# NOTE: UID 1000 matches the typical host user, so bind-mounted ./data
# stays writable. On Linux with a different UID, run:
#   chown -R $(id -u):$(id -g) data/

COPY --from=builder /app/target/release/ulpf /app/target/release/ulpf-generator /usr/local/bin/

# Only what the runtime or the documented tamper drill needs. `docs/` (~1.4 MB)
# is not copied: it is unused at runtime. `data/` is not copied either — it
# arrives via the bind mount in docker-compose.yml, so the tracked fixture
# blocks are not baked into the image.
COPY scripts/simulate_tamper.py ./scripts/simulate_tamper.py

RUN mkdir -p /opt/ulpf/data/parquet /opt/ulpf/data/parsers \
    && chown -R ulpf:ulpf /opt/ulpf

USER ulpf

# Syslog ingestion ports (unprivileged, safe for non-root).
EXPOSE 5140/udp 5140/tcp

ENV RUST_LOG=info

# `pidof` came from procps, which is no longer installed. /proc is always
# present, so scan it directly — no extra package, same signal.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD for p in /proc/[0-9]*; do \
            grep -qa '^Name:.*ulpf$' "$p/status" 2>/dev/null && exit 0; \
        done; exit 1

ENTRYPOINT ["ulpf"]
CMD ["ingest", "--udp", "0.0.0.0:5140", "--tcp", "0.0.0.0:5140", \
     "--parquet-dir", "/opt/ulpf/data/parquet", "--ledger", "/opt/ulpf/data/ledger.jsonl", \
     "--batch-size", "1000", "--batch-timeout", "2000"]
