# syntax=docker/dockerfile:1.7

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS cargo-chef
ARG TARGETARCH
RUN apk add --no-cache ca-certificates curl xz
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl; checksum=aca691abfbfbbe00d482e0ed2249eec3091b65e96a0ce92947fb5b254d48b16d ;; \
      arm64) target=aarch64-unknown-linux-musl; checksum=cd59b90fce5fa84c4189648fec33404ec5491791eebdb812df5e7fca8336408d ;; \
      *) echo "unsupported cargo-chef architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.78/cargo-chef-${target}.tar.xz" \
      -o /tmp/cargo-chef.tar.xz; \
    echo "$checksum  /tmp/cargo-chef.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/cargo-chef.tar.xz -C /usr/local/bin --strip-components=1 "cargo-chef-${target}/cargo-chef"; \
    rm /tmp/cargo-chef.tar.xz

FROM rust:1.88-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS planner
COPY --from=cargo-chef /usr/local/bin/cargo-chef /usr/local/bin/cargo-chef
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY vendor/ vendor/
COPY crates/ crates/
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS debug-dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev jq && \
    rm -rf /var/lib/apt/lists/*
COPY --from=cargo-chef /usr/local/bin/cargo-chef /usr/local/bin/cargo-chef
WORKDIR /build
COPY --from=planner /build/recipe.json recipe.json
COPY vendor/ vendor/
# GHA exports layers, not cache mounts: keep compiled dependencies and Cargo sources in the layer.
RUN cargo chef cook --locked --bin enclava-api --bin cap-migrate

FROM debug-dependencies AS debug-builder
ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX
ENV ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX}
RUN test -n "$ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX" || (echo "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg" >&2; exit 1)

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY scripts/require-platform-release-root.sh scripts/require-platform-release-root.sh

# Debug images may pin the dev fixture root only while the bundled envelope
# is fixture-signed; the root must still match that envelope.
RUN bash scripts/require-platform-release-root.sh --allow-dev-fixture
RUN printf "%s  crates/enclava-api/trust-roots/sigstore-public-good-1.root.json\n" \
      6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66 \
      | sha256sum -c >/dev/null

RUN cargo build --locked --bin enclava-api --bin cap-migrate && \
    cp /build/target/debug/enclava-api /usr/local/bin/enclava-api && \
    cp /build/target/debug/cap-migrate /usr/local/bin/cap-migrate

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime-debug

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates tzdata wget libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1000 enclava && \
    useradd -u 1000 -g enclava -M -s /usr/sbin/nologin enclava

COPY --from=debug-builder /usr/local/bin/enclava-api /usr/local/bin/enclava-api
COPY --from=debug-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate
RUN chown enclava:enclava /usr/local/bin/enclava-api /usr/local/bin/cap-migrate

USER enclava
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://localhost:3000/livez || exit 1

ENV DATABASE_URL="postgresql://host:5432/db" \
    API_URL="http://localhost:3000" \
    PLATFORM_DOMAIN="enclava.dev"

ENTRYPOINT ["/usr/local/bin/enclava-api"]

FROM rust:1.88-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS release-dependencies

# perl+make: the envelope verify step compiles enclava-cli, whose vendored
# openssl build needs them.
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf bash jq perl make
COPY --from=cargo-chef /usr/local/bin/cargo-chef /usr/local/bin/cargo-chef
WORKDIR /build
COPY --from=planner /build/recipe.json recipe.json
COPY vendor/ vendor/
# The CLI example and API resolve different dependency features; cache both graphs separately.
RUN cargo chef cook --locked --release -p enclava-cli --examples && \
    cargo chef cook --locked --release --bin enclava-api --bin cap-migrate --features prod-strict

FROM release-dependencies AS release-builder
ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX
ENV ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX}
RUN test -n "$ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX" || (echo "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg" >&2; exit 1)

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY scripts/require-platform-release-root.sh scripts/require-platform-release-root.sh

# Released images must pin a production root that matches the bundled
# envelope; the fixture root is rejected unconditionally here.
RUN bash scripts/require-platform-release-root.sh
RUN printf "%s  crates/enclava-api/trust-roots/sigstore-public-good-1.root.json\n" \
      6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66 \
      | sha256sum -c >/dev/null

# The bundled signed envelope is only a downgrade floor. Pre-trustee bytes
# remain valid for this floor, never for the mounted runtime release.
RUN cargo run --locked --release -p enclava-cli --example platform-release -- verify-baseline \
    crates/enclava-cli/platform-release.json "$ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX"

RUN cargo build --locked --release --bin enclava-api --bin cap-migrate --features prod-strict && \
    cp /build/target/release/enclava-api /usr/local/bin/enclava-api && \
    cp /build/target/release/cap-migrate /usr/local/bin/cap-migrate && \
    strip /usr/local/bin/enclava-api /usr/local/bin/cap-migrate

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS runtime-release

RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -g 1000 enclava && \
    adduser -D -u 1000 -G enclava enclava

# The pinned sigstore public-good trust root (TUF-verified target, see
# scripts/verify-sigstore-trust-root.sh). The release API refuses to verify
# cosign signatures without it: cosign.rs only honors a file-backed
# SIGSTORE_TUF_ROOT_PATH in release builds and never bootstraps trust from
# the network at runtime.
COPY --from=release-builder /usr/local/bin/enclava-api /usr/local/bin/enclava-api
COPY --from=release-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate
COPY crates/enclava-api/trust-roots/sigstore-public-good-1.root.json /etc/enclava/sigstore/trusted_root.json
ENV SIGSTORE_TUF_ROOT_PATH=/etc/enclava/sigstore/trusted_root.json
RUN chown enclava:enclava /usr/local/bin/enclava-api /usr/local/bin/cap-migrate

USER enclava
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://localhost:3000/livez || exit 1

ENV DATABASE_URL="postgresql://host:5432/db" \
    API_URL="http://localhost:3000" \
    PLATFORM_DOMAIN="enclava.dev"

ENTRYPOINT ["/usr/local/bin/enclava-api"]
