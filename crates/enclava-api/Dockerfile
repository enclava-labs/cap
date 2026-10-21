# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS cargo-chef
ARG TARGETARCH
COPY scripts/install-cargo-chef.sh /usr/local/bin/install-cargo-chef.sh
RUN sh /usr/local/bin/install-cargo-chef.sh "$TARGETARCH" && cargo-chef --version

FROM cargo-chef AS planner
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY vendor/ vendor/
COPY crates/ crates/
RUN cargo chef prepare --recipe-path recipe.json

FROM cargo-chef AS debug-dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev jq && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY --from=planner /build/recipe.json recipe.json
COPY vendor/ vendor/
# GHA exports layers, not cache mounts: keep compiled dependencies and Cargo sources in the layer.
RUN cargo chef cook --locked --bin enclava-api --bin cap-migrate

FROM debug-dependencies AS debug-builder
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN printf "%s  crates/enclava-api/trust-roots/sigstore-public-good-1.root.json\n" \
      6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66 \
      | sha256sum -c >/dev/null

RUN cargo build --locked --bin enclava-api --bin cap-migrate && \
    cp /build/target/debug/enclava-api /usr/local/bin/enclava-api && \
    cp /build/target/debug/cap-migrate /usr/local/bin/cap-migrate

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime-debug

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

FROM rust:1.88-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS cargo-chef-musl
ARG TARGETARCH
RUN apk add --no-cache musl-dev curl xz
COPY scripts/install-cargo-chef.sh /usr/local/bin/install-cargo-chef.sh
RUN sh /usr/local/bin/install-cargo-chef.sh "$TARGETARCH" && cargo-chef --version

FROM cargo-chef-musl AS release-dependencies

# perl+make: the envelope verify step compiles enclava-cli, whose vendored
# openssl build needs them.
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf bash jq perl make
WORKDIR /build
COPY --from=planner /build/recipe.json recipe.json
COPY vendor/ vendor/
# The CLI example and API resolve different dependency features; cache both graphs separately.
RUN cargo chef cook --locked --release -p enclava-cli --examples && \
    cargo chef cook --locked --release --bin enclava-api --bin cap-migrate --features prod-strict

FROM release-dependencies AS release-builder
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN printf "%s  crates/enclava-api/trust-roots/sigstore-public-good-1.root.json\n" \
      6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66 \
      | sha256sum -c >/dev/null

RUN cargo run --locked --release -p enclava-cli --example platform-release -- verify-profiles \
    crates/enclava-common/platform-release-profiles.json

RUN cargo build --locked --release --bin enclava-api --bin cap-migrate --features prod-strict && \
    cp /build/target/release/enclava-api /usr/local/bin/enclava-api && \
    cp /build/target/release/cap-migrate /usr/local/bin/cap-migrate && \
    strip /usr/local/bin/enclava-api /usr/local/bin/cap-migrate

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS runtime-release

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
