# syntax=docker/dockerfile:1.7

FROM rust:1.88-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS cargo-chef
ARG TARGETARCH
RUN apk add --no-cache musl-dev curl xz
COPY scripts/install-cargo-chef.sh /usr/local/bin/install-cargo-chef.sh
RUN sh /usr/local/bin/install-cargo-chef.sh "$TARGETARCH" && cargo-chef --version

FROM cargo-chef AS planner
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY vendor/ vendor/
COPY crates/ crates/
RUN cargo chef prepare --recipe-path recipe.json

# GHA exports layers, not cache mounts: compiled dependencies stay in this
# layer so source-only crate changes reuse them (same pattern as enclava-api).
FROM cargo-chef AS dependencies
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY --from=planner /build/recipe.json recipe.json
COPY vendor/ vendor/
RUN cargo chef cook --locked --release --bin enclava-appraiser

FROM dependencies AS builder
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# Binaries only in the layer diff: deleting target/ in the same RUN keeps
# the gha cache export off the per-commit compile tree.
RUN cargo build --locked --release --bin enclava-appraiser && \
    cp target/release/enclava-appraiser /usr/local/bin/enclava-appraiser && \
    rm -rf target

FROM alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4 AS runtime
RUN addgroup -g 1000 enclava && adduser -D -u 1000 -G enclava enclava
COPY --from=builder /usr/local/bin/enclava-appraiser /usr/local/bin/enclava-appraiser
USER enclava
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=3s --retries=3 \
    CMD wget -q -O- http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/enclava-appraiser"]
