# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS debug-builder

ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd
ENV ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX}

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --bin enclava-api --bin cap-clean-cut-retire --bin cap-migrate && \
    cp /build/target/debug/enclava-api /usr/local/bin/enclava-api && \
    cp /build/target/debug/cap-clean-cut-retire /usr/local/bin/cap-clean-cut-retire && \
    cp /build/target/debug/cap-migrate /usr/local/bin/cap-migrate

FROM debian:bookworm-slim AS runtime-debug

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates tzdata wget libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1000 enclava && \
    useradd -u 1000 -g enclava -M -s /usr/sbin/nologin enclava

COPY --from=debug-builder /usr/local/bin/enclava-api /usr/local/bin/enclava-api
COPY --from=debug-builder /usr/local/bin/cap-clean-cut-retire /usr/local/bin/cap-clean-cut-retire
COPY --from=debug-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate
RUN chown enclava:enclava \
    /usr/local/bin/enclava-api \
    /usr/local/bin/cap-clean-cut-retire \
    /usr/local/bin/cap-migrate

USER enclava
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://localhost:3000/health || exit 1

ENV DATABASE_URL="postgresql://host:5432/db" \
    API_URL="http://localhost:3000" \
    PLATFORM_DOMAIN="enclava.dev"

ENTRYPOINT ["/usr/local/bin/enclava-api"]

FROM rust:1.88-alpine AS release-builder

ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd
ENV ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX}

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin enclava-api --bin cap-clean-cut-retire --bin cap-migrate && \
    cp /build/target/release/enclava-api /usr/local/bin/enclava-api && \
    cp /build/target/release/cap-clean-cut-retire /usr/local/bin/cap-clean-cut-retire && \
    cp /build/target/release/cap-migrate /usr/local/bin/cap-migrate && \
    strip \
        /usr/local/bin/enclava-api \
        /usr/local/bin/cap-clean-cut-retire \
        /usr/local/bin/cap-migrate

FROM alpine:3.20 AS runtime-release

RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -g 1000 enclava && \
    adduser -D -u 1000 -G enclava enclava

COPY --from=release-builder /usr/local/bin/enclava-api /usr/local/bin/enclava-api
COPY --from=release-builder /usr/local/bin/cap-clean-cut-retire /usr/local/bin/cap-clean-cut-retire
COPY --from=release-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate
RUN chown enclava:enclava \
    /usr/local/bin/enclava-api \
    /usr/local/bin/cap-clean-cut-retire \
    /usr/local/bin/cap-migrate

USER enclava
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://localhost:3000/health || exit 1

ENV DATABASE_URL="postgresql://host:5432/db" \
    API_URL="http://localhost:3000" \
    PLATFORM_DOMAIN="enclava.dev"

ENTRYPOINT ["/usr/local/bin/enclava-api"]
