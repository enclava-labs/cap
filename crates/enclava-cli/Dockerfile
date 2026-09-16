# Cross-compilation builder for CLI releases
FROM rust:1.88-alpine AS builder

ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX
ENV ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX}
RUN test -n "$ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX" || (echo "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg" >&2; exit 1)

RUN apk add --no-cache musl-dev git perl make

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY vendor/ vendor/
COPY crates/ crates/

# Build for musl (static binary)
RUN cargo build --locked --release --bin enclava && \
    strip /build/target/release/enclava

FROM alpine:3.20

COPY --from=builder /build/target/release/enclava /usr/local/bin/enclava

ENTRYPOINT ["/usr/local/bin/enclava"]
