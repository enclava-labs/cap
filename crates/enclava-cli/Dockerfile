# Cross-compilation builder for CLI releases
FROM rust:1.88-alpine AS builder

ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd
ENV ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX}

RUN apk add --no-cache musl-dev git

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build for musl (static binary)
RUN cargo build --release --bin enclava && \
    strip /build/target/release/enclava

FROM alpine:3.20

COPY --from=builder /build/target/release/enclava /usr/local/bin/enclava

ENTRYPOINT ["/usr/local/bin/enclava"]
