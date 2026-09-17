# Cross-compilation builder for CLI releases
FROM rust:1.88-alpine AS builder

ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX
ENV ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX}
RUN test -n "$ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX" || (echo "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg" >&2; exit 1)

RUN apk add --no-cache musl-dev git perl make bash jq

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY vendor/ vendor/
COPY crates/ crates/
COPY scripts/require-platform-release-root.sh scripts/require-platform-release-root.sh

# Released CLI images must pin a production root that matches the bundled
# envelope; the fixture root is rejected unconditionally here.
RUN bash scripts/require-platform-release-root.sh

# Build for musl (static binary); prod-strict makes an invalid, missing, or
# fixture root a compile error instead of a runtime one.
RUN cargo build --locked --release --bin enclava --features prod-strict && \
    strip /build/target/release/enclava

FROM alpine:3.20

COPY --from=builder /build/target/release/enclava /usr/local/bin/enclava

ENTRYPOINT ["/usr/local/bin/enclava"]
