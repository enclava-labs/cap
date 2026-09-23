# Cross-compilation builder for CLI releases
FROM rust:1.88-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS builder

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

# The shell gate only compares pubkeys; verify the full envelope signature
# and payload invariants before the CLI binary is compiled.
RUN cargo run --locked --release -p enclava-cli --example platform-release -- verify \
    crates/enclava-cli/platform-release.json "$ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX"

# Build for musl (static binary); prod-strict makes an invalid, missing, or
# fixture root a compile error instead of a runtime one.
RUN cargo build --locked --release --bin enclava --features prod-strict && \
    strip /build/target/release/enclava

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

COPY --from=builder /build/target/release/enclava /usr/local/bin/enclava

ENTRYPOINT ["/usr/local/bin/enclava"]
