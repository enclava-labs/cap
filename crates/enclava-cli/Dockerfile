# Cross-compilation builder for CLI releases
FROM rust:1.88-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS builder

RUN apk add --no-cache musl-dev git perl make bash jq

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY vendor/ vendor/
COPY crates/ crates/
RUN cargo run --locked --release -p enclava-cli --example platform-release -- verify-profiles \
    crates/enclava-common/platform-release-profiles.json

RUN cargo build --locked --release --bin enclava --features prod-strict && \
    strip /build/target/release/enclava

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

COPY --from=builder /build/target/release/enclava /usr/local/bin/enclava

ENTRYPOINT ["/usr/local/bin/enclava"]
