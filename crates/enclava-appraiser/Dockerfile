# syntax=docker/dockerfile:1.7
FROM rust:1.88-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY vendor/ vendor/
COPY crates/ crates/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --locked --release --bin enclava-appraiser && \
    cp target/release/enclava-appraiser /usr/local/bin/enclava-appraiser

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN addgroup -g 1000 enclava && adduser -D -u 1000 -G enclava enclava
COPY --from=builder /usr/local/bin/enclava-appraiser /usr/local/bin/enclava-appraiser
USER enclava
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=3s --retries=3 \
    CMD wget -q -O- http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/enclava-appraiser"]
