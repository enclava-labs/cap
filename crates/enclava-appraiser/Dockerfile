# syntax=docker/dockerfile:1.7
FROM rust:1.88-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --bin enclava-appraiser && \
    cp target/release/enclava-appraiser /usr/local/bin/enclava-appraiser

FROM alpine:3.20
RUN addgroup -g 1000 enclava && adduser -D -u 1000 -G enclava enclava
COPY --from=builder /usr/local/bin/enclava-appraiser /usr/local/bin/enclava-appraiser
USER enclava
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=3s --retries=3 \
    CMD wget -q -O- http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/enclava-appraiser"]
