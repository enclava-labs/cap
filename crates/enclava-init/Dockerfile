FROM rust:1.88-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      clang \
      libclang-dev \
      libcryptsetup-dev \
      musl-tools \
      pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p enclava-init --bin enclava-init && \
    cargo build --release -p enclava-init --bin enclava-log-relay && \
    cargo build --release -p enclava-wait-exec --target x86_64-unknown-linux-musl

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      cryptsetup-bin \
      e2fsprogs \
      libcryptsetup12 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/enclava-init /usr/local/bin/enclava-init
COPY --from=builder /app/target/release/enclava-log-relay /usr/local/bin/enclava-log-relay
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/enclava-wait-exec /usr/local/bin/enclava-wait-exec

ENTRYPOINT ["/usr/local/bin/enclava-init"]
