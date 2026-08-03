FROM rust:1.88-bookworm AS builder

ARG BUILD_PROFILE=debug

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

RUN if [ "${BUILD_PROFILE}" = "release" ]; then \
      cargo build --release -p enclava-init --features prod-strict --bin enclava-init && \
      cargo build --release -p enclava-init --features prod-strict --bin enclava-log-relay && \
      cargo build --release -p enclava-wait-exec --target x86_64-unknown-linux-musl && \
      mkdir -p /out && \
      cp target/release/enclava-init /out/enclava-init && \
      cp target/release/enclava-log-relay /out/enclava-log-relay && \
      cp target/x86_64-unknown-linux-musl/release/enclava-wait-exec /out/enclava-wait-exec; \
    elif [ "${BUILD_PROFILE}" = "debug" ]; then \
      cargo build -p enclava-init --bin enclava-init && \
      cargo build -p enclava-init --bin enclava-log-relay && \
      cargo build -p enclava-wait-exec --target x86_64-unknown-linux-musl && \
      mkdir -p /out && \
      cp target/debug/enclava-init /out/enclava-init && \
      cp target/debug/enclava-log-relay /out/enclava-log-relay && \
      cp target/x86_64-unknown-linux-musl/debug/enclava-wait-exec /out/enclava-wait-exec; \
    else \
      echo "unsupported BUILD_PROFILE=${BUILD_PROFILE}; expected debug or release" >&2; \
      exit 1; \
    fi

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      cryptsetup-bin \
      e2fsprogs \
      libcryptsetup12 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/enclava-init /usr/local/bin/enclava-init
COPY --from=builder /out/enclava-log-relay /usr/local/bin/enclava-log-relay
COPY --from=builder /out/enclava-wait-exec /usr/local/bin/enclava-wait-exec

ENTRYPOINT ["/usr/local/bin/enclava-init"]
