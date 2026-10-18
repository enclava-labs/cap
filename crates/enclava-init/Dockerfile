FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder

ARG BUILD_PROFILE=release

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
COPY vendor ./vendor
COPY crates ./crates

RUN if [ "${BUILD_PROFILE}" = "release" ]; then \
      cargo build --locked --release -p enclava-init --features prod-strict --bin enclava-init && \
      cargo build --locked --release -p enclava-init --features prod-strict --bin enclava-log-relay && \
      cargo build --locked --release -p enclava-wait-exec --features prod-strict --target x86_64-unknown-linux-musl && \
      mkdir -p /out && \
      cp target/release/enclava-init /out/enclava-init && \
      cp target/release/enclava-log-relay /out/enclava-log-relay && \
      cp target/x86_64-unknown-linux-musl/release/enclava-wait-exec /out/enclava-wait-exec; \
    elif [ "${BUILD_PROFILE}" = "debug" ]; then \
      cargo build --locked -p enclava-init --bin enclava-init && \
      cargo build --locked -p enclava-init --bin enclava-log-relay && \
      cargo build --locked -p enclava-wait-exec --target x86_64-unknown-linux-musl && \
      mkdir -p /out && \
      cp target/debug/enclava-init /out/enclava-init && \
      cp target/debug/enclava-log-relay /out/enclava-log-relay && \
      cp target/x86_64-unknown-linux-musl/debug/enclava-wait-exec /out/enclava-wait-exec; \
    else \
      echo "unsupported BUILD_PROFILE=${BUILD_PROFILE}; expected debug or release" >&2; \
      exit 1; \
    fi

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

# cap#242: cryptsetup >= 2.8.1 floor (null keyslot ciphers rejected for
# nonempty passwords). Debian bookworm ships 2.6.x and the trixie/sid debs
# require glibc >= 2.38 (bookworm has 2.36), so build 2.8.8 from upstream
# source, downloaded at build time and verified against the pinned sha256
# (same pattern as the FRP tarball in the debian-ssh-frp template, #241).
# The binary links against the freshly-built libcryptsetup.so.12 plus
# bookworm runtime libs that are already present (libargon2, libblkid,
# libdevmapper, libjson-c, libpopt, libssl3, libuuid1), so only the two
# build artifacts are installed.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      libargon2-dev \
      libblkid-dev \
      libc6-dev \
      libdevmapper-dev \
      libjson-c-dev \
      libpopt-dev \
      libssl-dev \
      libuuid1 \
      pkg-config; \
    curl -fsSL -o /tmp/cryptsetup-2.8.8.tar.xz \
      https://www.kernel.org/pub/linux/utils/cryptsetup/v2.8/cryptsetup-2.8.8.tar.xz; \
    echo "3acfa685f2dd7fcc832e0b77bc7093aa7da554a51ce8dafbb4138eaa854eee35  /tmp/cryptsetup-2.8.8.tar.xz" | sha256sum -c -; \
    cd /tmp; \
    tar -xf cryptsetup-2.8.8.tar.xz; \
    cd cryptsetup-2.8.8; \
    ./configure \
      --disable-static \
      --disable-nls \
      --disable-asciidoc \
      --disable-ssh-token \
      --disable-veritysetup \
      --disable-integritysetup \
      --disable-kernel_crypto \
      --enable-static-cryptsetup; \
    make -j"$(nproc)" cryptsetup; \
    install -m 0755 .libs/cryptsetup /usr/local/sbin/cryptsetup; \
    install -m 0755 .libs/libcryptsetup.so.12* /usr/local/lib/; \
    ldconfig; \
    /usr/local/sbin/cryptsetup --version; \
    cd /; \
    rm -rf /tmp/cryptsetup-2.8.8 /tmp/cryptsetup-2.8.8.tar.xz; \
    apt-get purge -y build-essential libargon2-dev libblkid-dev libc6-dev libdevmapper-dev libjson-c-dev libpopt-dev libssl-dev pkg-config curl; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      libargon2-1 \
      libblkid1 \
      libdevmapper1.02.1 \
      libjson-c5 \
      libpopt0 \
      libssl3 \
      libuuid1; \
    rm -rf /var/lib/apt/lists/*; \
    ldd /usr/local/sbin/cryptsetup | tee /dev/stderr | grep -q "not found" && exit 1 || true; \
    /usr/local/sbin/cryptsetup --version

# cryptsetup 2.8.8 supersedes bookworm's cryptsetup-bin (2.6.x); only the
# runtime library of the distro package is still needed (enclava-init links
# libcryptsetup.so.12 — the 2.8.8 build above satisfies it via ldconfig).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      e2fsprogs && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/enclava-init /usr/local/bin/enclava-init
COPY --from=builder /out/enclava-log-relay /usr/local/bin/enclava-log-relay
COPY --from=builder /out/enclava-wait-exec /usr/local/bin/enclava-wait-exec

# cap#244 review: prove every NEEDED library of the runtime binaries is
# present in the final image; the build fails here rather than the guest
# failing at boot with a missing .so. enclava-wait-exec is statically linked
# (musl), where ldd exits nonzero with "not a dynamic executable" — that is
# a pass, not a failure.
RUN set -eux; \
    for bin in /usr/local/bin/enclava-init \
               /usr/local/bin/enclava-log-relay \
               /usr/local/bin/enclava-wait-exec; do \
        if ldd "$bin" 2>&1 | tee /dev/stderr | grep -q "not a dynamic executable"; then \
            continue; \
        fi; \
        if ldd "$bin" 2>&1 | grep -q "not found"; then \
            echo "missing NEEDED library for $bin" >&2; \
            exit 1; \
        fi; \
    done

ENTRYPOINT ["/usr/local/bin/enclava-init"]
