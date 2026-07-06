# syntax=docker/dockerfile:1.7

# Build stage
FROM rust:1.88-alpine AS builder

ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd
ARG BUILD_PROFILE=debug
ENV ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX}

# Install musl build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

# Set up working directory
WORKDIR /build

# Copy Cargo manifests and workspace crates
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build static binary. Main-branch images use debug profile for fast deploy
# feedback; tagged releases pass BUILD_PROFILE=release.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    if [ "${BUILD_PROFILE}" = "release" ]; then \
      cargo build --release --bin enclava-api && \
      cp /build/target/release/enclava-api /usr/local/bin/enclava-api && \
      strip /usr/local/bin/enclava-api; \
    elif [ "${BUILD_PROFILE}" = "debug" ]; then \
      cargo build --bin enclava-api && \
      cp /build/target/debug/enclava-api /usr/local/bin/enclava-api; \
    else \
      echo "unsupported BUILD_PROFILE=${BUILD_PROFILE}; expected debug or release" >&2; \
      exit 1; \
    fi

# Runtime stage
FROM alpine:3.20

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates tzdata wget

# Create non-root user
RUN addgroup -g 1000 enclava && \
    adduser -D -u 1000 -G enclava enclava

# Copy binary from builder
COPY --from=builder /usr/local/bin/enclava-api /usr/local/bin/enclava-api

# Set permissions
RUN chown enclava:enclava /usr/local/bin/enclava-api

# Switch to non-root user
USER enclava

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://localhost:3000/health || exit 1

# Set default environment (override in deployment)
ENV DATABASE_URL="postgresql://host:5432/db" \
    API_URL="http://localhost:3000" \
    PLATFORM_DOMAIN="enclava.dev"

ENTRYPOINT ["/usr/local/bin/enclava-api"]
