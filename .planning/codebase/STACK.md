# Technology Stack

**Analysis Date:** 2026-06-28

## Languages

**Primary:**
- Rust (edition `2024`, MSRV `1.85`) — entire workspace; declared in `Cargo.toml` `[workspace.package]`.

**Secondary:**
- Python 3 — only used for contract/proof helper tests (`tests/test_cap_hermes_proof.py`, `tests/test_generate_platform_release.py`, `scripts/cap_hermes_proof*.py`). Not part of any runtime artifact.
- Shell (`bash`) — operator scripts under `scripts/` and the `manifest/bootstrap_script.sh` embedded in the engine.

## Runtime

**Environment:**
- Linux only. The `enclava-api` binary ships as a static-musl Alpine image (`crates/enclava-api/Dockerfile`) and serves HTTP on `0.0.0.0:3000` (configurable via `BIND_ADDR`).
- `enclava-init` is a Linux binary that links system `libcryptsetup` and uses `nix` for mount namespace / `user` / `fs` / `sched` syscalls. It is the in-TEE sidecar.
- `enclava-wait-exec` is a Linux-only workload wrapper that exec's the real container command after `/run/enclava/init-ready` appears.
- Workload runtime target: Kubernetes with the `kata-qemu-snp` (Kata Containers + AMD SEV-SNP) runtime class — see `crates/enclava-cli/platform-release.json` (`expected_runtime_class`).

**Package Manager:**
- Cargo (Rust) — workspace with resolver `"2"` at `Cargo.toml`.
- Lockfile: `Cargo.lock` committed (171 KB).
- Python tests use `python3 -m pytest` with no pinned manifest; helper modules live alongside the tests.

## Frameworks

**Core:**
- `axum` 0.8 (with `macros`) — HTTP API framework. Router assembled in `crates/enclava-api/src/lib.rs` `build_router`.
- `tokio` 1 (`features = ["full"]`) — async runtime for every crate that does I/O.
- `clap` 4 (`derive`) — CLI parser for the `enclava` binary (`crates/enclava-cli/src/commands/mod.rs`).
- `kube` 3.1 (`runtime`, `client`, `derive`, `rustls-tls`, `aws-lc-rs`) — Kubernetes client used by `enclava-engine` for server-side apply, watch, drift, teardown.
- `k8s-openapi` 0.27 (`v1_35` feature) — Kubernetes API types pinned to v1.35.

**Testing:**
- Rust built-in `#[test]` + `cargo test` — primary test mechanism. Crates co-locate tests under `src/` (`#[cfg(test)]`) and `tests/` integration directories.
- `axum-test` 20, `tower` 0.5 (`util`), `http-body-util` 0.1 — API integration test harness (`crates/enclava-api/Cargo.toml` `[dev-dependencies]`).
- `tempfile` 3 — used by `enclava-cli` and `enclava-init` tests.
- `pytest` — Python contract tests under `tests/`.
- `scripts/test-ci-workflow.sh`, `scripts/test-stable-ssh-cli.sh`, `scripts/nutshell-fast-contract.sh` — bash contract gates run in CI.

**Build/Dev:**
- `rustfmt` and `clippy` (stable toolchain via `dtolnay/rust-toolchain@stable`).
- `cargo-audit` + `cargo-deny` (config: `deny.toml`) — advisories + sources gating.
- Docker Buildx → GHCR (`ghcr.io/enclava-labs/`) — image build/publish for `enclava-api` and `enclava-init`.
- Kustomize → `deploy/api/` — minimal API deployment overlay.

## Key Dependencies

**Critical (workspace-level, declared in `Cargo.toml` `[workspace.dependencies]`):**
- `sqlx` 0.8 (`runtime-tokio`, `tls-rustls`, `postgres`, `uuid`, `chrono`, `json`, `derive`, `migrate`, `macros`) — PostgreSQL pool + compile-time-checked queries + startup migrations (`crates/enclava-api/src/db/pool.rs`).
- `reqwest` 0.13 (`default-features = false`, `json`, `stream`, `rustls`) — outbound HTTPS for all external calls; `crates/enclava-api/src/clients.rs` wraps it with SSRF defenses (HTTPS-only, no redirects, custom resolver that blocks loopback / RFC1918 / IMDS / cluster CIDRs).
- `sigstore` 0.14 (`cosign`, `sigstore-trust-root`, `rustls-tls`) — cosign signature verification of platform sidecars at API startup and of user workload images on deploy (`crates/enclava-api/src/cosign.rs`).
- `jsonwebtoken` 10 (`aws_lc_rs`) — session/config JWT issue+verify.
- `ed25519-dalek` 2 (`rand_core`, `pkcs8`) — API signing key, descriptor signing, policy artifact verification.
- `argon2` 0.5 — legacy `enc_` API key verification and password derivation.
- `chacha20poly1305` 0.10, `hkdf` 0.12, `hmac` 0.12, `zeroize` 1, `subtle` 2 — crypto primitives for keyrings, seeds, secret derivation.
- `rustls` 0.23 (`aws_lc_rs`, `tls12`) + `tokio-rustls` 0.26 — TLS; default provider installed at startup in `crates/enclava-api/src/main.rs::install_default_rustls_crypto_provider`.
- `instant-acme` 0.8 — DNS-01 ACME certificate broker for tenant Caddy (`crates/enclava-api/src/acme.rs`).
- `hickory-resolver` 0.26.1 (`tokio`, `system-config`) — DNS TXT propagation polling for the ACME broker.
- `tower-http` 0.6 (`cors`, `trace`, `compression-gzip`), `tower` 0.5, `tower_governor` 0.8 — HTTP middleware (CORS, tracing, rate limiting).
- `nostr` 0.37 — NIP-98 HTTP auth provider (`crates/enclava-api/src/auth/nostr.rs`).
- `clap` 4 + `dialoguer` 0.11 + `indicatif` 0.17 + `colored` 3 + `dirs` 6 — CLI UX for the `enclava` binary.

**enclava-init-only (`crates/enclava-init/Cargo.toml`):**
- `libcryptsetup-rs` 0.15 — LUKS volume management (requires system `libcryptsetup` + `pkg-config` + `clang`/`libclang-dev`).
- `nix` 0.29 (`user`, `fs`, `mount`, `sched`) — mount namespace bind-mounts into workload containers.
- `aes-gcm` 0.10, `rcgen` 0.14, `toml_edit` 0.22, `x509-cert` 0.2.
- `sev` 7.1.0 (`snp`, `openssl`, `serde`) — **used by `enclava-cli`** (`crates/enclava-cli/Cargo.toml`) for parsing AMD SEV-SNP attestation reports (`crates/enclava-cli/src/attestation.rs`).

**enclava-wait-exec (`crates/enclava-wait-exec/Cargo.toml`):**
- std-only binary. No external dependencies. Uses `exec(2)` to become the workload command.

**Internal (path) dependencies:**
- `enclava-common` (`crates/enclava-common`) — descriptors, canonical encoding, image refs, hostnames, crypto helpers.
- `enclava-engine` (`crates/enclava-engine`) — Kubernetes manifest rendering (`src/manifest/`) and apply/watch/cleanup/drift logic (`src/apply/`).

## Configuration

**Environment:**
- All runtime config is environment-variable driven. There is no YAML/TOML config file for the API at runtime. `main.rs` reads env vars at startup, builds the `AppState`, and never re-reads them.
- The CLI reads `~/.config/enclava/` (via `dirs` crate) for session files and `enclava.toml` for project deploy config (`crates/enclava-cli/src/app_config.rs`, `crates/enclava-cli/src/config.rs`).
- `enclava-init` reads `/etc/enclava-init/config.toml` (path override: `ENCLAVA_INIT_CONFIG`) — see `crates/enclava-init/src/config.rs`.

**Key configs required at API startup (see `DEPLOYMENT.md` for the canonical list):**
- `DATABASE_URL` — PostgreSQL connection string; migrations run on boot.
- `API_SIGNING_KEY_PATH` or `API_SIGNING_KEY_PKCS8_BASE64` — Ed25519 PKCS#8 private key for config JWTs and deploy metadata. `ALLOW_EPHEMERAL_KEYS=1` is dev-only and rejected by release builds.
- `SESSION_HMAC_KEY_PATH` or `SESSION_HMAC_KEY_BASE64` — 32-byte HMAC key for session JWTs and signer-rotation tokens.
- `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX` — root public key verifying the signed platform release envelope (`crates/enclava-cli/platform-release.json`). Compile-time required for release builds; the published root is `5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd`.
- `TRUSTEE_POLICY_READ_AVAILABLE=true` — gate for the supported signed-policy/in-TEE verification path (production baseline).

**Build:**
- `Cargo.toml` (workspace root) — central dependency versions.
- `crates/*/Cargo.toml` — per-crate manifests with `prod-strict`, `testutil`, `luks-integration` feature flags.
- `deny.toml` — `cargo-deny` advisory + source policy (one pinned ignore: `RUSTSEC-2023-0071` transitive via `sigstore`/`openidconnect`).
- `docker-compose.yml` — dev-only stack (Postgres 16-alpine + API with `ALLOW_EPHEMERAL_KEYS=1`).
- `crates/enclava-api/Dockerfile`, `crates/enclava-init/Dockerfile` — production image builds.
- `deploy/api/{namespace,deployment,service,ingress,kustomization}.yaml` — minimal K8s overlay (digest placeholder must be replaced).

**`prod-strict` feature gate:** Every production-bound crate exposes `prod-strict`. `crates/enclava-engine/src/lib.rs` triggers `compile_error!` if both `prod-strict` and `testutil` are enabled; `enclava-init` similarly rejects `luks-integration`. CI verifies this in `.github/workflows/ci.yml` (`Verify prod-strict rejects debug-only features`).

**Debug-only env vars (rejected by release builds via `crates/enclava-api/src/env_gates.rs` and `crates/enclava-cli/src/main.rs::enforce_production_env_gates`):**
- `SKIP_COSIGN_VERIFY`, `COSIGN_ALLOW_HTTP_REGISTRY`, `ALLOW_EPHEMERAL_KEYS`, `TENANT_TEE_ACCEPT_INVALID_CERTS`, `ENCLAVA_TEE_ACCEPT_INVALID_CERTS`, `LEGACY_BOOTSTRAP_SCRIPT`, `TENANT_TEE_TLS_MODE=staging|insecure`, `ENCLAVA_TEE_TLS_MODE=staging|insecure`.

## Platform Requirements

**Development:**
- Rust stable toolchain (≥ 1.85) with `rustfmt` + `clippy`.
- `libcryptsetup-dev`, `pkg-config`, `clang`, `libclang-dev` (required only when building/testing `enclava-init`).
- Docker + Docker Compose for the local API stack (`docker compose up --build`).
- A reachable PostgreSQL for API integration tests (`DATABASE_URL`).
- Python 3 + `pytest` for the contract helper tests.

**Production:**
- A Kubernetes cluster exposing the `kata-qemu-snp` runtime class (Kata confidential containers + AMD SEV-SNP).
- PostgreSQL for API state.
- Digest-pinned `attestation-proxy`, `caddy-ingress`, and `enclava-init` images; bundle them via the signed platform release envelope.
- Trustee KBS reachable from guest AA/CDH path over the HTTPS endpoint pinned in the platform release.
- Platform policy signing service reachable from CAP for generated agent policy and signed policy artifacts.
- Cloudflare DNS credentials when CAP-managed tenant DNS is required.
- Container registry: GHCR (`ghcr.io/enclava-labs/enclava-api`, `ghcr.io/enclava-labs/enclava-init`) — see `.github/workflows/api-image.yml`, `.github/workflows/enclava-init-image.yml`.

---

*Stack analysis: 2026-06-28*
