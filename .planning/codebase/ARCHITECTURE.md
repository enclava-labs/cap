<!-- refreshed: 2026-06-28 -->
# Architecture

**Analysis Date:** 2026-06-28

## System Overview

Enclava CAP is a Rust workspace that deploys OCI images as confidential
workloads onto a Kubernetes cluster running Kata confidential containers with
AMD SEV-SNP. The repository is split into an **off-TEE control plane** (CLI +
HTTP API + manifest engine backed by PostgreSQL and Kubernetes) and an
**in-TEE runtime** (`enclava-init` mounter sidecar + `enclava-wait-exec`
wrapper). The hosted PaaS console is intentionally out of tree; CAP only owns
HTTP/API contracts a console can consume.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                         OFF-TEE CONTROL PLANE                            │
│                                                                          │
│  ┌──────────────────┐                       ┌─────────────────────────┐  │
│  │  enclava CLI     │  HTTPS (signed        │  enclava-api (Axum)     │  │
│  │  `enclava-cli/   │  descriptor +         │  `crates/enclava-api/   │  │
│  │   src/commands/  │  customer keys)       │   src/`                 │  │
│  │   app.rs`        │ ─────────────────────▶│  routes/ → deploy.rs    │  │
│  └──────────────────┘                       └───────────┬─────────────┘  │
│                                                         │                │
│                                  ┌──────────────────────┼─────────────┐  │
│                                  ▼                      ▼             ▼  │
│                         ┌──────────────┐   ┌──────────────┐  ┌──────────┐│
│                         │ PostgreSQL   │   │ enclava-     │  │ Trustee/ ││
│                         │ `db/` +      │   │ engine       │  │ signing  ││
│                         │ `migrations/`│   │ (manifest +  │  │ services ││
│                         │              │   │  SSA apply)  │  │ (HTTPS)  ││
│                         └──────────────┘   └──────┬───────┘  └──────────┘│
│                                                   │                      │
└───────────────────────────────────────────────────┼──────────────────────┘
                                                    │ kube client
                                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    KUBERNETES (Kata + SEV-SNP runtime)                   │
│                                                                          │
│   Per-app namespace:  Namespace, SA, CiliumNetworkPolicy, ResourceQuota, │
│     Service, Gateway API (EnvoyProxy/Gateway/TLSRoute), ConfigMaps,      │
│     StatefulSet (pod template with enclava-init + workload sidecars)     │
│                                                                          │
│   ┌──────────────────────── IN-TEE GUEST ─────────────────────────────┐  │
│   │ enclava-init sidecar:   waits for workload sentinels              │  │
│   │   → Argon2/KBS unlock   → opens LUKS (state + tls-state)          │  │
│   │   → verifies Trustee policy chain → writes per-component seeds    │  │
│   │   → bind-mounts decrypted volumes into workload namespaces        │  │
│   │   → writes `/run/enclava/init-ready` and stays alive              │  │
│   │                                                                   │  │
│   │ enclava-wait-exec wrapper (app + caddy entrypoints):              │  │
│   │   → writes sentinel into `/run/enclava/containers/<name>`         │  │
│   │   → polls `/run/enclava/init-ready` then `exec`s the workload     │  │
│   └───────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| `enclava-common` | Canonical encoding (CE-v1), deployment descriptor, image refs, validation, shared crypto — the single source of truth shared between CLI signer and in-TEE verifier | `crates/enclava-common/src/lib.rs` |
| `enclava-cli` | User-facing `enclava` binary: login/init/create/deploy, local keyring & descriptor signing, TEE attestation client | `crates/enclava-cli/src/lib.rs`, `crates/enclava-cli/src/commands/mod.rs` |
| `enclava-api` | Stateless Axum HTTP service: auth, orgs/apps/config/domains, deploy orchestration, image cosign verification, DNS/ACME/KBS clients | `crates/enclava-api/src/lib.rs`, `crates/enclava-api/src/main.rs` |
| `enclava-engine` | Pure Kubernetes manifest generation + server-side-apply/watch/cleanup/drift orchestration (no DB, no HTTP) | `crates/enclava-engine/src/lib.rs` |
| `enclava-init` | In-TEE mounter sidecar binary: LUKS, HKDF seed derivation, Trustee policy verification, namespace bind-mounts | `crates/enclava-init/src/main.rs`, `crates/enclava-init/src/lib.rs` |
| `enclava-wait-exec` | Tiny in-TEE wrapper that gates workload/caddy containers on the `enclava-init` ready sentinel | `crates/enclava-wait-exec/src/main.rs` |

## Pattern Overview

**Overall:** Cargo workspace of six crates organised as a layered control plane
with a shared-types core, plus a separate in-guest runtime pair. State lives in
PostgreSQL; the source of truth for manifests is the engine's `ConfidentialApp`
struct; all cryptographic transcripts use the shared CE-v1 TLV encoding so the
CLI signer and in-TEE verifier cannot drift.

**Key Characteristics:**
- **Library-first binaries.** Every crate that ships a binary also exposes a
  `lib.rs`. `enclava-api/src/lib.rs` builds the router; `enclava-api/src/main.rs`
  is wiring only. This makes the surface unit-testable with `axum-test`.
- **Workspace dependencies.** All external crate versions are pinned once in the
  root `Cargo.toml` `[workspace.dependencies]` and referenced with
  `{ workspace = true }` from each member.
- **Feature flags for prod hardening.** `prod-strict` (everywhere) and `testutil`
  / `luks-integration` (engine, init) are mutually exclusive — `lib.rs`
  `compile_error!` guards enforce that prod-strict builds never pull in test or
  dev code paths.
- **Signed platform release as the trust root.** Both API and CLI load
  `crates/enclava-cli/platform-release.json`, verify its signature against
  `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX`, and refuse startup when an env
  value diverges from a signed claim (`crates/enclava-api/src/main.rs:553`,
  `crates/enclava-api/src/platform_release.rs`).
- **Customer-owned keys.** The deploy path does not require a platform API key:
  the CLI derives customer-owned deploy keys from a local random recovery seed,
  signs the descriptor locally, and submits only signed artifacts.
- **Server-side apply with manifest-hash drift detection.** The engine stores a
  SHA-256 over all generated manifests under annotation
  `enclava.dev/manifest-hash` so later reconciles can detect drift.

## Layers

**Common / Canonical (`enclava-common`):**
- Purpose: types, encoding, and validation reused by every other crate.
- Location: `crates/enclava-common/src/`
- Contains: `canonical.rs` (CE-v1 TLV + hash), `descriptor.rs`
  (`DeploymentDescriptor`), `image.rs` (`ImageRef` with digest enforcement),
  `types.rs`, `crypto.rs`, `hostnames.rs`, `orgs.rs`, `validate.rs`.
- Depends on: `serde`, `sha2`, `hex`, `uuid`, `chrono`, `rand` only.
- Used by: every other crate.

**Engine (`enclava-engine`):**
- Purpose: turn a `ConfidentialApp` spec into Kubernetes manifests and apply
  them; no IO beyond `kube::Client`.
- Location: `crates/enclava-engine/src/`
- Contains: `manifest/` (one module per K8s resource), `apply/` (engine,
  orchestrator, watch, drift, cleanup, teardown), `types.rs`
  (`ConfidentialApp`, `AttestationConfig`, `Container`, `StorageSpec`),
  `validate.rs`.
- Depends on: `enclava-common`, `kube`, `k8s-openapi`, `serde_json/yaml`.
- Used by: `enclava-api` (deploy orchestration), `enclava-cli` (manifest hash
  pre-flight and `cc_init_data` reuse).

**API (`enclava-api`):**
- Purpose: HTTP control plane — auth, CRUD for orgs/apps/config/domains, deploy
  orchestration, image verification, DNS/ACME, workload-attested artifact and
  TLS endpoints consumed by `enclava-init`.
- Location: `crates/enclava-api/src/`
- Contains: `lib.rs` (router), `main.rs` (startup wiring), `state.rs`
  (`AppState`, `CapManagementMode`, `InternalAuthConfig`), `routes/`, `auth/`,
  `db/`, `deploy.rs`, `signing_service.rs`, `cosign.rs`, `kbs.rs`, `dns.rs`,
  `acme.rs`, `clients.rs`, `env_gates.rs`, `platform_release.rs`,
  `ratelimit.rs`, `edge.rs`, `entitlements.rs`, `source_provider.rs`,
  `registry.rs`, `models.rs`.
- Depends on: `enclava-engine`, `enclava-common`, `axum`, `sqlx` (postgres),
  `tower-http`, `tower_governor`, `ed25519-dalek`, `jsonwebtoken`, `sigstore`,
  `instant-acme`, `hickory-resolver`, `kube`.
- Used by: `enclava-cli` (HTTPS), browser console (out of tree), PaaS internal
  bridge (`/internal/paas/*` when `CAP_MANAGEMENT_MODE=paas_managed`).

**CLI (`enclava-cli`):**
- Purpose: the `enclava` binary and its reusable library.
- Location: `crates/enclava-cli/src/`
- Contains: `main.rs` (env-gate + clap dispatch), `commands/` (one module per
  subcommand), `api_client.rs`, `api_types.rs`, `app_config.rs` (`enclava.toml`),
  `config.rs` (session/credentials on disk), `descriptor.rs` (build + sign),
  `keyring.rs`, `keys.rs`, `policy_artifact.rs`, `platform_release.rs`,
  `attestation.rs`, `tee_client.rs` (+ `tls.rs`).
- Depends on: `enclava-common`, `enclava-engine`, `clap`, `reqwest`,
  `ed25519-dalek`, `argon2`, `chacha20poly1305`, `hkdf`, `nostr`, `sev`.
- Used by: end users and CI.

**In-TEE runtime (`enclava-init`, `enclava-wait-exec`):**
- Purpose: gate workload start on LUKS unlock + policy verification inside the
  Kata SEV-SNP guest.
- Location: `crates/enclava-init/src/` (binary `enclava-init` + lib),
  `crates/enclava-wait-exec/src/main.rs` (binary only).
- Contains: `luks.rs` (libcryptsetup), `seeds.rs`/`secrets.rs` (HKDF + Zeroize),
  `unlock.rs` (Argon2id + rate limit), `kbs_fetch.rs` (autounlock),
  `trustee_verify.rs` (signed policy chain), `tls_certificate.rs`,
  `socket.rs` (unlock Unix socket), `writes.rs` (atomic writes),
  `main/namespace_bind.rs` (bind-mount decrypted volumes into workload
  namespaces), `config.rs` (config.toml + cc_init_data reconciliation).
- Depends on: `enclava-common`, `libcryptsetup-rs`, `nix`, `reqwest`
  (blocking), `argon2`, `aes-gcm`, `ed25519-dalek`. `enclava-init` requires
  system `libcryptsetup` headers — build with `--exclude enclava-init` when
  unavailable.

## Data Flow

### Primary Request Path — Deploy

1. User runs `enclava deploy --image <ref>@sha256:<digest>`
   (`crates/enclava-cli/src/commands/app.rs:deploy`).
2. CLI loads `enclava.toml` (`app_config.rs`), platform release
   (`platform_release.rs`), and personal-org keyring (`keyring.rs`).
3. CLI builds the canonical `DeploymentDescriptor`
   (`crates/enclava-cli/src/descriptor.rs` →
   `enclava_common::descriptor::DeploymentDescriptor` + `canonical::ce_v1_bytes`),
   computes `descriptor_core_hash`, signs with the customer Ed25519 key.
4. CLI optionally calls `POST /apps/{name}/agent-policy` and forwards signed
   blobs to `POST /apps/{name}/deploy`
   (`crates/enclava-cli/src/api_client.rs`).
5. API handler validates auth (`auth/middleware.rs::AuthContext`), scopes
   (`auth/scopes.rs`), descriptor signature, image signer, org keyring,
   customer authority, and resolves the signed policy artifact
   (`crates/enclava-api/src/routes/deployments.rs`,
   `crates/enclava-api/src/signing_service.rs`).
6. API assembles `ConfidentialApp` from DB state and calls
   `apply_deployment_manifests` (`crates/enclava-api/src/deploy.rs`).
7. Engine generates manifests (`manifest::generate_all_manifests`) and applies
   them via `apply::orchestrator::apply_all` in five ordered steps: namespace →
   standard resources → CiliumNetworkPolicy → Gateway API → StatefulSet
   (manifest hash injected as annotation), then
   `apply::watch::watch_rollout` blocks until Running / Failed / TimedOut
   (`crates/enclava-engine/src/apply/orchestrator.rs`).
8. API records deploy status in PostgreSQL (`deploy.rs::classify_rollout_result`
   maps engine `DeployPhase` to `DeployStatus` / `AppStatus`).

### In-TEE Unlock Flow

1. Pod starts; `enclava-init` reads `/etc/enclava-init/config.toml`
   (`crates/enclava-init/src/config.rs`) and reconciles it against the signed
   `cc_init_data` (`main.rs::validate_configmap_transport_against_signed_cc_init_data`).
2. `enclava-init` waits for workload/caddy sentinels under
   `/run/enclava/containers/<name>` written by `enclava-wait-exec`.
3. Owner seed acquired via Password (Argon2id over Unix socket, rate-limited) or
   Autounlock (KBS fetch with retries) — `acquire_owner_seed_password` /
   `acquire_owner_seed_autounlock`.
4. Opens both LUKS volumes (`luks.rs`), runs the Trustee policy verification
   chain (`trustee_verify.rs::verify_chain_or_skip`), provisions the static TLS
   certificate (`tls_certificate.rs`), and writes per-component HKDF seeds
   (`seeds.rs`).
5. `enclava-init` bind-mounts decrypted volumes into the workload mount
   namespaces (`main/namespace_bind.rs`), writes `/run/enclava/init-ready`, and
   stays alive so the mount source remains present.
6. `enclava-wait-exec` instances polling that ready file `exec` the workload
   (`crates/enclava-wait-exec/src/main.rs::wait_until_ready`).

### Workload Artifact / TLS Broker Flow

- The pod's `enclava-init` calls CAP workload-attested endpoints
  `GET /workload/artifacts` and `POST /workload/tls/dns01-certificate`
  (`crates/enclava-api/src/routes/workload.rs`,
  `crates/enclava-api/src/routes/workload_tls.rs`). CAP verifies the workload
  attestation token via `TRUSTEE_ATTESTATION_VERIFY_URL` before returning
  descriptor/keyring/policy blobs or brokering DNS-01 certificates.

**State Management:**
- All persistent state lives in PostgreSQL. `AppState` (`state.rs`) holds the
  `PgPool` plus process-wide config and is `Clone` (cheap, `Arc`-backed fields).
- A `tokio::sync::Semaphore` named `deployment_apply_permits` (size
  `CAP_MAX_CONCURRENT_APPLIES`, default 1) caps per-instance Kubernetes apply
  concurrency because applying bursts can overwhelm a single Kata worker.
- No in-process cache of business objects: handlers read fresh from the DB.

## Key Abstractions

**`ConfidentialApp`:**
- Purpose: the single input to manifest generation; everything the engine needs
  to render a namespace.
- Examples: `crates/enclava-engine/src/types.rs:12`; assembled in
  `crates/enclava-api/src/deploy.rs` and re-assembled client-side for hashing in
  `crates/enclava-cli/src/commands/app.rs`.
- Pattern: plain `Serialize + Deserialize` struct with hex-byte serialization
  helpers (`hex_bytes32` module) for `[u8; 32]` fields.

**`DeploymentDescriptor` + CE-v1 canonical encoding:**
- Purpose: the customer-signed statement of what should be deployed. Shared by
  the CLI signer and the in-TEE verifier so they cannot drift.
- Examples: `crates/enclava-common/src/descriptor.rs`,
  `crates/enclava-common/src/canonical.rs`. Pinned vectors in
  `crates/enclava-cli/tests/fixtures/` lock the wire format.
- Pattern: TLV length-prefixed encoding (`label_len:u16_be || label ||
  value_len:u32_be || value`) — plain `||` concatenation is forbidden.

**`ApplyEngine`:**
- Purpose: thin wrapper around `kube::Client` + `ApplyConfig` carrying SSA field
  manager / prune / timeout settings uniformly.
- Examples: `crates/enclava-engine/src/apply/engine.rs`.
- Pattern: per-resource `apply_*` helpers take `&ApplyEngine` so callers can
  substitute a test client.

**`AppState`:**
- Purpose: axum shared state — DB pool, signing/HMAC keys, HTTP clients
  (guarded outbound, registry, Trustee, tenant TEE), attestation/DNS/ACME/KBS
  config, internal-auth config, apply semaphore.
- Examples: `crates/enclava-api/src/state.rs:148`.
- Pattern: `#[derive(Clone)]` with `Arc`-wrapped mutable/shared fields. A
  `CapManagementMode { Standalone, PaasManaged }` toggle controls whether
  `/internal/paas/*` routes are merged.

**`AuthContext` extractor:**
- Purpose: axum `FromRequestParts` that resolves `(user_id, org_id, role,
  api_key, management_origin)` from a Bearer session JWT, an API key, or the
  internal PaaS bridge.
- Examples: `crates/enclava-api/src/auth/middleware.rs:27`.
- Pattern: handlers take `AuthContext` as an extractor; scope checks live in
  `auth/scopes.rs`.

## Entry Points

**`enclava-api` binary:**
- Location: `crates/enclava-api/src/main.rs` (`#[tokio::main]` at line 535).
- Triggers: API server process (Deployment in `deploy/api/`).
- Responsibilities: install rustls crypto provider, enforce production env
  gates, load+verify platform release, cosign-verify sidecar images at startup,
  build `PgPool` + run migrations, construct `AppState`, call `build_router`,
  bind `BIND_ADDR` (default `0.0.0.0:3000`).

**`enclava-api/src/lib.rs::build_router`:**
- Location: `crates/enclava-api/src/lib.rs:29`.
- Triggers: `main.rs` (and `test_router` for tests).
- Responsibilities: assemble route groups (auth/users/platform/orgs/apps/deploy/
  config/domains/status/unlock/workload/health) and conditionally merge
  `internal_routes()` when `management_mode.internal_paas_routes_enabled()`.
  Applies `TraceLayer`, `CorsLayer`, and per-route `GovernorLayer` rate limits.

**`migrate-two-hostnames` binary:**
- Location: `crates/enclava-api/src/bin/migrate_two_hostnames.rs`.
- Triggers: manual one-off operator migration.
- Responsibilities: rename legacy dual-hostname records to the current shape.

**`enclava` CLI binary:**
- Location: `crates/enclava-cli/src/main.rs` → `commands::run`
  (`crates/enclava-cli/src/commands/mod.rs:86`).
- Triggers: end-user shell.
- Responsibilities: parse clap CLI, dispatch subcommands, route to handlers in
  `commands/*.rs`.

**`enclava-init` binary:**
- Location: `crates/enclava-init/src/main.rs`.
- Triggers: Kata guest init container (StatefulSet sidecar).
- Responsibilities: see In-TEE Unlock Flow above. Also handles hidden
  `--bind-mount-into-ns` and `--probe-ready` invocations used internally by
  the namespace bind step and readiness probes.

**`enclava-wait-exec` binary:**
- Location: `crates/enclava-wait-exec/src/main.rs`.
- Triggers: app + caddy container entrypoints (rendered into the StatefulSet by
  `enclava-engine::manifest::startup`).
- Responsibilities: write sentinel, wait for ready file, `execvp` the workload
  command (default `/startup/startup.sh`).

## Architectural Constraints

- **Threading:** API is `tokio`-based async multi-threaded (`#[tokio::main]`).
  `enclava-init` is a synchronous binary (uses `reqwest::blocking`, blocking
  `libcryptsetup` calls, and a forever-loop keep-alive thread). The apply
  pipeline is async but bounded by `AppState::deployment_apply_permits`.
- **Global state:** No mutable globals. All shared state is owned by `AppState`
  and propagated through axum extractors. rustls crypto provider is installed
  once at startup (`install_default_rustls_crypto_provider`).
- **Circular imports:** None observed. Dependency direction is strictly
  `common ← engine ← api`; `common ← engine ← cli`; `common ← init`;
  `enclava-wait-exec` depends only on `std`. `enclava-cli` reuses
  `enclava-engine`'s `cc_init_data` and `manifest` modules rather than
  duplicating them.
- **Native dependency:** `enclava-init` links `libcryptsetup`. Hosts without
  the dev headers must build the workspace with `--exclude enclava-init`.
- **Trust root:** `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX` is a compile-time
  constant consumed by release verification in both API and CLI. Release builds
  refuse startup unless the loaded release envelope verifies against it.
- **Feature exclusivity:** `prod-strict` is mutually exclusive with `testutil`
  (engine) and `luks-integration` (init); enforced by `compile_error!` in each
  crate's `lib.rs`.

## Anti-Patterns

### Plain byte concatenation for cryptographic transcripts

**What happens:** Naively hashing `a || b` to bind two values lets a
variable-length field shift boundaries and change meaning.
**Why it's wrong:** Produces ambiguous hashes that customers and the in-TEE
verifier could disagree on.
**Do this instead:** Always go through `enclava_common::canonical::ce_v1_bytes`
/ `ce_v1_hash` (`crates/enclava-common/src/canonical.rs`). The crates's test
suite pins this with a collision test.

### Reading mutable config into the engine

**What happens:** The engine is intentionally pure (no DB, no HTTP).
**Why it's wrong:** Pushing DB lookups or HTTP calls into engine helpers
re-introduces IO into a unit that is heavily unit-tested with static fixtures.
**Do this instead:** Resolve all dynamic state in `enclava-api`/`enclava-cli`,
build a fully populated `ConfidentialApp`, then call
`enclava_engine::manifest::generate_all_manifests`.

### Skipping the manifest-hash annotation

**What happens:** Later reconciles cannot tell whether live state drifted from
desired state.
**Why it's wrong:** Disables drift detection
(`crates/enclava-engine/src/apply/drift.rs`).
**Do this instead:** Always go through `apply::orchestrator::apply_all` (or the
API's `apply_all_with_tenant_image_pull_secret`) which inject
`MANIFEST_HASH_ANNOTATION` onto the StatefulSet.

### Adding management writes outside `/internal/paas/*` when PaaS-managed

**What happens:** Bypasses the internal-auth bridge and trusted-proxy
verification.
**Why it's wrong:** Defeats `CAP_MANAGEMENT_MODE=paas_managed`.
**Do this instead:** Add new management mutations under
`/internal/paas/orgs/{paas_org_id}/...` in `crates/enclava-api/src/routes/internal.rs`
and rely on `InternalAuthConfig` (`state.rs:60`) for caller verification.

## Error Handling

**Strategy:** `thiserror::Error` enums at module boundaries; `anyhow::Result`
inside binaries (`enclava-init`, `enclava-api/main.rs`) for context-rich
propagation; `Result<_, (StatusCode, Json<Value>)>` at axum handler edges.

**Patterns:**
- Engine: `ApplyError` (`apply/engine.rs:7`) and `ValidationError`
  (`validate.rs:3`) — typed enums, no `anyhow`.
- API deploy: `DeployError` (`deploy.rs:228`) wraps `sqlx::Error`,
  `ApplyError`, `KbsPolicyError`, `EdgeRouteError`. Handlers map these to HTTP
  via helpers like `signing_error_response`
  (`routes/deployments.rs:45`).
- Auth: `AuthError` (`auth/middleware.rs:45`) implements `IntoResponse` so
  extractors translate directly to status codes.
- Init: `errors.rs` plus `anyhow` with `.context(...)`. Failures write a
  termination log and (when `ENCLAVA_INIT_STAY_ALIVE` is set) keep the sidecar
  alive so diagnostics remain readable.

## Cross-Cutting Concerns

**Logging:** `tracing` + `tracing_subscriber` everywhere. API uses
`EnvFilter::try_from_default_env()` falling back to
`"enclava_api=debug,tower_http=debug"`. `enclava-init` emits JSON with no
target. Apply progress is logged as `step N/5` breadcrumbs per resource.

**Validation:** Input validation layered — `enclava_common::validate`
(hostnames, FQDNs, slugs) is the lowest layer; `enclava_engine::validate`
checks `ConfidentialApp` well-formedness (digest pins, exactly one primary
container, identity hashes); `enclava-api` enforces org/role scopes and
cluster/tier limits in handlers. `env_gates.rs` enforces production-vs-debug
env vars at startup.

**Authentication:** Three concurrent paths in `auth/middleware.rs`: session JWT
(HMAC `SESSION_HMAC_KEY_*`), API key (`X-API-Key` or `Bearer enc_...`), and the
internal PaaS bridge (`InternalAuthConfig` with SHA-256-hashed tokens and
optional trusted-proxy secret compared with `subtle::ConstantTimeEq`). Org
context resolved from `X-Enclava-Org` header, `?org=` query, or personal org
fallback.

**Outbound HTTP hardening:** `clients.rs` provides two narrow `reqwest`
clients (registry allowlist, webhook) that refuse redirects, force HTTPS, cap
response bodies, and resolve DNS through a resolver that rejects loopback /
link-local / RFC1918 / IMDS / configured cluster CIDRs (C12). Tenant-TEE and
Trustee clients are built separately in `main.rs` to honour their distinct CA
trust roots.

---

*Architecture analysis: 2026-06-28*
