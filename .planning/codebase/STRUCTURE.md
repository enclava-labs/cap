# Codebase Structure

**Analysis Date:** 2026-06-28

## Directory Layout

```
cap/
├── Cargo.toml                 # Workspace manifest + shared dependency versions
├── Cargo.lock                 # Pinned dependency lockfile
├── deny.toml                  # cargo-deny advisory/source/ban policy
├── docker-compose.yml         # Dev-only stack (Postgres + API with ephemeral keys)
├── .dockerignore
├── README.md                  # Project overview + repo layout
├── DEPLOYMENT.md              # API runtime + production env matrix
├── DEV.md                     # Local dev + verification commands
├── SECURITY_REVIEW.md         # Code-grounded security posture
├── SECURITY_MITIGATION_PLAN.md# Mitigation checklist / operating baseline
├── crates/                    # All Rust source (workspace members)
│   ├── enclava-common/        # Shared types, canonical encoding, validation
│   ├── enclava-engine/        # K8s manifest generation + SSA apply/watch
│   ├── enclava-api/           # Axum HTTP API + deploy orchestration
│   ├── enclava-cli/           # `enclava` user CLI binary + library
│   ├── enclava-init/          # In-TEE mounter sidecar binary + library
│   └── enclava-wait-exec/     # In-TEE workload entrypoint wrapper
├── deploy/
│   └── api/                   # Minimal kustomize overlay for the API server
├── runbooks/                  # Operator runbooks + deploy-flow infographic
├── scripts/                   # CI/contract bash scripts + Hermes proof Python
├── tests/                     # Repo-level Python tests (Hermes, release gen)
├── .github/workflows/         # ci.yml, api-image.yml, enclava-init-image.yml, release.yml
└── .planning/                 # GSD planning + codebase analysis docs (this file)
```

## Directory Purposes

**`crates/enclava-common/`:**
- Purpose: the dependency-free-ish shared core (only `serde`, `sha2`, `hex`,
  `uuid`, `chrono`, `rand`).
- Contains: canonical encoding (CE-v1), `DeploymentDescriptor`, `ImageRef`,
  shared `types`, validation helpers, hostnames/orgs/crypto utilities.
- Key files: `src/canonical.rs`, `src/descriptor.rs`, `src/image.rs`,
  `src/validate.rs`, `src/lib.rs`.

**`crates/enclava-engine/`:**
- Purpose: pure Kubernetes manifest generation + apply/watch/cleanup/drift.
  No DB, no HTTP.
- Contains: `manifest/` (one file per resource type), `apply/` (engine +
  orchestrator + per-resource appliers + watch + drift + cleanup + teardown),
  `types.rs` (`ConfidentialApp` and friends), `validate.rs`, `testutil.rs`
  (behind `testutil` feature).
- Key files: `src/manifest/mod.rs::generate_all_manifests`,
  `src/apply/orchestrator.rs::apply_all`, `src/apply/engine.rs::ApplyEngine`,
  `src/types.rs::ConfidentialApp`.

**`crates/enclava-api/`:**
- Purpose: the HTTP control plane.
- Contains: router + startup wiring, route handlers, auth, DB access + pool,
  deploy orchestration, image cosign verification, KBS/DNS/ACME/clients,
  rate limiting, models that map to PostgreSQL enums.
- Key files: `src/main.rs` (startup), `src/lib.rs::build_router`,
  `src/state.rs::AppState`, `src/deploy.rs`, `src/signing_service.rs`,
  `src/cosign.rs`, `src/auth/middleware.rs::AuthContext`,
  `src/platform_release.rs`, `src/env_gates.rs`, `migrations/` (33 SQL files).

**`crates/enclava-cli/`:**
- Purpose: the `enclava` binary and its library surface (so tests can call in
  directly).
- Contains: clap command tree under `commands/`, API client + types, local
  config + keyring + descriptor builder + signer, TEE attestation client,
  platform-release loader. `platform-release.json` lives at the crate root and
  is the signed release envelope shipped with the binary.
- Key files: `src/main.rs`, `src/commands/mod.rs::Command`,
  `src/commands/app.rs` (deploy path), `src/descriptor.rs`, `src/keyring.rs`,
  `src/api_client.rs`, `src/platform_release.rs`, `src/tee_client.rs`.

**`crates/enclava-init/`:**
- Purpose: in-guest mounter sidecar; links `libcryptsetup`.
- Contains: LUKS open/format, Argon2id unlock, KBS autounlock fetch, HKDF seed
  derivation (with `Zeroize`), Trustee policy verification chain, namespace
  bind-mount helpers, config.toml + cc_init_data reconciliation, atomic writes,
  TLS certificate provisioning.
- Key files: `src/main.rs` (binary), `src/lib.rs`, `src/config.rs`,
  `src/luks.rs`, `src/secrets.rs`, `src/seeds.rs`, `src/unlock.rs`,
  `src/trustee_verify.rs`, `src/main/namespace_bind.rs`.

**`crates/enclava-wait-exec/`:**
- Purpose: minimal entrypoint wrapper that gates workload start on
  `enclava-init` readiness. No library, no dependencies beyond `std`.
- Key files: `src/main.rs`.

**`deploy/api/`:**
- Purpose: minimal kustomize overlay for running `enclava-api` in a cluster.
- Contains: `namespace.yaml`, `deployment.yaml`, `service.yaml`,
  `ingress.yaml`, `kustomization.yaml` (image pin is a placeholder digest —
  operators must replace before production use).

**`runbooks/`:**
- Purpose: operator-facing procedures and visual aids.
- Contains: `cap-hermes-proof.md`, `ct-monitoring.md` + `.sh`,
  `trustee-policy-audit.sh`, and the deploy-flow infographic (`.html`+`.png`).

**`scripts/`:**
- Purpose: CI/pact verification scripts and Python hermes-proof helpers.
- Contains: `test-ci-workflow.sh`, `test-stable-ssh-cli.sh`,
  `nutshell-fast-contract.sh`, `render-api-release-manifest.sh`, and the
  `cap_hermes_proof*.py` modules referenced by `tests/`.

**`tests/`:**
- Purpose: repo-level Python tests (not Rust) that exercise cross-cutting
  contracts (platform release generation, hermes proof).
- Contains: `test_cap_hermes_proof.py`, `test_generate_platform_release.py`.

**`.github/workflows/`:**
- Purpose: CI/CD pipelines.
- Contains: `ci.yml` (fmt/clippy/test/build, cargo-audit + cargo-deny, CI and
  stable-SSH contract scripts), `api-image.yml`, `enclava-init-image.yml`,
  `release.yml`.

## Key File Locations

**Entry Points:**
- `crates/enclava-api/src/main.rs`: API server startup (env gates, release
  verification, pool, migrations, router, bind).
- `crates/enclava-api/src/lib.rs::build_router`: axum router assembly + route
  groups.
- `crates/enclava-cli/src/main.rs`: CLI binary entrypoint + production env
  gates; dispatches via `commands::run`.
- `crates/enclava-init/src/main.rs`: in-TEE sidecar binary entrypoint.
- `crates/enclava-wait-exec/src/main.rs`: workload entrypoint wrapper.
- `crates/enclava-api/src/bin/migrate_two_hostnames.rs`: one-off operator
  migration binary.

**Configuration:**
- `Cargo.toml`: workspace members + `[workspace.dependencies]` version pinning.
- `deny.toml`: cargo-deny policy (advisories, sources, bans).
- `docker-compose.yml`: dev-only Postgres + API.
- `deploy/api/`: production overlay starting point.
- `crates/enclava-cli/platform-release.json`: signed platform release envelope
  loaded at runtime by both API and CLI.
- `crates/enclava-init/` config.toml contract: `src/config.rs` (consumed at
  `/etc/enclava-init/config.toml` in the guest).

**Core Logic:**
- `crates/enclava-common/src/canonical.rs`: CE-v1 TLV encoding — every
  cryptographic transcript in the platform goes through here.
- `crates/enclava-common/src/descriptor.rs`: `DeploymentDescriptor` shared by
  CLI signer and in-TEE verifier.
- `crates/enclava-engine/src/manifest/mod.rs::generate_all_manifests`: turns a
  `ConfidentialApp` into every Kubernetes resource for one app.
- `crates/enclava-engine/src/apply/orchestrator.rs::apply_all`: ordered SSA
  pipeline + manifest-hash annotation.
- `crates/enclava-api/src/deploy.rs`: assembles `ConfidentialApp` from DB state
  and calls the engine.
- `crates/enclava-api/src/routes/deployments.rs`: deploy HTTP surface +
  customer-authority/policy-artifact resolution.
- `crates/enclava-api/src/signing_service.rs`: signed policy artifact handling.
- `crates/enclava-api/src/cosign.rs`: digest-pinned sidecar / workload image
  verification.
- `crates/enclava-init/src/trustee_verify.rs`: in-TEE signed policy chain.
- `crates/enclava-init/src/main/namespace_bind.rs`: bind-mount decrypted
  volumes into workload namespaces.

**State / Persistence:**
- `crates/enclava-api/migrations/`: 33 numbered SQL migrations (e.g.
  `0001_users_and_orgs.sql`, `0034_workload_tls_certificate_cache.sql`).
- `crates/enclava-api/src/db/pool.rs`: `sqlx` pool (max 20 conns) + migrate.
- `crates/enclava-api/src/models.rs`: row structs + PostgreSQL enum mappings
  (`Provider`, `Role`, `UnlockMode`, `AppStatus`, `DeployStatus`, `Trigger`).

**Testing:**
- Co-located inline `#[cfg(test)] mod tests` in most source files.
- `crates/enclava-api/tests/`, `crates/enclava-cli/tests/`,
  `crates/enclava-engine/tests/`, `crates/enclava-common/tests/`,
  `crates/enclava-init/src/main/tests/`, `crates/enclava-init/src/trustee_verify/tests/`,
  `crates/enclava-cli/src/commands/app/tests/`,
  `crates/enclava-cli/src/tee_client/tests/`,
  `crates/enclava-api/src/routes/apps/tests/`,
  `crates/enclava-api/src/routes/deployments/tests/`,
  `crates/enclava-api/src/signing_service/tests/`.
- `crates/enclava-cli/tests/fixtures/`: pinned descriptor wire-format vectors
  (`descriptor_canonical_v1.bin`, `descriptor_core_canonical_v1.bin`,
  `descriptor_core_hash_v1.hex`).
- `crates/enclava-engine/tests/fixtures/`: engine manifest fixtures.
- Repo-level Python tests under `tests/` (run with `python3 -m pytest`).

## Naming Conventions

**Crates / packages:**
- `enclava-<component>` (kebab-case) in `Cargo.toml`; library names use
  underscores (`enclava_api`, `enclava_cli`). The two pure-binary crates
  (`enclava-init`, `enclava-wait-exec`) have no `lib.rs`.

**Files:**
- `snake_case.rs` throughout. One module per Kubernetes resource type in
  `engine/src/manifest/` (`namespace.rs`, `statefulset.rs`, `gateway.rs`,
  `network_policy.rs`, `cc_init_data.rs`, …) and one module per resource family
  in `engine/src/apply/` (`namespace.rs`, `statefulset.rs`, `gateway.rs`,
  `network_policy.rs`, `resources.rs`, `watch.rs`, `drift.rs`, `cleanup.rs`,
  `teardown.rs`).
- Route files in `api/src/routes/` mirror the URL namespace: `apps.rs`,
  `deployments.rs`, `orgs.rs`, `auth.rs`, `config.rs`, `domains.rs`,
  `status.rs`, `unlock.rs`, `users.rs`, `workload.rs`, `workload_tls.rs`,
  `platform.rs`, `internal.rs`.
- CLI command files mirror the subcommand verb: `init.rs`, `prepare.rs`,
  `auth.rs`, `app.rs`, `config.rs`, `domains.rs`, `org.rs`, `key.rs`,
  `template.rs`, `ownership.rs`, `descriptor.rs`.
- Test files use `*_test.rs` (e.g. `image_test.rs`, `manifest_ingress_test.rs`)
  when co-located in a `tests/` directory; inline unit tests use the
  `#[cfg(test)] mod tests` pattern.

**Directories:**
- One `src/` per crate. `bin/` only under `enclava-api/src/` for additional
  binaries. `migrations/` only under `enclava-api/`. `fixtures/` only under
  test directories.

**Types:**
- PascalCase for structs/enums (`ConfidentialApp`, `ApplyEngine`,
  `DeployStatus`, `AppState`). PostgreSQL enum variants are `lowercase` via
  `#[serde(rename_all = "lowercase")]` + `#[sqlx(type_name = "..._enum",
  rename_all = "lowercase")]` (see `models.rs`).
- Constants are `SCREAMING_SNAKE_CASE`
  (`MANIFEST_HASH_ANNOTATION`, `DEFAULT_READY_FILE`).

**Functions / methods:**
- `snake_case`. Async fns named after the action (`apply_namespace`,
  `watch_rollout`, `generate_all_manifests`, `load_platform_release`).
  Builders/loaders consistently prefixed `load_*` / `build_*`
  (e.g. `load_attestation_config`, `build_router`, `build_cors_layer`).

## Where to Add New Code

**New HTTP route (API):**
1. Add the handler in `crates/enclava-api/src/routes/<area>.rs` (or a new file
   there, then declare it in `routes/mod.rs`).
2. Wire it in the matching `*_routes()` builder inside
   `crates/enclava-api/src/lib.rs`. Add scope checks in
   `crates/enclava-api/src/auth/scopes.rs` if the route is privileged.
3. For an internal PaaS management route, add it under
   `/internal/paas/orgs/{paas_org_id}/...` in `internal_routes()` so it
   inherits `InternalAuthConfig` verification.

**New Kubernetes resource (engine):**
1. Add a `generate_<thing>` function in a new
   `crates/enclava-engine/src/manifest/<thing>.rs`; declare it in
   `manifest/mod.rs`.
2. Add the field to `GeneratedManifests` (`manifest/mod.rs`) and include it in
   `generate_all_manifests`.
3. Add an `apply_<thing>` helper in `crates/enclava-engine/src/apply/` and
   sequence it inside `apply::orchestrator::apply_all` (and
   `apply_all_with_tenant_image_pull_secret` in `api/src/deploy.rs`). Update
   `manifest_hash` so drift detection covers the new resource.
4. Add a fixture-driven test under `crates/enclava-engine/tests/`.

**New CLI subcommand:**
1. Add a new file in `crates/enclava-cli/src/commands/<verb>.rs`.
2. Declare the module in `commands/mod.rs`, add a `Command` variant, and a
   match arm in `commands::run`.
3. If the command calls the API, add the request shape to
   `crates/enclava-cli/src/api_types.rs` and the call to `api_client.rs`.

**New DB table / migration:**
- Add `crates/enclava-api/migrations/00NN_<name>.sql` with the next sequence
  number. sqlx runs migrations on startup via `db::pool::run_migrations`.
- Add the row struct(s) to `crates/enclava-api/src/models.rs` with
  `#[derive(sqlx::FromRow)]` and any enum mappings.

**New shared type / canonical encoding change:**
- Put it in `crates/enclava-common/src/`. If it alters the customer-signed
  descriptor wire format, add a fixture vector under
  `crates/enclava-cli/tests/fixtures/` and update both
  `enclava-common::descriptor` and `enclava-init::trustee_verify` so signer and
  verifier stay in lockstep.

**New utility / helper:**
- Cross-crate reusable code → `crates/enclava-common/src/`.
- API-only helper → the matching module in `crates/enclava-api/src/`.
- Engine-only helper → `crates/enclava-engine/src/`.

**New test:**
- Inline `#[cfg(test)] mod tests` for unit tests next to the code under test.
- New `tests/<thing>_test.rs` file in the crate's `tests/` directory for
  fixture-driven / multi-module integration tests.
- Repo-level cross-language contracts → `tests/` (Python) and gate them in
  `.github/workflows/ci.yml` plus `scripts/test-ci-workflow.sh`.

## Special Directories

**`.planning/`:**
- Purpose: GSD workflow artifacts including this codebase analysis.
- Generated: partly (analysis docs are generated; roadmap/spec are authored).
- Committed: yes.

**`target/`:**
- Purpose: cargo build output.
- Generated: yes.
- Committed: no (gitignored).

**`crates/enclava-api/migrations/`:**
- Purpose: immutable, append-only SQL migrations run by sqlx at API startup.
- Generated: no.
- Committed: yes. Never edit a shipped migration — add a new numbered one.

**`crates/enclava-cli/tests/fixtures/` &
 `crates/enclava-engine/tests/fixtures/`:**
- Purpose: pinned wire-format / manifest vectors that lock cross-binary
  contracts (canonical descriptor, core hash).
- Generated: produced once from reference code, then committed verbatim.
- Committed: yes — changes here signal a contract break.

---

*Structure analysis: 2026-06-28*
