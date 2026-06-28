# Codebase Concerns

**Analysis Date:** 2026-06-28

## Tech Debt

**Stale TODO comments referencing completed phase work:**
- Issue: Three `TODO(phase-*)` / `TODO(phase-7-api)` comments describe work that has since been implemented on the API side. They mislead readers into thinking the work is still pending.
- Files: `crates/enclava-cli/src/keys.rs:465`, `crates/enclava-cli/src/keyring.rs:320`, `crates/enclava-api/src/routes/apps.rs:1026`
- Impact: Future agents may "implement" the missing endpoint a second time, or treat the surrounding code as provisional. The actual API surfaces (`POST /users/me/public-keys` in `crates/enclava-api/src/routes/users.rs:120`, `PUT /orgs/{name}/keyring` in `crates/enclava-api/src/routes/orgs.rs`, KBS Rego re-render path) already exist.
- Fix approach: Delete the `RegisterPublicKeyRequest` stub at `crates/enclava-cli/src/keys.rs:466` and the `TODO(phase-7-api)` comment at `crates/enclava-cli/src/keyring.rs:320`. Re-scope the `TODO(phase-2)` comment at `crates/enclava-api/src/routes/apps.rs:1026` to describe what re-render step is still missing, or delete if already covered by the signing-service path in `crates/enclava-api/src/signing_service.rs`.

**Legacy bootstrap_script.sh path still emittable behind `LEGACY_BOOTSTRAP_SCRIPT=true`:**
- Issue: The Rust `enclava-init` replacement is the default, but the engine still carries a parallel legacy shell-script container shape that branches in ~20 places.
- Files: `crates/enclava-engine/src/manifest/containers.rs` (the `legacy_bootstrap_enabled()` predicate is read at lines 181, 184, 229, 251, 297, 326, 569, 589, 604, 628, 664, 690, 730, 736, 777, 817, 846, 878), `crates/enclava-engine/src/manifest/volumes.rs:22`, `crates/enclava-engine/src/manifest/statefulset.rs:51,76`
- Impact: Two code paths must be maintained in lockstep for security-sensitive container settings (security context, volume mounts, env vars). Risk of divergent security posture between legacy and modern paths. Release builds reject the flag via `crates/enclava-api/src/env_gates.rs:28`, but the engine code remains branched.
- Fix approach: Once all in-flight workloads have rolled onto `enclava-init`, delete the `legacy_*` branches and the `LEGACY_BOOTSTRAP_SCRIPT` read. Track the removal in `SECURITY_MITIGATION_PLAN.md`.

**Legacy Argon2 API-key verification kept alive for migration window:**
- Issue: HMAC-format API keys are the canonical format, but the verifier still accepts `enc_*`-prefixed Argon2-hashed rows from the `api_keys` table.
- Files: `crates/enclava-api/src/auth/api_key.rs:35,150,178,256` (`LEGACY_HASH_FORMAT`, `LookupMaterial::Legacy`), migration `crates/enclava-api/migrations/0023_api_key_hmac_format.sql`
- Impact: Verifier carries Argon2 CPU cost on every legacy lookup; `crates/enclava-api/src/auth/api_key.rs:179` runs `verify_password` (Argon2id) per candidate. Constant-time comparison (`subtle::ConstantTimeEq`) is only applied on the HMAC path, not the legacy path.
- Fix approach: Set a firm cutover date, force-rotate remaining legacy keys via operator action, then delete the `LookupMaterial::Legacy` arm and the `argon2_legacy` `COALESCE` in the lookup SQL.

**CLI flag aliases retained for hosted automation compatibility:**
- Issue: `--ngrok-tcp-url` is kept as a `visible_alias` for `--stable-ssh-endpoint` indefinitely, even though `stable_ssh_endpoint` is the canonical field.
- Files: `crates/enclava-cli/src/commands/template.rs:68,91` and tests at `:2099,2127,2138,2176,2199`
- Impact: Two CLI surfaces must remain in sync; renaming the underlying concept doesn't propagate. Adding new features risks breaking the alias contract enforced by `scripts/test-stable-ssh-cli.sh`.
- Fix approach: Document an expiration in the README, plan a major-version bump that removes the alias, and update `scripts/test-stable-ssh-cli.sh` accordingly.

**Pinned K8s API version:**
- Issue: `k8s-openapi` is pinned to feature `v1_35`. Clusters on other versions require a workspace-wide rebuild.
- Files: `Cargo.toml:25`
- Impact: New cluster versions force a workspace dependency bump. Older clusters cannot build.
- Fix approach: Acceptable for now — track upstream k8s-openapi releases and bump as part of the release runbook.

**Hardcoded PostgreSQL pool size:**
- Issue: `PgPoolOptions::new().max_connections(20)` is compile-time fixed; no env override.
- Files: `crates/enclava-api/src/db/pool.rs:7`
- Impact: Cannot tune pool size for production without code change. A single API process caps at 20 concurrent DB queries.
- Fix approach: Read `DATABASE_POOL_MAX` env var with default 20, validate at startup.

## Known Bugs

**`/apps/{name}/logs` returns `501 NOT_IMPLEMENTED`:**
- Symptoms: `enclava logs` and any client hitting `GET /apps/{name}/logs` get a `logs_unavailable` JSON body with HTTP 501.
- Files: `crates/enclava-api/src/routes/status.rs:111-146`, route wired in `crates/enclava-api/src/lib.rs:368`, README `README.md:39-40` documents this explicitly.
- Trigger: Always — the Kubernetes log proxy is not yet wired.
- Workaround: Use `enclava status` or query the cluster directly.

**AMD SNP report parser returns a fixed error:**
- Symptoms: `enclava_cli::attestation::ParsedSnpReport::from_bytes` cannot be constructed from raw bytes; consumers must inject a pre-parsed report.
- Files: `crates/enclava-cli/src/attestation.rs:55-59` (`AttestationError::AmdSnpParsingUnavailable`)
- Trigger: Any caller that tries to parse an AMD SNP attestation report byte-for-byte from the CLI crate.
- Workaround: Tests and upstream callers construct `ParsedSnpReport` directly via the test-only constructor. Production attestation verification happens inside `enclava-init` (not the CLI crate).

**Background deploy task loses in-flight state on process restart:**
- Symptoms: A deployment that is mid-apply (status `applying` or `watching`) when the API process crashes will stay in that status until manual intervention.
- Files: `crates/enclava-api/src/routes/deployments.rs:813`, `crates/enclava-api/src/routes/unlock.rs:783` — both `tokio::spawn` a detached task that updates `deployments.status` only on success or failure of `apply_deployment_manifests`. No supervisor reattaches.
- Trigger: API pod restart, panic in the spawned task, OOM kill.
- Workaround: Operator manually marks the deployment `failed` and re-triggers. No reconciliation loop exists.
- Fix approach: Add a startup reconciliation pass that scans `deployments WHERE status IN ('applying','watching') AND updated_at < now() - interval '5 minutes'` and either resumes the watch or marks `failed`.

## Security Considerations

**Debug-bypass env vars only rejected in release builds:**
- Risk: A debug build accidentally promoted to production would accept `SKIP_COSIGN_VERIFY`, `ALLOW_EPHEMERAL_KEYS`, `TENANT_TEE_ACCEPT_INVALID_CERTS`, `LEGACY_BOOTSTRAP_SCRIPT`, plain-HTTP `TRUSTEE_KBS_URL`, and `TENANT_TEE_TLS_MODE=insecure`.
- Files: `crates/enclava-api/src/env_gates.rs:22-29,75-134`
- Current mitigation: `cfg!(debug_assertions)` gate; CI builds the `prod-strict` feature set in `release` mode (`.github/workflows/ci.yml:130-148`). Production deploys use the release binary.
- Recommendations: Add a defence-in-depth check that refuses to start if `ALLOW_EPHEMERAL_KEYS=1` regardless of build mode when `DATABASE_URL` points outside loopback / private ranges.

**Static `deploy/api` overlay ships placeholder secret references:**
- Risk: The committed overlay is a starting point. Operators who apply it without replacing secret references will get broken or empty env vars.
- Files: `deploy/api/{deployment,ingress,kustomization,namespace,service}.yaml`, documented in `DEPLOYMENT.md:31-34,135-141`
- Current mitigation: `DEPLOYMENT.md` explicitly calls out the replacement requirement; env gates fail closed at API startup.
- Recommendations: Add a `kustomize build deploy/api | opencode-conftest test` policy in CI that fails on placeholder secret names.

**AMD SNP VCEK certificate chain is not verified end-to-end:**
- Risk: The attestation verifier accepts `AmdSnpChainStatus::CertChainUnavailable` as a valid terminal state. Firmware measurement, host data, and report data are checked, but the VCEK chain that authenticates the report signature is not.
- Files: `crates/enclava-cli/src/attestation.rs:48-52,83-86` (`AmdSnpChainStatus::CertChainUnavailable`, `AttestationError::AmdChain`)
- Current mitigation: `enclava-init` performs its own in-TEE verification via `crates/enclava-init/src/trustee_verify.rs`; CAP itself does not gate deploys on a verified AMD chain.
- Recommendations: Wire the `sev` crate VCEK verifier in `crates/enclava-cli/src/attestation.rs` and require `AmdSnpChainStatus::Valid` before accepting attestation bundles. Track this as a security-hardening phase.

**`unsafe` blocks around raw Linux syscalls in `enclava-init` namespace bind:**
- Risk: `open_tree(2)` / `move_mount(2)` are invoked through `libc::syscall` with manually constructed `OwnedFd` wrappers. A bug here corrupts the bind-mount graph inside the TEE.
- Files: `crates/enclava-init/src/main/namespace_bind.rs:561-598`
- Current mitigation: Each `unsafe` block has a SAFETY comment justifying the invariant; tests at `crates/enclava-init/src/main/tests/mod.rs:105-150` exercise `paths_resolve_to_same_object` and the bind-mount plan.
- Recommendations: Audit with `cargo miri` once the target supports it; pin the `libc` constants behind a kernel-version assertion.

**`unsafe` std::env::set_var in tests (Rust 2024 edition):**
- Risk: Tests in `crates/enclava-cli/src/keys.rs:484`, `crates/enclava-api/src/cosign.rs:677,709,729,818`, `crates/enclava-api/tests/integration_test.rs:46`, `crates/enclava-cli/tests/manual_cli_mvp_test.rs:18,51`, `crates/enclava-cli/src/tee_client/tests/mod.rs:102,107,115`, `crates/enclava-init/src/main/tests/mod.rs:23,37` mutate process-global env vars under `unsafe`. The 2024 edition makes this explicit-unsafe because it can race with concurrent reads.
- Files: see above
- Current mitigation: Tests are serialised by an internal `static HOME_LOCK: Mutex<()>` in `crates/enclava-cli/src/keys.rs:478`. Other tests assume single-threaded execution.
- Recommendations: Switch env-mutating tests to `temp-env` or a per-test subprocess. Required before adding parallel test harnesses.

## Performance Bottlenecks

**Unbounded `fetch_all` list queries:**
- Problem: Several list endpoints call `fetch_all` without a `LIMIT` clause. Large orgs will return arbitrarily large result sets in a single round-trip.
- Files: `crates/enclava-api/src/routes/apps.rs:595` (`list_apps` — all apps in org), `crates/enclava-api/src/routes/internal.rs:957,1033,1080,1149` (`list_paas_apps`, `list_paas_deployments`, `list_paas_status`, `list_paas_members`), `crates/enclava-api/src/routes/orgs.rs:130,714` (`list_orgs`, `list_members`), `crates/enclava-api/src/routes/users.rs:62`, `crates/enclava-api/src/routes/config.rs:141`, `crates/enclava-api/src/kbs.rs:212,222,292`
- Cause: No pagination pattern in the codebase. The only `LIMIT` clauses are on point lookups (`LIMIT 1`) and `deployment_history` (`LIMIT 50` at `crates/enclava-api/src/routes/deployments.rs:917`).
- Improvement path: Add cursor-based pagination (`?after=ID&limit=N`) for list endpoints; cap default page size at 100; reject explicit `limit > 500`.

**Per-process apply semaphore defaults to 1:**
- Problem: `CAP_MAX_CONCURRENT_APPLIES` defaults to `1`, serialising all deploys through a single permit per API process.
- Files: `crates/enclava-api/src/main.rs:707-715`, permit acquired in `crates/enclava-api/src/routes/deployments.rs:814` and `crates/enclava-api/src/routes/unlock.rs:784`
- Cause: Intentional backpressure — applying a CAP deployment starts a Kata VM and attaches Longhorn volumes; bursts overwhelm a single worker node before Kubernetes has useful feedback. Documented at `crates/enclava-api/src/state.rs:197-200`.
- Improvement path: Acceptable default. Operators can raise the limit when cluster headroom is verified. Document the trade-off in `DEPLOYMENT.md`.

**Cosign verification performs TUF/network fetches when no bundled root is configured:**
- Problem: Without `SIGSTORE_TUF_ROOT_PATH`, the verifier falls back to the public Sigstore TUF root and performs a network fetch on every verification.
- Files: `crates/enclava-api/src/cosign.rs:14-23`
- Cause: Dev convenience; production is expected to ship a pinned `trusted_root.json` with the release.
- Improvement path: Cache the resolved trust root in `AppState` at startup rather than resolving it per call.

**`map_err(|_| db_error())` drops underlying DB error context from logs:**
- Problem: Roughly 100+ call sites convert `sqlx::Error` to a generic JSON 500 response without logging the original error. Operators cannot diagnose DB failures from API logs alone.
- Files: Throughout `crates/enclava-api/src/routes/{apps,auth,deployments,domains,internal,orgs,unlock,users,config}.rs` and `crates/enclava-api/src/auth/{middleware,scopes}.rs`. Representative samples: `crates/enclava-api/src/routes/internal.rs:290,306,344,375,390,428,445,484,496,504,513,524,546,567,618,647,675,713,726,804,854,922,929,972,1035,1082,1151`, `crates/enclava-api/src/routes/orgs.rs:333,415,435,469,517,563,611,629,638,650,670,672,698,716,749,760,771,788,802,804`
- Cause: Pattern chosen for security (avoid leaking internals to clients) without the corresponding `tracing::error!` on the server side.
- Improvement path: Introduce a `fn db_err(e: sqlx::Error) -> Response { tracing::error!(error = %e, "db"); generic_response() }` helper and replace the closures. Tracked as a mechanical refactor.

## Fragile Areas

**PaaS internal route surface (`crates/enclava-api/src/routes/internal.rs`, 1734 LOC):**
- Files: `crates/enclava-api/src/routes/internal.rs`, route wiring `crates/enclava-api/src/lib.rs:61-182`
- Why fragile: Single file holds every PaaS-internal sync endpoint (org/member/entitlement/app/deploy/signer/domain/config/unlock) plus hand-rolled idempotency (`begin_idempotent_request`, `idempotency_key`, `commit_idempotent_response` at `:248-320`). Auth is multi-stage (bearer token + trusted-proxy header + client SAN). Bug surface is large.
- Safe modification: Read `InternalAuth::from_request_parts` (`:52-104`) before touching any handler. Always use `begin_idempotent_request` for mutating endpoints. Add a test to `crates/enclava-api/tests/integration_test.rs` for any new internal route.
- Test coverage: Integration tests at `crates/enclava-api/tests/integration_test.rs:440-660` exercise the PaaS sync flow against a live PostgreSQL instance; they do not cover every handler.

**Hosted Debian SSH template CLI flow (`crates/enclava-cli/src/commands/template.rs`, 3591 LOC):**
- Files: `crates/enclava-cli/src/commands/template.rs`
- Why fragile: Encodes the full stable-SSH-endpoint contract — endpoint reservation, config delivery retries, polling, JSON output shape, `--ngrok-tcp-url` alias, ngrok/frp template selection. Contract is pinned by `scripts/test-stable-ssh-cli.sh`.
- Safe modification: Run `scripts/test-stable-ssh-cli.sh` before merging any change. Preserve the exact JSON keys (`stable_ssh_endpoint`, `stable_endpoint`, `command`, `endpoint`, `app_url`).
- Test coverage: `crates/enclava-cli/src/commands/template.rs:1901-2700` contains the inline test module covering CLI arg parsing, JSON shape, and idempotency-key behaviour.

**In-TEE init flow (`crates/enclava-init/src/main.rs`, 992 LOC):**
- Files: `crates/enclava-init/src/main.rs`, `crates/enclava-init/src/main/namespace_bind.rs:1-635`, `crates/enclava-init/src/trustee_verify.rs`
- Why fragile: Runs once per pod startup inside the SEV-SNP guest. Any failure blocks workload startup. Manual config-vs-signed-cc_init_data matching (`require_signed_config_match`, `require_optional_signed_config_match`, `require_optional_signed_string_list_match` at `:407-489`) is brittle to field renames.
- Safe modification: Add a test in `crates/enclava-init/src/main/tests/mod.rs` for any new `cc_init_data` claim. Run `cargo test -p enclava-init --lib` (requires `libcryptsetup-dev`).
- Test coverage: Comprehensive unit tests for the verification chain, namespace binding, and LUKS path. Live SEV-SNP validation is documented in `runbooks/cap-hermes-proof.md` and `scripts/cap_hermes_proof.py`.

**Cosign verification with bundled TUF root (`crates/enclava-api/src/cosign.rs`, 833 LOC):**
- Files: `crates/enclava-api/src/cosign.rs`
- Why fragile: Trust root pinning depends on a `trusted_root.json` shipped with the release artifact (`SIGSTORE_TUF_ROOT_PATH`). Without it, every verification hits the public Sigstore TUF repo. Verification policies (Fulcio URL, email, raw public key) must match how the customer actually signs.
- Safe modification: Add a test in the inline `tests` module (line 633+). Bump `Cargo.toml`'s `sigstore` workspace dep deliberately — it pulls in new TUF roots.
- Test coverage: Inline tests cover constraint building, policy parsing, env var fallbacks; live cosign verification is exercised in `crates/enclava-api/tests/integration_test.rs`.

**Detached deployment spawn (`tokio::spawn` in deploy routes):**
- Files: `crates/enclava-api/src/routes/deployments.rs:813-873`, `crates/enclava-api/src/routes/unlock.rs:783-843`
- Why fragile: Apply work runs on the tokio multi-threaded runtime detached from the request. Failures are caught and recorded in DB, but panics in third-party code (kube, reqwest) would terminate only the task; the deployment row would stay `applying`.
- Safe modification: Wrap the spawned future in `std::panic::catch_unwind` or use `tokio::task::JoinHandle::is_panicked` checking. Always pair a status update with the spawned task.
- Test coverage: No test asserts the failure-recording path inside the spawn. Add a test that injects a failing `apply_deployment_manifests` and verifies the deployment row becomes `failed`.

## Scaling Limits

**Single-process apply concurrency:**
- Current capacity: `CAP_MAX_CONCURRENT_APPLIES` defaults to `1` per API process.
- Limit: Cluster-wide throughput equals `N_API_PODS * CAP_MAX_CONCURRENT_APPLIES`. Default deploy of `deploy/api/deployment.yaml` is a single replica.
- Scaling path: Horizontally scale API pods first (stateless), then raise `CAP_MAX_CONCURRENT_APPLIES` once cluster headroom is verified. Apply work is Kubernetes-API-bound, not CPU-bound.

**PostgreSQL pool:**
- Current capacity: 20 connections per API process (`crates/enclava-api/src/db/pool.rs:7`).
- Limit: With multiple API pods, total DB connections equal `N_PODS * 20`. PgBouncer in transaction-pooling mode is not configured.
- Scaling path: Add `DATABASE_POOL_MAX` env knob; deploy PgBouncer sidecar or shared pooler.

**Migrations run on every API startup:**
- Current capacity: `run_migrations` (`crates/enclava-api/src/db/pool.rs:13`) executes `sqlx::migrate!("./migrations").run(pool)` at startup.
- Limit: Concurrent API pod startup races on migration locks. Ad-hvisory locks from sqlx serialize this, but a long migration blocks all replicas from serving traffic.
- Scaling path: Move migrations to an init job (`crates/enclava-api/src/bin/migrate_two_hostnames.rs` already exists as a precedent) and have API pods only verify schema is current.

## Dependencies at Risk

**`rsa 0.9.x` (RUSTSEC-2023-0071) — ignored advisory:**
- Risk: Marlin vulnerability in the `rsa` crate. CAP does not perform RSA private-key operations, but the crate is pulled in transitively through `sigstore`/`openidconnect`.
- Impact: If a future sigstore release moves to a vulnerable code path, advisory noise hides real issues. CI ignores this advisory at `.github/workflows/ci.yml:88-91` and `deny.toml:5`.
- Migration plan: Revisit when `sigstore` moves off `openidconnect`/`rsa 0.9.x`. Subscribe to the upstream issue; remove the ignore line in both `ci.yml` and `deny.toml` once fixed.

**`sigstore 0.14`:**
- Risk: Carries the bundled TUF root and Fulcio/Rekor verifiers. A breaking change in sigstore's verification model would invalidate existing app pins.
- Impact: Cosign verification in `crates/enclava-api/src/cosign.rs` is tightly coupled to sigstore's `CosignCapabilities`, `VerificationConstraintVec`, and `SigstoreTrustRoot` APIs.
- Migration plan: Bump deliberately as part of the release runbook; re-bundle `trusted_root.json`; re-run `scripts/nutshell-fast-contract.sh`.

**`libcryptsetup` system dependency for `enclava-init`:**
- Risk: Link-time requirement. `cargo build --workspace` fails on hosts without `libcryptsetup-dev`.
- Impact: Documented at `README.md:147-149` and `DEV.md:14-20`; CI installs it explicitly at `.github/workflows/ci.yml:36-37,103-106`.
- Migration plan: Acceptable. Pre-built `enclava-init` image is published by `.github/workflows/enclava-init-image.yml`. Developers exclude the crate locally when not needed.

**`sev 7.1.0` for AMD SNP parsing:**
- Risk: Pinned in `crates/enclava-cli/Cargo.toml`. The CLI's `attestation.rs` only uses `sev::parser::ByteParser` and explicitly does not wire VCEK verification.
- Impact: If the SNP report layout changes (new firmware), the parser may need an upstream bump.
- Migration plan: Track upstream `sev` crate; wire VCEK verification when adding `AmdSnpChainStatus::Valid` enforcement (see Security section).

## Missing Critical Features

**Live log streaming:**
- Problem: `GET /apps/{name}/logs` returns 501. There is no Kubernetes log proxy.
- Blocks: Operators and users cannot read workload logs through CAP. Must SSH into the TEE or use `kubectl` directly.
- Files: `crates/enclava-api/src/routes/status.rs:111-146`

**Deployment reconciliation on API startup:**
- Problem: No background task scans for stuck `applying`/`watching` deployments. A crashed apply leaves the row stuck.
- Blocks: Self-healing after API pod restart. Operators must manually mark rows `failed`.
- Files: `crates/enclava-api/src/main.rs:640-785` (startup), `crates/enclava-api/src/routes/deployments.rs:813` (spawn)

**Production Kubernetes overlay:**
- Problem: `deploy/api/` is intentionally minimal. No production-ready overlay with RBAC, PodDisruptionBudget, HorizontalPodAutoscaler, network policies, or secret references.
- Blocks: Out-of-the-box production deployment. Every operator must re-derive the production shape.
- Files: `deploy/api/{deployment,ingress,kustomization,namespace,service}.yaml`

**PgBouncer / connection pooler support:**
- Problem: Each API pod opens up to 20 direct PostgreSQL connections. There is no documented pooler.
- Blocks: Scaling beyond ~5 API pods against a single Postgres instance.
- Files: `crates/enclava-api/src/db/pool.rs`

**VCEK certificate chain verification:**
- Problem: `AmdSnpChainStatus::CertChainUnavailable` is accepted. CAP relies on `enclava-init` in-TEE verification instead of doing it server-side.
- Blocks: Defence-in-depth on attestation verification.
- Files: `crates/enclava-cli/src/attestation.rs:48-52,83-86`

## Test Coverage Gaps

**Live-PostgreSQL integration tests:**
- What's not tested: Any test in `crates/enclava-api/tests/integration_test.rs` (1747 LOC) requires `DATABASE_URL` to point at a live PostgreSQL. CI runs them; local devs often skip.
- Files: `crates/enclava-api/tests/integration_test.rs`
- Risk: Local refactors pass `cargo test -p enclava-api --lib` but break the integration suite. CI catches this; pre-push does not.
- Priority: Medium

**Background deploy failure-recording path:**
- What's not tested: The `tokio::spawn` block in `crates/enclava-api/src/routes/deployments.rs:813-873` records failure to DB when `apply_deployment_manifests` returns Err. No test injects a failure and verifies the deployment row becomes `failed`.
- Files: `crates/enclava-api/src/routes/deployments.rs:813`, `crates/enclava-api/src/routes/unlock.rs:783`
- Risk: A regression in the failure-recording path leaves deployments stuck in `applying` after an apply failure.
- Priority: High

**`enclava-init` LUKS integration tests behind a feature flag:**
- What's not tested: `luks-integration` feature is excluded from `prod-strict` builds (`.github/workflows/ci.yml:146-148`). LUKS format/open is exercised at `crates/enclava-init/src/luks.rs:444` but only on hosts with `libcryptsetup` installed.
- Files: `crates/enclava-init/src/luks.rs:444-468`, `crates/enclava-init/Cargo.toml`
- Risk: A refactor that breaks LUKS on a real guest image passes CI on hosts without libcryptsetup.
- Priority: Medium

**Cosign live-verification path:**
- What's not tested: Inline tests in `crates/enclava-api/src/cosign.rs:633-833` cover policy construction and constraint building. They do not exercise actual signature verification against a real signed image.
- Files: `crates/enclava-api/src/cosign.rs`
- Risk: A sigstore bump that breaks verification passes unit tests and only fails at deploy time.
- Priority: Medium — covered partially by `scripts/nutshell-fast-contract.sh` smoke tests.

**PaaS internal route coverage:**
- What's not tested: `crates/enclava-api/src/routes/internal.rs` has 1734 lines and ~25 handlers. Integration tests cover the org/member/entitlement sync flow but not every handler (e.g., `register_paas_public_key`, `bootstrap_paas_keyring_signing_service`, `generate_paas_agent_policy` have no direct integration test).
- Files: `crates/enclava-api/src/routes/internal.rs`, `crates/enclava-api/src/lib.rs:61-182`
- Risk: A scope leak or idempotency bug in an untested handler ships to production.
- Priority: Medium

**Trusted proxy rate-limit key extraction in production-shape deployments:**
- What's not tested: `TrustedProxyKeyExtractor` unit tests cover the matcher logic (`crates/enclava-api/src/ratelimit.rs:155-212`) but not the interaction with `tower_governor` under real load. No test asserts that production-shaped deployments correctly configure `TRUSTED_PROXY_CIDRS`.
- Files: `crates/enclava-api/src/ratelimit.rs`, `deploy/api/deployment.yaml`
- Risk: Operators who forget `TRUSTED_PROXY_CIDRS` get rate limiting keyed by direct peer (the load balancer), which collapses all tenants into one bucket.
- Priority: Low

---

*Concerns audit: 2026-06-28*
