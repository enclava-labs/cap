# Testing Patterns

**Analysis Date:** 2026-06-28

## Test Framework

**Runner:**
- Built-in Rust test harness (`#[test]`, `#[tokio::test]`).
- No external test runner (`nextest`, `cargo-test-types`) is configured.
- Doctests run via `cargo test --doc` (CI step in
  `/.github/workflows/ci.yml` line 71).
- Python tests use stdlib `unittest` and `pytest`
  (`/home/user/platform/cap/tests/test_cap_hermes_proof.py`,
  `/home/user/platform/cap/tests/test_generate_platform_release.py`).

**Assertion Library:**
- Standard `assert!`, `assert_eq!`, `assert_ne!`, `assert_matches!`.
- HTTP integration assertions via `axum_test::{TestServer, TestRequest}`
  (`assert_status_ok()`, `assert_status(StatusCode::...)`,
  `assert_text(...)`).
- Python tests use `unittest.TestCase` assertions and
  `pytest.raises(...)`.

**Run Commands** (canonical source: `DEV.md` and
`/.github/workflows/ci.yml`):
```bash
cargo fmt --all -- --check                              # formatting gate
cargo clippy --workspace --all-targets -- -D warnings   # lint gate
cargo test --workspace --all-features                   # full test suite
cargo test --workspace --exclude enclava-init           # without libcryptsetup
cargo test --doc                                        # doctests
cargo test -p enclava-api --lib                         # API unit tests only
cargo test -p enclava-cli                               # CLI tests only
cargo test -p enclava-engine                            # engine tests only
cargo test -p enclava-cli stable_ssh                    # stable-SSH filter
cargo test -p enclava-engine -- --ignored               # cluster-required tests
python3 -m pytest tests/test_cap_hermes_proof.py        # cross-lang CE-v1
                                                        #  hash cross-check
scripts/test-stable-ssh-cli.sh                          # stable SSH contract
scripts/test-ci-workflow.sh                             # CI YAML invariants
scripts/nutshell-fast-contract.sh                       # pre-push contract gate
```

CI also installs `pkg-config libcryptsetup-dev clang libclang-dev` to
build `enclava-init` (`/.github/workflows/ci.yml` lines 34–37).

## Test File Organization

**Location:** Three co-located patterns, used consistently:

1. **Inline `#[cfg(test)] mod tests` at the bottom of each source file**
   for unit tests of that module's internals. This is the dominant
   pattern (~77 files). Exemplars:
   - `crates/enclava-common/src/validate.rs` lines 155–386.
   - `crates/enclava-api/src/auth/scopes.rs` lines 152–268.
   - `crates/enclava-api/src/env_gates.rs` lines 136–326.
   - `crates/enclava-api/src/routes/status.rs` lines 148–172.

2. **In-crate `tests/` sub-directory with `mod.rs`** for tests that
   exercise a parent module's private items but span multiple files /
   need their own fixtures:
   - `crates/enclava-api/src/routes/apps/tests/mod.rs`
   - `crates/enclava-api/src/routes/deployments/tests/classifier.rs`
   - `crates/enclava-api/src/signing_service/tests/mod.rs`
   - `crates/enclava-cli/src/commands/app/tests/mod.rs`
   - `crates/enclava-cli/src/tee_client/tests/mod.rs`
   - `crates/enclava-init/src/trustee_verify/tests/mod.rs`
   - `crates/enclava-init/src/main/tests/`

3. **Crate-level `tests/` directory** for integration tests that exercise
   public APIs only:
   - `crates/enclava-api/tests/integration_test.rs` (1747 lines).
   - `crates/enclava-cli/tests/{api_client_test,api_contract_test,
     config_test,app_config_test,init_test,deploy_artifacts_test,
     descriptor_vectors,attestation_test,tee_client_test,
     manual_cli_mvp_test}.rs`.
   - `crates/enclava-engine/tests/{manifest_*,apply_*,validate_test,
     types_test}.rs` (35+ files).
   - `crates/enclava-common/tests/{crypto_test,image_test}.rs`.

**Naming:**
- Source modules: `foo.rs` → tests for it appear either inline or in
  `tests/foo_test.rs` (crate-level) — note the `_test.rs` suffix.
- Test binaries under `tests/` use snake_case ending in `_test.rs` or
  describe their scope (`descriptor_vectors.rs`,
  `manual_cli_mvp_test.rs`).
- Cluster-required integration tests live in the same file but are
  tagged `#[ignore]` so `cargo test` skips them unless `--ignored`
  is passed (see `crates/enclava-engine/tests/apply_statefulset_test.rs`).

**Structure** (typical engine test tree):
```
crates/enclava-engine/
├── src/
│   └── testutil.rs                          # gated behind feature "testutil"
└── tests/
    ├── fixtures/
    │   ├── phase12_manifest_security_snapshot.json
    │   ├── descriptor_canonical_v1.bin
    │   ├── descriptor_core_canonical_v1.bin
    │   └── descriptor_core_hash_v1.hex
    ├── manifest_service_test.rs
    ├── manifest_statefulset_test.rs
    ├── apply_statefulset_test.rs            # #[ignore] cluster tests
    └── ... (35+ manifest_*.rs and apply_*.rs)
```

## Test Structure

**Suite Organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;                            // bring parent items in

    #[test]
    fn dns_label_accepts_valid() {           // snake_case test name
        assert!(validate_dns_label("a").is_ok());
        assert!(validate_dns_label("app1").is_ok());
    }

    #[test]
    fn dns_label_rejects_unicode_and_rtl_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — visual spoofing vector
        assert!(validate_dns_label("a\u{202E}b").is_err());
        // Cyrillic 'а' (U+0430) mimicking Latin 'a'
        assert!(validate_dns_label("\u{0430}pp").is_err());
    }
}
```
(From `crates/enclava-common/src/validate.rs`.)

**Naming convention:**
- Test fns are `snake_case` and read as a behavioural assertion:
  `<subject>_<condition>_<expected>` — e.g.
  `admin_cannot_grant_or_remove_owner_role`,
  `release_rejects_skip_cosign_verify`,
  `manifest_hash_changes_when_enclava_init_configmap_changes`,
  `dns_label_accepts_all_digits`. These names are grep targets —
  `scripts/test-stable-ssh-cli.sh` filters by substring:
  `cargo test --locked -p enclava-cli stable_ssh`.

**Patterns:**
- **Setup / teardown:** Minimal. Tests construct their inputs inline.
  When DB or state is needed, call a helper:
  - `crate::test_support::lazy_state()` / `auth_context(role, &scopes)`
    (`crates/enclava-api/src/lib.rs` lines 484–569).
  - `setup_test_state()` / `setup_test_db()`
    (`crates/enclava-api/tests/integration_test.rs` lines 26–113).
  - `tempfile::tempdir()` for filesystem isolation
    (`crates/enclava-cli/tests/config_test.rs` line 5).
- **Assertion:** `assert!(...)` / `assert_eq!(...)` /
  `assert_matches!(err, EnvGateError::DebugOnlyFlagInRelease("..."))`.
- **Comment-first intent:** Many tests start with a comment explaining
  *what attack / invariant is being prevented* — see
  `crates/enclava-common/src/validate.rs` lines 202–206, 222–226.

## Mocking

**Framework:** No general-purpose mocking framework (`mockall`, etc.) is
in use. The codebase favours:

1. **Real fakes via in-process TCP** — CLI API client tests stand up a
   raw `std::net::TcpListener` on `127.0.0.1:0`, capture the request
   bytes, and write a hand-crafted HTTP response:
   ```rust
   let listener = TcpListener::bind("127.0.0.1:0").unwrap();
   let addr = listener.local_addr().unwrap();
   let handle = std::thread::spawn(move || {
       let (mut stream, _) = listener.accept().unwrap();
       let mut buf = [0u8; 4096];
       let n = stream.read(&mut buf).unwrap();
       stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
       String::from_utf8_lossy(&buf[..n]).to_string()
   });
   let client = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
   client.sync_config_key("demo/shell", "P0_KEY", false).await.unwrap();
   let request = handle.join().unwrap();
   assert!(request.starts_with("POST /apps/demo%2Fshell/config/sync "));
   assert!(request.contains("authorization: Bearer test-token"));
   ```
   (See `crates/enclava-cli/tests/api_client_test.rs` lines 54–79.)

2. **Lazy DB pools for unit tests** — `PgPoolOptions::new()
   .connect_lazy("postgresql://test:test@localhost:5432/test")` so unit
   tests that go through a handler can exercise the authorization path
   without a real DB (`crates/enclava-api/src/lib.rs` lines 518–521).
   The DB call itself fails after authorization has already returned
   `FORBIDDEN` — which is what the test asserts.

3. **`AppState` injection** — `AppState` is constructed by hand in
   `setup_test_state_with_mode(...)` with throwaway signing/HMAC keys
   (`crates/enclava-api/tests/integration_test.rs` lines 42–113). The
   test then builds a router with `test_router(state)` (rate limits
   disabled, see `crates/enclava-api/src/lib.rs` lines 478–481) and
   drives it with `axum_test::TestServer`.

4. **Env-injection for env-gate tests** — `enforce_with(debug, lookup)`
   takes an `impl Fn(&str) -> Option<String>` so tests can pass a
   `HashMap` instead of mutating process env
   (`crates/enclava-api/src/env_gates.rs` lines 75–77, 148–150).

**What to Mock:**
- Outbound HTTP from the CLI (`ApiClient`) — fake TCP listener.
- Env vars — `HashMap`-based lookup closure.
- Time — where time matters, accept it as a function parameter.

**What NOT to Mock:**
- The DB. Integration tests in `crates/enclava-api/tests/` run against
  a real Postgres service in CI (`/.github/workflows/ci.yml`
  lines 16–29) and apply real migrations with `sqlx::migrate!`.
- Kubernetes. Cluster tests are `#[ignore]`-tagged and run via
  `cargo test -- --ignored` against a real cluster
  (`crates/enclava-engine/tests/apply_statefulset_test.rs`).
- `subtle::ConstantTimeEq`. Token comparisons must use the real
  constant-time primitive.

## Fixtures and Factories

**Factories live in `src/testutil.rs`, gated behind `feature = "testutil"`.**

`crates/enclava-engine/src/testutil.rs` exports:
- `pub const TEST_PUBKEY_HASH: &str = "aabb...";`
- `pub fn sample_app() -> ConfidentialApp` — a fully populated
  auto-unlock-mode app with a deterministic UUID, namespace, and a
  digest-pinned test image.
- `pub fn sample_password_app() -> ConfidentialApp` — same app flipped
  to `UnlockMode::Password`.

`testutil` is **not** part of release builds: the `prod-strict` feature
mutually excludes it (`crates/enclava-engine/src/lib.rs` lines 1–2),
and CI verifies the exclusion in
`/.github/workflows/ci.yml` lines 140–148.

**Test-support for in-crate tests** lives in
`crates/enclava-api/src/lib.rs` lines 483–569 as a
`#[cfg(test)] pub(crate) mod test_support`:
- `auth_context(role: Role, scopes: &[&str]) -> AuthContext`
  (deterministic UUIDs `1111...`, `2222...`, `3333...`).
- `lazy_state() -> AppState` — constructs an `AppState` with a lazy
  Postgres pool, an in-memory signing key, and a stub
  `AttestationConfig` with deterministic image digests.

**Test fixtures** on disk:
- `crates/enclava-engine/tests/fixtures/phase12_manifest_security_snapshot.json`
  — golden manifest snapshot loaded with `include_str!`
  (`crates/enclava-engine/tests/manifest_phase12_gate_test.rs` line 7).
- `crates/enclava-engine/tests/fixtures/descriptor_canonical_v1.bin`,
  `descriptor_core_canonical_v1.bin`, `descriptor_core_hash_v1.hex`
  — canonical-bytes fixtures shared with the in-TEE verifier.
- `crates/enclava-cli/tests/fixtures/` — CLI fixtures directory.
- `crates/enclava-cli/platform-release.json` — sample signed release
  payload consumed by Python tests.

**Per-test inline data:** Most tests construct `serde_json::json!({...})`
inline rather than reaching for an external fixture file. See
`crates/enclava-api/src/routes/apps/tests/mod.rs` lines 12–19.

## Coverage

**Requirements:** No enforced coverage percentage. CI gates are:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace` (with `DATABASE_URL` env)
- `cargo test --doc`
- `scripts/test-ci-workflow.sh`
- `scripts/test-stable-ssh-cli.sh`
- `cargo audit --ignore RUSTSEC-2023-0071`
- `cargo deny check advisories sources`

**Current scale:**
- ~77 `#[cfg(test)]` blocks across source files.
- ~752 `#[test]` functions, ~56 `#[tokio::test]` async functions.
- 51 `*_test.rs` / `tests/mod.rs` files under `tests/` directories.
- Rust source: 139 files under `src/`; 183 total `.rs` files
  (incl. tests).

**View Coverage:**
```bash
cargo install cargo-tarpaulin    # not run in CI today
cargo tarpaulin --workspace --exclude enclava-init --out Html
```

## Test Types

**Unit Tests:**
- Live inline at the bottom of source files. Fast (<1s each), no
  external dependencies. Cover pure functions (`validate_*`,
  `classify_rollout_result`, `effective_app_status`), parsers
  (`ImageRef::parse`), and authorization predicates
  (`require_app_write`, `require_owner_role`).

**Integration Tests (crate-level `tests/`):**
- Exercise the public API of a crate.
- API integration tests (`crates/enclava-api/tests/integration_test.rs`)
  require `DATABASE_URL=postgresql://test:test@localhost:5432/test`
  and run all SQLx migrations before each test.
- CLI tests either spin up a fake TCP server (no DB needed) or assert
  against in-memory types (`api_client_test.rs`, `config_test.rs`).
- Engine `manifest_*_test.rs` tests render Kubernetes manifests from a
  `sample_app()` and assert on the YAML / JSON output without a
  cluster.

**Cluster Tests (`#[ignore]`):**
- Tests that need a real Kubernetes cluster with the
  `kata-qemu-snp` runtime class are tagged `#[ignore]` and only run
  with `cargo test -- --ignored`. Example:
  `crates/enclava-engine/tests/apply_statefulset_test.rs`.

**Contract / Cross-Language Tests:**
- `tests/test_cap_hermes_proof.py` imports
  `scripts/cap_hermes_proof.py` and re-derives the CE-v1 canonical
  bytes / SHA-256 hash to ensure the Python helper stays byte-for-byte
  compatible with `crates/enclava-common/src/canonical.rs` /
  `crypto.rs`.
- `tests/test_generate_platform_release.py` validates the platform
  release payload validator against `crates/enclava-cli/platform-release.json`.

**Shell-driven contract suites:**
- `scripts/test-stable-ssh-cli.sh` runs a curated subset of
  `cargo test` invocations filtered by test-name substring (e.g.
  `cargo test --locked -p enclava-cli stable_ssh`) and asserts that
  each filter actually ran ≥1 passing test.
- `scripts/nutshell-fast-contract.sh` is the pre-push gate documented
  in `DEV.md` lines 102–111; it cross-validates a downstream Nutshell
  app contract and runs focused CLI + signing-service tests.
- `scripts/test-ci-workflow.sh` lints the CI YAML itself.

## Common Patterns

**Async Testing:**
```rust
#[tokio::test]
async fn health_endpoint_returns_ok() {
    let (state, _pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);

    let response = server
        .get("/health")
        .add_header("x-forwarded-for", "127.0.0.1")
        .await;

    response.assert_status_ok();
    response.assert_text("ok");
}
```
(From `crates/enclava-api/tests/integration_test.rs` lines 266–280.)

**Error Testing:**
```rust
#[test]
fn release_rejects_skip_cosign_verify() {
    let mut env = ok_required();
    env.insert("SKIP_COSIGN_VERIFY", "1");
    let err = run(env, false).unwrap_err();
    assert!(matches!(
        err,
        EnvGateError::DebugOnlyFlagInRelease("SKIP_COSIGN_VERIFY")
    ));
}
```
(From `crates/enclava-api/src/env_gates.rs` lines 152–161.)

**Authorization Pre-DB-Access Test (assert handler short-circuits):**
```rust
#[tokio::test]
async fn create_app_rejects_member_before_database_access() {
    let result = create_app(
        crate::test_support::auth_context(Role::Member, &[]),
        State(crate::test_support::lazy_state()),
        Json(CreateAppRequest { /* ... */ }),
    ).await;

    let err = match result {
        Ok(_) => panic!("member app creation unexpectedly passed authorization"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::FORBIDDEN);
}
```
(From `crates/enclava-api/src/routes/apps/tests/mod.rs` lines 92–114.)

**Source-text inspection test (locks in code-level invariants):**
```rust
#[test]
fn deploy_bootstrap_probe_attests_before_calling_claim_endpoint() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("async fn wait_for_bootstrap_endpoint")
        .expect("wait_for_bootstrap_endpoint exists");
    // ... ensure attest call occurs before challenge call ...
}
```
(From `crates/enclava-cli/src/commands/app/tests/mod.rs` lines 257–279.)
This pattern is used heavily in CLI tests to lock in operational
invariants that are hard to express via runtime assertions.

**Database integration setup pattern:**
```rust
async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let pool = sqlx::PgPool::connect(&database_url).await
        .expect("failed to connect to test db");
    sqlx::migrate!("./migrations").run(&pool).await
        .expect("migrations failed");
    pool
}
```
(From `crates/enclava-api/tests/integration_test.rs` lines 26–40.)
Migrations live in `crates/enclava-api/migrations/` and are applied
verbatim — never recreate schema inline in tests.

## Conventions for Adding New Tests

- **Unit tests for new logic go inline in the same source file.** Add a
  `#[cfg(test)] mod tests { use super::*; ... }` block at the bottom.
- **Name tests as behaviour assertions** (`<subject>_<condition>`).
  The grep-able name is the test's contract.
- **For new HTTP routes**, add at minimum:
  1. An inline unit test asserting authorization fails before DB
     access (use `crate::test_support::auth_context` +
     `lazy_state()`).
  2. A crate-level integration test in
     `crates/enclava-api/tests/integration_test.rs` that exercises
     the happy path end-to-end through `axum_test::TestServer`.
- **For new CLI commands or subcommands**, add a contract test under
  `crates/enclava-cli/tests/` that asserts the wire-level request
  shape (URL, method, headers, JSON body) via a fake TCP listener.
- **For new engine manifest fields**, add a golden-snapshot or
  explicit field-assertion test alongside the existing
  `crates/enclava-engine/tests/manifest_*_test.rs` files.
- **For new validator functions** in `crates/enclava-common/src/validate.rs`,
  follow the existing test structure: cover the accept case, each
  distinct rejection case (length, charset, leading/trailing char,
  homograph/RTL, path traversal, control chars), and any RFC
  carve-out.
- **Production bug fix?** "Add the failing test before changing the
  implementation" (`DEV.md` line 82).
- **Tests requiring a cluster** are tagged `#[ignore]` with a
  `/// Run with: cargo test -- --ignored` doc comment.

---

*Testing analysis: 2026-06-28*
