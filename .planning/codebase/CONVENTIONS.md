# Coding Conventions

**Analysis Date:** 2026-06-28

## Language & Edition

- **Rust 2024 edition**, MSRV 1.85 (`Cargo.toml` lines 13–14).
- Workspace resolver `"2"`; all dependencies are declared once at the workspace
  root in `/home/user/platform/cap/Cargo.toml` under `[workspace.dependencies]`
  and consumed from crates with `{ workspace = true }`. Do not pin versions
  per-crate.
- Modern Rust idioms are expected and enforced by clippy `-D warnings`
  (see `/.github/workflows/ci.yml` line 57): `let-else`, `let-chains`
  (`if let ... && ...`), `cfg!(debug_assertions)`, `std::sync::Arc` for
  shared state, `impl Fn(&str) -> Option<String>` for env-lookup injection.

## Naming Patterns

**Crates / packages:**
- Hyphenated, prefixed `enclava-*`:
  `enclava-common`, `enclava-api`, `enclava-cli`, `enclava-engine`,
  `enclava-init`, `enclava-wait-exec`.
- Binary names match the user-facing tool: `enclava`, `enclava-api`,
  `enclava-init`, `enclava-wait-exec`, `migrate-two-hostnames`.

**Library crate names:**
- Underscored for the `lib` name so imports read naturally:
  `enclava_api`, `enclava_cli`, `enclava_engine`, `enclava_common`,
  `enclava_init` (see `crates/enclava-*/Cargo.toml` `[lib] name = "..."`).

**Modules / files:**
- `snake_case` single-word where possible (`canonical.rs`, `crypto.rs`,
  `keyring.rs`, `descriptor.rs`, `ratelimit.rs`).
- Module decl in `lib.rs` / `mod.rs` matches the file stem exactly; no
  `#[path]` overrides.
- Sub-modules live either in `foo.rs` + `foo/` directory pattern, or
  entirely under `foo/mod.rs`. Examples:
  - `crates/enclava-api/src/routes/mod.rs` lists route modules
    (`auth`, `apps`, `deployments`, ...).
  - `crates/enclava-api/src/signing_service.rs` + sub-dir
    `signing_service/{keyring.rs, tests/mod.rs}`.

**Types / structs:**
- `UpperCamelCase`: `ConfidentialApp`, `DeploymentDescriptor`,
  `ImageRef`, `AppState`, `AuthContext`, `SigningServiceClient`,
  `PolicyEnvelope`, `CcInitDataClaims`.
- Deserialized JSON request/response DTOs are named `*Request` /
  `*Response`: `CreateAppRequest`, `AppStatusResponse`,
  `GenericDeploymentRequest`, `RotateSignerRequest`.

**Enums:**
- `UpperCamelCase` for type, `UpperCamelCase` for variants:
  `Role::{Owner, Admin, Member}`, `AppStatus::{Creating, Running, ...}`,
  `UnlockMode::{Auto, Password}`, `CosignError::VerificationFailed(...)`.
- Serde wire format is forced via `#[serde(rename_all = "lowercase")]`
  (most API enums) or `#[serde(rename_all = "kebab-case")]`
  (`Durability`, `BootstrapPolicy` in `crates/enclava-common/src/types.rs`).
- Postgres enums mirror serde: `#[sqlx(type_name = "role_enum",
  rename_all = "lowercase")]` (`crates/enclava-api/src/models.rs`).
- One-off per-variant overrides use individual `#[serde(rename = "...")]`
  / `#[sqlx(rename = "...")]` (e.g. `DeployStatus::RolledBack` →
  `"rolled_back"`).

**Functions / methods:**
- `snake_case`. Constructor convention is `new(...) -> Self`,
  `from_<source>(...)`, `from_env()` for factories reading env vars.
- Async functions are the default for anything touching IO, DB, HTTP, or
  Kubernetes. Marker: returns `impl Future` / is `async fn`.
- Public helpers exposed as `pub fn`; internal helpers stay private with
  `pub(crate)` only when needed by integration tests in the same crate.
- `require_*` for authorization checks that return `Result`
  (`require_admin`, `require_app_write`, `require_owner_role`).
- `validate_*` for pure input validators returning `Result<(), E>`
  (`validate_dns_label`, `validate_image_digest`).
- `is_*` / `has_*` for boolean predicates (`has_digest`, `is_api_key_candidate`).

**Constants:**
- `SCREAMING_SNAKE_CASE`: `TOKEN_ISSUER`, `SESSION_AUDIENCE`,
  `DEFAULT_READY_FILE`, `MAX_DNS_LABEL_LEN`, `TEST_PUBKEY_HASH`,
  `DEBUG_ONLY_FLAGS`.

**Variables / locals:**
- `snake_case`. Common shortenings accepted: `cfg`, `ctx`, `req`, `resp`,
  `db` (a `PgPool`), `tx` (a `Transaction`).

## Code Style

**Formatting:**
- Enforced by `rustfmt` with default style (no `rustfmt.toml` checked in).
- CI gate: `cargo fmt --all -- --check`
  (`/.github/workflows/ci.yml` line 54, `DEV.md` line 9).
- Run `cargo fmt --all` before committing; never hand-format.

**Linting:**
- Clippy is mandatory at `-D warnings` for the whole workspace
  (`/.github/workflows/ci.yml` line 57).
- Where a binary cannot be built on the CI host without a system lib
  (`enclava-init` needs `libcryptsetup-dev`), exclude explicitly:
  `cargo clippy --workspace --all-targets --exclude enclava-init -- -D warnings`
  (see `DEV.md` lines 14–20).

**Toolchain pins:**
- GitHub Actions use `dtolnay/rust-toolchain@...` with `components: rustfmt, clippy`
  pinned by SHA (`/.github/workflows/ci.yml` lines 39, 80, 108).
- Actions are pinned by SHA, not by tag, with the version in a comment.

**`prod-strict` feature contract:**
- Every shippable crate defines a `prod-strict` feature
  (`crates/enclava-{common,api,cli,engine,init}/Cargo.toml`).
- `prod-strict` MUST be mutually exclusive with test-only features.
  Enforced with `compile_error!`:
  - `crates/enclava-engine/src/lib.rs` lines 1–2:
    `compile_error!("prod-strict builds must not enable enclava-engine/testutil")`
  - `crates/enclava-init/src/lib.rs` lines 12–13: same pattern for
    `luks-integration`.
- CI verifies the mutual exclusion in
  `/.github/workflows/ci.yml` lines 140–148 (`Verify prod-strict rejects
  debug-only features` job).

## Import Organization

Imports are grouped and ordered as:

1. Third-party crates, alphabetical within the group (`anyhow`, `axum`,
   `chrono`, `clap`, `ed25519_dalek`, `serde`, `sqlx`, `tokio`, ...).
2. Workspace / internal crates (`enclava_common::...`,
   `enclava_engine::...`).
3. `crate::` and `super::` imports.
4. `std::` imports (style is mixed; many files put `std::` last, especially
   in `crates/enclava-api/src/main.rs`).

`use` statements use braced groups with `{}` and the natural rustfmt sort.
There are no path aliases (`#[macro_use] extern crate ...` is not used).

Examples to mimic:
- `crates/enclava-api/src/routes/status.rs` lines 1–14.
- `crates/enclava-cli/src/commands/app.rs` lines 1–34.
- `crates/enclava-api/src/lib.rs` lines 21–27.

## Module Structure

**`lib.rs` is the module index.** Only `pub mod ...;` declarations and a
handful of crate-level items. Examples: `crates/enclava-common/src/lib.rs`
(8 lines), `crates/enclava-cli/src/lib.rs` (11 lines),
`crates/enclava-engine/src/lib.rs` (10 lines).

**`mod.rs` is the directory index.** See
`crates/enclava-api/src/routes/mod.rs` (13 lines) and
`crates/enclava-api/src/auth/mod.rs` (7 lines).

**Route files** in `crates/enclava-api/src/routes/<feature>.rs` define:
- Request/response DTOs (`#[derive(Debug, Serialize, Deserialize)]`).
- Handler functions `pub async fn name(auth: AuthContext, State(state):
   State<AppState>, ...) -> Result<Json<T>, (StatusCode, Json<Value>)>`.
- A `#[cfg(test)] mod tests { ... }` block at the bottom for unit tests.

**CLI commands** in `crates/enclava-cli/src/commands/<name>.rs` define:
- A clap `#[derive(Args)]` / `#[derive(Subcommand)]` type.
- The async command implementation.
- Internal helpers `fn build_api_client()`, `fn parse_config_vars(...)`, etc.

## Error Handling

**Two complementary strategies, by layer:**

1. **Domain errors — `thiserror::Error` enums.**
   - Used in every library-shaped module: `cosign.rs`, `dns.rs`,
     `clients.rs`, `env_gates.rs`, `kbs.rs`, `edge.rs`, `registry.rs`,
     `source_provider.rs`, `auth/middleware.rs`, `validate.rs`,
     `image.rs`, `config.rs`, `keys.rs`, `keyring.rs`, `attestation.rs`,
     `tee_client.rs`, `descriptor.rs`, `platform_release.rs`,
     `crates/enclava-init/src/errors.rs`.
   - Pattern:
     ```rust
     #[derive(Debug, thiserror::Error)]
     pub enum CosignError {
         #[error("cosign verification failed: {0}")]
         VerificationFailed(String),
         #[error("HTTP error: {0}")]
         Http(#[from] reqwest::Error),
         // ...
     }
     ```
   - Variants carry a human-readable `#[error("...")]` message.
   - Use `#[from]` to forward `From` for upstream errors
     (`Http(#[from] reqwest::Error)`,
     `Io(#[from] std::io::Error)`).
   - Per-crate canonical result alias: `crates/enclava-init/src/errors.rs`
     defines `pub type Result<T> = std::result::Result<T, InitError>;`
     and the rest of the crate uses `Result<T>`.

2. **Application / binary layer — `anyhow::{Result, Error}`.**
   - Used in `crates/enclava-api/src/main.rs`,
     `crates/enclava-init/src/main.rs`, CLI command entrypoints in
     `crates/enclava-cli/src/commands/*.rs`, and orchestrators like
     `crates/enclava-api/src/deploy.rs` that span many subsystems.
   - Add context with `.with_context(|| format!("..."))` /
     `.context("...")` (see `crates/enclava-init/src/main.rs` line 79).
   - Bail with `anyhow::bail!("...")` or `anyhow::anyhow!("...")` for
     ad-hoc errors.

**HTTP handler error responses:**
- Axum handlers return `Result<Json<T>, (StatusCode, Json<serde_json::Value>)>`.
- Error body is always `serde_json::json!({ "error": "<machine-friendly code>" })`
  or `json!({ "error": "...", "reason": "...", "message": "..." })`.
- Examples: `crates/enclava-api/src/routes/status.rs` lines 41–50;
  `crates/enclava-api/src/routes/deployments.rs` lines 14–27
  (`deploy_blocked_response`).
- Helper constructors preferred: `forbidden(msg)`, `database_error()`,
  `error(status, msg)` in `crates/enclava-api/src/auth/scopes.rs` lines 13–23.
- Never leak internal error strings verbatim from `sqlx` or `reqwest`;
  collapse to `"database error"` / `"upstream error"`.

**Authorization result type:**
- `crates/enclava-api/src/auth/scopes.rs` exports
  `pub type AuthzError = (StatusCode, Json<serde_json::Value>);`
  and `pub type AuthzResult<T = ()> = Result<T, AuthzError>;`
- All auth checks return `AuthzResult` so handlers can use the `?`
  operator for early-exit authorization failures.

**Panics:**
- Avoid in library code.
- Acceptable in `main.rs` for unrecoverable startup config failures
  (`expect("DATABASE_URL must be set")`,
  `panic!("CAP_MANAGEMENT_MODE=paas_managed requires ...")`).
- Test bodies use `.unwrap()` / `.expect("...")` freely.

**Fail-closed security posture:**
- Comparisons of secrets, tokens, and digests use
  `subtle::ConstantTimeEq` / `ct_eq`, never `==`. Enforced in:
  - `crates/enclava-api/src/state.rs` line 115 (token lookup).
  - `crates/enclava-api/src/auth/api_key.rs` line 361 (API key compare).
  - `crates/enclava-api/src/routes/domains.rs` line 326 (DNS challenge).
  - `crates/enclava-init/src/trustee_verify.rs` line 124 (`ct_eq_hex`).
- Production startup refuses dangerous env flags via
  `enclava_api::env_gates::enforce_production_env_gates()`
  (`crates/enclava-api/src/env_gates.rs`). Same gate is duplicated in
  the CLI binary (`crates/enclava-cli/src/main.rs` lines 6–36) — keep
  the two lists synchronized when adding a debug-only flag.

## Logging

**Framework:** `tracing` + `tracing-subscriber` with structured fields.

**Patterns:**
- API: bootstrap in `crates/enclava-api/src/main.rs` lines 539–545:
  ```rust
  tracing_subscriber::registry()
      .with(EnvFilter::try_from_default_env()
          .unwrap_or_else(|_| "enclava_api=debug,tower_http=debug".into()))
      .with(tracing_subscriber::fmt::layer())
      .init();
  ```
- `enclava-init` uses `.json()` output and `.with_target(false)`
  (`crates/enclava-init/src/main.rs` lines 47–54).
- Per-request HTTP logging via `tower_http::trace::TraceLayer`
  (`crates/enclava-api/src/lib.rs` line 56).
- Structured fields, not string interpolation:
  ```rust
  tracing::info!(namespace = %ns_name, "step 1/5: namespace ready");
  tracing::error!(deployment_id = %deployment_id, error = %e,
                  "failed to record deployment result");
  ```
  (`crates/enclava-api/src/deploy.rs` lines 165, 1062). Use `%var` for
  `Display`, `?var` for `Debug`.

**CLI user output:**
- `println!` / `eprintln!` for human-facing CLI output
  (`crates/enclava-cli/src/commands/init.rs` lines 179–221).
- `indicatif::ProgressBar` for long-running deploy progress
  (`crates/enclava-cli/src/commands/app.rs` imports).
- `colored` crate for status highlighting
  (`crates/enclava-cli/Cargo.toml` line 29).
- Errors at CLI top level: `eprintln!("error: {e}"); std::process::exit(1);`
  (`crates/enclava-cli/src/main.rs` lines 45–48).

## Comments

**When to Comment:**
- Module purpose: every non-trivial `.rs` file starts with a `//!`
  inner doc comment explaining what the module owns and the
  invariants it preserves. See `crates/enclava-api/src/cosign.rs`
  lines 1–23, `crates/enclava-init/src/lib.rs` lines 1–10,
  `crates/enclava-common/src/validate.rs` lines 1–7,
  `crates/enclava-init/src/trustee_verify.rs` lines 1–17.
- Item docs (`///`) on all `pub` items: functions, structs, enum
  variants, fields where intent is non-obvious. Examples:
  `crates/enclava-api/src/auth/jwt.rs` lines 10–24,
  `crates/enclava-api/src/state.rs` lines 15–19.
- Why-comments on security-sensitive or surprising code. Example,
  `crates/enclava-common/src/validate.rs` lines 30–36 explains why
  all-digit DNS labels are accepted (RFC 1123 dropped the alpha rule).

**Phase / cross-team markers:**
- Use `TODO(phase-N-<area>): <action>` for unfinished work tracked
  against a known phase. Examples in
  `crates/enclava-cli/src/keyring.rs` line 320,
  `crates/enclava-cli/src/keys.rs` lines 6, 465,
  `crates/enclava-api/src/routes/apps.rs` line 1026.
- Keep marker text grep-friendly and consistent; the CI shell checks
  such as `scripts/test-stable-ssh-cli.sh` rely on stable test names
  that mirror the marker scope.

**JSDoc / TSDoc:** Not applicable (Rust codebase).

## Function Design

**Size:** Prefer many small named functions over long inline blocks.
`classify_rollout_result`, `effective_app_status`,
`confidential_status_url` in `crates/enclava-api/src/routes/status.rs`
and `crates/enclava-api/src/deploy.rs` lines 45–80 are exemplars: pure,
small, individually unit-testable.

**Parameters:**
- Axum extractors first (`auth: AuthContext`), then `State<AppState>`,
  then `Path<...>` / `Query<...>`, then `Json<T>` body. See
  `crates/enclava-api/src/routes/status.rs` lines 29–33.
- For >4 args, introduce a `*Input` struct (Rust 2024 favors this).

**Async:**
- IO functions are `async fn` and return `Result<..., E>`.
- Pure transforms (`classify_rollout_result`, `validate_*`,
  `effective_app_status`) are sync and side-effect free — and therefore
  unit-testable without a tokio runtime.

**Return values:**
- Return `Result<T, E>` for anything fallible.
- Return `impl IntoResponse` from Axum handlers when the response shape
  varies; return concrete `Result<Json<T>, E>` when it does not.

## Module Design

**Exports:**
- Re-export only what consumers need from `lib.rs`/`mod.rs`. Module
  internals (helpers, validators, error types) stay private unless
  cross-crate tests require them.
- Public types from a crate are typically named after the module: a
  module `foo` exports `Foo`, `FooError`, `FooConfig`.

**Barrel files:**
- Not used. Each consumer imports the specific module path:
  `use enclava_common::descriptor::DeploymentDescriptor;`
  not `use enclava_common::DeploymentDescriptor;`.

**Feature gating:**
- Test-only helpers live behind `#[cfg(feature = "testutil")]` in
  `crates/enclava-engine/src/testutil.rs` and are exposed via
  `pub mod testutil;` in `crates/enclava-engine/src/lib.rs` line 9.
- Dev-only internal helpers go in `#[cfg(test)] pub(crate) mod test_support`
  (see `crates/enclava-api/src/lib.rs` lines 483–569).
- Production builds must be able to opt out: never leak test helpers
  into release binaries.

## Security-Sensitive Conventions

- All user-supplied identifiers go through `crates/enclava-common/src/validate.rs`
  before use: `validate_dns_label`, `validate_app_name`,
  `validate_org_slug`, `validate_fqdn`, `validate_image_digest`. These
  reject non-ASCII, control chars, RTL overrides, Punycode, and path
  traversal.
- All image references must be digest-pinned. `ImageRef::parse(...)`
  followed by `image.require_digest()` — see
  `crates/enclava-api/src/main.rs` `parse_image_ref` lines 262–269.
- Cryptographic secrets use `zeroize::Zeroize` on drop
  (`crates/enclava-init/Cargo.toml` line 17;
  `crates/enclava-init/src/lib.rs` line 9 doc comment).
- Startup must fail closed when signing keys / HMAC keys are missing
  (`crates/enclava-api/src/main.rs` lines 200–208, 254–260).
- New debug-only env flags belong in BOTH
  `crates/enclava-api/src/env_gates.rs::DEBUG_ONLY_FLAGS` and
  `crates/enclava-cli/src/main.rs::DEBUG_ONLY_FLAGS`.

---

*Convention analysis: 2026-06-28*
