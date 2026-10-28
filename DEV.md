# Development

## Toolchain

CAP is a Rust 2024 workspace with MSRV 1.85. Use the workspace root for normal
commands:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```

Workspace tests include the API integration suite, so set `DATABASE_URL` to a
disposable PostgreSQL database or use the targeted commands below. The role in
`DATABASE_URL` must also have the CREATEDB attribute (`ALTER ROLE "<role>"
WITH CREATEDB` as a superuser): tests whose fixtures must not share state
provision uniquely named per-test databases, migrate them, and drop them
when the test finishes.

`enclava-cli` links to OpenSSL, and `enclava-init` links to `libcryptsetup`.
On Debian/Ubuntu, install the native development packages:

```bash
sudo apt-get install -y pkg-config libssl-dev libcryptsetup-dev clang libclang-dev
```

If the `libcryptsetup` packages are not available locally, run the rest of the
workspace without `enclava-init` (`enclava-cli` still needs the OpenSSL headers):

```bash
cargo test --workspace --exclude enclava-init
cargo clippy --workspace --all-targets --exclude enclava-init -- -D warnings
```

Local API integration tests need a reachable PostgreSQL test database. When the
database is configured through the development compose stack, use:

```bash
DATABASE_URL=postgresql://enclava:enclava@localhost:5432/enclava \
  cargo test -p enclava-api --test integration_test
```

When the database is not configured, prefer targeted unit tests such as:

```bash
cargo test -p enclava-api --lib
cargo test -p enclava-cli
cargo test -p enclava-engine
python3 -m pytest tests
```

The Python checks require `pytest`; install it in your local virtualenv if
`python3 -m pytest` is not available.

CI runs the Rust dependency gates after installing `cargo-audit` and
`cargo-deny` (workspace doctests already run inside the two default test
selections):

```bash
cargo audit --ignore RUSTSEC-2023-0071
cargo deny check advisories sources
```

CI and API image workflow concurrency is scoped by workflow and pull-request
number, falling back to the Git ref for non-PR events. New runs supersede older
runs for the same PR; unrelated PRs must not cancel each other's checks.

The test and build jobs use the same pinned `Swatinem/rust-cache` action as the
CLI checks, with job- and compiler-specific cache keys. CI and release verifier
jobs install the pinned, checksum-verified prebuilt `wasm-bindgen-cli`, without
falling back to compiling it from source.

Docker layer caches use separate scopes for each image and profile:
`api-debug`, `api-release`, `init-debug`, `init-release`, and `appraiser`.
New scopes need a successful run to warm. GitHub's branch restrictions still
apply: PR caches do not seed `main`. These caches do not preserve Dockerfile
cache-mount contents across runners.

API builds use `cargo-chef` 0.1.78 to cache compiled dependencies separately
from application sources. The installer uses checksum-pinned binaries on amd64
and arm64, and builds the same locked version on other Rust image architectures.
The recipe tracks workspace manifests and `Cargo.lock`; the real vendored
`rdrand` patch is also copied before dependency compilation. Cargo sources and
compiled dependencies stay in exported layers rather than ephemeral cache mounts.

Main pushes seed `api-debug` with the `debug-dependencies` target in a separate,
non-publishing job so newly opened PRs can restore compiled dependencies.

Release dependency compilation uses separate CLI-example and API `prod-strict`
passes because their resolved dependency features differ. Real sources, the
signed envelope, and the root pin are applied afterward; the existing root,
signature, and trust-root checks still gate the final binaries. Source-only
edits can reuse dependency layers; manifest, lockfile, and vendored-source
changes invalidate them. Measure a source-edit rebuild, not just an unchanged
commit rerun, and include cache export/import costs when comparing CI times.

## Shared signed API image

The API image pins the platform-release root and verifies its bundled signed
envelope as a downgrade floor at build time. A pre-trustee-key envelope may
serve only as that floor; it is never a usable runtime release. Each environment
mounts its own current-schema, root-signed envelope at
`ENCLAVA_PLATFORM_RELEASE_PATH`. Startup rejects a missing or invalid trustee
policy key and refuses releases older than the image's verified floor. A new
envelope must have a later signed `created_at` than a different bundled floor.
Do not replace the shared CI envelope with one environment's release or
remove the floor to make a build pass. Deploying a new image requires a
compatible signed runtime envelope in every target environment.

## Local API

```bash
docker compose up --build
curl http://localhost:3000/health
```

The compose stack is development-only and uses ephemeral signing/session keys.
It is useful for route and client work, not for persistent deploy validation.

Device-login route work can be tested locally with the API integration suite.
The CLI starts `/auth/device/start`, polls `/auth/device/poll`, and stores the
approved session before calling `/users/me`. After login/signup, the CLI also
ensures the personal-org keyring is ready so manual deploy does not require
manual `enclava org keyring ...` commands.

Hosted PaaS template route work can be tested with the focused CLI package
checks:

```bash
cargo test -p enclava-cli template::tests -- --nocapture
cargo run -p enclava-cli -- template deploy --help
```

Before changing the hosted Debian SSH path, run the stable SSH gate:

```bash
scripts/test-stable-ssh-cli.sh
```

The deploy subcommand expects a hosted PaaS session and calls `GET /templates`
and `POST /template-instances`. It then delivers customer-owned values such as
`DEBIAN_SSH_AUTHORIZED_KEYS` directly to the TEE config endpoint. For the stable
SSH template, PaaS reserves and injects workload `NGROK_TCP_URL`, and injects
workload `NGROK_AUTHTOKEN` from its own PaaS deployment environment variable
`DEBIAN_SSH_NGROK_AUTHTOKEN`; the CLI must not prompt for, read, or deliver a
local ngrok token or ngrok API key.

## Deploy Flow Development

The current user-facing CLI path should stay free of platform-owned env
exports. `enclava deploy --image ...@sha256:...` obtains API signing, platform
release, TLS broker, and policy-signing context through authenticated API calls.
Users should not need `ENCLAVA_API_KEY` for the first manual deploy path.

When changing deploy behavior, check both sides of the contract:

- CLI descriptor construction in `crates/enclava-cli/src/commands/app.rs`,
  `descriptor.rs`, `keyring.rs`, and `policy_artifact.rs`.
- API validation and apply orchestration in
  `crates/enclava-api/src/routes/deployments.rs`,
  `signing_service.rs`, `deploy.rs`, `kbs.rs`, and `cosign.rs`.
- Engine manifest output in `crates/enclava-engine/src/manifest`.
- In-TEE verification in `crates/enclava-init/src/trustee_verify.rs`.

If a production bug is being fixed, add the failing test before changing the
implementation.

## Runtime Contract Notes

- Workload images and platform sidecar images that CAP wraps must include
  `/usr/local/bin/enclava-wait-exec`.
- `enclava-init` is the mount propagation source and writes
  `/run/enclava/init-ready` after LUKS open, verification, seed derivation, TLS
  certificate setup, and bind mounts complete.
- App data and TLS state are separate LUKS volumes. App data is owner-seed
  backed; TLS state is used by tenant Caddy for certificate continuity.
- Password-mode first deploy waits for the TEE bootstrap claim endpoint instead
  of app readiness because the workload is intentionally blocked until
  ownership is claimed.
- App bootstrap keys are deterministic from the recovery seed. If the cached
  key file is missing, `enclava deploy` and `enclava claim` can re-derive it
  after `enclava key restore <backup>`.
- Direct owner operations must use the TEE hostname and the ownership TEE
  client path, not the public app hostname.

## Fast Contract Gate

Run this before building or pushing API, signing-service, or Nutshell images for
live smoke testing:

```bash
scripts/nutshell-fast-contract.sh
```

It validates the Nutshell app contract and then runs the focused CAP and
signing-service checks that catch descriptor, runtime, and policy drift. The
script expects sibling `nutshell` and `policy-templates/signing-service`
checkouts by default; override `NUTSHELL_ROOT` and `POLICY_ROOT` when they live
elsewhere.
