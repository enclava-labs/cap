# Development

## Toolchain

CAP is a Rust 2024 workspace with MSRV 1.85. Use the workspace root for normal
commands:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```

`enclava-init` links to `libcryptsetup`. On hosts without the development
package, use:

```bash
cargo test --workspace --exclude enclava-init
cargo clippy --workspace --all-targets --exclude enclava-init -- -D warnings
```

Local API integration tests need a reachable PostgreSQL test database. When the
database is not configured, prefer targeted unit tests such as:

```bash
cargo test -p enclava-api --lib
cargo test -p enclava-cli
cargo test -p enclava-engine
python3 -m pytest tests/test_cap_hermes_proof.py
```

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

The deploy subcommand expects a hosted PaaS session and calls `GET /templates`
and `POST /template-instances`. It then delivers `NGROK_AUTHTOKEN`,
`DEBIAN_SSH_AUTHORIZED_KEYS`, and optional `NGROK_TCP_URL` directly to the TEE
config endpoint, so do not add PaaS-side storage of those config values.

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
signing-service checks that catch descriptor, runtime, and policy drift.
