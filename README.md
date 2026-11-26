# Enclava CAP

Enclava CAP is the open-source control plane core for running OCI images as confidential workloads on Kubernetes. It targets Kata confidential containers with AMD SEV-SNP and combines a user CLI, an API service, Kubernetes manifest generation, and an in-TEE init sidecar.


## What Is Included

| Path | Purpose |
| --- | --- |
| `crates/enclava-cli` | `enclava` CLI for login, app setup, deploys, config, ownership, and recovery |
| `crates/enclava-api` | Axum API service for auth, apps, deployments, domains, workload artifacts, and deploy orchestration |
| `crates/enclava-engine` | Kubernetes manifest rendering, apply, watch, cleanup, and validation logic |
| `crates/enclava-init` | In-TEE sidecar that verifies policy, unlocks storage, prepares TLS state, and signals workload readiness |
| `crates/enclava-wait-exec` | Small wrapper that blocks app and ingress processes until `enclava-init` is ready |
| `crates/enclava-common` | Shared descriptor, image-reference, validation, encoding, and crypto helpers |
| `crates/enclava-snp` | SNP-attested TLS channel to a TEE (evidence, AMD KDS, collateral policy), shared with the hosted PaaS |
| `crates/enclava-verifier` | Deterministic, I/O-free verification of proof bundles against a trust policy |
| `crates/enclava-verifier-wasm` and `web/verifier` | WebAssembly build of the verifier and the static page that runs it locally |
| `crates/enclava-appraiser` | Stateless appraiser service exposing the same verifier over HTTP |
| `fuzz` | `cargo-fuzz` targets for the verifier's parsers |
| `deploy/api` | Minimal Kubernetes overlay for the CAP API service |
| `scripts` and `runbooks` | Release manifest rendering, smoke-test helpers, and operator runbooks |

## How It Works

CAP deploys immutable OCI images by digest and validates the deployment before it reaches Kubernetes:

- the CLI creates or reads local app config and signs a deployment descriptor;
- CAP validates the descriptor, image digest, signer identity, org keyring, and
  generated policy artifacts;
- the engine renders the Kubernetes resources for the confidential workload;
- `enclava-init` runs inside the guest, verifies the runtime trust chain, opens
  encrypted app/TLS volumes, and releases runtime state only after verification.

This repository is useful for developing the CAP runtime, API contracts, CLI
flows, and confidential-workload deployment machinery.

## Running Your Own Installation

The released CLI binaries and container images are built for Enclava's own
installations: the trust roots and API origins they accept are compiled in.
Deploying CAP independently means building from a fork with your own trust
bundle, and providing the surrounding platform (SEV-SNP hosts with Kata, Trustee
KBS, the policy signing service, and the tenant edge). See
[docs/self-hosting.md](docs/self-hosting.md) for the prerequisites and the list
of values a fork replaces, then [DEPLOYMENT.md](DEPLOYMENT.md) for API
configuration.

## Install

macOS / Linux (musl-static binaries, checksum + cosign verified):

```bash
curl -fsSL https://raw.githubusercontent.com/enclava-labs/cap/main/scripts/install.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/enclava-labs/cap/main/scripts/install.ps1 | iex
```

These installers fetch the CLI released by Enclava, which connects to
Enclava-operated APIs only. For your own installation, build the CLI from your
fork (see [docs/self-hosting.md](docs/self-hosting.md)).

Installs the latest release to `~/.enclava/bin` (`%USERPROFILE%\.enclava\bin` on
Windows) and adds it to your PATH. Set `ENCLAVA_VERSION=vX.Y.Z` for a specific
release, `ENCLAVA_INSTALL_DIR` to change the destination. Other platforms:
`cargo install --locked --git https://github.com/enclava-labs/cap enclava-cli`.

## CLI Flow

After authenticating against a CAP API, the normal app flow is:

```bash
enclava login
enclava init
enclava create --signer-subject <cosign-subject>
enclava deploy --image <registry>/<image>@sha256:<digest>
enclava status
enclava key backup --out enclava-recovery.json
```

Every entry in `[storage]` `paths` (default `/data`) must be a directory the
image already contains: the restricted profile runs a read-only root
filesystem, so the init's bind stage cannot create it. Template images ship
`/state/app-data`; deploy those with `enclava template deploy` instead of
listing them in `paths`.

New apps and deployments are password-only. Auto-unlock creation, enable requests
and `enclava auto-unlock enable` fail with `auto_unlock_disabled`; the guest never
fetches its owner seed automatically. After guest replacement, use
`enclava unlock --app NAME --password-file PATH` with the existing storage password.

For a legacy auto-mode app, run
`enclava auto-unlock disable --app NAME --image REPO@sha256:DIGEST --password-file PATH`
from its original `enclava.toml` workspace before redeploying. This preserves the
owner seed and volumes, but cannot revoke a previously copied auto-sealed seed.

For encrypted workload logs, use the current CLI and the tenant's log private key:

```bash
enclava logs --follow --log-private-key-file /path/to/log-key.x25519
```

Approve `apps:logs` with `enclava login --approve-logs` if the session lacks it.
Successful follow streams have no total deadline; initial headers, error bodies
and ordinary API requests remain bounded.
Blank-line keepalives preserve idle streams without printing fake log messages.
Each encrypted record is size-bounded before decoding.

Images may be digest-pinned or tagged (`enclava deploy --image
<registry>/<image>:<tag>`). The CLI resolves tags to a content digest before
signing; CAP independently resolves the image and checks that the digests agree.
The signer subject should match the identity that signs the image, such as a
GitHub Actions keyless cosign subject.

The CLI also contains hosted-template commands used by Enclava-hosted API mode:

```bash
enclava template list
enclava template deploy --name shell --ssh-public-key-file ~/.ssh/id_ed25519.pub
enclava template ssh-command --name shell --wait
```

Those commands are convenience flows for hosted templates. They are not required
for the core manual deploy path.

If a deploy or template rollout fails terminally at startup (for example a
guest start error), the CLI reports the typed failure and exits promptly
instead of timing out; run `enclava status --app <name>` for the recorded
detail.

## Local Development

Requirements:

- Rust 1.88 or newer;
- Docker Compose for the local API/PostgreSQL stack;
- `pkg-config` and OpenSSL development headers (`libssl-dev`), required even
  for a standalone `cargo install enclava-cli`;
- `libcryptsetup` development headers, `clang`, and `libclang` for the full
  workspace, including `enclava-init`.

On Debian or Ubuntu:

```bash
sudo apt-get install -y pkg-config libssl-dev libcryptsetup-dev clang libclang-dev
```

Start the development API:

```bash
docker compose up --build
curl http://localhost:3000/health
```

The compose stack is for development only. It uses local PostgreSQL and
ephemeral API signing/session keys.

Common checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

The workspace test run already includes every package's doctests, so a
separate `cargo test --doc` is redundant. The suite must stay serialized:
API fixtures share global PostgreSQL provider fences, and enclava-cli,
enclava-init, and enclava-wait-exec tests mutate process-global
environment or init surface paths.

Do not use `--all-features` as the default workspace test command. Some feature
combinations intentionally fail, such as `prod-strict` with debug/test-only
features.

When local native dependencies are unavailable, run targeted checks:

```bash
cargo test -p enclava-api --lib -- --test-threads=1
cargo test -p enclava-cli
cargo test -p enclava-engine
cargo test --workspace --exclude enclava-init -- --test-threads=1
```

Database-backed API library tests require a dedicated local PostgreSQL superuser,
as in CI: isolated fixtures create/drop databases, and schema-guard tests mutate
system catalogs. Run the full suite serially because remaining fixtures share
global provider fences. Never point these tests at a persistent environment.

API integration tests need PostgreSQL:

```bash
DATABASE_URL=postgresql://enclava:enclava@localhost:5432/enclava \
  cargo test -p enclava-api --test integration_test
```

## Deployment

The checked-in `deploy/api` overlay is the reference Kubernetes deployment of
the CAP API. It contains values for Enclava's installation and omits secrets,
most required environment, and tenant-resource RBAC; see
[deploy/api/README.md](deploy/api/README.md). Production deployments must provide durable key material, PostgreSQL,
digest-pinned platform images, Trustee/KBS access, policy-signing service
access, DNS credentials when CAP manages tenant DNS, and tightly scoped
Kubernetes permissions.

See [docs/self-hosting.md](docs/self-hosting.md) for what an independent
installation needs, and [DEPLOYMENT.md](DEPLOYMENT.md) for the runtime
environment and production configuration checklist.

## Security

Security-relevant behavior is built into both the API and runtime path:

- release builds reject debug bypass flags;
- platform sidecars and workload images are expected to be digest-pinned;
- workload images are verified against configured signer identity;
- private tenant-image pulls require authentication inside the TEE; host
  registry credentials alone do not authorize them. Never release a platform
  registry token to a tenant guest;
- deployment descriptors, org keyrings, generated policies, and signed policy
  artifacts are bound together before deploy;
- `enclava-init` verifies the in-TEE trust chain before releasing app secrets or
  mounted state.

To report a vulnerability, see [SECURITY.md](.github/SECURITY.md).

## More Documentation

- [docs/self-hosting.md](docs/self-hosting.md) - prerequisites and fork
  checklist for an independent installation.
- [DEPLOYMENT.md](DEPLOYMENT.md) - API runtime and production configuration,
  plus upgrade, recovery, and CLI behavior notes.
- [deploy/api/README.md](deploy/api/README.md) - what the reference overlay
  contains and omits.
- [CONTRIBUTING.md](.github/CONTRIBUTING.md) - how to propose changes.
- [docs/verification/contracts-v1.md](docs/verification/contracts-v1.md) -
  proof-bundle and trust-policy contracts for independent verification.
- [DEV.md](DEV.md) - local development commands and workflow notes.
- [crates/enclava-init/README.md](crates/enclava-init/README.md) - in-TEE init
  sidecar contract.
- [runbooks/cap-hermes-proof.md](runbooks/cap-hermes-proof.md) - live app proof
  helper.
- [runbooks/ct-monitoring.md](runbooks/ct-monitoring.md) - certificate
  transparency monitoring notes.
- [runbooks/dns-mutation-reconciliation.md](runbooks/dns-mutation-reconciliation.md)
  - fail-closed Cloudflare mutation recovery.
- [runbooks/kubernetes-mutation-fence-recovery.md](runbooks/kubernetes-mutation-fence-recovery.md)
  - fail-closed Kubernetes namespace mutation recovery.
- [runbooks/trustee-policy-audit.sh](runbooks/trustee-policy-audit.sh) - KBS
  live-policy vs CAP-database binding audit.

## License

MIT. See [LICENSE](LICENSE).
