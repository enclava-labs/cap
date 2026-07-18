# Enclava CAP

Enclava CAP is the open-source control plane core for running OCI images as
confidential workloads on Kubernetes. It targets Kata confidential containers
with AMD SEV-SNP and combines a user CLI, an API service, Kubernetes manifest
generation, and an in-TEE init sidecar.

The hosted Enclava console, billing, and customer-management workflows are not
part of this repository. This repo contains the public API/CLI/runtime pieces
that those products build on.

## What Is Included

| Path | Purpose |
| --- | --- |
| `crates/enclava-cli` | `enclava` CLI for login, app setup, deploys, config, ownership, and recovery |
| `crates/enclava-api` | Axum API service for auth, apps, deployments, domains, workload artifacts, and deploy orchestration |
| `crates/enclava-engine` | Kubernetes manifest rendering, apply, watch, cleanup, and validation logic |
| `crates/enclava-init` | In-TEE sidecar that verifies policy, unlocks storage, prepares TLS state, and signals workload readiness |
| `crates/enclava-wait-exec` | Small wrapper that blocks app and ingress processes until `enclava-init` is ready |
| `crates/enclava-common` | Shared descriptor, image-reference, validation, encoding, and crypto helpers |
| `deploy/api` | Minimal Kubernetes overlay for the CAP API service |
| `scripts` and `runbooks` | Release manifest rendering, smoke-test helpers, and operator runbooks |

## How It Works

CAP deploys immutable OCI images by digest and validates the deployment before
it reaches Kubernetes:

- the CLI creates or reads local app config and signs a deployment descriptor;
- CAP validates the descriptor, image digest, signer identity, org keyring, and
  generated policy artifacts;
- the engine renders the Kubernetes resources for the confidential workload;
- `enclava-init` runs inside the guest, verifies the runtime trust chain, opens
  encrypted app/TLS volumes, and releases runtime state only after verification.

This repository is useful for developing the CAP runtime, API contracts, CLI
flows, and confidential-workload deployment machinery. A real deployment still
requires the surrounding platform services described in
[DEPLOYMENT.md](DEPLOYMENT.md).

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

The image must be digest-pinned. The signer subject should match the identity
that signs the image, such as a GitHub Actions keyless cosign subject.

The CLI also contains hosted-template commands used by Enclava-hosted API mode:

```bash
enclava template list
enclava template deploy --name shell --ssh-public-key-file ~/.ssh/id_ed25519.pub
enclava template ssh-command --name shell --wait
```

Those commands are convenience flows for hosted templates. They are not required
for the core manual deploy path.

## Local Development

Requirements:

- Rust 1.85 or newer;
- Docker Compose for the local API/PostgreSQL stack;
- `pkg-config`, `libcryptsetup` development headers, `clang`, and `libclang`
  for the full workspace, including `enclava-init`.

On Debian or Ubuntu:

```bash
sudo apt-get install -y pkg-config libcryptsetup-dev clang libclang-dev
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
cargo test --workspace
cargo test --doc
```

Do not use `--all-features` as the default workspace test command. Some feature
combinations intentionally fail, such as `prod-strict` with debug/test-only
features.

When local native dependencies are unavailable, run targeted checks:

```bash
cargo test -p enclava-api --lib
cargo test -p enclava-cli
cargo test -p enclava-engine
cargo test --workspace --exclude enclava-init
```

API integration tests need PostgreSQL:

```bash
DATABASE_URL=postgresql://enclava:enclava@localhost:5432/enclava \
  cargo test -p enclava-api --test integration_test
```

## Deployment

The checked-in `deploy/api` overlay is a minimal starting point for the CAP API.
Production deployments must provide durable key material, PostgreSQL,
digest-pinned platform images, Trustee/KBS access, policy-signing service
access, DNS credentials when CAP manages tenant DNS, and tightly scoped
Kubernetes permissions.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the runtime environment and production
configuration checklist.

## Security

Security-relevant behavior is built into both the API and runtime path:

- release builds reject debug bypass flags;
- platform sidecars and workload images are expected to be digest-pinned;
- workload images are verified against configured signer identity;
- deployment descriptors, org keyrings, generated policies, and signed policy
  artifacts are bound together before deploy;
- `enclava-init` verifies the in-TEE trust chain before releasing app secrets or
  mounted state.

See [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for the current security snapshot.

## More Documentation

- [DEPLOYMENT.md](DEPLOYMENT.md) - API runtime and production configuration.
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

## License

MIT. See [LICENSE](LICENSE).
