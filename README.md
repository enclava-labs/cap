# Enclava CAP

CAP is the Enclava control plane for deploying OCI images as confidential
workloads on a Kubernetes cluster with Kata confidential containers and AMD
SEV-SNP. The public core is API/CLI/runtime only; the hosted PaaS console lives
outside this repository.

The core platform supports manual CLI deploy as the baseline operating path:

1. `enclava login`
2. `enclava init` or `enclava prepare`
3. `enclava create`
4. `enclava signer set ...` or pass `--signer-subject` during create.
5. Build, sign, and publish a public digest-pinned image.
6. `enclava deploy --image <registry>/<image>@sha256:<digest>`
7. Save recovery state with `enclava key backup --out enclava-recovery.json`.

Signup/login commands remain available for development and standalone CAP
operators. Hosted registration, plan management, and customer workflows are
PaaS-console responsibilities and are not bundled with the public CAP core.

The deploy path does not require a workflow API key. The CLI authenticates with
a platform session, derives customer-owned deploy keys from a local random
recovery seed, initializes the personal-org keyring when needed, and signs the
deployment descriptor before calling the API.

For app projects, the usual local command sequence is:

1. `enclava login`
2. `enclava init` or `enclava prepare`
3. `enclava create`
4. `enclava deploy --image <registry>/<image>@sha256:<digest>`
5. `enclava status`
6. `enclava logs`

The CLI signs a deployment descriptor from the local app config and the signed
platform release. The API validates the descriptor, image signer, org keyring,
generated agent policy, and signed policy artifact before applying Kubernetes
resources. `enclava logs` currently returns an explicit unavailable response
until the Kubernetes log proxy is wired.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `crates/enclava-common` | Canonical encoding, descriptors, validation, image references, shared crypto helpers |
| `crates/enclava-cli` | `enclava` user CLI, local config, descriptor signing, TEE attestation client |
| `crates/enclava-api` | Axum API, auth, org/app/deploy/config/domain/workload routes, deploy orchestration |
| `crates/enclava-engine` | Kubernetes manifest rendering and server-side apply/cleanup/watch logic |
| `crates/enclava-init` | In-TEE LUKS, seed derivation, Trustee policy verification, TLS certificate broker client |
| `crates/enclava-wait-exec` | Workload wrapper that blocks app and ingress commands until `enclava-init` is ready |
| `deploy/api` | Minimal Kubernetes API deployment overlay |
| `runbooks` | Current operator runbooks and visual flow artifacts |

The previous in-tree Svelte console has moved to the private `enclava-paas`
project. CAP only exposes HTTP/API contracts for a console to consume.

## Current Docs

| Doc | Scope |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Current deploy/runtime architecture |
| [API.md](API.md) | Current HTTP route map and auth model |
| [DEPLOYMENT.md](DEPLOYMENT.md) | API runtime, production env, and deploy prerequisites |
| [DEV.md](DEV.md) | Local development and verification commands |
| [SECURITY_REVIEW.md](SECURITY_REVIEW.md) | Current code-grounded security posture |
| [SECURITY_MITIGATION_PLAN.md](SECURITY_MITIGATION_PLAN.md) | Current mitigation checklist and operating baseline |
| [crates/enclava-init/README.md](crates/enclava-init/README.md) | In-TEE init sidecar contract |

## Local Development

```bash
docker compose up --build
curl http://localhost:3000/health
```

`docker-compose.yml` is development-only. It starts PostgreSQL and the API with
ephemeral signing/session keys.

Common verification commands:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```

`enclava-init` links against system `libcryptsetup`. If that package is not
installed, run the rest of the workspace with `--exclude enclava-init` or use a
build image that includes the development headers.

## Runtime Requirements

CAP can start as a normal API service, but real deploys require the platform
runtime:

- PostgreSQL for API state.
- Digest-pinned `attestation-proxy`, `caddy-ingress`, and `enclava-init` images.
- A signed platform release compiled or supplied with the pinned release root
  key.
- A Kubernetes cluster with the confidential runtime class used by
  `enclava-engine`.
- Trustee KBS reachable by the guest AA/CDH path over the configured HTTPS
  endpoint.
- Policy signing service reachable by CAP for generated agent policy and signed
  policy artifacts.
- Cloudflare DNS credentials when CAP-managed tenant DNS is required.

## License

MIT. See [LICENSE](LICENSE).
