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

When the CLI is authenticated against hosted PaaS API mode, it also exposes the
hosted Debian SSH template flow. This is a PaaS convenience path layered on the
same CLI binary; CAP itself still stays plan-name-free and does not own hosted
billing or product semantics.

```bash
enclava template list
enclava template deploy --name shell \
  --ssh-public-key-file ~/.ssh/id_ed25519.pub \
  --json
enclava template ssh-command --name shell --wait
enclava template ssh-command --name shell --json
enclava status --app shell
```

Hosted Debian SSH deploys reserve their stable SSH endpoint in PaaS by default.
The CLI sends template creation to PaaS, reads the stored endpoint from the
template response, writes SSH public keys directly to the TEE config endpoint,
waits for the hosted PaaS
`/apps/<name>/ssh-command` API, and fails if the returned stable SSH endpoint
command does not match the reserved host and port. Ready API responses must
include the public `app_url`, canonical stable SSH endpoint `command`, and
canonical parsed `endpoint` fields; the command must already use the exact
`ssh -p <port> user@<lowercase-ngrok-host>` shape with a non-padded decimal
port. The CLI fails closed if any ready field is missing, non-canonical, or if
the endpoint does not match the stable SSH endpoint command. Pending API
responses may include the public `app_url` once CAP has returned it; `command`
and `endpoint` remain null until the stable SSH endpoint command is ready. Use
`enclava template ssh-command` after a `--no-wait`
deployment or timeout to fetch the same PaaS-rendered stable SSH endpoint
command later. The CLI
reads the stored stable SSH endpoint expectation from PaaS app metadata before
polling, so browser-created apps do not require retyping the reserved address.
Passing `--stable-ssh-endpoint` to `template deploy` imports an existing
reserved endpoint instead of letting PaaS reserve one. Passing it to
`template ssh-command` adds a caller-supplied assertion and makes the CLI reject
the lookup before polling if that assertion differs from the stored endpoint, or
reject any stable SSH endpoint command that does not match that endpoint. Pass
`--json` on deploy or command lookup when automation needs the
app URL, expected `stable_ssh_endpoint` (`stable_endpoint` is kept as a
compatibility alias), stable SSH endpoint command, and canonical parsed `endpoint`
as structured output. The `enclava status --app <name>` command also redisplays the stored
stable SSH endpoint for Debian SSH template apps and shows the validating
`template ssh-command` follow-up with
`--wait`; if the endpoint metadata is missing or invalid,
`status` prints a redeploy action instead of hiding stable SSH. If an
older hosted Debian SSH app returns `stable_ssh_endpoint_missing` or
`stable_ssh_endpoint_invalid`, redeploy it so PaaS reserves and stores the
non-secret stable SSH endpoint expectation it must enforce. The ngrok agent
authtoken is PaaS-managed and injected through the PaaS deployment environment
as `DEBIAN_SSH_NGROK_AUTHTOKEN`; endpoint reservation uses a separate PaaS
management credential, `NGROK_API_KEY`. The hosted CLI does not accept or read
ngrok token/API-key flags, local text/token files, or env vars. `--ngrok-tcp-url`
remains accepted as a compatibility alias for existing automation.

Run `scripts/test-stable-ssh-cli.sh` before changing the hosted Debian SSH CLI
path. It pins the endpoint-first human output, JSON fields, `/ssh-command`
response contract, and idempotency key behavior for stable SSH deployments.

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
