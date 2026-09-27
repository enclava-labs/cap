# Deploying CAP API

This guide covers the CAP API service in this repository. It is intended for
operators packaging CAP for a Kubernetes environment, not for hosted Enclava
console users.

For local development, see [README.md](README.md) and [DEV.md](DEV.md).

## Local API

The repository includes a development-only Compose stack:

```bash
docker compose up --build
curl http://localhost:3000/health
```

This mode starts PostgreSQL and the API with `ALLOW_EPHEMERAL_KEYS=1`. Do not
use it for any persistent environment: API signing and session keys are rotated
on restart. Compose also sets `CAP_DISABLE_EDGE_RECONCILIATION=true` because it
does not run Kubernetes or tenant HAProxy, and keeps deployment dispatch
disabled. Startup rejects combining the opt-out with enabled dispatch, and
release builds reject the opt-out entirely.

## Production Model

CAP API is a stateless HTTP service backed by PostgreSQL. At startup it:

- installs the rustls crypto provider;
- refuses debug-only flags in release builds;
- connects to PostgreSQL and runs migrations;
- loads API signing, session, and API-key HMAC material;
- verifies the signed platform release when policy-read mode is enabled;
- verifies digest-pinned platform sidecar images with cosign;
- configures DNS, Trustee/KBS, policy signing, registry access, and tenant TEE
  clients.

The API can start without every optional integration, but real confidential
workload deploys require the platform services below.

## Required Services

Production deploys need:

- PostgreSQL for API state.
- A Kubernetes cluster with the confidential runtime class expected by
  `enclava-engine`.
- Trustee KBS reachable by guest attestation and CAP callback paths.
- Policy signing service for generated agent policy and signed policy
  artifacts.
- Digest-pinned `attestation-proxy`, `caddy-ingress`, and `enclava-init`
  images.
- A signed platform release, or environment values that exactly match the
  signed release values.
- DNS credentials when CAP manages tenant hostnames.

## Required Environment

These variables are required for every persistent API process:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. Migrations run on startup. |
| `API_SIGNING_KEY_PATH` or `API_SIGNING_KEY_PKCS8_BASE64` | Ed25519 PKCS#8 private key for config JWTs and deployment metadata. |
| `SESSION_HMAC_KEY_PATH` or `SESSION_HMAC_KEY_BASE64` | 32-byte HMAC key for session JWTs and signer-rotation tokens. |

Release builds also require:

| Variable | Purpose |
| --- | --- |
| `API_KEY_HMAC_PEPPER` or `API_KEY_HMAC_PEPPER_BASE64` | Pepper for HMAC-format API keys. Must be at least 32 bytes. |
| `TRUSTEE_POLICY_READ_AVAILABLE=true` | Enables the supported signed-policy and in-TEE verification path. |
| `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX` | Compile-time root public key used to verify the bundled or supplied platform release. |

For production deploys with policy-read mode enabled:

| Variable | Purpose |
| --- | --- |
| `ATTESTATION_PROXY_IMAGE` | Digest-pinned attestation-proxy image, unless supplied by the platform release. |
| `CADDY_INGRESS_IMAGE` | Digest-pinned tenant ingress image, unless supplied by the platform release. |
| `TRUSTEE_KBS_URL` | HTTPS Trustee KBS URL. Release builds reject `http://` KBS URLs. |
| `TRUSTEE_KBS_CA_CERT_PEM` or `TRUSTEE_KBS_CA_CERT_PATH` | Root certificate for private Trustee KBS TLS. |
| `WORKLOAD_ARTIFACTS_URL` | Workload-attested CAP artifact endpoint used by `enclava-init`. |
| `TRUSTEE_POLICY_URL` | Workload-attested active Trustee policy endpoint used by `enclava-init`. |
| `TRUSTEE_ATTESTATION_VERIFY_URL` | Trustee callback endpoint used by CAP workload artifact and TLS broker routes. |
| `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN` | Bearer token CAP sends to the Trustee verification endpoint. Required when `TRUSTEE_ATTESTATION_VERIFY_URL` is set. |
| `PLATFORM_SIGNING_SERVICE_URL` | Policy signing service endpoint, unless supplied by the platform release. |
| `SIGNING_SERVICE_PUBKEY_HEX` or `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX` | Ed25519 public key used to verify signed policy artifacts, unless supplied by the platform release. |

## Optional Integrations

| Variable | Purpose |
| --- | --- |
| `DNS_MANAGEMENT_REQUIRED=1` | Fail startup unless CAP-managed DNS is configured. |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token for tenant DNS records. |
| `CLOUDFLARE_ZONE_NAME` | Managed DNS zone name. Defaults to `enclava.dev`. |
| `CLOUDFLARE_ZONE_ID` | Optional zone ID to skip zone lookup. |
| `TENANT_DNS_TARGET` | A/AAAA target for tenant DNS records. |
| `TLS_CERTIFICATE_BROKER_URL` | Required when `TENANT_CADDY_TLS_MODE=dns01-broker`. |
| `ACME_DIRECTORY_URL` | ACME directory for DNS-01 broker certificates. |
| `ACME_ACCOUNT_CREDENTIALS_PATH` | Optional persisted ACME account credentials path. |
| `ACME_DNS_PROPAGATION_SECONDS` | DNS propagation wait for the certificate broker. Defaults to `30`. |
| `ACME_DNS_LOOKUP_PREFER_SYSTEM` | Broker TXT resolver preference: exactly `true` or `false` (default). `true` tries the pod system resolver first; either order falls back only on lookup error, never on successful empty/nonmatching TXT answers. |
| `ACME_DNS_LOOKUP_TIMEOUT_SECONDS` | Optional positive integer timeout for each complete broker TXT resolver lookup, including fallback (two attempts can consume twice this budget). Invalid/zero values fail startup. Unset preserves native resolver budgets; the historical unmerged branch's ten-second default is deliberately not introduced. No DNS egress policy changes are required. |
| `CAP_ALLOW_PRODUCTION_ACME=true` | Required in release builds when `ACME_DIRECTORY_URL` or `TENANT_CADDY_ACME_CA` points at Let's Encrypt production. |
| `GHCR_USERNAME` and `GHCR_TOKEN` | Optional credentials used to create tenant namespace image-pull secrets for private GHCR images. |
| `TENANT_IMAGE_PULL_SECRET_NAME` | Tenant image-pull secret name. Defaults to `enclava-registry-auth` when GHCR credentials are configured. |
| `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES` | Optional comma-separated scope for the tenant pull secret. Use `registry/repository` for exact matches or `registry/repository/*` for subrepositories. |
| `KBS_POLICY_MANAGEMENT_REQUIRED=1` | Fail deploys unless CAP can update the Trustee KBS policy ConfigMap and restart the KBS deployment. |
| `KBS_POLICY_MANAGEMENT_ENABLED=1` | Enable KBS policy management without making it startup-fatal. |
| `KBS_POLICY_NAMESPACE` | Trustee KBS namespace. Defaults to `trustee-operator-system`. |
| `KBS_POLICY_CONFIGMAP` | Trustee policy ConfigMap. Defaults to `resource-policy`. |
| `KBS_POLICY_KEY` | Policy key inside the ConfigMap. Defaults to `policy.rego`. |
| `KBS_POLICY_DEPLOYMENT` | KBS deployment to restart after policy updates. Defaults to `trustee-deployment`. |
| `KBS_SIGNED_POLICY_RETENTION` | Number of signed policy artifacts to retain per app. |
| `KBS_SIGNED_POLICY_MAX_BYTES` | Maximum serialized signed policy artifact set bytes written to the shared KBS policy ConfigMap. Defaults to 900 KiB, below Kubernetes' 1 MiB ConfigMap data limit. |

## Common Defaults

| Variable | Default | Purpose |
| --- | --- | --- |
| `BIND_ADDR` | `0.0.0.0:3000` | API listen address. |
| `API_URL` | `http://localhost:3000` | Public API base URL embedded in deployment metadata. |
| `ENCLAVA_DASHBOARD_URL` | unset | Optional hosted-console URL for CLI device-login approval. |
| `PLATFORM_DOMAIN` | `enclava.dev` | Public app hostname suffix. |
| `TEE_DOMAIN_SUFFIX` | `tee.<PLATFORM_DOMAIN>` | TEE/attestation hostname suffix. |
| `TENANT_CADDY_TLS_MODE` | `acme` | Tenant TLS mode: `acme`, `dns01-broker`, or `internal`. Release builds reject `internal`. |
| `TENANT_CADDY_ACME_CA` | engine default ACME directory | ACME directory used by tenant Caddy. |
| `CAP_MAX_CONCURRENT_APPLIES` | `1` | Per-process deployment apply concurrency. |
| `CORS_ALLOWED_ORIGINS` | empty in release, localhost in debug | Browser origins allowed by CORS. |
| `TRUSTED_PROXY_CIDRS` | empty | CIDRs trusted for rate-limit client IP extraction. |
| `REGISTRY_ALLOWLIST` | built-in registry allowlist | Registry hosts CAP may contact for image metadata. |
| `OUTBOUND_HTTP_BODY_LIMIT_BYTES` | code default | Body-size limit for guarded outbound HTTP responses. |
| `CAP_PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS` | unset | Public-internet egress CIDRs excluded from generated tenant egress policy. |

## Release-Build Safety Gates

Release builds refuse to start when dangerous development settings are enabled:

```text
SKIP_COSIGN_VERIFY
COSIGN_ALLOW_HTTP_REGISTRY
ALLOW_EPHEMERAL_KEYS
CAP_DISABLE_EDGE_RECONCILIATION
TENANT_TEE_ACCEPT_INVALID_CERTS
ENCLAVA_TEE_ACCEPT_INVALID_CERTS
LEGACY_BOOTSTRAP_SCRIPT
TENANT_TEE_TLS_MODE=staging|insecure
TENANT_CADDY_TLS_MODE=internal
TRUSTEE_KBS_URL=http://...
```

Release builds also require `API_KEY_HMAC_PEPPER` or
`API_KEY_HMAC_PEPPER_BASE64`, and `TRUSTEE_POLICY_READ_AVAILABLE=true`.

## Platform Release

The API and CLI load the bundled
`crates/enclava-cli/platform-release.json` unless
`ENCLAVA_PLATFORM_RELEASE_PATH` points at another signed release envelope.

Release verification checks:

- envelope signature against `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX`;
- digest pins for platform sidecar images;
- HTTPS Trustee KBS URL;
- HTTPS tenant Caddy ACME CA URL;
- genpolicy version;
- policy template hash;
- runtime class expected by the engine;
- when `ENCLAVA_PLATFORM_RELEASE_PATH` overrides the bundle: the override
  is not older than the bundled release (downgrade refused), not older than
  the newest release ever accepted on this override lane (persisted
  high-water mark, downgrade refused), and not a same-`{version, created_at}`
  envelope with different signed content (the mark pins the canonical
  payload digest). A PostgreSQL transaction locks the shared row while
  comparing and advancing it, including the first concurrent acceptance.

When the signed release supplies a value, an explicit environment override must
match it exactly or startup fails.

The high-water mark lives in `platform_release_state` in CAP's existing
PostgreSQL database (`DATABASE_URL`), shared by all API replicas in that
environment. It contains the accepted release version, signed creation time,
and canonical payload SHA-256, not credentials or user data. It is platform
state, independent of user profiles. No additional database service, state PVC,
filesystem lock, or storage environment variable is required.

Apply migration `0050_platform_release_state.sql` before starting the new API
image, using the `cap-migrate` Job and `DATABASE_MIGRATION_MODE=verify`
startup ordering documented under [Kubernetes](#kubernetes). The migration seeds
a singleton row; a missing row or table,
corrupt record, or unavailable database refuses startup rather than silently
resetting the floor. The API advances the row only after all release-derived
startup configuration validates. Updates use a row lock and synchronous commit.
A check-only bundled startup never advances the accepted-override mark.

Removing `ENCLAVA_PLATFORM_RELEASE_PATH`, disabling policy-read mode, or
replacing a pod does not remove this gate. Every startup compares its effective
release (the compiled bundle when the release lane is disabled) against the
database floor. Every running replica rechecks it every 60 seconds and stops
if another replica has accepted a release that makes its own release stale or
unorderable. Transient database errors during a running recheck are logged and
retried, matching the former file watchdog; startup itself fails closed.

Treat this row as security state during backup and restore. An older database
backup can lower the remembered floor. Before resuming CAP, preserve or
reconcile the highest previously accepted version, timestamp and payload hash
against trusted signed release history. Do not delete/reseed the row to make a
rollback boot. Anyone holding CAP's database write credentials, including a
compromised API pod, can alter or delete this unsigned record. The gate does
not defend against that access or rollback of the entire database. A stronger
threat model needs independently protected state.

### Adopting from preview file state

The retired `ENCLAVA_PLATFORM_RELEASE_STATE` setting fails startup with a
migration message even if the release lane is disabled. If a preview deployment
already has a file mark, stop all CAP replicas, preserve the file, verify its
version/timestamp/hash against trusted signed release history, and reconcile
it with any existing database mark under a transaction locking the singleton
row. Keep the newest compatible mark; equal-timestamp divergent content must
be resolved against trusted history, not overwritten. Only after verifying the
committed database record may the old setting/mount be removed and CAP resumed.
The optional PVC component has been removed; retain any existing volume until
its state has been safely adopted. Fresh installations need only the normal
migration, with no file import.

### Rotating the production root

The committed `platform-release.json` is signed by a well-known dev fixture
root whose seed is public. Publishing requires a production root held outside
this repository; gates reject the fixture root and any root that does not sign
the envelope the build bundles, so the root and the envelope always rotate
together:

1. Generate the production root offline:
   `openssl genpkey -algorithm ed25519 -out root.pem`
   (`openssl pkey -in root.pem -noout -text` shows the seed and pubkey hex.)
2. Sign the payload with the repository's canonical encoding. Keep the seed
   in a protected file and redirect it into the helper — it never appears in
   argv or shell history:
   `cargo run --locked -p enclava-cli --example platform-release -- sign \
   payload.json < root-seed.hex > platform-release.json`
3. Sanity-check it: `cargo run --locked -p enclava-cli --example \
   platform-release -- verify platform-release.json <root-pubkey-hex>`
4. Set both repository secrets in one sitting:
   `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX` (pubkey hex) and
   `ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON` (the signed envelope contents).

Release workflows materialize the envelope secret over
`crates/enclava-cli/platform-release.json` before building, verify its full
signature against the pinned root, and embed it in every published binary and
image. With only one of the two secrets set (or neither), publishing fails
closed.

## Images

The GitHub workflow [`.github/workflows/api-image.yml`](.github/workflows/api-image.yml)
builds `ghcr.io/enclava-labs/enclava-api` for pushes to `main`, version tags,
and manual dispatches. For non-PR events it also uploads an
`enclava-api-release-manifest` artifact containing:

- `enclava-api-image.txt` with the digest-pinned image reference;
- `enclava-api-deploy.yaml` rendered from `deploy/api`.

Deploy the digest reference from that artifact, not a mutable tag.

## Kubernetes

The API uses `DATABASE_MIGRATION_MODE=verify`. On both first installation and
every upgrade, run migrations from the **same digest-pinned image** before
applying the API overlay. Provision `api-secrets` (including `database-url`)
and `ghcr-login` in `enclava-platform` first. The migration Job is deliberately
excluded from the overlay: applying a Job and Deployment together does not
order their execution.

Run from the repository root, with the digest from the release artifact:

```bash
set -euo pipefail
CAP_API_IMAGE='ghcr.io/enclava-labs/enclava-api@sha256:<release-digest>'
(cd deploy/api && kustomize edit set image "ghcr.io/enclava-labs/enclava-api=$CAP_API_IMAGE")
kubectl apply -f deploy/api/namespace.yaml
CAP_MIGRATION_JOB=$(kubectl set image --local -f deploy/api/migration.yaml "migrate=$CAP_API_IMAGE" -o yaml |
  kubectl create -f - -o name)
kubectl -n enclava-platform wait --for=condition=complete "$CAP_MIGRATION_JOB" --timeout=600s
kubectl apply -k deploy/api/
kubectl -n enclava-platform rollout status deploy/enclava-api
```

If migration fails or times out, stop before applying the API and inspect
`kubectl -n enclava-platform logs "$CAP_MIGRATION_JOB"`. Correct the cause before
retrying; retain the existing API and database state.

Before using it outside local experimentation:

- replace placeholder secret references with your secret-management system;
- pin the API image digest in `deploy/api/kustomization.yaml`;
- add the required production environment variables;
- configure service account/RBAC for only the tenant resources CAP owns;
- configure network policy for PostgreSQL, Trustee/KBS, policy signing,
  registry metadata, DNS, and tenant TEE callbacks;
- decide whether CAP-managed DNS and KBS policy management are required.

## Smoke Checks

After rollout:

```bash
kubectl -n enclava-platform get deploy enclava-api
kubectl -n enclava-platform exec deploy/enclava-api -- wget -q -O- http://127.0.0.1:3000/health
```

