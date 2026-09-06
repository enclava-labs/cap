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
- genpolicy version;
- policy template hash;
- runtime class expected by the engine.

When the signed release supplies a value, an explicit environment override must
match it exactly or startup fails.

## Images

The GitHub workflow [`.github/workflows/api-image.yml`](.github/workflows/api-image.yml)
builds `ghcr.io/enclava-labs/enclava-api` for pushes to `main`, version tags,
and manual dispatches. For non-PR events it also uploads an
`enclava-api-release-manifest` artifact containing:

- `enclava-api-image.txt` with the digest-pinned image reference;
- `enclava-api-deploy.yaml` rendered from `deploy/api`.

Deploy the digest reference from that artifact, not a mutable tag.

## Kubernetes

The checked-in overlay is intentionally minimal:

```bash
kubectl apply -k deploy/api/
kubectl -n enclava-platform rollout status deploy/enclava-api
```

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

For a live app proof that does not require direct cluster access:

```bash
python3 scripts/cap_hermes_proof.py --help
```
