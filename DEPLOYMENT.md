# Deployment

This document describes the current CAP API runtime. It is based on
`crates/enclava-api/src/main.rs`, `env_gates.rs`, `platform_release.rs`,
`cosign.rs`, `kbs.rs`, `dns.rs`, and the `deploy/api` overlay.

## Local Development

```bash
docker compose up --build
curl http://localhost:3000/health
```

The compose file is intentionally development-only. It uses a local PostgreSQL
container, placeholder BTCPay values, and `ALLOW_EPHEMERAL_KEYS=1`. Do not use
that mode for any persistent environment because restarts rotate API signing and
session keys.

## Production Shape

CAP API is a stateless HTTP service backed by PostgreSQL. It performs these
startup checks before serving traffic:

- installs the rustls crypto provider;
- rejects debug-only flags in release builds;
- loads PostgreSQL config and runs migrations;
- loads API signing and session HMAC keys;
- verifies the signed platform release when policy-read mode is enabled;
- verifies digest-pinned platform sidecar images with cosign;
- builds DNS, Trustee/KBS, policy signing, registry, and tenant TEE clients.

The `deploy/api` overlay is a minimal starting point. Production manifests must
provide the full env set below, mount key material from a real secret manager,
pin images by digest, and grant the API only the Kubernetes permissions needed
for CAP-managed tenant resources.

## Required Environment

Required for every persistent API process:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. Migrations run on startup. |
| `BTCPAY_WEBHOOK_SECRET` | Required by startup gates even if billing routes are not exercised. |
| `API_SIGNING_KEY_PATH` or `API_SIGNING_KEY_PKCS8_BASE64` | Ed25519 PKCS#8 private key used for config JWTs and deploy metadata. |
| `SESSION_HMAC_KEY_PATH` or `SESSION_HMAC_KEY_BASE64` | 32-byte HMAC key used for session JWTs and signer rotation tokens. |

Required in release builds:

| Variable | Purpose |
| --- | --- |
| `API_KEY_HMAC_PEPPER` or `API_KEY_HMAC_PEPPER_BASE64` | Pepper for HMAC-format API keys. Must be at least 32 bytes. |
| `TRUSTEE_POLICY_READ_AVAILABLE=true` | Enables the supported signed-policy/in-TEE verification path. |
| `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX` | Compile-time root public key required to verify the bundled or supplied platform release. |

Required for production deploys:

| Variable | Purpose |
| --- | --- |
| `ATTESTATION_PROXY_IMAGE` | Digest-pinned attestation-proxy image. Can come from the signed platform release. |
| `CADDY_INGRESS_IMAGE` | Digest-pinned tenant ingress image. Can come from the signed platform release. |
| `TRUSTEE_KBS_URL` | HTTPS Trustee KBS URL. Release builds reject `http://` values. |
| `TRUSTEE_KBS_CA_CERT_PEM` or `TRUSTEE_KBS_CA_CERT_PATH` | Root certificate for private Trustee KBS TLS, when not using public roots. |
| `WORKLOAD_ARTIFACTS_URL` | Workload-attested CAP artifact endpoint used by `enclava-init`. |
| `TRUSTEE_POLICY_URL` | Workload-attested active Trustee policy endpoint used by `enclava-init`. |
| `TRUSTEE_ATTESTATION_VERIFY_URL` | Trustee callback used by CAP workload artifact and TLS broker routes. |
| `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN` | Caller auth token CAP presents to the Trustee verify endpoint. |
| `PLATFORM_SIGNING_SERVICE_URL` | Policy signing service endpoint. Can come from the signed platform release. |
| `SIGNING_SERVICE_PUBKEY_HEX` or `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX` | Ed25519 public key used to verify signed policy artifacts. Can come from the platform release. |

Required only when the matching feature is enabled:

| Variable | Purpose |
| --- | --- |
| `TLS_CERTIFICATE_BROKER_URL` | Required when `TENANT_CADDY_TLS_MODE=dns01-broker`. |
| `PLATFORM_SIGNING_SERVICE_TOKEN` | Bearer token sent to the policy signing service when configured. |
| `DNS_MANAGEMENT_REQUIRED=1` | Makes CAP fail startup unless DNS credentials are configured. |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token used for CAP-managed tenant records. |
| `TENANT_DNS_TARGET` | A/AAAA target for managed tenant records. |

## Defaulted Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `BIND_ADDR` | `0.0.0.0:3000` | API listen address. |
| `API_URL` | `http://localhost:3000` | Public API base URL embedded in deploy metadata. |
| `PLATFORM_DOMAIN` | `enclava.dev` | Public app hostname suffix. |
| `TEE_DOMAIN_SUFFIX` | `tee.<PLATFORM_DOMAIN>` | TEE/attestation hostname suffix. |
| `BTCPAY_URL` | `http://localhost:23001` | BTCPay Greenfield API base URL. |
| `BTCPAY_API_KEY` | empty | Billing API key. Billing calls need a real value. |
| `TENANT_CADDY_TLS_MODE` | `acme` | Tenant TLS mode: `acme`, `dns01-broker`, or `internal`. |
| `TENANT_CADDY_ACME_CA` | Let's Encrypt production directory | ACME directory URL used by tenant Caddy. |
| `CLOUDFLARE_ZONE_NAME` | `enclava.dev` | Managed DNS zone name. |
| `CLOUDFLARE_ZONE_ID` | unset | Optional zone ID to skip lookup. |
| `CAP_MAX_CONCURRENT_APPLIES` | `1` | Per-process apply concurrency limit. |
| `CORS_ALLOWED_ORIGINS` | empty in release, localhost in debug | Comma-separated allowed browser origins. |
| `TRUSTED_PROXY_CIDRS` | empty | CIDRs trusted for rate-limit client IP extraction. |
| `REGISTRY_ALLOWLIST` | built-in defaults | Registry host allowlist for outbound image metadata requests. |
| `OUTBOUND_HTTP_BODY_LIMIT_BYTES` | code default | Max outbound HTTP body size for guarded client responses. |
| `ACME_DIRECTORY_URL` | tenant Caddy ACME CA | ACME directory for the DNS-01 broker. |
| `ACME_ACCOUNT_CREDENTIALS_PATH` | unset | Optional persisted ACME account credentials path. |
| `ACME_DNS_PROPAGATION_SECONDS` | `30` | DNS propagation wait used by the broker. |

Debug-only flags rejected by release builds:

```text
SKIP_COSIGN_VERIFY
COSIGN_ALLOW_HTTP_REGISTRY
ALLOW_EPHEMERAL_KEYS
TENANT_TEE_ACCEPT_INVALID_CERTS
ENCLAVA_TEE_ACCEPT_INVALID_CERTS
LEGACY_BOOTSTRAP_SCRIPT
TENANT_TEE_TLS_MODE=staging|insecure
```

## Platform Release

The API and CLI both load `crates/enclava-cli/platform-release.json` unless
`ENCLAVA_PLATFORM_RELEASE_PATH` points at another signed release envelope.
Release verification checks:

- the envelope signature against `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX`;
- digest pins for `attestation_proxy_image` and `caddy_ingress_image`;
- HTTPS Trustee KBS URL;
- concrete genpolicy version;
- policy template hash;
- runtime class match between release metadata and the engine.

When release metadata supplies a value, an explicit env override must match it
exactly or startup fails.

## Kubernetes

The minimal overlay:

```bash
kubectl apply -k deploy/api/
kubectl -n enclava-platform rollout status deploy/enclava-api
```

Before using it for a real environment, replace placeholder secret references,
pin the API image digest in `deploy/api/kustomization.yaml`, add the production
env values above, and verify the service account/RBAC can apply only the
tenant resources CAP owns.

## Image Verification

CAP verifies platform sidecars at API startup and verifies user workload images
on deploy. Apps must have a pinned signer identity before deploy. The CLI
starter workflow generated by `enclava init` signs images with GitHub Actions
keyless cosign and deploys by immutable digest. Integrations may instead submit
provider metadata through `POST /deployments`; CAP validates GitHub/GHCR and
GitLab/GitLab Registry identities without calling either provider API.
