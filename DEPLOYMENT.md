# Deployment

This guide covers three deployment paths:

1. **Local development** — Docker Compose.
2. **Single host** — Docker + an external PostgreSQL.
3. **Kubernetes** — the reference overlay in `deploy/api/`.

CAP's API is a stateless HTTP service. It needs PostgreSQL for platform state
and a [BTCPay Server](https://btcpayserver.org) instance for Bitcoin payments.
To actually provision workloads into confidential enclaves you also need a
Kubernetes cluster with AMD SEV-SNP nodes and the companion attestation-proxy,
but the API itself runs anywhere a normal container runs.

## 1. Local development (Docker Compose)

```bash
docker compose up --build
curl http://localhost:3000/health
```

This spins up PostgreSQL and the API with placeholder credentials (see
`docker-compose.yml`). `ALLOW_EPHEMERAL_KEYS=1` lets the API generate signing
and session keys on boot — fine for development, never enable in production.

## 2. Single host (Docker + external PostgreSQL)

```bash
docker run --rm -d --name cap-api \
  -p 3000:3000 \
  -e DATABASE_URL="postgres://USER:PASS@HOST:5432/enclava" \
  -e API_URL="https://api.example.com" \
  -e PLATFORM_DOMAIN="example.com" \
  -e BTCPAY_URL="https://btcpay.example.com" \
  -e BTCPAY_API_KEY="..." \
  -e BTCPAY_WEBHOOK_SECRET="..." \
  -e API_SIGNING_KEY_PKCS8_BASE64="$(cat api-signing-key.b64)" \
  -e SESSION_HMAC_KEY_BASE64="$(cat session-hmac.b64)" \
  ghcr.io/enclava-ai/enclava-api:main
```

Database migrations run automatically on boot.

## 3. Kubernetes

The `deploy/api/` directory is a Kustomize overlay with the minimal resources
(Namespace, Deployment, Service, Ingress, and a placeholder `api-secrets`
Secret).

```bash
# Edit deploy/api/ingress.yaml to match your DNS and ingress class.
# Edit deploy/api/kustomization.yaml to set real secret values, or replace the
# secretGenerator with a SealedSecret / ExternalSecret.

kubectl apply -k deploy/api/
kubectl -n enclava-platform rollout status deploy/enclava-api
```

The overlay assumes cert-manager with a `letsencrypt-prod` ClusterIssuer and an
`nginx` IngressClass. Swap those annotations if your cluster is different.

## Environment variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DATABASE_URL` | yes | — | PostgreSQL 16+ connection string |
| `API_URL` | yes (prod) | `http://localhost:3000` | Public base URL of the API |
| `PLATFORM_DOMAIN` | yes (prod) | `enclava.dev` | Suffix used for per-app subdomains |
| `BIND_ADDR` | no | `0.0.0.0:3000` | Listen address |
| `BTCPAY_URL` | yes (billing) | `http://localhost:23001` | BTCPay Greenfield API base URL |
| `BTCPAY_API_KEY` | yes (billing) | — | BTCPay API key |
| `BTCPAY_WEBHOOK_SECRET` | yes (billing) | — | BTCPay webhook HMAC secret |
| `API_SIGNING_KEY_PATH` | one of these | — | Path to PKCS#8 Ed25519 private key |
| `API_SIGNING_KEY_PKCS8_BASE64` | one of these | — | Same key, base64-encoded |
| `SESSION_HMAC_KEY_PATH` | one of these | — | Path to 32-byte session HMAC key |
| `SESSION_HMAC_KEY_BASE64` | one of these | — | Same key, base64-encoded |
| `ALLOW_EPHEMERAL_KEYS` | dev only | unset | If `1`, generate signing/HMAC keys in memory |
| `COSIGN_PUBLIC_KEY_PATH` | one of these | — | Cosign public key file for image verification |
| `COSIGN_PUBLIC_KEY_PEM` | one of these | — | Same key, inline PEM |
| `SKIP_COSIGN_VERIFY` | dev only | unset | If `1`, bypass cosign signature verification |
| `ATTESTATION_PROXY_IMAGE` | yes (deploy) | — | Digest-pinned attestation-proxy image (`name@sha256:...`) |
| `CADDY_INGRESS_IMAGE` | yes (deploy) | — | Digest-pinned tenant ingress Caddy image (`name@sha256:...`) |
| `TENANT_CADDY_TLS_MODE` | no | `acme` | Tenant Caddy issuer mode. Use `internal` only for staging/live-smoke loops with insecure client TLS verification |
| `TENANT_CADDY_ACME_CA` | no | Let's Encrypt production | ACME directory URL used when `TENANT_CADDY_TLS_MODE=acme` |
| `CLOUDFLARE_API_TOKEN` | no | — | Cloudflare API token used by CAP to manage tenant A/AAAA records |
| `CLOUDFLARE_ZONE_NAME` | no | `enclava.dev` | Cloudflare zone name CAP manages |
| `CLOUDFLARE_ZONE_ID` | no | — | Optional Cloudflare zone ID; avoids zone lookup when set |
| `TENANT_DNS_TARGET` | no | — | Public tenant ingress IP for CAP-managed A/AAAA records |
| `DNS_MANAGEMENT_REQUIRED` | no | unset | If `1`, API startup fails unless CAP DNS env is configured |
| `RUST_LOG` | no | `enclava_api=debug,tower_http=debug` | Log filter |

CAP manages public tenant DNS records. Tenant TLS private keys and certificates
remain workload-owned: the generated tenant ingress sidecar performs ACME
TLS-ALPN-01 by default and stores certificate state in the tenant TLS volume.

### Signing keys

Generate an Ed25519 signing key (PKCS#8) and a 32-byte session HMAC key:

```bash
openssl genpkey -algorithm ed25519 -outform DER | base64 -w0 > api-signing-key.b64
openssl rand -base64 32 > session-hmac.b64
```

Mount them via `*_PATH` or inject via `*_BASE64`. **Never** run with
`ALLOW_EPHEMERAL_KEYS=1` in production — restarts rotate keys, invalidating
every issued token.

## BTCPay Server

CAP expects a self-hosted BTCPay Server. See
[btcpayserver.org](https://btcpayserver.org) for installation. Create a store,
generate a Greenfield API key with `btcpay.store.cancreateinvoice` permission,
and configure a webhook pointing at `$API_URL/v1/webhooks/btcpay` with the
shared secret from `BTCPAY_WEBHOOK_SECRET`.

## Image builds

`.github/workflows/api-image.yml` builds and pushes
`ghcr.io/enclava-ai/enclava-api:<branch>` and `:<sha>` on every push to `main`.
For your own fork, retarget `images:` in `.github/workflows/api-image.yml` and
`deploy/api/kustomization.yaml`.

## Confidential workloads

Running end-user applications inside SEV-SNP enclaves additionally requires:

- A Kubernetes cluster with kata-containers + the confidential runtime class.
- AMD SEV-SNP capable nodes.
- The attestation-proxy sidecar image.
- A KBS (Key Broker Service) reachable from workload pods.

Those pieces are outside the scope of this repo. The API generates the
manifests (see `crates/enclava-engine`) and applies them via server-side apply
when the runtime is in place.
