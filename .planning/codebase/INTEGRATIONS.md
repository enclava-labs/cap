# External Integrations

**Analysis Date:** 2026-06-28

## APIs & External Services

**Container Registries (read-only metadata):**
- Purpose: Resolve image tags to immutable digests during deploy.
- Client: `crates/enclava-api/src/registry.rs` (`resolve_tag_to_digest`) via `crates/enclava-api/src/clients.rs::RegistryClient`.
- Default allowlist: `ghcr.io`, `docker.io`, `registry-1.docker.io`, `quay.io`, `gcr.io`, `registry.gitlab.com`, plus wildcard suffix `pkg.dev`. Override with `REGISTRY_ALLOWLIST` (comma-separated, `*.suffix` for wildcards).
- All requests are HTTPS-only, redirect-refusing, and SSRF-guarded (loopback / RFC1918 / link-local / IMDS / cluster CIDRs blocked at DNS resolve time).

**Cosign / Sigstore Trust Root:**
- Purpose: Verify platform sidecar images at API startup and user workload images on deploy.
- Client: `crates/enclava-api/src/cosign.rs` using `sigstore` 0.14 (`cosign`, `sigstore-trust-root`, `rustls-tls`).
- Verification model: per-app `VerificationPolicy` (`FulcioUrlIdentity`, `FulcioEmailIdentity`, or raw `PublicKey`). Rekor inclusion is required (`trusted_signature_layers`).
- Trust root pinning: production sets `SIGSTORE_TUF_ROOT_PATH` to a `trusted_root.json` bundled with the CAP release. Without it, falls back to the Sigstore Public Good Instance via TUF (network fetch — refused by surrounding production ops policy).
- Debug-only escape hatches (release builds refuse to start): `SKIP_COSIGN_VERIFY`, `COSIGN_ALLOW_HTTP_REGISTRY`.

**Trustee KBS (Confidential Computing / Kata CDH):**
- Purpose: Workload-attested release of owner seeds, descriptors, keyrings, and signed policy artifacts inside the TEE.
- Two CAP-side roles:
  - API manages KBS owner/TLS bindings and rolls out the Trustee `resource-policy.rego` ConfigMap — `crates/enclava-api/src/kbs.rs`.
  - API delegates workload attestation-token verification back to Trustee before returning artifacts — `crates/enclava-api/src/routes/workload.rs::trustee_attestation_verify_request` (`POST $TRUSTEE_ATTESTATION_VERIFY_URL` with bearer `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN`).
- In-TEE caller: `crates/enclava-init/src/kbs_fetch.rs::KbsClient::fetch_wrap_key` — `GET <kbs_url>/<resource_path>` returns the raw 32-byte wrap key.
- Configuration:
  - `TRUSTEE_KBS_URL` (HTTPS only in release — `enclava_api::env_gates::ensure_kbs_url_allowed`).
  - `TRUSTEE_KBS_CA_CERT_PEM` or `TRUSTEE_KBS_CA_CERT_PATH` for private-CA TLS.
  - `WORKLOAD_ARTIFACTS_URL`, `TRUSTEE_POLICY_URL`, `TRUSTEE_ATTESTATION_VERIFY_URL`, `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN`.
- KBS policy ConfigMap location: `KbsPolicyConfig { namespace, configmap_name, policy_key, deployment_name, required, signed_policy_retention }` — populated via `enclava_api::kbs::config_from_env`.

**Platform Policy Signing Service:**
- Purpose: Forwards the customer-signed deployment descriptor and owner-signed org keyring; receives the Ed25519-signed policy artifact and agent-policy (genpolicy) text. CAP does not author Rego itself.
- Client: `crates/enclava-api/src/signing_service.rs::SigningServiceClient` (redirect-refusing `reqwest` client with optional bearer auth).
- Endpoints (relative to `PLATFORM_SIGNING_SERVICE_URL`):
  - `POST /sign` — produce a `SignedPolicyArtifact`.
  - `POST /agent-policy` — produce `AgentPolicyResponse { agent_policy_text, agent_policy_sha256, genpolicy_version_pin }`.
  - `POST /bootstrap-org` — bootstrap an org keyring signing service identity.
- Auth: optional `PLATFORM_SIGNING_SERVICE_TOKEN` (bearer). Timeout: `PLATFORM_SIGNING_SERVICE_TIMEOUT_SECONDS` (default 120s).
- Signature verification of returned artifacts is performed against `SIGNING_SERVICE_PUBKEY_HEX` or `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX` (Ed25519 32-byte hex), which may be supplied by the signed platform release.

**Cloudflare DNS API:**
- Purpose: CAP-managed tenant A/AAAA records and DNS-01 ACME `_acme-challenge` TXT records.
- Client: `crates/enclava-api/src/dns.rs` (`ensure_a_record`, `ensure_txt_record`, etc.) using the SSRF-defended `http_client` from `state`.
- Auth: `CLOUDFLARE_API_TOKEN` (bearer). Optional `CLOUDFLARE_ZONE_ID` to skip the zone lookup; otherwise resolved from `CLOUDFLARE_ZONE_NAME` (default `enclava.dev`).
- Required when: `DNS_MANAGEMENT_REQUIRED=1`, or when `TENANT_CADDY_TLS_MODE=dns01-broker` (ACME DNS-01 path).

**ACME / Let's Encrypt (DNS-01 broker):**
- Purpose: Issue tenant Caddy TLS certificates via DNS-01 challenges when `TENANT_CADDY_TLS_MODE=dns01-broker`.
- Client: `crates/enclava-api/src/acme.rs::issue_dns01_certificate` using `instant_acme` 0.8 + `hickory-resolver` 0.26 for TXT propagation polling.
- Config: `ACME_DIRECTORY_URL` (defaults to the tenant Caddy ACME CA, which defaults to the Let's Encrypt production directory), `ACME_ACCOUNT_CREDENTIALS_PATH`, `ACME_DNS_PROPAGATION_SECONDS` (default 30).
- Debug: `TENANT_CADDY_TLS_MODE=staging|insecure` and `TENANT_TEE_TLS_MODE=staging|insecure` are rejected by release builds.

**Kubernetes API:**
- Purpose: Server-side apply, watch, drift detection, teardown, and rollout orchestration of tenant confidential-app resources (StatefulSets, NetworkPolicies, gateways, services, etc.).
- Client: `crates/enclava-engine/src/apply/engine.rs::ApplyEngine` wraps `kube::Client::try_default()` (in-cluster service account or `KUBECONFIG`). Manifests rendered under `crates/enclava-engine/src/manifest/`.
- RBAC: `deploy/api/` overlay grants only the tenant-resource permissions CAP owns; production manifests must replace placeholder secret refs and pin the API image digest.

**AMD SEV-SNP Attestation:**
- Purpose: Parse and verify AMD SEV-SNP attestation reports presented by the TEE TLS handshake (Phase 7 attestation verifier).
- Client: `crates/enclava-cli/src/attestation.rs` using `sev` 7.1.0 (`snp`, `openssl`, `serde`).
- Verification targets include `report_data`, `host_data`, `firmware_measurement`, and the TEE TLS leaf certificate SPKI; bindings flow through `DeploymentDescriptor` (`crates/enclava-common/src/descriptor.rs`).

**OCI Image Signers (validated client-side, no provider API call):**
- Purpose: Bind GitHub/GitLab source repositories to expected cosign Fulcio identities.
- Implementation: `crates/enclava-api/src/source_provider.rs::validate_signing_identity` validates the `source_repository`, the image registry host (`ghcr.io` for GitHub, `registry.gitlab.com` for GitLab), the Fulcio issuer (`https://token.actions.githubusercontent.com` or `https://gitlab.com`), and the cosign subject. **CAP does NOT call GitHub or GitLab APIs** — it validates provider metadata submitted by the integrator.

**Nostr NIP-98 (auth provider, no relay dependency):**
- Purpose: Stateless HTTP auth via signed kind-27235 Nostr events (`crates/enclava-api/src/auth/nostr.rs`).
- Implementation: server-side signature + `url` / `method` / `payload` (sha256 body) tag verification. No relay subscription; events arrive in `Authorization` header or JSON body.

**BTCPay Server (webhook client — admin-controlled):**
- Purpose: Optional outbound webhook calls to an admin-configured BTCPay host.
- Client: `crates/enclava-api/src/clients.rs::WebhookClient`. Same SSRF defenses as the registry client but no host allowlist (admin-controlled destination). HTTPS-only, redirect-refusing, capped response body.

## Data Storage

**Databases:**
- PostgreSQL 16 (dev compose uses `postgres:16-alpine`).
- Connection: `DATABASE_URL` (e.g. `postgresql://user:pass@host:5432/db`).
- Client: `sqlx` 0.8 `PgPool`, max 20 connections (`crates/enclava-api/src/db/pool.rs::create_pool`).
- Migrations: SQLx embedded migrations under `crates/enclava-api/migrations/` (34 files: `0001_users_and_orgs.sql` through `0034_workload_tls_certificate_cache.sql`); run on startup via `sqlx::migrate!("./migrations")`.
- Schema ownership: `crates/enclava-api/src/db/{mod,orgs,pool}.rs` plus per-feature SQL scattered through route handlers.

**File Storage:**
- Local filesystem only inside the TEE: `enclava-init` writes seeds, certificates, and ready/error/stage files under `/run/enclava/` and the configured persistent root. Two LUKS volumes per app: app data (owner-seed backed) and TLS state (for tenant Caddy continuity).
- API state is fully in PostgreSQL — no on-disk persistence outside the DB.

**Caching:**
- None. Stateless API; Trustee/KBS, signing service, and Kubernetes API are queried live. Workload TLS certificate material is cached in the `workload_tls_certificate_cache` migration but not in an external cache.

## Authentication & Identity

**Auth Provider:**
- Custom (multi-provider, all in-tree under `crates/enclava-api/src/auth/`):
  - Email + password (`auth/email.rs`) — Argon2 verification.
  - Nostr NIP-98 (`auth/nostr.rs`).
  - API keys (`auth/api_key.rs`) — new `enclava_` HMAC-SHA256 format; legacy `enc_` Argon2 keys remain verifiable during the migration window. Scopes: `apps:read`, `apps:write`, `config:write`, `org:admin`.
  - Session JWT (`auth/jwt.rs`) — signed with the 32-byte `SESSION_HMAC_KEY` HMAC key.
  - Config JWTs — signed with the Ed25519 `API_SIGNING_KEY`.
  - Device login (`auth/device/start|poll|approve` routes) — dashboard-approved at `ENCLAVA_DASHBOARD_URL` (falls back to `API_URL`).
- PaaS-internal route auth (`routes/internal.rs::InternalAuth`): bearer token (`CAP_INTERNAL_SERVICE_TOKEN`, with rotation via `CAP_INTERNAL_SERVICE_TOKEN_NEXT`), mTLS client SAN (`CAP_INTERNAL_ALLOWED_CLIENT_SANS`), and optional trusted-proxy secret (`CAP_INTERNAL_TRUSTED_PROXY_SECRET`). Required when `CAP_MANAGEMENT_MODE=paas_managed`. Tokens stored as SHA-256 digests; comparisons constant-time.

## Monitoring & Observability

**Error Tracking:**
- None (no Sentry/Datadog/etc. dependency detected).

**Logs:**
- `tracing` 0.1 + `tracing-subscriber` 0.3 (`env-filter`, `json`). API uses `EnvFilter::try_from_default_env().unwrap_or_else(|_| "enclava_api=debug,tower_http=debug")` with `fmt::layer()` (`crates/enclava-api/src/main.rs`).
- `enclava-init` writes JSON-formatted tracing to stdout, plus stage/error files at `/run/enclava/init-stage`, `/run/enclava/init-error`, and the Kubernetes termination log (`ENCLAVA_INIT_TERMINATION_LOG`).
- HTTP request tracing via `tower_http::trace::TraceLayer` in `crates/enclava-api/src/lib.rs::build_router`.

## CI/CD & Deployment

**Hosting:**
- Container images at GHCR (`ghcr.io/enclava-labs/enclava-api`, `ghcr.io/enclava-labs/enclava-init`).
- Production target: Kubernetes (`deploy/api/` Kustomize overlay).

**CI Pipeline:**
- GitHub Actions (`.github/workflows/`):
  - `ci.yml` — fmt check, clippy (`-D warnings`), `cargo test --workspace`, doctests, `cargo audit` (ignoring `RUSTSEC-2023-0071`), `cargo deny check advisories sources`, full workspace build, release-bin builds, `prod-strict` builds, and prod-strict-vs-debug feature rejection tests. Postgres 16-alpine service container provides `DATABASE_URL=postgresql://test:test@localhost:5432/test`.
  - `api-image.yml` — builds/pushes `ghcr.io/enclava-labs/enclava-api` on `main` and tags `v*`; renders a digest-pinned deploy manifest via `scripts/render-api-release-manifest.sh` and uploads it as a workflow artifact.
  - `enclava-init-image.yml` — builds/pushes `ghcr.io/enclava-labs/enclava-init` on `main`.
  - `release.yml` — on `v*` tags, builds `enclava` CLI for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, publishes a GitHub Release with `SHA256SUMS.txt` via `softprops/action-gh-release@v2`.
- All third-party actions are pinned by SHA (e.g. `actions/checkout@34e1148...`, `dtolnay/rust-toolchain@29eef33...`).

## Environment Configuration

**Required env vars (every persistent API process):**
- `DATABASE_URL`, `API_SIGNING_KEY_PATH` (or `API_SIGNING_KEY_PKCS8_BASE64`), `SESSION_HMAC_KEY_PATH` (or `SESSION_HMAC_KEY_BASE64`).

**Required in release builds:**
- `API_KEY_HMAC_PEPPER` (or `API_KEY_HMAC_PEPPER_BASE64`) — ≥32 bytes.
- `TRUSTEE_POLICY_READ_AVAILABLE=true`.
- `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX`.

**Required for production deploys:**
- `ATTESTATION_PROXY_IMAGE`, `CADDY_INGRESS_IMAGE` (digest-pinned; can come from the signed platform release).
- `TRUSTEE_KBS_URL`, `TRUSTEE_KBS_CA_CERT_PEM`/`TRUSTEE_KBS_CA_CERT_PATH`.
- `WORKLOAD_ARTIFACTS_URL`, `TRUSTEE_POLICY_URL`, `TRUSTEE_ATTESTATION_VERIFY_URL`, `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN`.
- `PLATFORM_SIGNING_SERVICE_URL`, `SIGNING_SERVICE_PUBKEY_HEX`/`PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX`.

**Conditionally required:**
- `TLS_CERTIFICATE_BROKER_URL` when `TENANT_CADDY_TLS_MODE=dns01-broker`.
- `PLATFORM_SIGNING_SERVICE_TOKEN` when the signing service requires bearer auth.
- `CLOUDFLARE_API_TOKEN`, `TENANT_DNS_TARGET` when `DNS_MANAGEMENT_REQUIRED=1`.
- `CAP_INTERNAL_SERVICE_TOKEN`, `CAP_INTERNAL_ALLOWED_CLIENT_SANS` when `CAP_MANAGEMENT_MODE=paas_managed`.

**Defaulted env vars:** `BIND_ADDR=0.0.0.0:3000`, `API_URL=http://localhost:3000`, `PLATFORM_DOMAIN=enclava.dev`, `TEE_DOMAIN_SUFFIX=tee.<PLATFORM_DOMAIN>`, `TENANT_CADDY_TLS_MODE=acme`, `CLOUDFLARE_ZONE_NAME=enclava.dev`, `CAP_MAX_CONCURRENT_APPLIES=1`, `ACME_DNS_PROPAGATION_SECONDS=30`.

**Secrets location:**
- Injected by the deployment environment (Kubernetes secrets → env or mounted files). The `deploy/api/` overlay references placeholders that must be replaced with real secret-manager mounts.
- `.gitignore` excludes `*.env`, `.env.*`, `*.pem`, `*.key`, `private-age-key*`, `*.sops.yaml`.
- `docker-compose.yml` ships with placeholder dev credentials and must never be used for persistent environments.

## Webhooks & Callbacks

**Incoming:**
- Public API routes under `crates/enclava-api/src/lib.rs::build_api_routes` (auth, users, orgs, apps, deployments, config, domains, status, unlock, workload artifacts/TLS).
- PaaS-only internal routes under `/internal/paas/*` (`crates/enclava-api/src/lib.rs::internal_routes`) — enabled only when `CAP_MANAGEMENT_MODE=paas_managed`. Authenticated via `InternalAuth` (bearer + client SAN + optional trusted-proxy secret).
- Workload-attested endpoints: `GET /api/v1/workload/artifacts` and `POST /api/v1/workload/tls/dns01-certificate` (`crates/enclava-api/src/routes/{workload,workload_tls}.rs`). Both delegate attestation-token verification to Trustee before responding.

**Outgoing:**
- Platform signing service (`POST /sign`, `/agent-policy`, `/bootstrap-org`) — `crates/enclava-api/src/signing_service.rs`.
- Trustee attestation verify (`POST $TRUSTEE_ATTESTATION_VERIFY_URL`) — `crates/enclava-api/src/routes/workload.rs`.
- Cloudflare DNS API (`POST/GET/PUT/DELETE /zones/.../dns_records`) — `crates/enclava-api/src/dns.rs`.
- ACME directory + account + order endpoints — `crates/enclava-api/src/acme.rs`.
- OCI registry manifest endpoints (`HEAD /v2/<repo>/manifests/<tag>`) — `crates/enclava-api/src/registry.rs`.
- Kubernetes API server (apply/watch/patch/delete) — `crates/enclava-engine/src/apply/`.
- Trustee KBS (`GET <kbs_url>/<resource_path>`) — `crates/enclava-init/src/kbs_fetch.rs` (workload-side).
- TLS certificate broker (`POST $TLS_CERTIFICATE_BROKER_URL`) — `crates/enclava-init/src/tls_certificate.rs` (workload-side).
- BTCPay webhook callbacks (admin-configured host) — `crates/enclava-api/src/clients.rs::WebhookClient`.

---

*Integration audit: 2026-06-28*
