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
| `TRUSTEE_ATTESTATION_VERIFY_URL` | Trustee callback endpoint used by CAP workload artifact and TLS broker routes. Must be an `https://` URL: release builds reject `http://` verify URLs at startup (the verify bearer token must never transit cleartext), and the trustee client refuses cleartext requests in all builds. |
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
| `CAP_EGRESS_ALLOW_INTERNAL_HOSTS=true` | Operator opt-out: tenant `egress_allowlist` hosts matching internal hostname patterns are accepted instead of rejected; each accepted host is audit-logged. Matched patterns include `localhost`/`*.localhost`, `*.svc`/`*.svc.cluster.local`, `*.cluster.local`, `*.internal`, `*.local`/`*.localdomain`, `metadata.*`, and rebinding helpers (`*.nip.io`, `*.sslip.io`, `*.localtest.me`, `*.lvh.me`) — see `egress_allowlist_host_audit_reasons` for the full set; this is a hostname-pattern check, not a DNS resolution check. When any allowlisted host on an app matches such a pattern, the app's generated Cilium policy shrinks its `egressDeny` CIDR list to metadata/link-local only for every allowlisted name on that app — all other non-public space (RFC1918, loopback, CGNAT, ULA) becomes reachable via any allowlisted FQDN, while metadata (169.254.0.0/16, fd00:ec2::254) and link-local stay denied. |
| `CAP_ALLOW_PRODUCTION_INTERNAL_EGRESS=true` | Required in release builds when `CAP_EGRESS_ALLOW_INTERNAL_HOSTS` is enabled: an explicit second acknowledgment that tenant egress to internal endpoints is intended in production. Release builds without it refuse to start (and the runtime check stays disarmed even if startup gating is bypassed); debug builds ignore it. |
| `GHCR_USERNAME` and `GHCR_TOKEN` | Optional credentials used to create tenant namespace image-pull secrets for private GHCR images. Requires `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES` — startup is refused without it (issue #225). |
| `TENANT_IMAGE_PULL_SECRET_NAME` | Tenant image-pull secret name. Defaults to `enclava-registry-auth` when GHCR credentials are configured. |
| `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES` | Required comma-separated scope for the tenant pull secret when GHCR credentials are set (startup is refused otherwise). Use `registry/repository` for exact matches or `registry/repository/*` for subrepositories — only a single trailing `/*` is a wildcard, and any other `*` (including repeated suffixes like `registry/repository/*/*`) is rejected instead of being widened. Entries must use the workload-image reference grammar (`registry` = dotted host or `host:port`, no scheme; repository path components cannot be empty, `.`, `..`, or carry `:tag`/`@digest` suffixes) and must live under the literal `ghcr.io` host — the generated secret's only auth entry is `ghcr.io` (made from `GHCR_USERNAME`/`GHCR_TOKEN`), so a scope at any other registry would expose the platform token to workloads that can never use it. A scope such as `ghcr.io/org/private:latest` or `https://ghcr.io/org/private` can never match a digest-pinned workload image and is rejected at startup instead of silently withholding the pull secret from affected workloads. Every entry must parse; an invalid entry refuses startup and the error names the offending entries instead of being silently dropped. The secret is only attached when every container image in a workload matches the scope — it is never attached to arbitrary tenant namespaces. Managed pull secrets are removed from namespaces where they no longer belong: at every deploy of an out-of-scope workload and by a startup sweep (also run on a bounded backoff while it cannot converge). Cleanup is name-independent — every secret carrying the `cap.enclava.dev/tenant-image-pull-secret=true` label is discovered under any name, so changing or removing `TENANT_IMAGE_PULL_SECRET_NAME` cannot strand an old platform PAT (a renamed secret stays only while a generated ServiceAccount still references it, i.e. until that workload redeploys), and stale `imagePullSecrets` references are cleared from the generated ServiceAccounts alongside the delete. Only CAP-generated secrets are ever deleted and only their references are cleared — secrets carrying the dedicated `cap.enclava.dev/tenant-image-pull-secret=true` label (the cleanup's discovery/deletion selector; it also carries the generic `managed-by: enclava-platform` marker), or pre-label legacy secrets whose embedded credentials match the configured GHCR pair; a tenant-owned look-alike under the same name is never deleted and its ServiceAccount references keep working. Discovery selects the dedicated label only, so no other managed Secret can ever enter the sweep. Kept legacy secrets are adopted (labeled) as soon as they are seen in a still-in-scope namespace, so the ownership proof survives the GHCR token rotation; upgrade and rotate in this order: upgrade to this version while the old token is still configured (so the sweep can prove and label pre-label secrets), then rotate the token — rotating first leaves unlabeled legacy secrets unverifiable and therefore in place. After a rotation, kept configured-name secrets in still-in-scope namespaces are refreshed to the current `GHCR_USERNAME`/`GHCR_TOKEN` by the sweep (the write is pinned to the live object's resourceVersion and ownership-proven, so tenant look-alikes are never touched) — pods pull with the new credential without waiting for a redeploy. Reference clears carry durable repair intent on the ServiceAccount (`cap.enclava.dev/pending-pull-secret-reference-repairs`), so a transiently failed restoration after a mid-cleanup replacement is completed by the next sweep instead of silently converging with the ServiceAccount detached. Until the first sweep converges (e.g. during a Kubernetes outage at startup), workload admission stays closed (`deploy_blocked`) and a background reconciler retries with bounded backoff, opening admission and the deployment dispatcher together as soon as a sweep converges — a transient failure no longer requires a restart. |
| `COSIGN_REGISTRY_ALLOWED_HOSTS` | Required when `COSIGN_REGISTRY_BEARER_TOKEN` or `COSIGN_REGISTRY_USERNAME`/`COSIGN_REGISTRY_PASSWORD` is set (startup is refused otherwise). Comma-separated host patterns — exactly `host[:port]`, `*.host[:port]`, or `*` — that may receive the platform cosign registry credentials; entries outside this grammar (e.g. `*ghcr.io`, `**.host`, `ghcr..io`) can never match a registry host and refuse startup instead of silently withholding credentials. Matching: `host[:port]` matches the exact registry host string (case-insensitive; a reference carrying a port only matches a pattern that lists the same port), `*.host` matches `host` and its one-label subdomains (`*.corp.example` matches `reg.corp.example`, but not `reg.corp.example:5000` or `a.b.corp.example` — add exact entries for those), and bare `*` matches every host (explicit all-hosts opt-in, see `COSIGN_REGISTRY_ALLOW_ALL_HOSTS`; startup logs a warning). Matching is always against the host the registry client actually dials (`resolve_registry`) — for example Docker Hub references dial `index.docker.io`, and a `docker.io` entry is canonicalized to match that endpoint — never against the platform's custom image-ref parser. Note the canonicalization rewrites only the bare `docker.io` name: a reference that dials `docker.io:443` is matched as `docker.io:443`, so allowlist that exact host if used (the mismatch fails closed — credentials are withheld, not leaked). Credentials are never sent to any other registry host, including hosts named by tenant-supplied digest-pinned image references. |
| `COSIGN_REGISTRY_ALLOW_ALL_HOSTS=true` | Required in release builds when `COSIGN_REGISTRY_ALLOWED_HOSTS` contains a bare `*`: an explicit second acknowledgment that forwarding the platform cosign registry credentials to every tenant-chosen registry host is intended in production (the same bar as `CAP_ALLOW_PRODUCTION_INTERNAL_EGRESS`). Release builds without it refuse to start; debug builds warn only. |
| `KBS_POLICY_MANAGEMENT_REQUIRED=1` | Fail deploys unless CAP can update the Trustee KBS policy ConfigMap and restart the KBS deployment. |
| `KBS_POLICY_MANAGEMENT_ENABLED=1` | Enable KBS policy management without making it startup-fatal. |
| `KBS_POLICY_NAMESPACE` | Trustee KBS namespace. Defaults to `trustee-operator-system`. |
| `KBS_POLICY_CONFIGMAP` | Trustee policy ConfigMap. Defaults to `resource-policy`. |
| `KBS_POLICY_KEY` | Policy key inside the ConfigMap. Defaults to `policy.rego`. |
| `KBS_POLICY_DEPLOYMENT` | KBS deployment to restart after policy updates. Defaults to `trustee-deployment`. |
| `KBS_SIGNED_POLICY_RETENTION` | Number of signed policy artifacts to retain per app. |
| `KBS_SIGNED_POLICY_MAX_BYTES` | Maximum serialized signed policy artifact set bytes written to the shared KBS policy ConfigMap. Defaults to 900 KiB, below Kubernetes' 1 MiB ConfigMap data limit. |

Rollout coordination: the registry-credential scope gates (`TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES`, `COSIGN_REGISTRY_ALLOWED_HOSTS`) are startup-fatal whenever the corresponding `GHCR_*`/`COSIGN_REGISTRY_*` credentials are set. Land these variables in the environment manifests (e.g. `enclava-ops-manifests`) before or together with this image — an existing environment that carries the credentials without the scopes will crash-loop on this version (AGENTS.md cross-project dependency schema).

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
TRUSTEE_ATTESTATION_VERIFY_URL=http://...
CAP_EGRESS_ALLOW_INTERNAL_HOSTS (without CAP_ALLOW_PRODUCTION_INTERNAL_EGRESS=true)
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
- API overrides must not predate the binary's bundled release; equal timestamps
  with different signed payloads are rejected.

The API compares overrides only with its compiled bundle. Accepting a newer
override does not change that minimum: a previous signed override can be
restored if it still passes validation and is not older than the bundle.
Removing the override selects the bundle again. This check adds no database
migration, persistent release state, or replica-termination watchdog.
Existing database-schema compatibility and CLI per-API release-history checks
still apply; this is not a guarantee that any older API image or client will
accept a rollback.

When the signed release supplies a value, an explicit environment override must
match it exactly or startup fails.

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

## Customer-config roll holds

Internal PaaS redeploys may request `customer_config_roll_hold_seconds`
(30–7200 seconds). CAP freezes setup only when a settled live TEE exists;
a missing or scaled-down workload starts recovery without a hold. An
unreadable or converging workload fails closed with a retryable conflict.

The CLI stores customer config directly in the TEE, then PaaS proxies
`POST /internal/paas/orgs/{org}/deployments/{id}/customer-config-released`.
While an unreleased hold is active, another deploy or rollback cannot
supersede its delivery. Release or expiry permits the next operation;
explicit deletion remains available. Expiry never applies the replacement
and preserves the running workload's signed or legacy KBS authority.

Deploy the PaaS response contract first: every held response, including a
replay, must carry a fresh CAP database-clock
`customer_config_hold_remaining_ms`. The CLI anchors it before sending
the create request and rejects held responses without it. The absolute
`customer_config_hold_until` is diagnostic, not client clock authority.

Apply migrations `0060_customer_config_roll_hold.sql` and
`0071_deployment_apply_committed_at.sql` before the API cutover. Drain old
workers with the existing `Recreate` deployment strategy: the old-worker
claim fence does not make mixed-binary policy writers safe. Public
login, config delivery, release, replacement HTTPS, and persistence must
pass on the explicitly selected environment before rollout acceptance.

## Rollout Compatibility: initdata uid/gid claims

`cc_init_data` uid/gid claims (`app_uid`, `app_gid`, `caddy_uid`,
`caddy_gid`, `managed_config_gid`, `managed_config_dir_mode`) are rendered
as quoted TOML strings, matching kata-agent's requirement that every
`[data]` value be a string. On Kata installations enforcing that format,
the old integer form fails pod creation with `FailedCreatePodSandBox`.

Quoting changes the rendered bytes, and a signed descriptor's
`expected_cc_init_data_hash` covers exactly those bytes. Descriptors signed
with the old integer renderer therefore cannot be replayed against a fixed
API: unlock and rollback validation re-render with the corrected encoder
and reject them with HTTP 400 `signed_artifact_mismatch`
(`expected_cc_init_data_hash`); deployment jobs fail with
`artifact_invalid` on the same mismatch. This is deliberate fail-closed
behavior — the API holds no deployer signing key and cannot re-sign
stored artifacts, and preserving the old render would keep initdata that
Kata rejects anyway. No compatibility fallback exists.

Roll out and recover as follows:

1. Deploy an API image built from a tree containing this change
   (see [Images](#images)).
2. Upgrade the `enclava` CLI to a build from the same tree. The CLI renders
   `expected_cc_init_data_hash` locally when signing and the API re-renders
   and compares it at deploy, so a mixed old/new CLI+API pair is rejected
   at deploy time. Upgrade both before signing new deployments.
3. Re-deploy each app signed before the change, from its app directory
   (the one containing `enclava.toml`):

   ```bash
   enclava deploy --image <image>@sha256:<digest>
   ```

   The CLI signs a fresh descriptor with the deployer key and the API
   verifies the re-rendered hash before applying a new workload rollout.
   Use the existing app configuration, signing identity, and persistent
   volumes; do not delete the app or reset its storage to recover.
   Roll forward with a fresh deploy rather than rolling back — rollback to
   a pre-change deployment artifact hits the same hash rejection.
4. Verify the public boot, claim/unlock, HTTPS, and persistence flow before
   treating the rollout as accepted. CI alone does not establish runtime
   compatibility.

## Smoke Checks

After rollout:

```bash
kubectl -n enclava-platform get deploy enclava-api
kubectl -n enclava-platform exec deploy/enclava-api -- wget -q -O- http://127.0.0.1:3000/health
```

