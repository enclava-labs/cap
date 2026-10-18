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

## Owner Rotation Recovery

Owner-rotation state spans five append-only migrations:

| Migration | Purpose |
| --- | --- |
| `0062_org_rotation_directives.sql` | Consume-once ledger of accepted rotation-directive digests. |
| `0063_org_keyrings_created_at_clock.sql` | `org_keyrings.created_at` defaults to `clock_timestamp()` so freshness bounds measure real insertion time, not transaction start. |
| `0064_org_rotation_intents.sql` | Presentation record for each authenticated, signature-verified directive; proof of presentation only, never of upstream success. |
| `0065_org_keyrings_created_at_watermark.sql` | Floors directive version-recency checks for pre-0063 rows with legacy `created_at` semantics. |
| `0066_org_rotation_upstream_receipts.sql` | Receipts binding a validated signing-service `rotate-owner` response (owner version, `rotated_at`) to the exact directive and normalized keyring digests. |

Note on `0064`'s in-file comment: the SQL comment inside
`0064_org_rotation_intents.sql` is historical and byte-frozen (sqlx
checksums applied migration bytes, and this file's checksum is already
recorded in databases), and it describes the earlier intent-row waiver that
`0066` superseded. Do not read it as current semantics. An intent row is
proof of presentation only: it never grants an authority or freshness waiver.
New distinct presentations are capped at 50 per org per rolling hour (HTTP
429); exact replays of recorded directive/keyring digests remain exempt, so
the quota does not block retrying an already-recorded recovery. The
expired-retry waiver is granted exclusively by a matching
`org_rotation_upstream_receipts` row (see `expired_rotation_waived_by_receipt`
in `routes/orgs.rs`); a captured or unactioned presentation is inert.

Recovery semantics: a rotation directive is first-use bounded by its
`signed_at` max-age. An expired retry of a new-version rotation is accepted
only when a committed upstream receipt proves that this exact request's
`rotate-owner` RPC succeeded and the signing service's current owner
(replacement pubkey, version, `last_changed_at`) still matches the receipt.
Rotations whose upstream response was lost before this deployment -- or any
drift without a matching receipt -- are not waived; the owner must sign and
present a fresh directive.
If the initiator loses owner access after the upstream RPC, another current
org owner can finish the exact receipt-bound request while the replacement
key still has an active registration. The removed owner remains denied;
fresh rotations still require the caller's own active signing-key
registration.

Successor-version keyring writes are fenced on the live owner authority:
after an org has a configured signing service or any recorded rotation
history, a `PUT` keyring request for a new version requires the service to
be reachable and to report either no owner (`not_configured`) or exactly the
current pinned owner. An unreachable, malformed, or owner-mismatched
authority rejects the write (502/409), and an org with rotation history but
no service configuration rejects with 503 until the configuration is
restored. New keyring versions therefore depend on signing-service
availability once owner rotation is in play; exact same-version replays and
rotation receipt retries are unaffected.

Cutover notes for `0066`:

- Migrations run at API startup. During rollout, old API pods never mint
  receipts; drain old pods cleanly (let in-flight requests finish before
  terminating them) rather than leaving a mixed fleet serving rotations.
- Never backfill `org_rotation_upstream_receipts`: presentation alone is
  not proof of upstream success.
- Keep historical intent/directive/keyring rows and applied migration files
  unchanged; do not repair recovery by rewriting ledgers or checksums.

## Quarantined Org Reinitialization

Migration `0061_org_keyring_payload_shape.sql` archives removed keyrings in
`org_keyring_repairs`. If the CURRENT keyring is malformed, it removes every
keyring version of that org; a clean current version that survives retains
its authority. Migration `0085_org_keyring_shape_recoveries.sql` records orgs
that lost all versions in the durable `org_keyring_shape_recoveries` table,
including the highest quarantined version needed to resolve the displaced
signer. The archive is provenance, not the recovery gate: removing archive
rows does not remove the marker or make the org a fresh initialization.

For a marked org, `PUT .../keyring` with version 1 must pass the fenced
recovery path under the org signing-authority lane:

- When a live signing-service owner exists, the replacement keyring signer
  must match that owner. A different signer receives HTTP `409`.
- With no live owner registration, or with no configured service and no
  rotation history, the signer must match the highest quarantined version's
  signing key, resolved through `org_keyring_repairs.signing_key_id` and
  `user_signing_keys`. A mismatch receives `409`; unavailable provenance
  receives `503`.
- A configured but unreachable or malformed service fails closed rather
  than falling back to the archive. Rotation history without a configured
  service also fails closed (`503`); restore the service configuration first.
- The caller must still be an active org owner, and the replacement envelope
  must be validly signed by an active signing key registered to that caller.

The accepted recovery deletes the **marker**, not the archive, in the same
transaction immediately before inserting the replacement version 1. A failed
insert rolls the marker deletion back. Migration `0085` installs the database
`BEFORE INSERT` fence `org_keyrings_fence_quarantine_recovery`, which rejects
any keyring insertion while the marker remains. Older binaries cannot bypass
recovery by uploading an unrestricted first version after the migration.

`0085` checks both remaining markers and live/archive version collisions,
regardless of whether the earlier divergent `0061` marker table exists. It
removes every live generation of an affected org and restores or retains its
marker from the original archive. Marker absence is not proof of authorization:
earlier successor handlers could consume a marker after an unfenced version-1
capture. Even legitimate recoveries with archive-colliding versions must repeat
the fenced upload, because this migration cannot distinguish them from those
captures. Clean survivors without a marker or archive collision remain intact.
Inspect migration notices and expect affected orgs to need a fresh fenced
version-1 upload.
Drain old API replicas before resuming writes; the database fence is a
fail-closed guard, not support for mixed-version operation or reader rollback.

Preserve the archive, marker, signing-key provenance, and applied migration
bytes. Do not manually delete recovery state or disable the trigger to force
initialization. If the required signing key is lost or no active caller-owned
registration is available, normal reinitialization cannot proceed. Escalate
for operator-assisted recovery based on verified out-of-band owner intent;
there is no supported archive-deletion bypass.

## Internal Keyring API Deferred Responses

The internal keyring endpoints (`PUT /internal/paas/orgs/{org}/keyring`,
`POST /internal/paas/orgs/{org}/keyring/rotate-owner`) now defer a
publication-pending failure instead of failing the request outright. When
the keyring mutation is committed but KBS policy reconciliation cannot be
confirmed (503 `keyring_policy_reconciliation_pending`), the request's
idempotency record is checkpointed and the caller receives
409 `idempotency_request_in_progress` with `retryable: true`,
`disposition: retry_same_key`, `idempotency_disposition: "deferred"` and
`cause: keyring_policy_reconciliation_pending`. A retry with the same
idempotency key resumes the deferred request -- the checkpoint keeps that
pending code out of the fail-closed disposition -- and re-confirms publication
instead of repeating the mutation. An unrelated 5xx on that reclaim is not
rewritten as publication-pending. Authority mismatches and uncertain upstream
writes terminalize as `idempotency_recovery_required`
(`reconcile_then_retry_with_new_key`) so the same key cannot re-issue the
mutation. The checkpointed lease is the short (~5 s) retry interval, not a
terminal outcome.

Cross-project rollout gate (AGENTS.md): the CAP internal API response shape
changed, so update and test enclava-paas against this response **before**
deploying CAP API. Retries must keep the original idempotency key:
enclava-paas forwards a caller-supplied `Idempotency-Key` deterministically
(namespaced `paas:{org}:sha256(key)`), but when the caller sends none it
derives a per-attempt random key (`cli_cap_idempotency_key`), so a plain
retry would open a new CAP idempotency record instead of resuming the
deferred one. Hosted keyring flows must therefore carry a stable
`Idempotency-Key` (caller-supplied, or a PaaS-derived deterministic key as
the template config-token retry already does) before CAP API with this
change is deployed.

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
| `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX` | Ed25519 public key of the platform trustee policy authority (in-TEE policy verification), unless supplied by the platform release. |
| `SIGNING_SERVICE_PUBKEY_HEX` | Ed25519 public key of the off-cluster signing service that produces signed policy artifacts (`/sign`); policy acceptance verifies against this key. Distinct from `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX`: they are two trust domains, and setting both to the same key fails startup. Never load the trustee policy private key into the signing service — that would collapse the two domains again. |

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
| `TENANT_IMAGE_PULL_CREDENTIAL_GENERATION` | Monotonically increasing unsigned rotation epoch (defaults to 0). Bump it whenever `GHCR_USERNAME`/`GHCR_TOKEN` changes; newer replicas annotate refreshed Secrets with this epoch and older replicas skip refresh when the Secret carries a higher epoch. Without a bump, mixed replicas cannot distinguish old credentials from new. |
| `TENANT_IMAGE_PULL_SCOPE_GENERATION` | Monotonically increasing unsigned repository-scope rollout epoch (defaults to 0). After all replicas run a version with scope fencing, bump this on every repository-scope change — expansion AND narrowing. A newer replica stamps managed Secrets; older replicas refuse to delete/refresh higher-epoch Secrets and keep their workload admission closed until they are upgraded or retired, even when their inventory mutation generation is current. Do not change the scope while pre-fence replicas remain: those binaries cannot honor the marker. Narrowing is additionally fenced outside the deletable Secret: every sweep and deploy records the epoch it acted under in the shared `tenant_pull_secret_scope_fences` table, so after a narrowing rollout deletes a Secret, an older replica running the broader configuration defers (requeueable) instead of recreating the platform PAT on the next deployment — its workload admission likewise stays closed until it is upgraded or retired. A rollout-wide authority (`tenant_pull_secret_rollout_authority`, round-3 review) extends the same contract to namespaces the newer rollout has not swept yet (including brand-new namespaces with no fence row and namespaces without a live Secret to carry the credential epoch): once ANY replica records a newer scope or credential epoch, every older replica defers all tenant pull-secret work fleet-wide until upgraded. |
| `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES` | Required comma-separated scope for the tenant pull secret when GHCR credentials are set (startup is refused otherwise). Use `registry/repository` for exact matches or `registry/repository/*` for subrepositories — only a single trailing `/*` is a wildcard, and any other `*` (including repeated suffixes like `registry/repository/*/*`) is rejected instead of being widened. Entries must use the workload-image reference grammar (`registry` = dotted host or `host:port`, no scheme; repository path components cannot be empty, `.`, `..`, or carry `:tag`/`@digest` suffixes) and must live under the literal `ghcr.io` host — the generated secret's only auth entry is `ghcr.io` (made from `GHCR_USERNAME`/`GHCR_TOKEN`), so a scope at any other registry would expose the platform token to workloads that can never use it. A scope such as `ghcr.io/org/private:latest` or `https://ghcr.io/org/private` can never match a digest-pinned workload image and is rejected at startup instead of silently withholding the pull secret from affected workloads. Every entry must parse; an invalid entry refuses startup and the error names the offending entries instead of being silently dropped. The secret is only attached when every container image in a workload matches the scope — it is never attached to arbitrary tenant namespaces. Managed pull secrets are removed from single-app namespaces on out-of-scope deploys; shared namespaces use the namespace-wide sweep so one app cannot erase another's credentials — and the sweep decides per app: when a shared namespace's apps split across the scope boundary, the Secret stays for the still-matching apps while the no-longer-matching apps' `imagePullSecrets` attachments are cleared (with durable repair intent, so a later broadening re-attaches them without waiting for a redeploy). Cleanup is name-independent — every secret carrying the `cap.enclava.dev/tenant-image-pull-secret=true` label is discovered under any name, so changing or removing `TENANT_IMAGE_PULL_SECRET_NAME` cannot strand an old platform PAT (a renamed secret stays only while a generated ServiceAccount still references it, i.e. until that workload redeploys), and stale `imagePullSecrets` references are cleared from the generated ServiceAccounts alongside the delete. Only CAP-generated secrets are ever deleted and only their references are cleared — secrets carrying the dedicated `cap.enclava.dev/tenant-image-pull-secret=true` label (the cleanup's discovery/deletion selector; it also carries the generic `managed-by: enclava-platform` marker), or pre-label legacy secrets whose embedded credentials match the configured GHCR pair; a tenant-owned look-alike under the same name is never deleted and its ServiceAccount references keep working. Discovery selects the dedicated label only, so no other managed Secret can ever enter the sweep. Kept legacy secrets are adopted (labeled) as soon as they are seen in a still-in-scope namespace, so the ownership proof survives the GHCR token rotation; upgrade and rotate in this order: upgrade to this version while the old token is still configured (so the sweep can prove and label pre-label secrets), then rotate the token — rotating first leaves unlabeled legacy secrets unverifiable and therefore in place. After a rotation, kept configured-name secrets in still-in-scope namespaces are refreshed to the current `GHCR_USERNAME`/`GHCR_TOKEN` by the sweep (the write is pinned to the live object's resourceVersion and ownership-proven, so tenant look-alikes are never touched) — pods pull with the new credential without waiting for a redeploy. Reference clears carry durable repair intent on the ServiceAccount (`cap.enclava.dev/pending-pull-secret-reference-repairs`), so a transiently failed restoration after a mid-cleanup replacement is completed by the next sweep instead of silently converging with the ServiceAccount detached. Until the first sweep converges (e.g. during a Kubernetes outage at startup), workload admission stays closed (`deploy_blocked`) and a background reconciler retries with bounded backoff, opening admission and the deployment dispatcher together as soon as a sweep converges — a transient failure no longer requires a restart. |
| `COSIGN_REGISTRY_ALLOWED_HOSTS` | Required when `COSIGN_REGISTRY_BEARER_TOKEN` or `COSIGN_REGISTRY_USERNAME`/`COSIGN_REGISTRY_PASSWORD` is set (startup is refused otherwise). Comma-separated patterns: `host[:port]`, `*.host[:port]`, or `*`; invalid patterns refuse startup. Matching is case-insensitive, against the OCI-resolved registry and token-realm authority. Bare hosts match only the scheme's default port (443 for HTTPS, 80 for opted-in HTTP); explicit default ports match implicit ones. Wildcards match the base and one-label subdomains, never other ports. Docker Hub `docker.io` and `index.docker.io` are equivalent credential scopes; guarded Hub prechecks use `registry-1.docker.io`. Basic credentials are exchanged for a pull-scoped bearer token by CAP, with the actual token destination checked against this list and token redirects disabled. List token hosts too (e.g. `auth.docker.io`). Token realms require HTTPS unless `COSIGN_ALLOW_HTTP_REGISTRY=true` is explicitly enabled, even with `*`. Raw Basic credentials are never given to OCI; missing/non-Bearer challenges, rejected realms, and failed exchanges fail verification explicitly, not anonymously. Basic-only registries are not supported by this hardened path. Legacy `GHCR_TOKEN` credentials retain an implicit HTTPS/default-port `ghcr.io` realm scope without requiring this list. Bare `*` authorizes every host (see the production acknowledgment below). |
| `COSIGN_REGISTRY_ALLOW_ALL_HOSTS=true` | Required in release builds when `COSIGN_REGISTRY_ALLOWED_HOSTS` contains a bare `*` AND a platform cosign registry credential (`COSIGN_REGISTRY_BEARER_TOKEN` or a complete `COSIGN_REGISTRY_USERNAME`/`COSIGN_REGISTRY_PASSWORD` pair) is configured: an explicit second acknowledgment that forwarding the platform cosign registry credentials to every tenant-chosen registry host is intended in production (the same bar as `CAP_ALLOW_PRODUCTION_INTERNAL_EGRESS`). With no credential configured the wildcard is inert — nothing can be forwarded — so staging the allowlist before enabling credentials is not startup-fatal. Release builds without it refuse to start; debug builds warn only. Setting only one of `COSIGN_REGISTRY_USERNAME`/`COSIGN_REGISTRY_PASSWORD` is always a startup error: an incomplete pair attaches no credential and every private-registry verification would silently run anonymously. |
| `KBS_POLICY_MANAGEMENT_REQUIRED=1` | Fail deploys unless CAP can update the Trustee KBS policy ConfigMap and restart the KBS deployment. |
| `KBS_POLICY_MANAGEMENT_ENABLED=1` | Enable KBS policy management without making it startup-fatal. |
| `KBS_POLICY_NAMESPACE` | Trustee KBS namespace. Defaults to `trustee-operator-system`. |
| `KBS_POLICY_CONFIGMAP` | Trustee policy ConfigMap. Defaults to `resource-policy`. |
| `KBS_POLICY_KEY` | Policy key inside the ConfigMap. Defaults to `policy.rego`. |
| `KBS_POLICY_DEPLOYMENT` | KBS deployment to restart after policy updates. Defaults to `trustee-deployment`. |
| `KBS_SIGNED_POLICY_RETENTION` | Number of signed policy artifacts to retain per app. |
| `KBS_SIGNED_POLICY_MAX_BYTES` | Maximum serialized signed policy artifact set bytes written to the shared KBS policy ConfigMap. Defaults to 900 KiB, below Kubernetes' 1 MiB ConfigMap data limit. |

Rollout coordination: the registry-credential scope gates (`TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES`, `COSIGN_REGISTRY_ALLOWED_HOSTS`) are startup-fatal whenever the corresponding `GHCR_*`/`COSIGN_REGISTRY_*` credentials are set. Land these variables in the environment manifests (e.g. `enclava-ops-manifests`) before or together with this image — an existing environment that carries the credentials without the scopes will crash-loop on this version (AGENTS.md cross-project dependency schema).

Apply `0088_tenant_pull_secret_scope_fences.sql` before starting this API,
including on a fresh database. The API requires both fence tables; it does not
fall back to annotation-only scoping. Drain pre-fence API writers before the
cutover: those binaries cannot honor the database authority. Scope epochs are
monotonic; never lower them to permit an older writer. The shared mutation guard
disables `idle_in_transaction_session_timeout` for its own transaction only.
Created pull Secrets must retain the dedicated managed label and its field
ownership. Missing evidence triggers UID/resourceVersion-conditional deletion;
admission stays closed until removal is observed as 404. A tenant replacement
at the configured name never satisfies platform-credential convergence.

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
- `platform_trustee_policy_pubkey_hex` is present and distinct from
  `signing_service_pubkey_hex` (the in-TEE policy authority and the
  off-cluster signing service are separate trust domains);
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

### Upgrading across the policy-key split (cap#118)

Signed deployment artifacts pin the exact hash of their rendered
`cc_init_data`, which includes the policy-key claims. Artifacts signed
before the platform trustee policy key was split from the signing-service
key were rendered with the collapsed layout (trustee slot = signing-service
key). Such artifacts — rollback targets, unlock transitions, queued-job
replays — still validate after the upgrade: when only the collapsed render
matches the signed hash, the API pins the artifact to that layout and every
consumer (statefulset, enclava-init ConfigMap, KBS policy/TLS bindings)
renders the exact signed bytes, so the workload boots exactly as it did
before the upgrade. No workload-artifact re-signing is required before
rollout; re-deploying (re-signing) an app moves it to the split layout. The
same render-pin mechanism covers artifacts signed before the
`log_encryption_json` claim existed (`omit_log_encryption_claim`). The
production platform-release envelope is the exception: the new
`platform_trustee_policy_pubkey_hex` field is required with no default, so
re-sign the production envelope with a distinct trustee key before
deploying this binary — an old envelope will not load.

### Rotating the production root

The committed `platform-release.json` is signed by a well-known dev fixture
root whose seed is public. Publishing requires a production root held outside
this repository; gates reject the fixture root and any root that does not sign
the envelope the build bundles, so the root and the envelope always rotate
together:

1. Generate the production root offline:
   `openssl genpkey -algorithm ed25519 -out root.pem`
   (`openssl pkey -in root.pem -noout -text` shows the seed and pubkey hex.)
2. Prepare `payload.json`: a copy of the current release payload with the
   fields you are rotating. It MUST include a `platform_trustee_policy_pubkey_hex`
   distinct from `signing_service_pubkey_hex` — releases that omit the field or
   collapse the two keys onto one key are rejected (the in-TEE policy authority
   and the signing service are separate trust domains). The committed payload
   pins the public dev-fixture trustee key: REPLACE that pin with a freshly
   generated trustee key — keeping the committed value is rejected at signing
   and verification time (its seed is public, so anyone with the repo could
   forge policy envelopes). Generate the trustee policy keypair with its own
   offline seed, never reused as the signing-service or root key.
3. Sign the payload with the repository's canonical encoding. Keep the seed
   in a protected file and redirect it into the helper — it never appears in
   argv or shell history:
   `cargo run --locked -p enclava-cli --example platform-release -- sign \
   payload.json < root-seed.hex > platform-release.json`
4. Sanity-check it: `cargo run --locked -p enclava-cli --example \
   platform-release -- verify platform-release.json <root-pubkey-hex>`
5. Set both repository secrets in one sitting:
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


## Keyring Revocation Completion

In signed-policy mode, keyring uploads and owner rotations confirm success only
after the filtered KBS policy has converged. A `503` response with code
`keyring_policy_reconciliation_pending` means the keyring change committed, but
policy publication is still unconfirmed. It does not mean the keyring rolled back.

Confidential teardown admission uses the same signer eligibility as policy
publication: only owner/admin/deployer keys in the latest org keyring qualify,
withdrawn artifacts stay excluded, and unreleased customer-config holds add no
authority. Deletion does not restore revoked signer authority. Its projected
required policy must fit the shared byte budget unless deletion leaves that
policy the same size or smaller.

Retry the same request after restoring KBS availability. Internal PaaS callers
must retain the same idempotency key when the response is stamped `deferred`.
For CLI owner-rotation recovery, reuse the encrypted replacement backup:

```bash
enclava key rotate-owner --backup-out ./owner-replacement.json \
  --passphrase-file ./backup.pass --yes
```

Preserve both the replacement backup and the previous backup until a
fresh login and deployment succeed. Use the updated API and CLI together; drain
old API replicas before relying on these completion semantics.

`enclava key setup` and owner rotation confirm the accepted keyring's
publication before finalizing local state, so they require the acting owner's
keyring write authority and a reachable policy publication path. `enclava key
restore` is read-and-verify: it validates the signed remote keyring and works
for any active member whose derived key is still Owner in that keyring,
without requiring keyring write permission or KBS availability.

Setup also attempts signing-service bootstrap after confirming an existing
keyring, using the accepted envelope's signing owner even when the caller owns
a different authorized key. Bootstrap failures stop setup before local authority
is stored, except for the existing optional-service HTTP `503` compatibility
case. Successful key setup therefore does not certify signing-service readiness.

## Signer Rotation Completion

In signed-policy mode, missing KBS publication configuration rejects a signer
rotation before changing the app or consuming its single-use token. This check
runs under the app authority locks and serializes with signed-mode activation.
Restore the configuration and retry the same request.

After a rotation commits, a public API publication failure returns HTTP `503`
with `signer_rotation_publication_pending`. Internal PaaS callers receive a `deferred`
disposition and must retry with the same idempotency key and request body. CAP
retains the committed response and retries publication only; it does not consume
the rotation token or apply the mutation again. Unrelated, uncertain failures
remain fail-closed and require recovery rather than automatic mutation replay.

CAP checks the committed signer and its database-maintained generation under
authority lanes before and after publication. The generation is captured inside
the authority transaction and stored only as private checkpoint metadata, never
in the successful app response. A later rotation, including a rotation away and
back to the same identity, app deletion, or deletion in progress terminates a
still-pending operation with HTTP `409` and `signer_rotation_superseded`. Internal
callers receive a terminal `completed` disposition; repeating that key returns
the same conflict without another token consumption. Already completed receipts
continue to replay their recorded historical result.

Older or malformed publication checkpoints without a verifiable generation fail closed with
a terminal `idempotency_recovery_required` / `reconcile_then_retry_with_new_key`
disposition. Repeating that key replays the same terminal result; it does not
re-execute the mutation or retry indefinitely. Reconcile the app's current signer
and policy publication before choosing a recovery request with a new key.

The database withdrawal trigger tracks every identity update that commits.
A separate deferred constraint trigger rejects a non-initial identity change
unless the same transaction inserted the rotation token's jti into
`consumed_signer_rotation_tokens`. Older replicas verify the JWT and update
`apps` without that insert, so their rotation fails closed instead of
consuming the token off-ledger. Drain old API replicas before relying on
these semantics: older checkpoint readers do not understand the new
generation, so mixed-version operation and reader rollback are unsupported.

A currently authorized org owner may confirm an already committed signer
identity without a new rotation token. The stateless public endpoint confirms
the current identity, not the historical event behind an earlier request;
event-attributed retries require the internal idempotency checkpoint. A
confirmation cannot change the signer or consume another token. A real identity
transition still requires a fresh, bound, single-use token.

A withdrawn legacy TLS binding stays withdrawn even if a newer artifact has the
same image and init-data measurements. Those measurements do not bind the old
entry to the new workload instance. Fresh deployments must authorize through
signed-policy candidates instead of readmitting the old legacy binding.

Legacy Rego publication is confirmed only when the Trustee pod template carries
the token for the configured ConfigMap namespace, name, policy key, content hash,
and publication event, and that rollout is ready. A content update atomically
persists a new event token in the ConfigMap's publication-token annotation.
Retries reuse it after a crash, including when an intervening policy write must
be repaired back to identical bytes. An unmarked legacy install needs one
adoption rollout; converged retries write neither the ConfigMap nor the Deployment.
Changes to labels, unrelated data keys, or resourceVersion alone do not restart
Trustee when the policy content and publication event are unchanged.
A failed Deployment update is retried. If the template token was already
stored, retries wait for that rollout without creating another generation.
Both legacy and signed publication wait for old replicas to leave and all
updated replicas to become available. Changed policy content or a signed-authority
handoff during confirmation must be reconciled before success is returned.

## Smoke Checks

After rollout:

```bash
kubectl -n enclava-platform get deploy enclava-api
kubectl -n enclava-platform exec deploy/enclava-api -- wget -q -O- http://127.0.0.1:3000/health
```

