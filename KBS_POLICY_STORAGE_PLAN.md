# KBS Policy Artifact Storage Plan

## Purpose

Move deployed workload artifact storage out of the Trustee/KBS policy
ConfigMap. KBS should authorize access to resources. CAP should store full
signed deployment artifacts in its own database and give `enclava-init` enough
signed data to verify that KBS, CAP, and the attested workload all agree before
unlocking state.

This document is the implementation plan for replacing the current compact KBS
policy-set mitigation with a durable CAP-Postgres-backed artifact and receipt
architecture. The migration is allowed to be breaking: old deployments can be
destroyed during the cutover, so the final implementation does not need to keep
legacy full-body or compact-v2 artifact read paths alive.

## Problem

CAP currently publishes active signed policy artifacts through the Trustee KBS
`resource-policy` ConfigMap path. That made issue #18 possible: every active
artifact competes for one Kubernetes ConfigMap data object, which is capped at
1 MiB by Kubernetes. Raising `KBS_SIGNED_POLICY_MAX_BYTES` is not a durable fix
while the backend is still a ConfigMap.

There are two separate concerns that should not share this storage boundary:

- KBS authorization state: small rules or claims that decide whether an
  attested workload may read a resource.
- Workload policy artifacts: larger signed deployment artifacts that
  `enclava-init` verifies before releasing workload state.

The current compact `enclava-signed-policy-set-v2` payload is a safe bridge,
but it is still a shared growing payload. It reduces artifact bytes, but the
payload still grows with retained active artifacts and still depends on the
Kubernetes ConfigMap object limit.

## Current Mitigation

The short-term fix keeps the existing KBS ConfigMap flow but writes compact
`enclava-signed-policy-set-v2` policy sets. The compact body omits
`agent_policy_text` and keeps only the metadata, Rego text, hashes, signature,
verification key, and optional keyring reference needed for active policy
matching. `enclava-init` fetches the full artifact bundle from CAP and verifies
that the compact KBS body matches the signed full artifact.

Reasoning:

- This was the smallest safe emergency change because it did not require a
  Trustee backend change.
- It keeps fail-closed artifact verification: compact KBS data must still match
  the full signed CAP artifact.
- It must remain temporary because any design that serializes active artifacts
  into one ConfigMap will eventually fail again.

## Target Architecture

KBS should authorize access, not store full signed workload artifacts.

CAP remains the artifact authority:

- Store full signed policy artifacts and receipt records in CAP PostgreSQL.
- Serve artifacts through an attestation-gated CAP endpoint.
- Select artifacts by attested `descriptor_core_hash`, `init_data_hash`, app,
  deployment, and instance identity.

KBS stores only small authorization material:

- Static or near-static Rego policy that decides whether an attested workload
  may read a KBS resource path.
- Owner seed and sealed seed resources.
- A tiny per-deployment receipt resource.

`enclava-init` verifies both sides:

- Fetch a small KBS authorization receipt.
- Fetch the full artifact bundle from the CAP URL bound into that receipt.
- Verify that the CAP artifact hashes, identity bindings, and signatures match
  the KBS receipt.
- Continue refusing seed release on any mismatch.

## Architecture Decisions And Reasoning

### Decision: CAP PostgreSQL Is The Artifact Store For V1

Use CAP PostgreSQL for full artifact bundles, receipt rows, retention metadata,
and lookup indexes.

Reasoning:

- CAP already has a database and SQLx migration infrastructure.
- The artifact authority belongs in CAP because CAP already creates, signs,
  serves, and audits deployment artifacts.
- Postgres gives transactional coupling between deployment state, artifact
  rows, receipt rows, and outbox/audit events.
- Postgres avoids introducing object storage credentials, backup policy,
  network policy, and lifecycle complexity before artifact volume requires it.
- Moving from Postgres `jsonb`/`bytea` to object storage later is a contained
  internal storage migration if the external receipt and artifact endpoint
  contracts stay stable.

### Decision: KBS ConfigMap Must Not Contain Dynamic Artifact Lists

Keep the Trustee/KBS ConfigMap for static authorization policy only.

Reasoning:

- Kubernetes ConfigMaps have a hard object-size cliff.
- Dynamic artifact lists grow with deployment count and retention depth.
- A single shared policy object creates cross-deployment blast radius: one large
  artifact set can break unrelated workloads.
- Static policy size is reviewable, predictable, and easy to alert on.

### Decision: Receipts Bind KBS Authorization To CAP Artifacts

Introduce a compact signed receipt that names the exact CAP artifact bundle and
the exact workload identity that may use it.

Reasoning:

- KBS should be able to authorize a resource read without storing the full
  artifact body.
- `enclava-init` needs cryptographic evidence that the small KBS-side object
  and the larger CAP-side artifact are the same deployment decision.
- Receipts make mismatches explicit and testable.
- Receipts remain small enough for KBS resource storage even with many
  deployments because they are per-resource, not a single shared aggregate.

### Decision: KBS Receipt Resources Are Mandatory

Store one receipt per deployment/instance as a KBS resource. Do not rely on the
shared KBS policy ConfigMap for receipts, and do not make CAP's artifact
response the only source of receipt truth.

Reasoning:

- The receipt is the KBS-side authorization binding. If CAP alone supplies it,
  the guest is only comparing CAP to CAP.
- Per-resource KBS receipt storage scales with normal resource count instead of
  one global ConfigMap payload.
- If the current Trustee deployment cannot cleanly store dynamic receipt
  resources, the implementation should first configure or add a proper KBS
  resource backend. It should not fall back to embedding receipts in
  `resource-policy`.

### Decision: CAP Artifact Endpoint Remains Attestation-Gated

Do not make artifact bundles public. `enclava-init` fetches them through a
CAP endpoint gated by workload attestation and deployment identity.

Reasoning:

- Artifact bundles can reveal policy and deployment metadata.
- CAP already has the deployment database needed to decide whether an attested
  workload may fetch a particular bundle.
- Keeping CAP in the authorization path preserves auditability and lets CAP
  revoke or retire artifacts without rewriting KBS policy.

### Decision: `enclava-init` Verifies Before Unlock

`enclava-init` must verify the receipt, artifact bundle, artifact signature,
descriptor hash, init-data hash, and app/deployment/instance binding before
unlocking storage.

Reasoning:

- The TEE guest is the last enforcement point before releasing persistent
  workload state.
- CAP and KBS are separate systems; the guest must fail closed if they disagree.
- This keeps the security property of the compact v2 mitigation while removing
  the ConfigMap growth problem.

### Decision: Migration Is A Breaking Cutover

Destroy old deployments during the migration and switch new deployments to the
receipt-only architecture.

Reasoning:

- Carrying legacy full-body and compact-v2 readers makes the permanent path more
  complex and keeps the old failure mode reachable.
- If old deployments can be destroyed, there is no need to support restarts of
  old pods that depend on ConfigMap artifact-set history.
- A clean cutover gives better test coverage: every post-migration workload must
  use receipt mode, and any legacy format observed after cutover is a bug.
- This is only acceptable when the environment/product owner has approved
  deleting old workload namespaces/PVCs or has separately migrated any customer
  data that must survive.

### Decision: Deploy New `enclava-init` Before New CAP API Anyway

Even with a breaking cutover, update the workload consumer image reference
before deploying CAP API code that creates receipt-only workloads.

Reasoning:

- CAP renders workload manifests with an `ENCLAVA_INIT_IMAGE` reference from its
  environment.
- Deploying the init image reference first ensures every new workload created by
  the receipt-only CAP API starts with receipt-aware init.
- The rollout order is cheap and prevents accidental locked workloads if an old
  pod or old API process briefly remains during deployment.

## Receipt Contract

Schema name: `enclava-kbs-artifact-receipt-v1`

Canonical fields:

```json
{
  "schema_version": "enclava-kbs-artifact-receipt-v1",
  "app_id": "uuid",
  "deployment_id": "uuid",
  "instance_id": "cap-org-app-instance",
  "namespace": "kubernetes-namespace",
  "resource_path": "/default/<instance-id>/policy/receipt",
  "descriptor_core_hash": "hex-sha256",
  "init_data_hash": "hex-sha256",
  "rego_sha256": "hex-sha256",
  "agent_policy_sha256": "hex-sha256",
  "artifact_bundle_sha256": "hex-sha256",
  "artifact_url": "https://cap.../api/v1/workload/artifacts/<deployment-id>/<instance-id>",
  "issuer_key_id": "platform-signing-key-id",
  "issued_at": "rfc3339",
  "expires_at": "rfc3339-or-null",
  "signature_alg": "ed25519",
  "signature": "base64"
}
```

Receipt signing input:

- Use canonical JSON over all fields except `signature`.
- Include `schema_version` and `signature_alg` in the signed payload.
- Bind `resource_path` into the signature.

Reasoning:

- Canonical JSON keeps signatures stable across Rust, Trustee tooling, and
  future test fixtures.
- Binding the resource path prevents a valid receipt from being copied to a
  different KBS resource.
- Binding `namespace` and `instance_id` prevents cross-tenant replay.
- Binding both descriptor and init-data hashes ties the receipt to the measured
  workload identity, not just a user-facing app id.
- Keeping `expires_at` nullable allows non-expiring receipts during the initial
  breaking cutover while preserving an explicit field for future rotation.

## CAP Database Model

Add SQLx migrations for these tables. Names can be adjusted to match existing
CAP naming conventions during implementation.

### `workload_artifact_bundles`

Stores the full signed artifact body served to `enclava-init`.

Columns:

- `id uuid primary key`
- `app_id uuid not null`
- `deployment_id uuid not null`
- `instance_id text not null`
- `namespace text not null`
- `descriptor_core_hash text not null`
- `init_data_hash text not null`
- `rego_sha256 text not null`
- `agent_policy_sha256 text not null`
- `artifact_bundle_sha256 text not null`
- `signed_policy_artifact jsonb not null`
- `artifact_bundle jsonb not null`
- `created_at timestamptz not null`
- `superseded_at timestamptz null`
- `revoked_at timestamptz null`

Indexes:

- Unique active artifact by `(deployment_id, instance_id, descriptor_core_hash,
  init_data_hash)` where `revoked_at is null`.
- Lookup by `(app_id, created_at desc)`.
- Lookup by `artifact_bundle_sha256`.

Reasoning:

- `jsonb` is acceptable for v1 because CAP already serializes these artifacts
  as JSON and the records are modest in size.
- Storing the hash separately gives stable lookup and audit without parsing
  JSON.
- `superseded_at` and `revoked_at` allow retention and incident response
  without deleting rows needed for audit.

### `workload_artifact_receipts`

Stores the compact signed receipt.

Columns:

- `id uuid primary key`
- `artifact_bundle_id uuid not null references workload_artifact_bundles(id)`
- `app_id uuid not null`
- `deployment_id uuid not null`
- `instance_id text not null`
- `resource_path text not null`
- `schema_version text not null`
- `receipt_sha256 text not null`
- `receipt_json jsonb not null`
- `issued_at timestamptz not null`
- `expires_at timestamptz null`
- `published_to_kbs_at timestamptz null`
- `revoked_at timestamptz null`

Indexes:

- Unique active receipt by `(deployment_id, instance_id, resource_path)` where
  `revoked_at is null`.
- Lookup by `artifact_bundle_id`.
- Lookup by `receipt_sha256`.

Reasoning:

- Keeping receipts separate from artifacts makes publication/retry state
  explicit.
- `published_to_kbs_at` supports idempotent workers and operational debugging.
- The active uniqueness constraint prevents two receipts from claiming the same
  live KBS resource path.

## KBS Resource Paths

Recommended paths:

- `/default/<instance-id>/owner/seed-encrypted`
- `/default/<instance-id>/owner/seed-sealed`
- `/default/<instance-id>/policy/receipt`

Reasoning:

- Keeping owner seed resources and receipt resources under the same instance id
  makes teardown and audit simple.
- The path avoids template names and hosted product semantics inside KBS.
- Per-instance paths avoid a global shared object that grows with deployment
  count.

## API Changes

### CAP Internal Artifact Endpoint

Add or extend an endpoint similar to:

`GET /api/v1/workload/artifacts/{deployment_id}/{instance_id}`

Response:

- Full signed artifact bundle.
- Artifact bundle hash.
- Receipt resource path and receipt hash.
- Schema version.

Authorization:

- Require attested workload identity.
- Verify app/deployment/instance mapping.
- Verify descriptor and init-data hashes from attestation claims.

Reasoning:

- Passing deployment and instance in the URL makes operational debugging easier.
- Authorization must not rely only on bearer tokens; it must bind to attested
  workload identity.
- Returning the receipt resource path and hash helps `enclava-init` and
  operators diagnose mismatches while keeping KBS as the receipt source of
  truth.

### CAP KBS Publication Worker

Publish only:

- owner seed resources
- sealed seed resources
- receipt resources

Stop publishing:

- full artifact bodies
- compact artifact-set arrays
- historical artifact lists

Reasoning:

- KBS resource writes should be per deployment and idempotent.
- Artifact history belongs in CAP DB, where retention does not affect KBS
  policy size.

## `enclava-init` Changes

Add receipt mode:

1. Attest to KBS and CAP as today.
2. Fetch receipt from KBS resource path.
3. Fetch full artifact bundle from the CAP artifact URL bound into the receipt.
4. Verify receipt signature using configured platform/Trustee policy public key.
5. Verify receipt fields match the artifact bundle.
6. Verify artifact bundle signatures and hashes as today.
7. Fetch owner seed and sealed seed resources.
8. Unlock only after every check passes.

Remove legacy modes in the breaking cutover:

- Do not support the legacy single full body after cutover.
- Do not support compact `enclava-signed-policy-set-v2` after cutover.
- Treat receipt `enclava-kbs-artifact-receipt-v1` as the only valid active
  KBS/CAP artifact authorization format.

Reasoning:

- Old deployments are destroyed as part of the migration.
- The guest should not have hidden paths that continue accepting the old
  ConfigMap-backed artifact formats.
- Keeping all verification in `enclava-init` ensures a compromised or stale CAP
  response cannot unlock state unless it matches the KBS receipt.

## Rollout Plan

### Phase 1: Schema And Storage

- Add receipt and artifact DB migrations.
- Add Rust structs for receipt canonicalization and signing.
- Add unit tests for stable canonical JSON and signature verification.

Reasoning:

- Contracts must exist before changing runtime behavior.
- Stable canonicalization prevents future cross-language signature breakage.

### Phase 2: Receipt-Only CAP Write Path

- Store full artifacts in `workload_artifact_bundles`.
- Generate and store receipts in `workload_artifact_receipts`.
- Publish receipt resources to KBS.
- Stop writing full or compact signed artifact sets into `resource-policy`.
- Keep only static KBS authorization policy in the ConfigMap.

Reasoning:

- The migration is explicitly breaking, so dual-write is unnecessary.
- Removing artifact-set publication in the same implementation prevents the old
  ConfigMap-size failure from remaining reachable.
- CAP DB becomes the artifact history and retention boundary.

### Phase 3: `enclava-init` Receipt-Only Read Support

- Add receipt fetch and verification.
- Reject missing, legacy full-body, or compact-v2 policy bodies after cutover.
- Add explicit logs for selected mode.

Reasoning:

- Deploying the consumer before switching the producer avoids locked instances.
- Rejecting legacy formats makes accidental rollback to ConfigMap artifact
  storage visible immediately.

### Phase 4: Breaking Cutover Runbook

- Announce/approve destructive migration scope for the target environment.
- Stop or block new deploys during the cutover.
- Destroy all existing workload deployments that depend on legacy or compact-v2
  KBS artifact sets.
- Verify workload namespaces and PVC/PV resources are gone, or explicitly
  preserved outside this migration if data must survive.
- Deploy the receipt-aware `enclava-init` image reference through GitOps.
- Deploy receipt-only CAP API through GitOps.
- Reconcile static KBS policy and verify its size is independent of deployment
  count.
- Re-enable deploys.

Reasoning:

- Destroying old workloads before receipt-only CAP deploys avoids supporting two
  artifact authorization systems.
- Verifying namespace/PVC removal prevents accidental storage reuse and avoids
  old pods trying to restart on unsupported formats.
- Keeping deploys blocked during the cutover prevents new workloads from being
  created with inconsistent producer/consumer versions.

### Phase 5: Receipt-Only Validation

- Fresh template deploy succeeds.
- Deployed pod uses the new `enclava-init` digest.
- CAP stores artifact and receipt rows in Postgres.
- KBS policy ConfigMap remains static/small.
- Workload unlock uses receipt mode.
- Pod restart unlocks again using CAP DB artifact and KBS receipt.
- SSH or application-level smoke test passes.

Reasoning:

- The restart test proves artifact availability moved from ConfigMap history to
  CAP DB.
- The pod image check proves the cutover is not accidentally using the old
  init parser.
- The smoke test proves PaaS-managed config still works after receipt unlock.

### Phase 6: Remove Dead Code And Guardrails

- Remove byte-budget pruning logic for artifact sets.
- Remove compact-v2 serialization tests except archival fixtures if useful for
  explaining the deleted migration.
- Keep a startup/config check that rejects any attempt to write dynamic artifact
  lists into the KBS policy ConfigMap.

Reasoning:

- Dead compatibility paths become future risk and should not survive a breaking
  migration.
- A guardrail prevents accidental reintroduction of ConfigMap-backed artifact
  lists.

## Verification Plan

Unit tests:

- Receipt canonical JSON is stable.
- Receipt signature verifies.
- Tampering with any identity/hash/signature field fails.
- CAP artifact hash matches receipt `artifact_bundle_sha256`.
- Receipt DB uniqueness prevents conflicting active receipts.

Integration tests:

- Fresh deploy unlocks in receipt mode.
- Pod restart unlocks without artifact-set ConfigMap history.
- App destroy removes Kubernetes namespace/PVCs and revokes or supersedes active
  receipt rows.
- Legacy full-body and compact-v2 KBS policy bodies are rejected after cutover.

Scale tests:

- Create thousands of artifact rows and receipts.
- Assert KBS policy ConfigMap size stays effectively constant.
- Assert artifact lookup remains indexed and bounded.

Operational checks:

- CAP logs `receipt_mode=receipt-v1` for new workloads.
- KBS policy bytes do not correlate with deployment count.
- `legacy_kbs_policy_format_seen_total` remains zero after cutover.

Reasoning:

- The previous failure was a scale and restart-path problem, so tests must
  cover scale and restart, not just first deployment.

## Metrics And Alerts

Add metrics:

- `kbs_policy_bytes`
- `kbs_receipts_written_total`
- `kbs_receipt_write_failures_total`
- `artifact_bundle_rows_total`
- `artifact_bundle_fetch_failures_total`
- `receipt_verification_failures_total`
- `legacy_kbs_policy_format_seen_total`
- `init_unlock_failures_by_reason`

Alerts:

- KBS policy bytes exceed a fixed small threshold.
- KBS policy bytes grow with deployment count.
- receipt verification failures are nonzero.
- any legacy KBS policy format is observed after cutover.

Reasoning:

- The durable design should make KBS policy size boring and nearly constant.
- Alerting on growth catches architectural regressions early.

## Acceptance Criteria

- Deploying more active workloads does not grow the KBS ConfigMap by signed
  artifact size.
- `resource-policy` contains static authorization policy only.
- Full signed artifacts are stored in CAP PostgreSQL.
- A workload cannot release seeds unless the CAP artifact and KBS receipt agree
  on app id, deployment id, instance id, resource path, descriptor hash,
  init-data hash, Rego hash, agent policy hash, artifact bundle hash, and
  signature identity.
- Old deployments are destroyed before or during cutover.
- New deployments use receipt mode only.
- Restarting a receipt-mode workload unlocks without any artifact-set history in
  the KBS ConfigMap.
- Legacy full-body and compact-v2 KBS policy bodies are rejected after cutover.
- CAP surfaces receipt or artifact mismatches as deployment errors, and PaaS
  exposes those errors to hosted-template users.

## Operational Notes

- Continue deploying KBS policy/artifact contract changes consumer-first:
  `enclava-init`, then CAP API, then PaaS or GitOps dependents.
- Do not raise `KBS_SIGNED_POLICY_MAX_BYTES` into multi-MiB territory while any
  artifact-set fallback remains before the breaking cutover.
- The permanent fix should be deployed through the ops/GitOps repository, not
  as a one-off live patch.
- CAP Postgres backups become part of workload restart durability because full
  artifact bundles live there.
- If the environment has customer data that must survive, migrate or export that
  data before destroying old deployments; otherwise this plan assumes old
  workload storage is disposable.
