# KBS Policy Artifact Storage And Authorization Plan

Status: architecture reviewed and corrected on 2026-07-10; implementation is
complete in local worktrees through the pre-cutover stages, but production
cutover is not approved or complete.

## Implementation And Rollout Status

Implemented and locally verified:

- the shared CE-v1 authorization and bundle contracts;
- independently signed authorizations and owner-registry checks in the policy
  signing service;
- immutable CAP bundle/authorization/activation/outbox storage, publish
  read-back, crash-safe retry, rollback, supersession, graceful destroy, and
  emergency terminal revocation;
- periodic active-record read-back repair, a purge-resistant terminal
  tombstone ledger, and automatic old-owner receipt revocation after a bounded
  key-rotation grace window;
- the claim-selected CAP artifact endpoint over the dedicated private TLS
  listener;
- the KBS authorization namespace, strict resolver, terminal tombstones,
  scoped publisher bearer, PostgreSQL configuration, and one signed static
  policy;
- receipt-first `enclava-init` verification before seed or LUKS use;
- receipt-mode manifest, network-policy, GitOps, admission-policy, secret
  template, and infrastructure-role changes; and
- a receipt-mode startup/storage/evaluation guard that rejects the legacy
  dynamic policy artifact set, pins the exact static policy digest/key id, and
  exports the specified CAP/KBS metrics.

Production remains deliberately blocked until all of these external gates are
closed:

- build, publish, and pin the new signing-service, KBS, `enclava-init`, PaaS,
  and CAP image digests in consumer-first order;
- generate the production-signed static policy artifact and issuer trust maps;
- encrypt and commit the live SOPS publisher/database secrets using an
  authorized age key (the repository contains templates only);
- inventory and migrate the live KBS/AS/RVPS backend namespaces, then exercise
  CAP and KBS backup/restore and reconciliation;
- obtain explicit approval for destructive pre-cutover workload/PVC handling;
- load the provided dashboard and validated alert rules into the production
  remote monitoring backend, configure routed notifications, and complete HA,
  restart, lifecycle, and end-to-end UAT; and
- run the database-backed concurrent/p95/p99 production scale test; the local
  10,000-record independent KBS backend scale gate already passes, and the
  PostgreSQL harness passes locally at concurrency 32 with 289 ms p95 / 301 ms
  p99 publish and 79 ms p95 / 81 ms p99 mixed lifecycle latency.

Phase 6 runtime-code and legacy-table deletion must occur only after the live
maintenance cutover proves no legacy workloads remain. Keeping that code
temporarily available for the old mode does not authorize enabling it in
receipt-mode GitOps; CAP has no receipt-mode RBAC or environment setting that
can mutate Trustee's static policy.

The current requirement-to-evidence matrix is maintained in
`KBS_POLICY_STORAGE_IMPLEMENTATION_AUDIT.md`.

## Executive Outcome

The overall direction is sound: full workload artifacts belong in CAP
PostgreSQL, while Trustee/KBS should make a small authorization decision and
`enclava-init` should verify the result before unlocking state.

The original receipt-only proposal was not safe or directly implementable,
however. It had six blocking gaps:

1. A receipt stored in KBS did not participate in KBS policy evaluation. A
   static Rego policy cannot safely trust a resource path asserted by arbitrary
   measured init-data; an attacker can launch a genuine TEE with self-chosen
   init-data.
2. The proposed receipt path had four segments and a leading slash. Trustee
   resource identifiers are exactly `repository/type/tag`.
3. Standard KBS resource reads return a TEE-encrypted response. `enclava-init`
   must obtain the plaintext receipt through the guest CDH, not deserialize a
   direct KBS response as JSON. The attestation-proxy's generic CDH route is
   ownership-gated before unlock, so it cannot be the initial receipt path.
4. CAP already has `workload_artifacts` and an attestation-gated artifact
   endpoint. Creating a second, duplicate JSON bundle store would introduce
   conflicting sources of truth.
5. Hashing reserialized `jsonb` is not a stable bundle contract, and canonical
   JSON would introduce a second canonicalization scheme beside the CE-v1
   format already shared by CAP components.
6. Publication, revocation, rollback, TLS, claim ambiguity, and partial-failure
   behavior were underspecified.

This corrected plan makes the small KBS object a signed deployment
authorization record. The Enclava KBS fork resolves and verifies that record by
the attested `descriptor_core_hash` before every relevant policy evaluation.
The single KBS policy is static and signed. CAP is the artifact system of
record and distributor, but the policy-signing service remains the
cryptographic authorization authority.

## Purpose

Permanently remove per-deployment policy artifacts from the shared Trustee
`resource-policy` ConfigMap and eliminate the scalability ceiling reported in
[CAP issue #18](https://github.com/enclava-labs/cap/issues/18).

The target design must preserve these properties:

- KBS releases or mutates a resource only for an authorized attested workload.
- CAP cannot make an unsigned artifact or authorization record valid.
- `enclava-init` does not unlock LUKS or release component seeds until KBS,
  CAP, the signed descriptor, and measured init-data agree.
- Artifact count and retention do not increase the KBS policy ConfigMap size.
- A failed KBS publication never creates a workload that can only fail later.
- A stale, superseded, or revoked deployment cannot fetch a usable artifact
  bundle or KBS seed.

The cutover may be breaking. Pre-cutover workloads and their disposable
storage may be destroyed with explicit product-owner approval. The final code
must not retain legacy full-body or compact-set readers.

## Current State And Review Baseline

CAP already implements part of the target:

- Migration `0025_workload_artifacts.sql` stores the descriptor, org keyring,
  and full signed policy artifact in PostgreSQL.
- `GET /api/v1/workload/artifacts` verifies a Trustee attestation token and
  selects a row by `descriptor_core_hash`.
- `enclava-init` verifies the descriptor, keyring, signed policy, Rego hash,
  agent-policy hash, and measured init-data.
- The temporary `enclava-signed-policy-set-v2` ConfigMap body omits
  `agent_policy_text`.

The remaining shared object still grows with active descriptors, so compact-v2
is only a bridge.

The live preprod baseline observed on 2026-07-10 was:

- `resource-policy`: compact-v2, one artifact, 8,931 bytes.
- KBS resource backend: `LocalFs` on a 1 GiB Longhorn RWO PVC.
- KBS admin mode: `DenyAll`.
- signed-policy enforcement: enabled with the platform signing key and
  customer trust roots.
- workload artifact URL: in-cluster plain HTTP.

Those facts create three concrete rollout prerequisites: a receipt-aware KBS
image, a narrowly scoped publisher identity, and authenticated HTTPS for the
CAP workload endpoint.

## Security And Availability Model

### Trusted

- TEE hardware and the accepted Trustee attestation chain.
- The policy-signing service key configured independently in KBS and pinned in
  measured workload configuration.
- The signing service's durable, independently bootstrapped org-owner registry;
  receipt signing occurs only after owner-signed keyring, descriptor membership,
  and descriptor signature verification.
- Customer descriptor and org-keyring signatures, which `enclava-init`
  rechecks against the owner fingerprint countersigned in the authorization.
- The static KBS policy signing key and reviewed static policy.

### Not trusted for signed-content integrity

- CAP artifact storage and HTTP responses.
- Kubernetes ConfigMaps, Secrets delivered to a guest, the node, and the
  pod/network transport.
- The CAP-to-KBS publisher as a source of unsigned facts. It may publish or
  withhold bytes, but it cannot forge a valid authorization.

V1 still trusts CAP's scoped publisher for reversible lifecycle activation,
including rollback. It does not protect against an already-compromised
publisher deliberately reactivating a previously valid, merely superseded
descriptor. Terminal revocations are different: once KBS records a terminal
tombstone, no publisher operation can reactivate that descriptor. Protecting
all lifecycle freshness from CAP would require a separate customer/operator
online authorization service and is outside V1.

### Explicit V1 trust decision

`enclava-kbs-deployment-authorization-v1` is countersigned by the platform
policy-signing service. KBS authorization therefore has the platform signer as
a trust root. Customer descriptor/keyring signatures are still verified in the
artifact bundle, but they are not the sole KBS authorization root in V1.

If a product mode promises customer-only KBS authorization, that mode is
blocked from this cutover until the authorization schema and KBS resolver also
support the existing owner-keyring-to-descriptor-key trust chain. Do not
silently weaken that mode to platform-only authorization.

### Identity granularity

The receipt authorizes one signed deployment identity: descriptor, measured
init-data, namespace/service-account claims, owner path, image, and signer. It
does not by itself prove that only one physical VM/pod is running those exact
bytes. A malicious control plane able to clone an otherwise valid measured
workload is a separate fork/clone-resistance problem. If the product threat
model requires cryptographic single-instance uniqueness, add an attested
per-instance persistent key/enrollment design before claiming that property;
StatefulSet replica count is not cryptographic uniqueness.

### Availability consequence

Every cold start or restart requires:

- the KBS authorization backend,
- Trustee attestation,
- the CAP workload artifact endpoint, and
- CAP PostgreSQL.

Failure of any dependency fails closed. Production rollout therefore requires
HA, backup, and restore tests for both CAP and KBS storage. This plan does not
claim offline restart availability.

## Target Architecture

~~~mermaid
flowchart LR
    Signer[Policy-signing service]
    CAP[CAP API]
    CAPDB[(CAP PostgreSQL)]
    Pub[CAP KBS publisher]
    KBS[KBS + static signed policy]
    KBSDB[(KBS PostgreSQL backend)]
    Init[enclava-init in TEE]
    CDH[Guest CDH on 127.0.0.1:8006]

    Signer -->|signed artifact + signed authorization| CAP
    CAP --> CAPDB
    CAPDB --> Pub
    Pub -->|scoped publish/deactivate/revoke| KBS
    KBS --> KBSDB
    Init -->|attested receipt read| CDH
    CDH --> KBS
    Init -->|attestation token over pinned HTTPS| CAP
    CAP --> CAPDB
~~~

Request-time authorization works as follows:

1. Trustee verifies the workload attestation token.
2. The KBS fork extracts one unambiguous canonical value for every
   receipt-bound identity claim from recognized claim locations.
3. KBS loads the exact authorization bytes from its dedicated
   `deployment_authorizations` storage namespace. The attested guest still
   addresses those bytes through the logical resource path
   `default/policy-receipts/<descriptor_core_hash>`; the generic resource
   plugin never owns or mutates receipt storage.
4. KBS verifies the authorization signature, time bounds, derived storage
   path, descriptor hash, init-data hash, and schema limits.
5. KBS injects the verified authorization into the static Rego input.
6. Static Rego compares all expected workload claims and permits only a path
   listed in `authorized_resource_paths`. Existing lifecycle receipt checks
   remain mandatory for workload-owned PUT/DELETE operations.
7. `enclava-init` retrieves the same authorization through the guest CDH,
   fetches the
   full bundle from CAP, verifies all signatures and semantic digests, and only
   then obtains/uses the owner seed and opens LUKS.

The KBS receipt is not an independent co-signature by CAP and KBS. Its security
comes from the trusted signer plus two separately gated retrieval paths. A
compromised CAP can deny service or replay bytes, but cannot authorize a
different measured descriptor or artifact bundle.

## Architecture Decisions

### CAP PostgreSQL Remains The Full Artifact Store

Evolve the existing `workload_artifacts` table instead of creating a parallel
bundle store.

Reasons:

- the full artifacts are already persisted and consumed by rollback and
  workload fetch paths;
- one immutable row avoids `signed_policy_artifact` versus
  `artifact_bundle` drift;
- PostgreSQL gives indexed lookup, transaction state, backup, and a natural
  outbox boundary;
- object storage can be introduced later without changing the receipt or
  workload endpoint contracts.

CAP is the artifact system of record and distribution service. It is not the
cryptographic authority.

V1 retains the existing signed per-deployment policy artifact, including its
rendered Rego, inside the CAP audit/verification bundle. KBS never executes or
stores that per-deployment Rego in receipt mode; `rego_sha256` only binds the
historical artifact chain. A later signed-artifact schema may remove it, but
that cleanup is not required to solve the shared-storage boundary.

### KBS Resolves A Per-Descriptor Authorization Before Rego

The receipt must be part of KBS authorization, not merely a resource fetched
after KBS has already authorized the caller.

The KBS fork must add a deployment-authorization resolver that:

- derives the receipt key from the attested descriptor hash;
- loads it internally from a separate KBS-owned authorization namespace on
  the same durable backend;
- verifies it against configured trust anchors;
- rejects missing, malformed, expired, conflicting, or revoked records; and
- exposes only verified fields to the static policy.

No receipt means deny. Resolver errors must never fall back to trusting raw
init-data claims.

### The Shared KBS Policy Is Static And Signed

`resource-policy` contains one platform-signed static policy artifact, not raw
unsigned Rego and not an array of deployment artifacts.

The static policy must cover:

- receipt GET;
- owner `seed-encrypted` and `seed-sealed` GET;
- existing first-write/create and rekey/replace rules;
- existing teardown/delete rules; and
- any currently supported workload secret path explicitly listed by the
  authorization schema.

The KBS fork may require a new
`enclava-kbs-static-resource-policy-v1` wrapper because the current signed
policy metadata is deployment-specific. Turning off
`require_signed_policy` is not an acceptable shortcut.

Build the static policy as a release artifact: review its exact bytes, sign its
CE-v1 digest with the platform policy key, record the digest/key id in platform
release metadata, and deploy the same bytes through GitOps. KBS verifies the
signature and the configured release digest at ingestion and startup; CAP
never generates or patches this artifact.

The static wrapper includes a monotonically increasing `policy_epoch`. KBS
persists the highest accepted epoch and digest in its own backend, rejects a
lower epoch, and rejects different bytes at an already accepted epoch. This
prevents policy-file replay of an older but correctly signed vulnerable policy
while KBS state is intact. It does not survive a coordinated rollback of the
KBS database itself; cryptographic rollback resistance against storage-snapshot
rollback requires an external monotonic anchor and is outside V1.

### KBS Uses A Durable Per-Resource Backend

Production target: Trustee unified `Postgres` storage, with a KBS-owned
database/role and no access to CAP tables.

The `repository` namespace stores receipts and encrypted owner resources; the
`kbs` namespace stores KBS policy state. Credentials, backups, and restore
procedures remain separate from CAP.

The current LocalFs PVC is acceptable only as an explicitly time-bounded,
single-replica transition if its RPO and failover limitations are approved. It
solves the ConfigMap size problem but does not meet the production HA target.

Before changing `storage_backend`, inventory every KBS namespace and confirm
whether the external AS/RVPS retain separate storage. Export/import any owner
resources that must survive, the static policy, attestation policy, and
reference values affected by the selected Trustee deployment mode. A receipt
fix must not silently reset attestation or seed state.

### Receipt Resources Use Valid Trustee Paths

Canonical receipt path:

`default/policy-receipts/<64-lowercase-hex-descriptor-core-hash>`

This is exactly three segments:

- repository: `default`
- type: `policy-receipts`
- tag: descriptor hash

Stored and signed paths have no leading slash. HTTP clients add the endpoint
prefix and slash separately.

### Artifact Fetch Is Claim-Selected, Not URL-Selected

Keep one stable endpoint:

`GET /api/v1/workload/artifacts`

Do not put app, deployment, instance, or a full CAP URL in the receipt. The
verified attestation claims select the only eligible row. This avoids IDOR
confusion, signed redirects, SSRF behavior, and receipt coupling to service
discovery.

The CAP endpoint base URL and CA are pinned in measured init-data. HTTPS is
mandatory outside a loopback connection; the current preprod plain-HTTP
service URL is a rollout blocker.

### Use CE-v1 Semantic Digests

Do not hash reserialized `jsonb` and do not introduce canonical JSON.

Add shared `enclava-common` functions and fixed test vectors for:

- `enclava-workload-artifact-bundle-v1` semantic digest; and
- `enclava-kbs-deployment-authorization-v1` signing bytes.

The bundle digest commits to the canonical full descriptor, descriptor
signature/key id, complete owner-signed org-keyring envelope, and the complete
signed policy artifact semantics. JSON is only a transport envelope.

### Artifacts And Authorizations Are Immutable

For a descriptor hash:

- an identical insert or publication is idempotent;
- different bytes or a different semantic digest are a hard conflict;
- CAP must not use `ON CONFLICT DO UPDATE` for signed material; and
- KBS publication is create-if-absent, with same-bytes success and
  different-bytes conflict.

Terminal security revocation is distinct from normal supersession. Revoked
material receives an irreversible KBS tombstone and cannot be reactivated by
rollback. Normal supersession only deactivates the receipt and remains
reversible.

### Publication Precedes Manifest Apply

CAP must not create a pod until:

- the artifact and authorization are committed;
- the authorization is published to KBS;
- KBS read-back returns the expected digest; and
- the CAP row is marked active.

Use a transactional outbox and an explicit deployment state. There is no
cross-database transaction, so idempotency and reconciliation are mandatory.

### `enclava-init` Verifies Before Unlock

The current order acquires the owner seed and opens LUKS before completing the
Trustee artifact verification chain. Receipt mode must reverse that order.

No owner seed may be used, no LUKS mapping may be opened, and no component seed
may be written before receipt and artifact verification succeeds.

## Deployment Authorization Contract

Schema: `enclava-kbs-deployment-authorization-v1`

Illustrative JSON transport:

~~~json
{
  "schema_version": "enclava-kbs-deployment-authorization-v1",
  "authorization_id": "uuid",
  "org_id": "uuid",
  "app_id": "uuid",
  "descriptor_deploy_id": "uuid",
  "descriptor_core_hash": "64-lowercase-hex",
  "expected_init_data_hash": "64-lowercase-hex",
  "namespace": "kubernetes-namespace",
  "service_account": "kubernetes-service-account",
  "tenant_instance_identity_hash": "64-lowercase-hex",
  "org_owner_version": 1,
  "org_owner_pubkey_sha256": "64-lowercase-hex",
  "image_digest": "sha256:64-lowercase-hex",
  "signer_identity": {
    "subject": "exact-subject",
    "issuer": "exact-issuer"
  },
  "receipt_resource_path": "default/policy-receipts/<descriptor-core-hash>",
  "authorized_resource_paths": [
    "default/<owner-type>/seed-encrypted",
    "default/<owner-type>/seed-sealed",
    "default/policy-receipts/<descriptor-core-hash>"
  ],
  "rego_sha256": "64-lowercase-hex",
  "agent_policy_sha256": "64-lowercase-hex",
  "artifact_bundle_digest": "64-lowercase-hex",
  "issuer_key_id": "platform-signing-key-id",
  "issued_at": "normalized-rfc3339-utc",
  "expires_at": null,
  "signature_alg": "ed25519",
  "signature": "base64url-no-pad"
}
~~~

Contract rules:

- `descriptor_deploy_id` is the deploy id inside the signed descriptor. It is
  not necessarily the CAP management deployment id of a later rollback.
- `apps.instance_id` is deliberately absent because it is not a field in the
  current signed descriptor. The security binding uses app/deploy ids,
  namespace, service account, owner path, and
  `tenant_instance_identity_hash`. Adding a signed instance id later requires
  a descriptor schema bump; do not copy an unsigned CAP value into the receipt.
- `receipt_resource_path` must equal the path derived from
  `descriptor_core_hash`.
- `authorized_resource_paths` is sorted, unique, bounded, and contains the
  receipt path.
- Every path is exactly three nonempty ASCII segments. Segments use only the
  agreed KBS key character set, cannot start with `.`, and cannot contain
  percent escapes, backslashes, `.`/`..` traversal segments, or encoded
  separators. KBS compares one decoded canonical representation.
- The signing service derives allowed owner sibling paths from the signed
  descriptor only after validating
  `default/<owner-type>/seed-encrypted` (or its defined sealed sibling), with
  `owner-type` ending in `-owner`. CAP cannot submit arbitrary KBS paths for
  countersigning.
- `org_owner_pubkey_sha256` comes from the signing service's independent owner
  registry after it verifies the submitted keyring; it never comes from an
  unverified CAP request field.
- `org_id`, `org_owner_version`, and the owner-key hash must match the verified
  descriptor, keyring, and owner-registry record.
- All hashes are decoded to 32 bytes before signing or comparing.
- UUIDs are signed as 16 bytes, not presentation strings.
- Integer versions are signed as unsigned 64-bit big-endian values.
- Timestamps are normalized once and their normalized UTF-8 form is signed.
- Unknown fields are rejected (`deny_unknown_fields` behavior).
- V1 receipt bodies are limited to 16 KiB and at most eight authorized paths.
- `issuer_key_id` is a lookup into independently configured KBS/init trust
  material; a public key supplied in the receipt is never trusted.
- KBS keeps an explicit key-id-to-public-key authorization trust map, including
  retiring keys until every receipt under them is terminally revoked, expired,
  or no longer rollback-eligible under the retention policy. Mere reversible
  deactivation is not enough to retire a key.
- `expires_at = null` means explicit revocation controls lifetime. If finite
  expiry is enabled later, refresh and immutable version-selection semantics
  must be designed first.

Signature input uses CE-v1 with purpose
`enclava-kbs-deployment-authorization-v1` and includes every field except
`signature`. `signature_alg` is included. List fields are committed through a
length-delimited, sorted-list hash.

`authorization_digest` is SHA-256 over the exact stored JSON bytes, including
the signature. It is used only for immutable publication/read-back. Security
verification always reparses the strict schema and verifies the CE-v1
signature; it never treats the byte digest alone as authorization.

The policy-signing service creates the authorization at the same time it
validates/signs the canonical policy artifact. CAP stores and republishes the
exact returned bytes; CAP does not hold the receipt signing key.

Signing is idempotent by `descriptor_core_hash` plus
`artifact_bundle_digest`. A retry after a lost response returns the same
artifact and exact authorization bytes, not a new UUID/timestamp/signature.
The signing service may persist the result or derive deterministic receipt
fields from already-signed metadata, but this behavior is part of the API
contract.

## KBS Fork Changes

### Verified Authorization Resolver

Before evaluating the static resource policy:

1. Parse claims using a typed extractor for the supported Trustee EAR layouts.
2. Collect all recognized values for descriptor hash, init-data hash,
   namespace, service account, identity hash, image digest, and signer
   subject/issuer.
3. Normalize each field and require exactly one unique valid value;
   equivalent duplicates are allowed, but conflicting duplicates deny.
4. Load the derived receipt path from the KBS backend.
5. Parse with strict schema and size limits.
6. Verify signature, trust anchor/key id, receipt path, descriptor hash,
   init-data hash, time bounds, and canonical path list.
7. Inject a `deployment_authorization` object plus
   `authorization_verified = true` into policy data.

Apply the same resolver to GET and workload-resource PUT/DELETE evaluation.
Never expose an unverified receipt object to Rego as if it were trusted.

### Static Policy

The static Rego must:

- require `authorization_verified`;
- compare the receipt's namespace, service account, identity hash, image
  digest, signer subject/issuer, descriptor hash, and init-data hash with
  attested claims;
- require the normalized requested path in
  `authorized_resource_paths`;
- preserve lifecycle receipt signature/pubkey/value-hash checks for rekey and
  teardown, including create-if-absent versus replace-if-present
  preconditions; and
- deny unsupported plugins, methods, paths, or missing values.

The Rust resolver and Rego comparisons intentionally overlap as defense in
depth.

### Scoped Publication API

Add a narrow KBS API rather than giving CAP the root admin key:

- `PUT /kbs/v0/deployment-authorization/{descriptor_core_hash}`
- `GET /kbs/v0/deployment-authorization/{descriptor_core_hash}` for publisher
  read-back only
- `DELETE /kbs/v0/deployment-authorization/{descriptor_core_hash}`
- `POST /kbs/v0/deployment-authorization/{descriptor_core_hash}/revoke` for
  irreversible revocation

Required behavior:

- a dedicated constant-time bearer authenticator used only by these four
  handlers. It is intentionally separate from KBS general admin auth, so the
  CAP credential cannot call policy, repository, or other admin endpoints;
- HTTPS with the internal CA and network policy permitting only CAP/publisher;
- create-only immutable PUT;
- same payload digest is idempotent success;
- different payload at the same hash is `409 Conflict`;
- DELETE is idempotent reversible deactivation; KBS retains the immutable
  digest/bytes as inactive state so only the exact receipt can be reactivated;
- terminal revoke first writes a durable tombstone, then marks the receipt
  inactive; publish checks the tombstone and can never clear it;
- strict body/schema/signature validation at ingestion and again at use; and
- audit logs without receipt bodies, tokens, or secret resource values.

The live general-admin configuration may remain `DenyAll`; receipt publication
does not require enabling it. Install the same publisher bearer in KBS and CAP
before receipt CAP code is enabled. Do not reuse a broad KBS root credential in
CAP.

### Caching And Revocation

V1 should not cache deployment authorization records across requests. If a
cache is later required, it needs a short bounded TTL, state-change invalidation,
digest-keyed entries, and an explicit measured revocation SLA.

The initial receipt should use the direct guest CDH endpoint and avoid the
attestation-proxy cache. If an implementation later adds receipt caching,
CAP's artifact endpoint must still independently deny inactive/revoked
descriptors. A cached receipt alone must never be sufficient to unlock.

KBS must check the terminal-tombstone namespace before returning or evaluating
an authorization. Tombstone write precedes receipt deactivation so a crash
between the two operations remains fail-closed. Tombstones are included in
backup, restore, reconciliation, and orphan-cleanup protection.

## CAP Database Model

Use a breaking migration to evolve or rename `workload_artifacts`. Do not
create two authoritative copies of the bundle.

### `workload_artifact_bundles`

Recommended columns:

- `descriptor_core_hash bytea primary key` with a 32-byte check
- `descriptor_deploy_id uuid not null`
- `app_id uuid not null`
- `namespace text not null`
- `expected_init_data_hash bytea not null` with a 32-byte check
- existing descriptor payload/signature/signing-key columns
- `org_keyring_envelope jsonb not null`, retaining keyring payload, owner
  signature, and owner signing public key as one validated object
- `signed_policy_artifact jsonb not null`
- `bundle_schema_version text not null`
- `artifact_bundle_digest bytea not null unique` with a 32-byte check
- `created_at timestamptz not null`
- `terminally_revoked_at timestamptz null`
- `revocation_reason text null`

Do not also store a duplicate `artifact_bundle jsonb`. Assemble the response
from the component columns and recompute/verify the semantic digest on write
and read. If `signed_policy_artifact.org_keyring` remains present for backward
schema reasons during migration, require exact semantic equality with
`org_keyring_envelope` before accepting the row; remove the duplicate in the
final schema.

Signed rows are immutable. The existing upsert-update behavior must be
replaced by insert-or-compare-identical behavior.

### `workload_artifact_authorizations`

Recommended columns:

- `descriptor_core_hash bytea primary key` referencing the bundle
- `authorization_id uuid not null unique`
- `receipt_resource_path text not null unique`
- `authorization_bytes bytea not null`
- `authorization_digest bytea not null unique`
- `issuer_key_id text not null`
- `issued_at timestamptz not null`
- `expires_at timestamptz null`
- `publication_state text not null` (`pending`, `active`, `inactive`, or
  `tombstoned`)
- `published_at timestamptz null`
- `deactivated_at timestamptz null`
- `publication_digest bytea null`
- `terminally_revoked_at timestamptz null`
- `kbs_tombstoned_at timestamptz null`
- `created_at timestamptz not null`

Exact bytes, not `jsonb` reserialization, are the publication source. Parsed
columns support indexes and diagnostics.

### Deployment Activation

Add `artifact_descriptor_core_hash` to deployments or a separate
`deployment_artifact_activations` relation.

This distinction is required for rollback:

- a normal deployment has a newly signed descriptor;
- a rollback management operation may reactivate an older immutable
  descriptor and receipt;
- its new CAP deployment id must not be confused with the signed
  `descriptor_deploy_id`.

The workload endpoint authorizes a bundle only when at least one allowed
activation for that descriptor is active. A terminally revoked bundle cannot
be reactivated.

### Transactional Outbox

Add `kbs_authorization_outbox`:

- event id
- descriptor hash
- operation (`publish`, `deactivate`, or `revoke`)
- payload digest and exact bytes for publish
- state (`pending`, `processing`, `succeeded`, `failed`)
- attempt count, next-attempt time, last error code
- created/updated/completed timestamps

Create the bundle, authorization, activation, and publish event in one CAP
transaction. Workers use row locking/`SKIP LOCKED`, bounded exponential retry,
and deterministic idempotency keys. Deployment status exposes
`authorization_pending` while retrying and transitions to a stable
`kbs_authorization_publish_failed` error at the deploy deadline; no pod is
created. Reconciliation may continue safe cleanup/recovery without hiding the
user-visible failure. A late publish after the deployment deadline is
deactivated; it never applies manifests unless the user explicitly retries the
deployment.

The signed response is obtained and fully verified before this transaction;
never hold a PostgreSQL transaction open across the signing-service network
call. The deployment request row and receipt state should be finalized in one
database transaction. If an implementation temporarily creates the pending
deployment intent first, it must provide deterministic recovery for a crash
between intent creation and receipt finalization before production cutover.

Do not make live artifact rows disappear through an uncontrolled
`ON DELETE CASCADE`. Revoke and complete KBS cleanup first; archive or delete
later according to the product retention policy.

## CAP Workload Artifact Endpoint

Keep `GET /api/v1/workload/artifacts` and harden it:

- require an attestation token;
- verify it through Trustee over authenticated HTTPS using the internal caller
  credential;
- extract every receipt-bound identity claim from recognized locations and
  reject ambiguous/conflicting duplicates;
- select by the unique attested descriptor hash, never by caller-supplied ids;
- require the attested init-data hash to match both bundle and authorization;
- require stored org/app/descriptor-deploy relationships to match the signed
  descriptor and authorization;
- join an active deployment activation;
- reject unpublished, superseded-only, expired, or terminally revoked
  authorization state;
- recompute the semantic bundle digest before returning;
- return `Cache-Control: no-store`;
- cap response size and rate-limit by verified descriptor; and
- audit success/failure by hashes and ids, never token or artifact body.

Response:

~~~json
{
  "schema_version": "enclava-workload-artifact-bundle-v1",
  "artifact_bundle_digest": "64-lowercase-hex",
  "authorization_digest": "64-lowercase-hex",
  "receipt_resource_path": "default/policy-receipts/<descriptor-core-hash>",
  "descriptor_payload": {},
  "descriptor_signature": "hex",
  "descriptor_signing_key_id": "key-id",
  "org_keyring_envelope": {
    "keyring": {},
    "signature": "hex",
    "signing_pubkey": "hex"
  },
  "signed_policy_artifact": {}
}
~~~

Transport requirements:

- HTTPS is mandatory for the non-loopback endpoint.
- The CA or server identity is pinned in measured init-data and checked against
  the ConfigMap transport copy.
- The receipt contains no URL. `enclava-init` uses the measured configured
  endpoint.
- Network policy permits workload egress only to required KBS and CAP
  endpoints.

Remove production `file://`/local ConfigMap delivery of
`workload-artifacts.json` and `trustee-policy.json`. Those paths duplicate
large artifacts per workload and can remain only as explicit test fixtures.
The measured `cc_init_data` still contains the agent policy required by the
Kata runtime; that per-workload measured input is not the shared ConfigMap
problem from issue #18.

## `enclava-init` Receipt Mode

Receipt mode is the only production mode after cutover:

1. Load and validate measured config, including descriptor hash, CAP HTTPS
   origin/CA, signing key, and KBS/CDH settings.
2. Derive
   `default/policy-receipts/<descriptor_core_hash>` locally.
3. Fetch plaintext receipt bytes through the Kata guest CDH at
   `http://127.0.0.1:8006/cdh/resource/<receipt-path>`, not by parsing a direct
   KBS JWE response. Do not use the attestation-proxy's
   `127.0.0.1:8081/cdh/resource` route for this bootstrap read: its ownership
   middleware correctly gates generic CDH paths until unlock. If that route is
   ever used instead, add and test an exact pre-unlock exception only for
   `default/policy-receipts/<descriptor_core_hash>`.
4. Strictly parse and verify receipt signature and every measured identity
   binding.
5. Obtain a fresh attestation token and fetch the bundle from the measured CAP
   HTTPS endpoint.
6. Hash the exact receipt bytes and compare the result with CAP's
   `authorization_digest`; recompute `artifact_bundle_digest` and compare it
   with the KBS receipt.
7. Verify the org-keyring owner signature and receipt-bound owner-key
   fingerprint, descriptor signer membership, descriptor full signature/core
   hash, signed policy artifact signature, Rego hash, agent-policy text hash,
   and all descriptor forward-chain anchors.
8. Only now acquire/use the owner seed, open LUKS, mount state, and write
   component seeds.

Any mismatch fails closed with a stable reason code. Receipt or artifact
contents and tokens must not be logged.

Remove:

- legacy single-policy parsing;
- `enclava-signed-policy-set-v1/v2` parsing;
- `TRUSTEE_POLICY_URL` and active policy-body fetch;
- production local artifact/policy files; and
- any skip path that permits seed use without verification.

## Lifecycle And Consistency

### New Deployment

1. Validate customer descriptor/keyring and canonical agent policy.
2. Obtain the signed policy artifact and deployment authorization from the
   policy-signing service.
3. Verify both in CAP.
4. In one CAP transaction, insert immutable bundle/authorization rows, create
   the deployment activation, and enqueue KBS publish.
5. Publisher performs immutable KBS create and digest read-back.
6. Mark authorization published/active.
7. Apply workload manifests.
8. When the new workload is healthy, supersede the old activation and
   reversibly deactivate the old descriptor's KBS authorization unless another
   active activation needs it.

A short old/new authorization overlap during a healthy rollout is intentional
for availability. On new deployment failure, deactivate the new receipt and
keep the old activation authorized.

### Rollback

- Only post-cutover bundles with stored authorizations are eligible.
- Reactivate the old immutable descriptor; do not claim that the rollback's
  new management deployment id was signed into it.
- Republish the identical old receipt before applying manifests.
- Deny rollback if the bundle was terminally revoked.
- After health, retire the replaced descriptor authorization.

### Graceful App Destroy

1. Mark CAP artifact fetch as draining so no restart can obtain a new bundle.
2. While the attested workload and its authorization are still active, invoke
   the existing in-TEE teardown flow so lifecycle receipts authorize deletion
   of owner resources.
3. Stop/delete workload resources.
4. Mark CAP activations/bundles terminally revoked, enqueue irreversible KBS
   revocation, and require tombstone read-back.
5. Complete namespace/PVC handling and archival according to the approved
   destructive-migration/retention policy.

### Emergency Security Revocation

1. Mark CAP activations/bundles terminally revoked so artifact fetch fails.
2. Immediately stop/scale down the workload and block its network path.
3. Enqueue irreversible KBS revocation and require tombstone read-back.
4. If owner resources must be deleted after the workload is stopped, use a
   separately authorized, audited operator cleanup path; do not weaken the
   workload policy or give the receipt publisher general resource-delete
   permission.

### Org Owner Rotation

- Treat `org_owner_pubkey_sha256` as authorization state, not diagnostic
  metadata.
- Coordinate the existing CAP/signing-service owner update before issuing new
  receipts.
- Redeploy or explicitly grandfather running workloads according to the
  approved rotation window.
- After the window, terminally revoke every old-owner authorization and make
  those artifacts ineligible for rollback. Merely changing the signing-service
  owner registry does not invalidate already signed receipts in KBS.

### Platform Authorization Key Rotation

- For planned rotation, add the new key before use and retain the old key until
  no receipt it signed is active or rollback-eligible.
- Do not replace a receipt signature in place; immutability makes the original
  signer part of that descriptor's lifetime contract.
- For key compromise, block deploys, remove the compromised key from KBS/init
  release trust, stop affected workloads, terminally revoke their descriptor
  receipts, install a higher-epoch static policy under the replacement trust
  key when the key is shared, and issue new descriptors/receipts.

KBS revoke failure remains visible and retried. A reconciliation job compares
active CAP authorization digests and terminal revocations with KBS publisher
read-back, repairs missing active records, and deactivates orphans after a
safety delay. It never deletes terminal tombstones.

### Restore

CAP and KBS backups do not need a distributed snapshot for integrity:
mismatches fail closed and reconciliation repairs publication state. They do
need tested RPO/RTO and a runbook:

- restore KBS and CAP independently;
- keep deploys blocked;
- reconcile active authorization digests;
- prove no terminally revoked receipt reappeared;
- prove all expected KBS terminal tombstones survived;
- perform restart UAT; and
- only then re-enable deploys.

## Cross-Project Implementation And Rollout

This change spans:

- CAP / `enclava-common` / `enclava-init` / CLI descriptor hash generation;
- policy-signing service;
- Enclava Trustee/KBS fork;
- policy templates/static policy;
- `enclava-infra` KBS backend, publisher identity, TLS, and backup config;
- `enclava-ops-manifests` image digests, environment, network policy, and
  platform release metadata; and
- `enclava-paas` error propagation if internal deployment DTOs change.

CAP's structured receipt-publication failures are allowlisted through PaaS
without exposing arbitrary CAP 5xx bodies. The CAP and KBS `PodMonitor`
resources and monitoring NetworkPolicies are part of the pre-cutover manifests.

### Phase 0: Contracts And Threat Tests

- Implement CE-v1 bundle and authorization functions in shared code.
- Publish fixed positive and tamper test vectors for Rust components and KBS.
- Freeze the receipt, static policy input, KBS publisher, and CAP response
  schemas.
- Decide and document whether any deployed product mode requires
  customer-only KBS authorization.

Gate: independent implementations produce identical bytes/digests and every
field-tamper test fails.

### Phase 1: Signing Service

- Add backward-compatible authorization signing output/API.
- Resolve the org owner from the signing service's independent durable registry
  and verify the owner-signed keyring, descriptor signer membership, and
  descriptor signature before producing an authorization.
- Validate all remaining receipt inputs from the signed descriptor and
  canonical policy; do not countersign arbitrary CAP paths or hashes.
- Add request idempotency and exact-byte replay for lost-response retries.
- Add key-id and key-rotation tests.
- Verify durable owner-registry backup/restore and CAP/signing-service owner
  drift checks before enabling receipt signing.

Deploy this before CAP requests receipts.

### Phase 2: KBS Consumer And Storage

- Add static signed policy support, verified authorization resolver, strict
  claim extraction, and scoped publisher API.
- Configure KBS PostgreSQL storage and backup/restore.
- Inventory and migrate every KBS/AS/RVPS namespace affected by the unified
  backend switch; prove reference values and attestation policy are unchanged.
- Provision the scoped CAP publisher persona and CA material.
- Use the private-CA CAP proxy listener that exposes exactly
  `/api/v1/workload/artifacts`; measured workloads do not receive the PaaS mTLS
  client credential.
- Keep legacy policy-set support behind the old mode only until maintenance
  cutover; receipt mode itself has no fallback.

Deploy and validate the KBS consumer before CAP emits receipt-only workloads.

### Phase 3: CAP Storage, Publisher, And Endpoint

- Migrate the existing artifact table to the immutable model.
- Add authorization, activation, and outbox state.
- Add publisher/read-back/reconciler.
- Harden the claim-selected artifact endpoint and enable pinned HTTPS.
- Add stable deployment failure codes and the allowlisted PaaS mapping before
  changing the internal response shape. Promote the backward-compatible PaaS
  consumer before receipt-mode CAP.

Do not enable receipt mode yet.

### Phase 4: `enclava-init` And Platform Release

- Implement receipt-only verification and verification-before-unlock ordering.
- Remove production local artifact delivery and legacy readers.
- Build and publish digest-pinned `enclava-init`.
- Issue a signed platform-release v2 envelope that commits the exact static
  policy wrapper SHA-256 and embedded issuer key id; update CLI hash generation
  and GitOps image references.

Because the consumer is incompatible with the old producer, block new deploys
before switching the image reference. “Consumer first” here means the image and
reference are ready while deploys are locked, not that old CAP may continue
creating workloads with the new init.

### Phase 5: Breaking Maintenance Cutover

1. Obtain explicit approval for namespace/PVC/customer-data destruction.
2. Block deploy, rollback, unlock-mode transition, and app lifecycle writes.
3. Drain CAP apply workers and prove no pending publication/apply jobs remain.
4. Destroy all pre-cutover workloads and handle PVC/PV data as approved.
5. Prove no legacy workload pods remain.
6. Switch KBS to the static signed policy, receipt resolver, scoped publisher,
   and target backend.
7. Update CAP's `ENCLAVA_INIT_IMAGE` reference and measured platform release
   metadata.
8. Deploy the PaaS image that safely propagates the structured KBS failures.
9. Deploy receipt-only CAP API and fully drain old CAP replicas.
10. Run publisher self-test and fresh-deploy/restart UAT.
11. Re-enable writes only after every gate passes.

### Phase 6: Cleanup

- Remove `reconcile_signed_policy_artifacts`, retention/byte-budget settings,
  artifact-set serializers, ConfigMap restart logic, and legacy metrics.
- Remove `ensure_owner_binding`/`ensure_tls_binding` dynamic policy mutation
  and retire the `kbs_owner_bindings`/`kbs_tls_bindings` tables once receipt
  path authorization is proven. Do not leave a second ConfigMap-growing policy
  path behind.
- Remove `KBS_SIGNED_POLICY_RETENTION` and
  `KBS_SIGNED_POLICY_MAX_BYTES` from ops.
- Remove CAP's Kubernetes RBAC and environment settings for patching the
  Trustee policy ConfigMap or restarting the Trustee deployment. GitOps owns
  the static signed policy; CAP keeps only the scoped receipt publisher
  credential.
- Add startup guards that reject a dynamic artifact set in
  `resource-policy`.
- Retain legacy fixtures only in archival migration tests, not runtime parsers.

## Verification Plan

### Contract And Unit Tests

- CE-v1 bundle/receipt vectors match in CAP, signing service, KBS, and init.
- Every receipt field tamper fails.
- A CAP-supplied self-signed or wrong-owner keyring is refused by the signing
  service and cannot obtain a deployment authorization.
- Unknown fields, noncanonical hashes/paths/timestamps, oversize bodies, and
  duplicate paths fail.
- Different bytes at one descriptor hash conflict.
- Existing identical publication is idempotent.
- Conflicting recognized locations for every receipt-bound claim deny instead
  of “first match wins”; equivalent duplicate encodings normalize identically.

### KBS Authorization Tests

- A real attested TEE with self-chosen init-data and no signed authorization is
  denied.
- A valid receipt permits only its exact paths and methods.
- Cross-app, cross-namespace, descriptor, init-data, image, signer, service
  account, identity-hash, and org-owner replay fail.
- Missing, expired, inactive, bad-signature, wrong-key-id, and terminally
  revoked receipts fail.
- Deactivation permits an authorized rollback republish; a terminal tombstone
  permanently rejects the same otherwise-valid receipt.
- Receipt GET succeeds through direct guest CDH before unlock; the
  attestation-proxy ownership gate remains closed for unrelated CDH paths; and
  direct KBS bytes are not incorrectly parsed as plaintext JSON.
- Rekey and teardown lifecycle receipt checks still fail closed.
- Scoped publisher cannot set arbitrary resources or policy.
- A lower static-policy epoch and conflicting bytes at the same epoch are
  rejected even when their Ed25519 signature is otherwise valid.

### CAP Endpoint Tests

- No token, invalid token, conflicting claims, inactive activation, unpublished
  receipt, revoked bundle, or digest drift fail.
- Caller-supplied ids cannot select another bundle.
- HTTPS CA/hostname failure is fatal.
- Response digest matches the receipt and exact semantic bundle.
- Tokens and bodies are absent from logs.

### State-Machine And Failure-Injection Tests

- CAP commit plus KBS outage creates no pod.
- KBS publish plus CAP crash before acknowledgement converges idempotently.
- Manifest apply failure deactivates the new authorization and keeps the prior
  healthy deployment authorized.
- Supersession denies the old descriptor after the rollout window.
- Rollback republishes the old immutable receipt and does not rewrite signed
  ids.
- Terminal revocation cannot be rolled back.
- A crash between tombstone write and receipt deactivation still denies access.
- Graceful destroy completes in-TEE owner cleanup before tombstoning; emergency
  revocation stops the workload first and requires the separate audited cleanup
  path.
- Owner rotation makes old-owner artifacts non-rollbackable after the declared
  grace window and tombstones their receipts.
- Planned signer rotation preserves old rollback receipts; compromised-key
  recovery rejects the old key and requires new descriptors.
- CAP/KBS restore mismatch fails closed and reconciliation repairs it.

### Scale And Performance Tests

- Store at least 10,000 bundles and authorizations.
- Run concurrent publish/deactivate/revoke/read workloads.
- Assert `resource-policy` bytes and digest remain constant.
- Assert descriptor lookup uses indexes and has an agreed p95/p99 SLO.
- Assert KBS backend growth is per row/resource with no aggregate serialization
  cliff.

### End-To-End UAT

- Deploy well beyond the issue #18 active-app threshold.
- Verify every pod uses the new `enclava-init` digest.
- Verify no dynamic artifact appears in `resource-policy`.
- Verify receipt fetch, CAP fetch, and verification occur before LUKS open.
- Restart pods and nodes and unlock successfully.
- Perform app-level/SSH smoke tests.
- Exercise rekey, teardown, normal upgrade, failed upgrade, and rollback.
- Confirm PaaS/CLI surfaces deterministic publication or verification errors
  immediately instead of a ten-minute ownership timeout.

Run the repository-required Rust, audit, release-build, and Docker checks from
`AGENTS.md` for implementation changes. Also run the KBS fork, signing-service,
infra, ops, and PaaS contract suites affected by this cross-project change.

## Metrics And Alerts

CAP:

- `kbs_authorization_outbox_pending`
- `kbs_authorization_publication_total{result}`
- `kbs_authorization_publication_lag_seconds`
- `artifact_bundle_fetch_total{result}`
- `artifact_bundle_digest_mismatch_total`
- `attestation_claim_conflict_total`
- `legacy_kbs_policy_format_seen_total`

KBS:

- `kbs_deployment_authorization_lookup_total{result}`
- `kbs_deployment_authorization_verify_total{result}`
- `kbs_deployment_authorization_lookup_seconds`
- `kbs_static_resource_policy_bytes`
- `kbs_static_resource_policy_digest_info`
- `kbs_deployment_authorization_publisher_request_total{operation,result}`

`enclava-init` logs stable, non-secret reason codes for receipt fetch,
signature, identity, CAP transport, bundle digest, artifact-chain, and
revocation failures. Avoid high-cardinality labels; descriptor/app ids belong
in structured logs, not metric labels.

Validated Prometheus rules are maintained in
`deploy/kbs-policy-storage-alerts.prometheus.yml`, the Grafana import artifact
is `deploy/kbs-policy-storage-dashboard.json`, and incident/restore procedures
are in `runbooks/kbs-policy-storage.md`. Prometheus Agent only scrapes and
remote-writes, so rule loading, dashboard import, and notification routing must
be completed in the remote monitoring backend during rollout.

Alert on:

- any legacy policy format after cutover;
- static policy byte/digest drift;
- publication backlog age over the deploy SLO;
- receipt verification or claim-conflict failures;
- KBS/CAP restore reconciliation mismatch;
- publisher authorization failures; and
- artifact endpoint TLS failures.

## Acceptance Criteria

- `resource-policy` contains one reviewed, signed, static policy whose size is
  independent of deployment and retention count.
- KBS resolves and verifies a per-descriptor authorization before permitting
  receipt, seed, rekey, or teardown access.
- Full bundles have one immutable CAP PostgreSQL source of truth.
- Receipt and artifact semantic digests use shared CE-v1 test vectors.
- Every receipt carries the independently registered org-owner fingerprint,
  and `enclava-init` verifies the owner-signed keyring and descriptor chain.
- The KBS resource path is valid `repository/type/tag` and stored without a
  leading slash.
- CAP publication is scoped, immutable, read-back verified, and complete
  before manifest apply.
- The artifact endpoint is claim-selected, active-state checked, and served
  over measured/pinned HTTPS.
- `enclava-init` verifies receipt and artifact before owner-seed use or LUKS
  open.
- Superseded, revoked, missing, ambiguous, or mismatched state fails closed.
- Rollback reactivates an old signed descriptor without misrepresenting the new
  management deployment id.
- Old deployments are destroyed at cutover and final binaries reject legacy
  full-body and compact-v2 formats.
- Restart, restore, scale, lifecycle, and hosted error-propagation tests pass.
- No runtime setting can re-enable a dynamic deployment-artifact list in the
  KBS ConfigMap.
- CAP has no Kubernetes permission to rewrite the static KBS policy or restart
  Trustee.

## Reference Material

- [CAP issue #18](https://github.com/enclava-labs/cap/issues/18)
- [Trustee resource storage backend](https://github.com/enclava-labs/trustee/blob/main/kbs/docs/resource_storage_backend.md)
- [Trustee KBS configuration](https://github.com/enclava-labs/trustee/blob/main/kbs/docs/config.md)
- [Confidential Containers policy overview](https://confidentialcontainers.org/docs/attestation/policies/)
