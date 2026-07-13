# KBS Receipt-Mode Coordinated Rollout

Coordination ID: `KBS-RECEIPT-ROLLOUT-2026-07`

Status: **rollout blocked**. This document is the release-control plan for the
receipt-mode implementation in `KBS_POLICY_STORAGE_PLAN.md`. Merging an
individual implementation PR does not authorize a cluster cutover.

## Outcome

Replace CAP-managed, deployment-growing KBS policy artifacts with:

- one immutable signed static KBS policy;
- independently signed per-descriptor deployment authorizations;
- durable CAP publication, activation, reconciliation, and tombstone state;
- receipt-first `enclava-init` verification before any seed or LUKS use; and
- scoped CAP-to-KBS publication without general KBS administration access.

The rollout is intentionally a maintenance cutover. Old CAP and
`enclava-init` producers/consumers must not run alongside receipt-only
components.

## Coordinated PR Set

Every PR must carry the labels `coordinated-rollout`, `kbs-receipt-mode`, and
`rollout-blocked` until the release lead closes all gates.

| Component | Repository | PR | Purpose |
|---|---|---|---|
| CAP, CLI, and `enclava-init` | `enclava-labs/cap` | This PR | Receipt contract, persistence, lifecycle, strict verification, observability, and rollout authority |
| Trustee/KBS | `enclava-labs/trustee` | TBD | Authorization resolver/storage, scoped publisher API, static policy enforcement, and KBS metrics |
| Policy signing service | `enclava-labs/policy-templates` | TBD | Independent authorization issuance, owner registry validation, and static-policy artifact tooling |
| Infrastructure | `enclava-labs/enclava-infra` | TBD | KBS PostgreSQL authority, policy pins, publisher secret, backup expectations, and PodMonitor |
| Hosted PaaS | `enclava-labs/enclava-paas` | TBD | Safe propagation of structured CAP receipt-publication failures |
| GitOps | `enclava-labs/enclava-ops-manifests` | TBD | Runtime configuration, scoped networking/RBAC, monitoring, secrets, images, and rollout ordering |

## Current Preprod Baseline

Read-only inspection through `control1.encl` on 2026-07-13 found:

- one CAP replica using the legacy API image;
- one Trustee/KBS replica without receipt-mode configuration;
- one legacy policy-signing-service replica;
- two PaaS API replicas and one worker on the legacy PaaS image;
- one live legacy workload, `capture1`, using the old `enclava-init`;
- bound `capture1` PVCs of 5 GiB and 2 GiB;
- no CAP or KBS receipt-mode PodMonitor in the live cluster; and
- healthy Flux reconciliation of `enclava-ops-manifests`.

This inventory must be refreshed at the start of the maintenance window.

## Gate 0: Contract Convergence

Do not publish release candidates until all of these are resolved:

1. CAP release startup currently requires
   `TRUSTEE_POLICY_READ_AVAILABLE=true`, while the draft GitOps receipt-mode
   overlay removes it. Choose and test one contract:
   - preferred: add an explicit receipt-mode startup gate that requires the
     publisher, artifact endpoint, trust map, and platform-release v2 without
     enabling legacy policy reconciliation; or
   - compatibility path: retain `TRUSTEE_POLICY_READ_AVAILABLE=true` and the
     read-only static-policy URL while removing all CAP policy mutation RBAC
     and `KBS_POLICY_*` settings.
2. CAP GitOps must provide a non-empty
   `SIGNING_SERVICE_TRUSTED_PUBKEYS_JSON`. Its issuer IDs and keys must exactly
   match KBS `deployment_authorization_public_keys` and include every current
   or retiring key referenced by an active or rollback-eligible receipt.
3. Receipt mode must hard-deny a missing or inactive authorization. It must
   never fall through to dynamic policy aggregation or owner/TLS binding
   mutation.
4. The signed platform release must use schema `v2` and contain the exact
   static-policy wrapper SHA-256 and embedded issuer key ID.
5. An explicit write-freeze control must block deploy, rollback, unlock-mode
   transitions, rekey, teardown, and app destruction while allowing operators
   to inspect status and health.

Gate owner: CAP + GitOps maintainers. Evidence: contract tests, rendered
manifests, release-binary startup test, and negative legacy-fallback test.

## Required Artifacts And Authorities

The release lead records immutable values in the change ticket without placing
secrets in GitHub comments or logs:

| Artifact/authority | Required evidence |
|---|---|
| CAP API image | Source commit, GHCR digest, signature/provenance verification |
| `enclava-init` image | Source commit, GHCR digest, signature/provenance verification |
| CLI | Source commit and signed release artifact |
| Trustee/KBS image | Source commit, GHCR digest, signature/provenance verification |
| Signing-service image | Source commit, GHCR digest, signature/provenance verification |
| PaaS image | Source commit, GHCR digest, signature/provenance verification |
| Static KBS policy | Monotonic epoch, wrapper SHA-256, issuer ID, offline signature verification |
| Platform release | Schema v2 envelope signed by the compiled-in release root; static-policy pins match exactly |
| Authorization trust | Same current-and-retiring issuer map in KBS, CAP, and generated init configuration |
| Publisher identity | Dedicated random bearer installed only in KBS and CAP; never a KBS admin or attestation token |
| KBS PostgreSQL | TLS-verifying URL, encrypted storage, backup/PITR configuration, isolated restore evidence |
| Signing owner registry | Complete org inventory, durable backup, and isolated restore evidence |

## Roles And Approvals

Assign named people before scheduling the window:

- release lead: owns the go/no-go decision and evidence ledger;
- CAP owner: migrations, API rollout, outbox, and reconciliation;
- KBS/infra owner: backend migration, policy epoch, publisher API, and restore;
- security/key owner: issuer maps, policy signature, platform release, and
  publisher rotation;
- PaaS owner: write freeze, worker drain, error propagation, and reopen;
- GitOps owner: immutable digests, manifest validation, Flux, and imageID proof;
- monitoring owner: rule loading, dashboard, routing, and alert tests; and
- workload/data owner: written disposition for every pre-cutover workload and
  PVC, including `capture1`.

Required approvals:

- destructive workload/PVC handling;
- maintenance window and customer communication;
- static policy and platform-release v2 signatures;
- database backup/restore evidence; and
- release lead go/no-go at Gates 4, 6, and 8 below.

## Phase 1: Merge And Build Release Candidates

1. Review and merge the companion implementation PRs without enabling receipt
   mode in live GitOps.
2. Run every repository's required checks.
3. Build and publish digest-pinned candidate images.
4. Verify signatures/provenance and record source commit-to-digest mappings.
5. Generate the signed static policy from the reviewed Rego template with a
   strictly greater policy epoch.
6. Generate and independently verify platform-release v2 using the exact
   static wrapper digest and issuer ID.
7. Encrypt live publisher/database values with the authorized SOPS age key.

Exit gate:

- all candidate artifacts exist and verify;
- all PR CI is green;
- no placeholder digest, trust map, signature, or secret remains; and
- `kustomize build` plus Kubernetes server-side dry run passes.

## Phase 2: Backward-Compatible Predeployment

1. Deploy PaaS safe-error propagation before receipt-mode CAP.
2. Bootstrap and verify the signing-service owner registry for every live org;
   back up the owner database.
3. Deploy the patched signing service only after proving existing CAP signing
   calls remain compatible.
4. Deploy the patched KBS image with receipt mode still disabled and verify
   existing attestation/resource behavior.
5. Install CAP and KBS PodMonitors, dashboard, alert rules, and notification
   routing.
6. Publish the new `enclava-init` image but do not yet change the workload image
   reference.

Exit gate:

- existing workloads still restart and unlock;
- owner inventory is complete;
- both CAP and KBS metric families are visible; and
- an alert-routing test reaches the designated responder.

## Phase 3: Backup, Restore, And Scale Rehearsal

1. Snapshot CAP PostgreSQL, all KBS/AS/RVPS namespaces, KBS target PostgreSQL,
   the signing owner database, and relevant persistent volumes.
2. Restore into isolated namespaces/databases; never overwrite live state.
3. Prove active KBS resources, attestation policy, reference values, owner
   records, receipt bytes, and tombstones survive.
4. Run the 10,000-record PostgreSQL concurrency test and retain p95/p99 output.
5. Rehearse the entire maintenance playbook, including failed KBS publication,
   CAP crash after outbox commit, and restart recovery.

Exit gate: restore reconciliation and the agreed latency/error SLO pass.

## Phase 4: Enter Maintenance And Drain

1. Announce the window and activate the write freeze at PaaS and CAP ingress.
2. Pause PaaS workers and reject all lifecycle mutations with a stable
   maintenance response.
3. Wait for CAP apply workers and deployment transitions to finish.
4. Take final CAP, KBS, signing-owner, and PVC snapshots and record restore
   identifiers.
5. Execute the approved backup/migration/destruction plan for `capture1` and
   its PVCs.
6. Prove no pod uses an old `enclava-init` image.
7. Scale the old CAP API fully to zero. Do not use a rolling mixed-version
   deployment for the receipt cutover.

Exit gate:

- no mutation traffic, apply work, legacy workload pod, or old CAP replica;
- final backups are complete and readable; and
- release lead explicitly approves KBS authority cutover.

## Phase 5: KBS Authority Cutover

1. Migrate/inventory the KBS, AS, and RVPS namespaces into the target
   PostgreSQL backend.
2. Install the exact approved signed static policy bytes.
3. Configure signed-policy verification, the exact policy digest and issuer
   pins, `require_deployment_authorization=true`, and the complete receipt
   issuer map.
4. Install the dedicated publisher bearer and PostgreSQL secret.
5. Restart KBS on the approved image and wait for readiness.
6. Verify the stored policy SHA-256 and byte count against platform-release v2.
7. Confirm exactly one `kbs_static_resource_policy_digest_info` series and test
   authorized/unauthorized publisher calls without logging credentials.

Exit gate: KBS is healthy, pinned, durable, monitored, and rejects unknown
issuers and unauthorized publishers.

Point of no return: accepting the new monotonic static-policy epoch. From this
point onward use a higher-epoch corrective policy and forward fixes; do not
restore an older live KBS database or policy.

## Phase 6: Consumer-First References And CAP Migration

1. While writes remain frozen, pin the same new `ENCLAVA_INIT_IMAGE` digest in
   CAP and the policy signing service.
2. Install the approved platform-release v2 envelope.
3. Run CAP SQLx migrations `0038` through `0041` from exactly one migration
   job/process.
4. Validate new constraints, indexes, tables, and migration checksums.
5. Deploy one receipt-mode CAP API replica with:
   - the HTTPS KBS publisher URL and dedicated bearer;
   - the private HTTPS workload-artifact URL and pinned CA;
   - the complete signing-service issuer trust map;
   - the approved signing-service and static-policy trust material; and
   - platform-release v2.
6. Confirm the authorization reconciler starts and startup refuses incomplete
   trust/publisher configuration.

Exit gate:

```sql
SELECT version, success
FROM _sqlx_migrations
WHERE version BETWEEN 38 AND 41
ORDER BY version;
```

All four migrations report success, CAP is ready, required metrics are present,
and no old CAP replica exists.

## Phase 7: Frozen Canary And Failure Tests

Deploy one disposable approved workload while general writes remain frozen.

Verify:

1. CAP atomically stores bundle, authorization, activation, deployment, and
   outbox state.
2. KBS publication and exact-byte read-back complete before manifest apply.
3. The pod uses the approved `enclava-init` digest.
4. Receipt, issuer, claims, bundle digest, and artifact chain verify before
   owner seed or LUKS open.
5. The static KBS policy digest and byte size do not change after deployment.
6. CAP's service account cannot patch KBS configuration or restart Trustee.
7. A known issuer succeeds and unknown/retired IDs fail closed.
8. In an isolated failure test, timeout, `429`, and `5xx` read-back failures
   preserve an already active workload and retry without local deactivation.
9. Restart, node restart, normal upgrade, failed upgrade, rollback, rekey,
   graceful teardown, and terminal revocation all pass.
10. PaaS/CLI return only the bounded structured publication errors.

Database checks:

```sql
SELECT state, count(*) FROM kbs_authorization_outbox GROUP BY state;
SELECT publication_state, count(*)
FROM workload_artifact_authorizations GROUP BY publication_state;
SELECT activation_state, count(*)
FROM deployment_artifact_activations GROUP BY activation_state;
```

Exit gate:

- outbox pending is zero and publication lag is below five minutes;
- expected active/terminal states match the canary lifecycle;
- no legacy-policy, mismatch, drift, claim-conflict, or unauthorized-publisher
  alert fires outside intentional negative tests; and
- at least two five-minute active-reconciliation cycles pass.

## Phase 8: Reopen And Soak

1. Re-enable writes with `CAP_MAX_CONCURRENT_APPLIES=1`.
2. Observe each initial deployment through publication, apply, unlock, and
   health before accepting the next.
3. Keep the maintenance rollback team available throughout the initial soak.
4. Soak preprod for at least 24 hours and repeat full lifecycle UAT.
5. Schedule production only after preprod evidence is attached and separately
   approved.

Production acceptance requires:

- `kbs_authorization_outbox_pending == 0`;
- no publication lag over five minutes;
- no read-back mismatch or authoritative reconciliation drift;
- `legacy_kbs_policy_format_seen_total` remains zero;
- one static-policy digest across all KBS replicas;
- no unknown issuer acceptance;
- active workloads remain active across inconclusive KBS audits; and
- all running pod `imageID` values match approved digests.

## Rollback And Forward-Fix Rules

### Before KBS accepts the new static-policy epoch

- remove the write freeze only after restoring the legacy component set and
  proving it healthy;
- candidate image/config changes may be reverted;
- leave additive CAP migrations installed unless a separately reviewed schema
  rollback is proven safe; and
- never restore a database over a newer live authority without an isolated
  comparison.

### After KBS accepts the new static-policy epoch

- freeze writes and forward-fix with a higher policy epoch;
- do not re-enable dynamic CAP policy mutation;
- do not roll back to an old KBS image that cannot resolve receipts; and
- do not restore an older KBS database, because it may erase terminal
  tombstones or reduce authority state.

### After the first receipt or tombstone

- keep KBS, CAP, and `enclava-init` on receipt-compatible versions;
- preserve CAP's last confirmed active state for transport, rate-limit, and
  upstream read-back failures;
- repair only authoritative `404` or exact-byte/digest drift;
- allow the durable outbox and tombstone ledger to retry; and
- never remove an issuer key while any active or rollback-eligible receipt
  references it.

## Evidence Ledger

The release ticket must link or attach:

- all coordinated PRs and merge commits;
- CI results and image digest/signature evidence;
- signed platform-release v2 and static-policy verification output;
- trust-map issuer inventory;
- SOPS change review without plaintext values;
- database/PVC snapshot identifiers and isolated restore report;
- scale-test p95/p99 results;
- rendered-manifest and server-side dry-run output;
- Flux revision and running `imageID` proof;
- migration query results;
- canary database/metric checks and UAT record;
- alert-routing evidence; and
- named approvals for destructive data handling and final write reopen.

Incident procedures remain in `runbooks/kbs-policy-storage.md`. Requirement and
implementation evidence remain in `KBS_POLICY_STORAGE_IMPLEMENTATION_AUDIT.md`.
