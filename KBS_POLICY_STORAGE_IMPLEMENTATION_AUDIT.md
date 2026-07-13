# KBS Policy Storage Implementation Audit

Audit date: 2026-07-10

This is the requirement-to-evidence companion to
`KBS_POLICY_STORAGE_PLAN.md`. “Implemented” means current source and local
tests prove the requirement. “Rollout gate” means code exists but production
evidence cannot exist until signed artifacts, images, secrets, or destructive
approval are supplied.

## Architecture And Contracts

| Requirement | Status | Authoritative evidence |
|---|---|---|
| One immutable CAP bundle source of truth | Implemented | migrations 0038–0040 and `signing_service::persist_workload_artifacts` insert-or-compare behavior |
| CE-v1 semantic bundle and authorization digests | Implemented | `enclava-common::kbs_authorization`, signing-service independent implementation, shared fixed vectors |
| Strict signed authorization schema and valid three-segment paths | Implemented | CAP/common, signing-service, and KBS parsers plus tamper/path tests |
| Signing service independently verifies owner/keyring/descriptor authority | Implemented | durable `OwnerStore`, `validate_customer_authority`, exact signing-result replay, wrong-owner tests |
| Platform release records static policy digest and key id | Implemented for next release | platform-release schema v2 supports and signs both fields; production v2 envelope remains a rollout gate |

## KBS Consumer And Storage

| Requirement | Status | Authoritative evidence |
|---|---|---|
| Authorization resolved and verified before Rego for GET/PUT/DELETE | Implemented | `kbs/src/deployment_authorization.rs` and hard gates in `api_server.rs` |
| Missing, ambiguous, expired, mismatched, inactive, or revoked receipt denies | Implemented | typed claim collector and KBS authorization tests |
| Dedicated durable authorization namespace | Implemented | `DEPLOYMENT_AUTHORIZATION_STORAGE_NAMESPACE` using the selected KBS backend |
| Narrow publisher API with separate constant-time bearer | Implemented | four fixed `/kbs/v0/deployment-authorization/...` handlers and bearer tests |
| Immutable publish, reversible deactivate, irreversible tombstone | Implemented | `AuthorizationStore` state machine and lifecycle test |
| Static signed policy only in receipt mode | Implemented | ingestion/startup/evaluation guards reject legacy artifact sets |
| Exact static policy release digest/key-id pin | Implemented | KBS config validation plus mismatch tests; infra role validates staged file digest |
| Monotonic static policy epoch | Implemented | stored-policy transition validation and rollback/conflict tests |
| PostgreSQL production backend | Implemented in configuration | infra role requires Postgres in receipt mode; live migration/restore is a rollout gate |
| 10,000 independent authorization records | Implemented and run | explicit ignored scale test passes 10,000 immutable publish/read-back operations |
| Concurrent PostgreSQL p95/p99 harness | Implemented and run locally | 10,000-record concurrency-32 test passes at publish p95/p99 289/301 ms and mixed read/publish/deactivate/revoke p95/p99 79/81 ms; production-class DB results remain a rollout gate |

## CAP Producer And Lifecycle

| Requirement | Status | Authoritative evidence |
|---|---|---|
| Bundle, authorization, activation, deployment, and outbox commit atomically | Implemented | deploy and unlock routes use the same SQL transaction through artifact persistence |
| Publish plus exact read-back before manifest apply | Implemented | `publish_descriptor` precedes apply and records stable failures |
| Crash-safe outbox and abandoned lease recovery | Implemented | durable retry states, backoff, lease reclaim, integration failure injection |
| Claim-selected artifact endpoint with active-state and digest checks | Implemented | stable `/api/v1/workload/artifacts`, strict duplicate claims, activation/expiry/revocation query |
| Measured/pinned HTTPS artifact delivery | Implemented | engine/init configuration, private TLS proxy, CA pin, egress/network policy tests |
| Rollback reuses exact old receipt without rewriting signed deployment id | Implemented | rollback activation state and immutable republish path |
| Supersession deactivates old receipt only after replacement health | Implemented | rollout monitor invokes `supersede_old_activations` only after the healthy transition |
| Graceful destroy order | Implemented | drain, in-TEE teardown, namespace stop, terminal revoke/read-back, then purge |
| Emergency revocation order | Implemented | local terminal deny/outbox, namespace stop, then KBS tombstone attempt |
| Terminal tombstone survives CAP artifact purge | Implemented | permanent ledger and integration test proving ledger retention after bundle purge |
| CAP/KBS restore mismatch fails closed and repairs | Implemented | periodic exact active read-back queues local-deny repair; ledger replays all terminal revocations |
| Owner rotation expires old rollback receipts | Implemented | bounded grace record and transactional terminal revocation integration test |

## In-TEE Consumer

| Requirement | Status | Authoritative evidence |
|---|---|---|
| Receipt fetched through direct guest CDH before unlock | Implemented | `ReceiptArtifactFetcher` and main ordering tests |
| Receipt and bundle verified before seed/LUKS use | Implemented | main ordering test and full authorization/artifact-chain verifier tests |
| Owner fingerprint/keyring/descriptor/policy/agent hashes reverified | Implemented | `trustee_verify` receipt chain and tamper tests |
| Production binary has no legacy policy-set reader | Implemented | old parser/fetcher is `cfg(test)` archival code only; receipt is mandatory from the signing service |

## Operations And Observability

| Requirement | Status | Authoritative evidence |
|---|---|---|
| CAP cannot mutate/restart Trustee policy in receipt-mode GitOps | Implemented | RBAC removal plus ValidatingAdmissionPolicy guard |
| Private proxy exposes only the workload artifact route | Implemented | dedicated 3444 TLS listener configuration |
| Publisher, database, and CA secrets are separated | Implemented as templates | live SOPS encryption with an authorized age key is a rollout gate |
| CAP and KBS specified metrics exist | Implemented | CAP `/metrics` registry and KBS Prometheus registry tests |
| CAP and KBS metrics are scraped | Implemented in manifests | CAP and Trustee `PodMonitor` resources, TLS-verified KBS scrape, and monitoring NetworkPolicy rules; live application is a rollout gate |
| Dashboards and alerts | Implemented as validated artifacts | 13-rule Prometheus file passes `promtool`; Grafana dashboard and operations runbook have contract tests; remote loading/routing is a rollout gate |
| Backup/restore runbooks | Implemented | KBS infra and signing-owner database documentation; live restore drill remains a rollout gate |
| Hosted KBS failure propagation | Implemented | CAP emits bounded structured publication reasons; PaaS preserves only allowlisted safe 502/503 bodies and wraps unknown 5xx responses |

## Local Verification Record

The 2026-07-10 implementation pass completed these checks against the current
worktrees:

- CAP: formatting, strict workspace Clippy, workspace/unit/integration/doc
  tests, audit, deny, workspace build, all three required release builds, and
  both required Docker builds.
- Trustee/KBS: normal tests, strict no-default-feature Clippy, the explicit
  10,000-record independent-backend test, the 10,000-record concurrent local
  PostgreSQL test, and the production `coco-as-grpc` Docker build.
- Policy-signing service: all tests, strict Clippy, and its production Docker
  build.
- Infrastructure: YAML parsing and the Trustee role's Ansible syntax check.
- Operations: complete Kustomize rendering and server-side validation of the
  non-Secret resources against the live cluster. Raw SOPS Secret manifests
  were intentionally not claimed as server-validated because Flux normally
  decrypts them before admission and no authorized age key was available.
- Monitoring: CAP and KBS `PodMonitor` plus NetworkPolicy resources pass live
  server-side dry-run; the 13 alert rules pass Prometheus `promtool` validation.
- PaaS: formatting, strict Clippy, all Rust tests, UI tests/check/build, Rust
  audit, real-PostgreSQL CLI contracts, and the stable-SSH production-polish
  suite pass with the structured KBS failure proxy contract.
- All six worktrees pass `git diff --check`; the Trustee and signing-service
  static Rego sources have the same SHA-256
  (`cc24517ebd3b01fc530a665098510d0b57695580d8d8bd8cb53b63dfd67e498f`).

Read-only cluster inspection also confirmed that preprod is still on the
legacy compact-v2 baseline: Trustee has no receipt-authorization settings,
uses `LocalFs`, and serves an 8,931-byte dynamic `resource-policy`. One legacy
tenant StatefulSet and two tenant/CAP PVCs remain. This is baseline evidence,
not cutover evidence; no live resource was changed.

## Required External Evidence Before Completion

The implementation cannot be called deployed or cut over until all of the
following exist:

1. Published, signed, digest-pinned signing-service, KBS, `enclava-init`, PaaS,
   and CAP images in consumer-first order, with the compatible PaaS error
   consumer promoted before receipt-mode CAP.
2. A production platform-release v2 envelope, signed static policy artifact,
   issuer maps, and exact digest/key-id pins.
3. Live SOPS-encrypted KBS publisher and PostgreSQL credentials.
4. Approved and executed KBS namespace export/import plus isolated restore
   drill proving owner resources, policy epoch, active receipts, and terminal
   tombstones.
5. Explicit product-owner approval for destructive legacy workload/PVC
   handling, followed by proof that no legacy pods remain.
6. Production HA, restart, rekey, teardown, upgrade/failure/rollback,
   app/SSH, concurrent DB, and p95/p99 UAT.
7. Import the supplied monitoring dashboard/rules and prove routed alerts in
   the production remote monitoring backend.
8. Post-cutover removal of legacy CAP policy mutation code/tables only after
   the live no-legacy proof makes that deletion safe.
