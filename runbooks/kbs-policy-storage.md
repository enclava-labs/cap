# KBS Policy Storage Operations

Use this runbook only for the receipt-mode architecture described in
`KBS_POLICY_STORAGE_PLAN.md`. Never recover availability by enabling the legacy
dynamic policy set or by granting CAP general KBS admin access.

## Publication failure or backlog

1. Block new deploy, rollback, unlock-mode, and lifecycle writes.
2. Check `kbs_authorization_outbox_pending`, publication lag,
   `kbs_authorization_publication_total`, and
   `kbs_authorization_reconciliation_total`. Do not log or print receipt bodies
   or publisher credentials.
3. Verify CAP-to-KBS TLS, the dedicated publisher bearer, KBS health, and the
   authorization backend without changing authorization state.
4. For `publisher_readback_mismatch`, preserve CAP/KBS database snapshots and
   compare exact authorization bytes and SHA-256 values before retrying.
5. Let the durable outbox retry. Do not manually apply a workload manifest.
6. Re-enable writes only after the outbox is empty, active read-back audit
   passes, and a fresh deployment completes publication before manifest apply.

## Static-policy drift

1. Block writes and compare the KBS metric's `sha256` label and byte gauge with
   the signed platform-release v2 envelope.
2. Verify the exact signed wrapper and issuer key id staged by the Trustee role.
3. If any replica differs, drain it and redeploy the approved digest-pinned KBS
   image/config. Never patch policy bytes in place through CAP.
4. Require one digest series across all replicas before re-enabling writes.

## CAP/KBS restore reconciliation

1. Restore into an isolated namespace and retain the damaged databases.
2. Verify static-policy epoch, owner resources, active authorization bytes, and
   the permanent CAP tombstone ledger.
3. Treat `404` or a successful exact-byte/digest mismatch as authoritative
   drift: CAP locally denies only that authorization and queues restore repair.
4. Treat transport/body errors, `408`/`425`/`429`, `5xx`, `401`/`403`, and other
   unexpected statuses as inconclusive. CAP preserves the last confirmed active
   state, records the attempt, and retries; an outage is not evidence of drift.
5. Replay every terminal tombstone and confirm it in KBS before allowing bundle
   purge or workload access.
6. Run fresh deploy, restart, rollback, rekey, and teardown UAT before promotion.

## Authorization issuer key rotation

1. Inventory every issuer on active and rollback-eligible receipts before
   changing trust configuration:

   ```sql
   SELECT issuer_key_id, count(*)
   FROM workload_artifact_authorizations
   WHERE terminally_revoked_at IS NULL
   GROUP BY issuer_key_id
   ORDER BY issuer_key_id;
   ```

2. Require every inventoried ID in the independently managed KBS, CAP, and
   `enclava-init` trust maps. Receipt verification never falls back from an
   unknown ID to the scalar current key.
3. Keep retiring keys mapped until all receipts under them are terminally
   revoked, expired, or no longer rollback-eligible. Reversible deactivation is
   not sufficient for key retirement.
4. Provision the complete map before deploying strict consumers. Deploy and
   verify the `enclava-init` digest first, then deploy CAP API, and test known,
   unknown, and retired key IDs before enabling writes.

## Publisher authorization failure

1. Treat an unexpected failure as a potential credential-use incident.
2. Identify the source from network and KBS audit metadata without exposing the
   bearer. Confirm CAP uses only the fixed deployment-authorization endpoints.
3. Rotate the dedicated bearer in KBS first, then CAP, within an approved write
   freeze. Do not reuse KBS admin or attestation-verification credentials.

## Artifact integrity or claim conflict

1. Stop the affected workload and preserve the attestation token metadata,
   receipt digest, CAP bundle digest, descriptor hash, and database snapshots.
2. Do not choose one of multiple claim values. Ambiguity is a hard deny.
3. Verify the owner keyring, descriptor signature, measured init-data, receipt,
   and CE-v1 bundle digest independently before deciding whether to repair.

The alert rules are in `deploy/kbs-policy-storage-alerts.prometheus.yml`; the
Grafana import artifact is `deploy/kbs-policy-storage-dashboard.json`. Loading
and routing them in the remote monitoring backend is a production rollout gate.

## PostgreSQL scale gate

Create an empty disposable table with `key TEXT PRIMARY KEY, value BYTEA` in a
production-class isolated database. Then run the ignored KBS test with
`POSTGRES_URL`, `KBS_AUTHORIZATION_SCALE_NAMESPACE`, the agreed
`KBS_AUTHORIZATION_SCALE_P99_MILLIS`, and optionally
`KBS_AUTHORIZATION_SCALE_CONCURRENCY` (default 32):

```bash
cargo test -p kbs --lib --no-default-features postgres_authorization_concurrency_and_latency_gate -- --ignored --nocapture
```

The gate publishes 10,000 independently signed records and then runs a
concurrent mix of exact read-back, idempotent publish, deactivate, and terminal
revoke operations. Retain p95/p99 output with the release evidence and drop the
disposable table afterward.
