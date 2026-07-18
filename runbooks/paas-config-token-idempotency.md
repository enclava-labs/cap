# PaaS config-token idempotency

CAP's two internal PaaS config-token routes use durable, non-secret receipt
version 1:

- `POST /internal/paas/orgs/{org}/apps/{app}/config-token`
- `POST /internal/paas/orgs/{org}/deployments/{deployment}/config-token`

The ledger stores the request-derived operation ID, immutable app UUID and
token instance identity, receipt version, DB-authored issuance time, and
completion state. It never stores a bearer token, successful response body,
TEE URL, or resolved IP. Ed25519 signing deterministically regenerates the same
JWT while the receipt remains returnable; endpoint metadata is resolved again.

## Lifetime and retry contract

- `issued_at` is `created_at` truncated to a whole second by PostgreSQL.
- JWT `iat` equals `issued_at`; JWT `exp` and response `expires_at` equal
  `issued_at + 300 seconds` exactly.
- JWT validation for config tokens has zero expiry leeway. Session and signer
  token validation are unchanged.
- CAP's route attempt is capped at 30 seconds and bounded cancellation at 5
  seconds. The incomplete receipt lease is fixed at 60 seconds and has no
  heartbeat.
- CAP does not return a bearer in the final 30 seconds before absolute expiry.
  It retains a completed non-secret receipt and returns
  `idempotency_request_in_progress`; callers retry the same key until expiry.
- At or after absolute expiry, the same key receives HTTP 409 with
  `idempotency_capability_expired`, `retryable: false`, disposition
  `new_key_after_expiry`, receipt proof version
  `deterministic_config_token_receipt_v1`, and exact `capability_issued_at` /
  `capability_expires_at` timestamps.
- A pre-receipt `expiring_capability` row receives the conservative legacy
  proof `legacy_expiring_capability_lease_v1` only after its six-minute
  DB-authored lease. Its timestamp is named `recovery_after`; it is not a JWT
  expiry assertion.

PaaS must retain one idempotency key for a logical token generation until the
absolute `expires_at`. The 30-second return cutoff controls response handoff;
it does not authorize a second overlapping generation. Only after the terminal
409 may PaaS create a new durable generation with a new key.

## Rollout and signing-key invariant

Receipt v1 can regenerate an exact JWT only with the same Ed25519 API signing
key. Every CAP replica serving these routes must use the same durable
`API_SIGNING_KEY_PATH` or `API_SIGNING_KEY_PKCS8_BASE64` secret. Ephemeral keys
are forbidden. Do not rotate that key while any deterministic receipt is live.

Deploy CAP API with `Recreate` (or explicitly drain all old API pods before
starting the new binary). Never run old and new receipt-contract binaries at
the same time. The preprod overlay is expected to use one replica and
`Recreate`; verify both before reconciling it.

For an API binary rollout without key rotation:

1. Stop config-token issuance at the PaaS boundary and drain CAP API pods.
2. Confirm no old CAP API pod remains.
3. Start only the new binary with the unchanged signing-key secret.
4. Verify readiness, then issue one app-route token and one deployment-route
   token; repeat each request with the same key and compare JWT, `issued_at`,
   and `expires_at` exactly.
5. Re-enable PaaS issuance.

For signing-key rotation while retaining a receipt-v1-compatible binary:

1. Stop PaaS config-token issuance and durably record the last possible
   issuance time. Keep the current compatible CAP binary and signing key
   available for retries during the drain window.
2. Wait at least 300 seconds after that recorded time. An earlier transition is
   allowed only if PaaS and CAP can prove that no deterministic receipt remains
   live.
3. Replay every outstanding deterministic idempotency key through its normal
   HTTP route. Require the exact terminal HTTP 409 proof, including
   `deterministic_config_token_receipt_v1`, `capability_issued_at`, and
   `capability_expires_at`, and durably record that proof in PaaS. PaaS must
   prove that its outstanding-key set is empty before rotation continues.
4. Drain every CAP API pod, rotate the durable Ed25519 secret, and start the
   complete replica set with the same receipt-v1-compatible binary. Never
   overlap old and new keys.
5. Verify that a pre-rotation terminal control key still replays the exact 409
   proof. Then issue one new token through each route and verify exact same-key
   JWT, `issued_at`, and `expires_at` replay before restoring issuance.

## Incompatible rollback

A rollback to a binary that cannot regenerate and interpret receipt v1 is not
equivalent to signing-key rotation. Waiting 300 seconds or changing CAP ledger
rows with offline SQL is insufficient: the older binary may not recognize the
resource-bound request hash, and CAP's ledger alone cannot prove that PaaS has
stopped retrying a durable key.

An incompatible rollback is permitted only after all of the following are
true:

1. PaaS config-token issuance is stopped and its complete durable set of
   outstanding deterministic idempotency keys is known.
2. A receipt-v1-compatible CAP binary with the original signing key remains or
   is restored so those requests can be interpreted correctly.
3. That compatible CAP generation terminalizes every outstanding key through
   the normal route at or after its DB-authored expiry.
4. PaaS receives, validates, and durably records the exact terminal 409 proof
   for every key, then proves that zero deterministic keys remain outstanding.
5. Only then are all compatible CAP pods drained and the incompatible binary
   started with no overlap.

If any key or proof cannot be accounted for, keep issuance fail-closed, retain
or restore the compatible CAP binary and original key, and forward-fix. Do not
perform the incompatible rollback. Database inspection may corroborate this
procedure, but it cannot substitute for PaaS-observed terminal proofs or repair
old request-hash incompatibility.

## Database verification

Migration `0043_deterministic_config_token_receipts.sql` scrubs legacy completed
config-token responses, rejects 2xx ledger bodies for both route families under
every recovery kind, and permits deterministic receipts to store only the exact
safe terminal 409 proof. During rollout, verify:

```sql
SELECT idempotency_key, path, recovery_kind, response_status
FROM cap_internal_idempotency
WHERE method = 'POST'
  AND (path LIKE '%/config-token')
  AND response_status BETWEEN 200 AND 299;
```

The query must return no rows. Also inspect deterministic rows only through
bounded metadata columns; never export request hashes or response content into
operator logs.
