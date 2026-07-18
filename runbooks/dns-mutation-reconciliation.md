# DNS Mutation Reconciliation

CAP poisons a managed DNS hostname by setting its
`external_resource_mutation_leases.reclaim_after` to PostgreSQL `infinity`
before it sends an unconditional Cloudflare write. A normal successful
operation clears that owner in the same publication transaction as the CAP
state change. A crash, heartbeat loss, or ambiguous provider response leaves
the poison in place so a delayed old request cannot race hostname reuse.

`infinity` is an intentional fail-closed condition. Do not clear it merely
because `locked_until` elapsed or an immediate Cloudflare lookup returned no
record. Cloudflare may have accepted work whose response was lost.

## Inspect

Find poisoned resources and retain the exact token and generation as the
reconciliation identity:

```sql
SELECT resource_scope, resource_key, generation, owner_token,
       operation_kind, operation_id, locked_until, updated_at
  FROM external_resource_mutation_leases
 WHERE reclaim_after = 'infinity'::timestamptz
 ORDER BY resource_scope, resource_key;

SELECT app_id, generation, owner_token, operation_kind, operation_id,
       locked_until, reclaim_after
  FROM app_mutation_leases
 WHERE owner_token = '<owner-token>'::uuid;
```

Confirm all of the following before touching Cloudflare or the lease row:

1. The owning CAP process/request is no longer running and `locked_until` has
   expired. During an incident, stop the affected writer or scale API/workers
   down so it cannot still send provider writes.
2. The authoritative app/deployment state says whether each hostname must
   exist or be absent. Active platform hostnames must have exactly the
   configured A/AAAA target; deleting or failed-cleanup apps must have no
   managed record. User-owned custom DNS is not a Cloudflare mutation.
3. Cloudflare has confirmed that accepted work from the lost request has
   quiesced. Two immediate empty reads are not sufficient. If the provider
   cannot establish quiescence, leave the row poisoned and escalate rather
   than risking reuse.

## Reconcile the provider

Using the Cloudflare console or API, list all records for each exact hostname
and zone. Converge them to the authoritative state from CAP. Record the zone,
hostname, provider record IDs, before/after values, operation ID, and incident
reference. Re-read the provider state only after the provider's accepted work
is known to be quiescent.

For ACME TXT records, CAP creates a distinct immutable record for every
challenge and cleans it up by the returned provider record ID. A lost create
response can therefore leave an orphan TXT record, but an old cleanup cannot
delete a newer challenge. Remove an orphan only by its exact provider ID and
only after confirming that no issuance still owns it; never delete the first
TXT record found by hostname.

## Unpoison with an exact CAS

Clear every reconciled hostname in one transaction. Substitute values captured
during inspection; a zero-row update means authority changed and the procedure
must stop.

```sql
BEGIN;

SELECT generation, owner_token, operation_kind, operation_id,
       locked_until, reclaim_after
  FROM external_resource_mutation_leases
 WHERE resource_scope = 'dns_hostname'
   AND resource_key = '<canonical-hostname>'
 FOR UPDATE;

UPDATE external_resource_mutation_leases
   SET owner_token = NULL,
       operation_kind = NULL,
       operation_id = NULL,
       locked_until = NULL,
       reclaim_after = NULL,
       updated_at = clock_timestamp()
 WHERE resource_scope = 'dns_hostname'
   AND resource_key = '<canonical-hostname>'
   AND generation = <captured-generation>
   AND owner_token = '<captured-owner-token>'::uuid
   AND reclaim_after = 'infinity'::timestamptz
   AND locked_until <= clock_timestamp();

-- Repeat the SELECT/UPDATE pair for every hostname owned by the operation.

-- Clear the app owner only when it is the same expired owner and no other
-- provider resource still depends on that token.
UPDATE app_mutation_leases AS app
   SET owner_token = NULL,
       operation_kind = NULL,
       operation_id = NULL,
       locked_until = NULL,
       reclaim_after = NULL,
       updated_at = clock_timestamp()
 WHERE app.app_id = '<app-id>'::uuid
   AND app.generation = <captured-app-generation>
   AND app.owner_token = '<captured-owner-token>'::uuid
   AND app.locked_until <= clock_timestamp()
   AND NOT EXISTS (
       SELECT 1
         FROM external_resource_mutation_leases AS resource
        WHERE resource.owner_token = app.owner_token
   );

COMMIT;
```

Afterward, retry the original CAP operation and verify both CAP's `dns_records`
state and Cloudflare's exact hostname records. Preserve the reconciliation
evidence with the incident record.
