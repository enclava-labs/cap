# KBS Policy Artifact Storage Plan

## Problem

CAP currently publishes active signed policy artifacts through the Trustee KBS
`resource-policy` ConfigMap path. That made issue #18 possible: every active
artifact competes for one Kubernetes ConfigMap data object, which is capped at
1 MiB by Kubernetes. Raising `KBS_SIGNED_POLICY_MAX_BYTES` is not a durable fix
while the storage backend is still a ConfigMap.

There are two separate concerns that should not share this storage boundary:

- KBS authorization state: small rules or claims that decide whether an attested
  workload may read a resource.
- Workload policy artifacts: larger signed deployment artifacts that
  `enclava-init` verifies before releasing workload state.

## Current Mitigation

The short-term fix keeps the existing KBS ConfigMap flow but writes compact
`enclava-signed-policy-set-v2` policy sets. The compact body omits
`agent_policy_text` and keeps only the metadata, Rego text, hashes, signature,
verification key, and optional keyring reference needed for active policy
matching. `enclava-init` fetches the full artifact bundle from CAP and verifies
that the compact KBS body matches the signed full artifact.

This reduces the per-deployment ConfigMap footprint enough for current testing,
but it still scales with active signed artifacts and remains bounded by the
ConfigMap object limit.

## Target Architecture

KBS should authorize access, not store full signed workload artifacts.

CAP remains the artifact authority:

- Store full signed policy artifacts in CAP PostgreSQL or object storage.
- Serve artifacts through the existing attestation-gated
  `/api/v1/workload/artifacts` endpoint.
- Keep artifact selection keyed by attested `descriptor_core_hash` and
  `init_data_hash`.

KBS stores only small authorization material:

- A resource binding or receipt keyed by descriptor hash, deployment id, or KBS
  resource path.
- Hashes such as `descriptor_core_hash`, `rego_sha256`, and
  `agent_policy_sha256`.
- Signature metadata needed to bind the KBS authorization decision to the CAP
  artifact.

`enclava-init` verifies both sides:

- Fetch the full artifact bundle from CAP after KBS/Trustee attestation.
- Fetch a small KBS authorization receipt or policy reference.
- Verify that the CAP artifact hashes and signatures match the KBS reference.
- Continue refusing seed release on any mismatch.

## Implementation Phases

1. Define a compact authorization receipt schema.
   - Include schema version, descriptor hash, deployment id, Rego hash, agent
     policy hash, policy signature hash or signature, and issuer key id.
   - Make the schema independent of Kubernetes ConfigMap storage.

2. Add CAP API support for receipt generation.
   - Generate receipts from stored `workload_artifacts`.
   - Add unit tests proving receipt fields match the signed artifact.
   - Preserve the current full artifact endpoint contract.

3. Add `enclava-init` support for receipt verification.
   - Accept the existing full body and compact v2 body during migration.
   - Add receipt verification as the preferred path.
   - Fail closed when receipt and full CAP artifact disagree.

4. Replace ConfigMap artifact publication.
   - Stop writing signed policy artifact sets into `resource-policy`.
   - Keep ConfigMap mutation only for small Trustee/KBS authorization policy
     rules if Trustee still requires that path.
   - Prefer a dynamic KBS resource backend backed by DB, PVC, or object storage
     if available in the deployed Trustee version.

5. Migrate deployment config.
   - Roll out the new `enclava-init` image first.
   - Roll out CAP with receipt generation enabled but ConfigMap artifact writes
     still available as fallback.
   - Enable receipt-only mode after test workloads pass.

6. Remove the fallback.
   - Delete ConfigMap artifact set serialization and byte-budget pruning.
   - Keep an explicit startup check that prevents large artifact payloads from
     being written into ConfigMaps again.

## Acceptance Criteria

- Deploying more active workloads does not grow the KBS ConfigMap by signed
  artifact size.
- `resource-policy` remains comfortably below the Kubernetes 1 MiB ConfigMap
  data limit.
- A workload cannot release seeds unless the CAP artifact and KBS authorization
  receipt agree on descriptor hash, Rego hash, agent policy hash, and signature
  identity.
- Old full-body and compact-v2 deployments continue through the migration
  window.
- CAP surfaces KBS authorization or artifact mismatches as deployment errors,
  and PaaS exposes those errors to hosted-template users.

## Operational Notes

- The current compact v2 mitigation is safe for further testing only after
  `enclava-init` has been rolled out with compact policy parsing support.
- The permanent fix should be deployed through the ops/GitOps repository, not
  as a one-off live patch.
- Do not raise `KBS_SIGNED_POLICY_MAX_BYTES` into multi-MiB territory while the
  backend is a ConfigMap.
