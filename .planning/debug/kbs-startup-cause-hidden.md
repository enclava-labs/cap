---
status: investigating
trigger: "CAP activation repeatedly exits during required startup KBS reconciliation while the displayed wrapper hides the inner typed cause"
created: 2026-07-28
updated: 2026-07-28
---

## Symptoms

- Expected: the exact deployed CAP image recognizes the already-converged signed policy generation and becomes ready.
- Actual: CAP claims the global `kbs_policy` lease, exits with code 1 within one second, and its replacement waits through the finite 360-second reclaim quarantine. This repeated at the next natural retry.
- Error: the current `KbsPolicyReconciliationError` display reports only the outer category, so the safe inner `KbsPolicyError` is not preserved in the startup diagnostic.
- Timeline: first observed after preprod activation at 2026-07-28 11:48 UTC; reproduced at the natural retry around 11:57 UTC.
- Reproduction: start the exact CAP image against the current preprod database and Kubernetes authority state.

## Current Focus

- hypothesis: the deterministic inner KBS failure is hidden by a generic error wrapper even though visible database, ConfigMap, and Trustee generation/hash/token state is converged
- test: preserve the typed source error in Display, prove formatting with focused unit tests, then perform one controlled retry and inspect only the control-plane startup diagnostic
- expecting: a precise safe variant such as database, Kubernetes API, serialization, generation conflict, or lease loss without artifact payloads or customer data
- next_action: implement the minimal source-chain formatting change and focused tests

## Evidence

- timestamp: 2026-07-28T11:57:06Z
  observation: second natural retry acquired the global lease and exited within one second
- timestamp: 2026-07-28T11:59:00Z
  observation: exact candidate selection reconstructs the live 17,783-byte policy body and SHA-256 f96073ac6fd85bcf344284a44d9d521731c908384a09b7a23f1f38950e7d8d4b
- timestamp: 2026-07-28T12:00:00Z
  observation: CAP runtime role sees both eligible artifact-bound candidates; in-pod service-account reads and RBAC checks succeed

## Eliminated

- hypothesis: same-generation candidate/content conflict
  reason: exact selected descriptor set, ordering, serialized bytes, ConfigMap body, database hash, and Trustee annotations match
- hypothesis: policy byte budget exceeded
  reason: 17,783 bytes is below the configured 921,600-byte limit
- hypothesis: one-off transient provider failure
  reason: the failure repeated at the natural lease boundary with the same sub-second timing

## Resolution

- root_cause:
- fix:
- verification:
- files_changed:
