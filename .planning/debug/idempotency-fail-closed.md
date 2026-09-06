---
status: investigating
trigger: "Validate and, if compactly safe, fix busy-409 cancellation deleting incomplete idempotency request_hash bindings and generic internal post-lease completion blanket-deferring all 5xx."
created: 2026-07-29
updated: 2026-07-29
---

# Symptoms

- expected_behavior: An accepted idempotency key remains permanently bound to its original request hash, and retry disposition after internal side effects is derived from typed knowledge of whether those side effects were applied.
- actual_behavior: Reported behavior says busy-409 cancellation deletes the incomplete row and generic internal completion defers every 5xx.
- error_messages: No runtime error supplied; validate directly from current code and focused tests.
- timeline: Present on current origin/main if confirmed.
- reproduction: Trace and test cancellation/completion paths around mutation leases and idempotency records.

# Current Focus

- hypothesis: Both claims are present on exact origin/main and can be fixed without a new framework by preserving hash-bound cancellations and narrowing deferred completion to a typed known-not-applied disposition.
- test: Inspect current SQL and handler call graph, then add focused regression tests before implementation.
- expecting: A same-key/different-hash retry conflicts after cancellation, and only explicitly known-not-applied failures remain retryable.
- next_action: Gather exact code and test evidence.
- reasoning_checkpoint:
- tdd_checkpoint:

# Evidence

# Eliminated

# Resolution

- root_cause:
- fix:
- verification:
- files_changed:
