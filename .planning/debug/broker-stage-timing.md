---
status: awaiting_human_verify
trigger: "Implement minimal fixed-label CAP broker stage timing instrumentation for this confirmed visibility gap"
created: 2026-09-06
updated: 2026-09-06
---

## Symptoms
expected: Distinguish TLS broker attestation, DNS visibility and ACME waiting using bounded metadata without guest logs or confidential values.
actual: DEV N stayed CPU-idle and returned423 for roughly75seconds after initial CPU work; existing safe metadata cannot attribute this wait.
errors: No functional broker failure established; missing safe stage attribution.
reproduction: Normal-auth fresh DEV app; correlate existing numeric worker and pod CPU metadata.

## Current Focus
hypothesis: Fixed-label numeric stage timings can isolate broker wait without modifying DNS/ACME behavior or revealing request content.
test: Capture logger records for success, private error and cancellation; assert closed schema, fixed labels and no private sentinel strings.
next_action: Root to review producer PR/full CI and collector PR94, then validate numeric broker timings in a separately approved signed DEV release. No live telemetry validation claimed.
reasoning_checkpoint:
  hypothesis: Current API has no bounded broker-phase timing so metadata cannot distinguish its sequential blocking dependencies.
  confirming_evidence:
    - acme.rs performs account/order/authorization/TXT propagation/challenge/order-ready/finalize/certificate/cleanup sequentially without durations.
    - N init CPU plateau7.44seconds at16:14:47 but423continued until16:16:03; source TLS broker client permits180seconds.
  falsification_test: If existing safe API records already expose these durations, a new timer is unnecessary; source search found none.
  fix_rationale: Add opt-in metadata only around existing calls; do not modify provisioning behavior or security prerequisites.
  blind_spots: Broker may not dominate N idle interval; signed DEV validation must test that hypothesis. Numeric timers alone do not prove guest phase completion.

## Evidence
- Isolated API library407/407 tests passed22.10s using explicit local cap_test_broker_timing_260906. API all-target clippy with warnings denied, workspace formatting and diff checks passed. Exact disposable database removed after tests; no sharedfixture cleanup attempted.
- Root approved15 fixed phase labels and numeric positive process-local request_seq. Explicit parent:None prevents request-span inheritance; no new global log level/config/dependency.
- Focused captured-logger test passed: default disabled, exact-target enabled, success/error/cancelled outcomes, strict field count and private span/value/error non-disclosure.
- Actual Devin CLI SWE-1.7 supplied-source review completed PASS/no blockers. Initial tool-based review was permission-blocked and was not counted; no permissions widened. Static review limitations checked by compilation.
- First full407-test API library run passed but omitted DATABASE_URL and used built-in localhost5432/test fixture. No live environment involved; shared fixture was not reset/deleted. Dedicated cap_test_broker_timing_260906 created for explicit isolated rerun; only isolated result will be cited as final validation.
- Source-only worktree created from main4cf9d4b; no existing user edits.
- Root owns all live operations and releases. PREPROD untouched.

## Eliminated

## Resolution
root_cause: Existing broker phases lack bounded metadata-only durations; cannot distinguish DNS/ACME/attestation wait from aggregate init readiness.
fix: Opt-in fixed-label RAII timings around existing broker operations, preserving public helper signature, control flow, security validation and retries.
verification: Focused strict-schema/redaction/cancellation test, isolated407 API library tests, API all-target clippy and workspace formatting pass. Full workspace/image CI and signed DEV observation still required; no live broker timing evidence yet.
files_changed: [crates/enclava-api/src/workload_tls_timing.rs, crates/enclava-api/src/acme.rs, crates/enclava-api/src/routes/workload_tls.rs, crates/enclava-api/src/lib.rs]
