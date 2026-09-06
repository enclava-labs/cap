---
status: resolved
trigger: "CAP pull request 54 exact head 697e030b9cb43eef15845bb0f0f3be517ad26f4d received four fresh actionable review findings after CI passed."
created: 2026-07-28
updated: 2026-07-28
---

# Symptoms

- expected: Partial Kubernetes authority metadata fails closed; clean-cut targets retain a safe ordinary DELETE path through provider cleanup; signed-only validation applies only to explicit restored clean-cut authority; migration-recovered cleanup drains its retained fence before any competing global KBS claim.
- actual: Epoch-without-restore-generation is treated as a legacy upgrade; clean-cut route reconciliation removes the teardown route before DELETE; every historical unsigned job is treated as restored authority; startup validation can claim the KBS fence before migration-recovered cleanup releases it.
- errors: Fresh exact-head Codex review reported three P1 findings and one P2 finding on PR 54.
- timeline: Detected by the fresh review submitted at 2026-07-28T06:29:52Z after exact-head CI completed successfully.
- reproduction: Exercise malformed paired authority annotations, ordinary DELETE after clean-cut retirement and HAProxy reconciliation, normal unsigned history without a clean-cut receipt, and migration-0045/0046 retained cleanup authority during startup.

# Current Focus

- hypothesis: Confirmed for partial authority metadata, signed-only scope, and startup fence ordering. The claimed teardown blockage was already transport-best-effort, but the first clean-cut DELETE still unnecessarily attempted a route removed by reconciliation.
- test: Focused regressions now cover symmetric paired authority annotations, pre-transition teardown selection plus retry-safe endpoint failure, exact-receipt-scoped validation, terminal history exclusion, retained KBS-fence non-contention, and database-only-before-provider startup ordering.
- expecting: All focused and full workspace tests pass without weakening explicit clean-cut rejection of unsupported nonterminal authority.
- next_action: Commit and push the verified patch, answer the four exact review threads, and request a fresh exact-head review.
- reasoning_checkpoint: User explicitly permits deleting legacy deployments and requires a clean cut; ordinary non-clean-cut installations must nevertheless not be reclassified as restore authority merely because historical jobs were unsigned.
- tdd_checkpoint: The partial-metadata, ordinary-history, and startup-order regressions failed before implementation and passed after it. The teardown transport regression passed before the change, proving the review's stated blocking mechanism was already absent; the added pre-transition decision regression verifies the strengthened clean-cut path.

# Evidence

- timestamp: 2026-07-28T06:29:53Z
  observation: Thread PRRT_kwDOSHSH5s6UTi0A identifies the asymmetric partial-authority annotation path in generation.rs.
- timestamp: 2026-07-28T06:29:53Z
  observation: Thread PRRT_kwDOSHSH5s6UTi0D identifies failed clean-cut targets losing HAProxy teardown reachability before ordinary DELETE.
- timestamp: 2026-07-28T06:29:53Z
  observation: Thread PRRT_kwDOSHSH5s6UTi0G identifies the global historical-job scan in require_clean_cut_restore_jobs.
- timestamp: 2026-07-28T06:29:53Z
  observation: Thread PRRT_kwDOSHSH5s6UTi0I identifies startup validation preceding migration-recovered failed-rollout cleanup while both require the global KBS fence.
- timestamp: 2026-07-28T07:00:00Z
  observation: Fresh-database clean-cut group passed 16/16, app route tests passed 20/20, and generation tests passed 6/6.
- timestamp: 2026-07-28T07:01:00Z
  observation: Full locked workspace tests passed serially against a fresh database; enclava-api passed 450 library, 1 clean-cut binary, 12 startup, 2 contract, and 26 integration tests, with every remaining workspace and doc test green.
- timestamp: 2026-07-28T07:02:00Z
  observation: Warnings-denied locked all-targets Clippy, cargo fmt check, and git diff whitespace checks passed.

# Eliminated

# Resolution

- root_cause: Authority metadata validation was asymmetric; teardown necessity was recomputed after the lifecycle changed to deleting; signed-only validation was globally activated and scanned terminal history; and the global clean-cut KBS claim preceded the exact migration-recovered cleanup owner.
- fix: Reject either half of paired authority metadata; capture teardown need from the pre-transition status while keeping retry transport failures best-effort; activate clean-cut validation only for a receipt bound to the current runtime authority and scan only nonterminal jobs; run a database-only clean-cut preflight, drain exact cleanup, then recheck under the global KBS fence.
- verification: Focused red/green regressions, fresh-database clean-cut/app/generation groups, full serial locked workspace tests, locked warnings-denied all-targets Clippy, formatting, and diff checks all passed.
- files_changed: `crates/enclava-engine/src/apply/generation.rs`; `crates/enclava-api/src/routes/apps.rs`; `crates/enclava-api/src/routes/apps/tests/mod.rs`; `crates/enclava-api/src/deployment_jobs.rs`; `crates/enclava-api/src/main.rs`; this debug artifact.
