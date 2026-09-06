---
status: resolved
trigger: "Explicit database restore can skip KBS reconciliation when KBS configuration is absent and the restored authority has no required signed artifact."
created: 2026-07-28
updated: 2026-07-28
---

# Symptoms

- expected: Explicit restore must fail closed before any Kubernetes mutation when durable signed or legacy KBS authority, retained workloads, or CAP-owned namespace inventory requires Trustee reconciliation but KBS management is not configured.
- actual: Restore fencing currently depends only on KBS environment configuration or a non-empty required signed-artifact set, so empty signed-policy and legacy/orphan cases can bypass KBS reconciliation.
- errors: No error is returned; startup can proceed to restored Kubernetes mutation and later treat missing KBS configuration as a no-op.
- timeline: Found while addressing the final review findings on CAP pull request 54.
- reproduction: Advance CAP_DATABASE_RESTORE_GENERATION with KBS policy management disabled and either desired_generation greater than zero with no candidates, active legacy bindings, retained workloads, or CAP-owned orphan namespace inventory.

# Current Focus

- hypothesis: Confirmed. The restore decision lacked durable/database and live namespace authority evidence, and it read durable KBS state before owning the global KBS fence.
- test: Full restore-entrypoint regressions now cover fully applied empty signed mode, active owner/TLS legacy bindings, unsigned retained workloads, incomplete current namespaces, and CAP-owned orphans.
- expecting: Signed/orphan evidence without configuration returns KBS NotConfigured; legacy bindings and unsigned restore candidates are rejected without reconciliation; every case leaves the restore witness pending and makes no Kubernetes write.
- next_action: Hand the verified CAP patch and read-only preprod gate evidence back to the rollout owner.
- reasoning_checkpoint: Clean-cut rollout policy forbids recovery of legacy bindings/deployments. Restore now uses only signed-policy reconciliation and claims the KBS fence before reading durable authority.
- tdd_checkpoint: All new full-path tests failed against the original predicate/recovery path, then passed after the fail-closed implementation.

# Evidence

- timestamp: 2026-07-28T00:00:00Z
  observation: `restore_kbs_fence_required(false, 0)` returns false and gates the only pre-Kubernetes KBS convergence path.
- timestamp: 2026-07-28T00:00:01Z
  observation: `reconcile_policy_once` returns Ok immediately when `state.kbs_policy` is None.
- timestamp: 2026-07-28T00:00:02Z
  observation: Live preprod currently configures `KBS_POLICY_MANAGEMENT_REQUIRED=true`, so the blocker is permanent-code safety rather than the contained cluster's active branch.
- timestamp: 2026-07-28T00:00:03Z
  observation: Read-only live SQL found 0 active owner bindings, 0 active TLS bindings, signed desired/applied generation 6/6, 2 signed jobs, 0 unsigned jobs, and 2 apps in creating state.
- timestamp: 2026-07-28T00:00:04Z
  observation: Read-only live namespace inventory found 2 CAP-prefixed namespaces, both strictly CAP-owned and neither ambiguous. They correspond to incomplete database authority and must be removed or otherwise completed before the clean-cut restore gate can pass.
- timestamp: 2026-07-28T00:00:05Z
  observation: A serial fresh-schema run of all 51 deployment_jobs tests passed after missing-config paths began releasing the provably unmutated KBS fence; provider/authority errors continue to quarantine it.
- timestamp: 2026-07-28T00:00:06Z
  observation: Final verification passed fmt, locked check, strict locked Clippy, all 52 deployment_jobs tests, and the entire enclava-api package (425 library, 11 binary, 2 contract, and 26 integration tests) serially on fresh schemas.

# Eliminated

- hypothesis: Production environment validation always forces KBS policy management.
  reason: The release gate requires `TRUSTEE_POLICY_READ_AVAILABLE`, but does not require either KBS policy management flag.

# Resolution

- root_cause: Restore inferred KBS work only from runtime configuration and retained signed artifacts. It ignored durable empty signed mode, legacy binding rows, retained/namespace inventory, and did not own the KBS fence while proving authority.
- fix: Claim the global KBS fence before durable authority reads; reject legacy bindings and unsigned retained deployments; use signed-only reconciliation for signed/orphan/current evidence; return NotConfigured before Kubernetes writes; release the fence only for the provably provider-free NotConfigured/legacy/no-evidence paths.
- verification: Focused red/green tests passed on separate fresh schemas; the 3-test missing-config sequence passed on one fresh schema; all 52 deployment_jobs tests passed serially on another; the full enclava-api package passed 425 library, 11 binary, 2 contract, and 26 integration tests on a final fresh schema. Fmt, locked check, strict locked Clippy, and diff whitespace checks passed.
- files_changed: `crates/enclava-api/src/deployment_jobs.rs`; this debug artifact.
