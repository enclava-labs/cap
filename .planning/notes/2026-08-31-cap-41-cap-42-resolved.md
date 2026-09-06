---
date: "2026-08-31 06:59"
promoted: false
---

Code-backed review: CAP-41 and CAP-42 require no further work. Both stale ticket branches (`cap-41`, `cap-42`) point to the same pre-fix commit and were never advanced. Their fixes are merged into `origin/main` via PR #44 (deployment validation/persistence atomicity) and PR #43 (HAProxy generation reconciliation). Focused regressions passed: signed-deployment rejection leaves persisted rows unchanged; HAProxy retries converge after ConfigMap/DaemonSet partial failures and lost responses; ConfigMap growth is rejected before a write. Do not merge or rebase the stale branches. Their abandoned alternative PRs #47 and #45 are superseded by the current shared paths and later authority/rollout hardening.
