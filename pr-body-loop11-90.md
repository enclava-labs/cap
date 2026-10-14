## Summary

Owner-facing deployment lifecycle diagnostics for #90: project the active deployment's durable lifecycle state (apply-job phase, progress condition, redacted reason code, retry/lease timing) through an authenticated, read-only contract so a tenant can distinguish progress, retry, lease-blocked, and terminal states without cluster access — answering the issue's six questions (phase? progressing/waiting/stalled? blocked by what? retry when? safe owner action? cancel?) from the CLI.

## The 5 commits

1. **359a517b feat(api,cli): owner-facing deployment lifecycle diagnostics (#90)** — `GET /apps/{name}/deployment/diagnostics` (normalized phase/condition/reason, started_at, last_progress_at, attempts, next_retry_at, blocked_until, blocking_operation, observing_since; redacted by construction — fixed tokens and durable row values only); additive `deployment` block on `GET /apps/{name}/status` (skip-serialized, older consumers unaffected); CLI `enclava status` renders the block with one actionable sentence per common condition.
2. **afc521c1 fix(api): complete diagnostics projection** — sqlx column aliases so `FromRow` decodes, `attempts` typed int4, and the status `deployment` block degrades to omitted on a diagnostics-query error instead of failing the whole status response.
3. **b1eebbdf fix(api): split applying vs watching phases** — a running apply job spans manifest apply and rollout watch; `from_job_state` distinguishes them from the deployment row's sub-phase.
4. **878487b6 fix(api,cli): truthful lifecycle projection (round-1 review)** — terminal rollout failure no longer reports healthy; watch-slice gap is Watching/waiting_external; setup-failure cleanup is terminal `deployment_setup_failed`; no-deployment-row apps return phase unknown without fabricated data; foreign mutation lease → `blocked_by_operation` with the 409-consistent deadline and an allowlisted operation kind; queued-and-due is progressing; CLI relative timestamps + per-phase terminal actions.
5. **36b341b2 fix(api,cli): claimable jobs are progress, own lane never blocks (round-2 review)** — due retries and expired-lock jobs are progress, never stalled; own lease kinds never populate blocked fields; foreign lease beats scheduled retry; new Destroying phase for deleting apps; failed-with-cleanup-job keeps its schedule; SettingUp reachable on real rows; reason prefers the durable `error_message` token; 26 unit tests covering every new shape.

## Tests

- 26+ projection unit tests (poisoned fence, due-retry, expired-lock, foreign-lease precedence, watch-slice, failed-rollout, blocked-by-operation shapes).
- Integration fixtures parameterized by deployment status exercising the projection over HTTP.

Local gates: `cargo fmt --all -- --check` ✅ · `cargo clippy --workspace --all-targets -- -D warnings` ✅ · `cargo test --workspace -- --test-threads=1` on a fresh DB ✅

Fixes #90

— enclava-coder (automated)
