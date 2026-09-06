---
status: resolved
trigger: "Kubernetes deletion leaves an encrypted-log workload container and Kata sandbox stuck"
created: 2026-07-31
updated: 2026-07-31
---

# Symptoms

- Expected: deleting a tenant pod terminates every container within its 30-second grace period and creates a replacement.
- Actual: three sidecars exit, but the web container remains running; Kata `StopContainer` and `StopPodSandbox` time out.
- Error: kubelet reports `DeadlineExceeded` for `StopContainer`; the Kata sandbox task remains `UNKNOWN` while its shim and QEMU stay alive.
- Timeline: reproduced during the first complete restart/persistence E2E on the new dev cluster.
- Reproduction: deploy an app with encrypted workload logs, wait until ready, then delete its StatefulSet pod normally.

# Current Focus

- result: the platform wrapper now forwards termination signals, but that was hardening rather than the observed workload hang's root cause.
- next_action: none for this incident; the final payload terminated in one second during live pod replacement.
- reasoning_checkpoint: reproducing SIGTERM against the real payload first isolated its same-thread Python `HTTPServer.shutdown()` deadlock; a threaded graceful shutdown fixed Docker but could still hang inside Kata, so the disposable canary now exits directly on TERM/INT.
- tdd_checkpoint: both the wrapper forwarding regression and the corrected payload process-level shutdown check pass.

# Evidence

- timestamp: 2026-07-31T12:40:50Z
  observation: kubelet `StopContainer` for the web container exceeded its runtime request deadline.
- timestamp: 2026-07-31T12:43:00Z
  observation: Kata shim and QEMU were still alive and the sandbox task remained `UNKNOWN`.
- timestamp: 2026-07-31T12:43:30Z
  observation: source inspection showed the non-encrypted path uses `exec`, while the encrypted path uses `spawn` plus `wait` without signal forwarding.
- timestamp: 2026-07-31T12:48:00Z
  observation: process-level regression passes after forwarding termination signals from the encrypted-log wrapper to its child.
- timestamp: 2026-07-31T13:20:00Z
  observation: the real payload deadlocked locally because its signal handler called `HTTPServer.shutdown()` on the same thread running `serve_forever()`.
- timestamp: 2026-07-31T13:54:00Z
  observation: after moving payload shutdown onto a daemon thread, controlled deletion of the confidential pod completed in two seconds.
- timestamp: 2026-07-31T14:33:08Z
  observation: a later live run showed the threaded graceful shutdown could still hold the payload container for 120 seconds inside Kata even though the exact image stopped in one second under Docker.
- timestamp: 2026-07-31T14:43:00Z
  observation: after changing the disposable canary to exit directly from TERM/INT, live confidential pod deletion completed in one second.

# Eliminated

- hypothesis: CAP, DNS, storage, or Kubernetes finalizers block deletion.
  reason: the failure begins inside the web container stop call before provider or control-plane teardown.
- hypothesis: worker resource exhaustion causes the timeout.
  reason: worker load and memory were healthy during reproduction.
- hypothesis: missing signal forwarding alone caused the observed 30-second workload hang.
  reason: forwarding correctly delivered SIGTERM, but the payload then deadlocked inside Python's documented shutdown threading contract.

# Resolution

- root_cause: the test payload's Python `HTTPServer.shutdown()` path was not a reliable container termination primitive under Kata: same-thread shutdown deadlocked, and the threaded graceful variant still hung in one live run.
- fix: exit this disposable canary directly on TERM/INT; separately harden encrypted-log mode by forwarding HUP, INT, QUIT, and TERM from `enclava-wait-exec` to its child.
- verification: the final payload passes its process-level SIGTERM check and the live confidential pod was deleted in one second.
- files_changed: crates/enclava-wait-exec/Cargo.toml, crates/enclava-wait-exec/src/main.rs, crates/enclava-wait-exec/tests/signal_forwarding.rs
