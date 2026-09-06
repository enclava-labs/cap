---
status: resolved
trigger: "Tagged CAP CLI release binaries may be built without ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX and then be unable to verify the bundled signed platform release."
created: 2026-07-28
updated: 2026-07-28T19:33:13Z
---

## Symptoms

- Expected behavior: every tagged `enclava` CLI release binary embeds the same
  pinned platform release root public key used by verified CI and image builds.
- Actual behavior: `.github/workflows/release.yml` may invoke the tagged CLI
  build without `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX`.
- Errors: a released CLI without the key fails closed when verifying its bundled
  signed platform release.
- Timeline: identified while reviewing CAP PR 63 and current `origin/main`.
- Reproduction: compare the CLI build environment in the tagged release workflow
  with CI/Docker release paths and the CLI compile-time key lookup.

## Current Focus

- hypothesis: confirmed — the tagged release build was the only CLI
  distribution path that omitted the compile-time root key.
- test: trace every release build invocation and existing workflow regression
  tests, then prove the tagged path either inherits or omits the key.
- expecting: a minimal workflow environment binding plus a focused static
  regression test, with no runtime or release-format changes.
- next_action: complete local checks and commit the two-file production/test
  change without pushing.
- reasoning_checkpoint: this is build-path validation only; no cluster mutation
  or documentation assumption is needed.
- tdd_checkpoint: pending

## Evidence

- timestamp: 2026-07-28T19:31:00Z
  observation: `option_env!` makes the root key compile-time-only outside tests;
  CI release builds and both CLI/API Dockerfiles set the exact bundled release
  signing key, while both Linux and macOS tag builds in `release.yml` did not.
- timestamp: 2026-07-28T19:31:30Z
  observation: the focused workflow contract test failed against unmodified
  `release.yml` because the workflow-level key was absent.
- timestamp: 2026-07-28T19:32:00Z
  observation: after adding the single workflow-level environment binding, all
  six platform-release tests pass and the contract test confirms the value
  equals the bundled envelope's `signing_pubkey`.
- timestamp: 2026-07-28T19:33:13Z
  observation: format, diff check, relaxed YAML syntax, warnings-denied CLI
  Clippy, and an exact release CLI build pass; `strings` confirms the release
  binary embeds the pinned root.
- timestamp: 2026-07-28T19:34:00Z
  observation: the full locked `enclava-cli` package suite passes all 247 unit
  and integration tests plus doctests.

## Eliminated

- hypothesis: CI or Docker release builds share the omission.
  evidence: `.github/workflows/ci.yml`, `crates/enclava-cli/Dockerfile`, and
  `crates/enclava-api/Dockerfile` already supply the exact compile-time key.
- hypothesis: runtime environment can repair an affected binary.
  evidence: the non-test verifier uses `option_env!`, so the value is compiled
  into the binary and cannot be supplied after release.

## Resolution

- root_cause: the original tag-only release workflow predated the compile-time
  platform release verifier and its four CLI builds never inherited the key.
- fix: bind the bundled release root once at workflow scope, inherited by every
  Linux and macOS matrix build.
- verification: focused red/green contract test, all 247 CLI tests, fmt, diff
  check, YAML syntax, CLI Clippy, and exact release CLI build.
- files_changed: `.github/workflows/release.yml` and
  `crates/enclava-cli/src/platform_release.rs`.
