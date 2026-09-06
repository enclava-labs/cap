---
status: awaiting_human_verify
trigger: "Implement the smallest permanent CAP CLI fix for confirmed incident: `template deploy` must verify the signed platform deployment-context/release root before `ensure_template_app` performs app_create, so a CLI built without ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX fails before remote side effects."
created: 2026-07-29T13:45:49Z
updated: 2026-07-29T13:50:26Z
---

## Current Focus

hypothesis: confirmed
test: red-green source-order regression, adjacent trust tests, full CLI binary unit suite, formatting, and clippy
expecting: all local checks pass with platform trust verification ordered before template bootstrap and app creation
next_action: parent reviews the minimal diff and decides whether to commit/push/open a PR
reasoning_checkpoint:
  hypothesis: the delayed call to platform_release_from_deployment_context is the cause of post-mutation trust failure
  confirming_evidence: deploy calls template_bootstrap_pubkey_hash and ensure_template_app before build_signed_deploy_blobs; build_signed_deploy_blobs is where deployment_context and the release root are first verified
  falsification_test: require the deploy source to call the shared verified-context fetch before both mutating helpers
  fix_rationale: reuse one shared fetch-and-verify helper in both the preflight and descriptor builder, avoiding a broader signing API refactor
  blind_spots: the preflight is a second read before the builder read, but a binary missing the compiled root fails deterministically on the first read and no remote mutation can occur
tdd_checkpoint: null

## Symptoms

expected: signed platform deployment context and the compiled release root are verified before any remote app mutation
actual: app_create can occur before a missing or invalid compiled platform release root causes template deploy to fail
errors: platform release root pubkey is not configured at compile time
reproduction: run template deploy with a CLI built without ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX against a signed deployment context when no app exists
started: confirmed in the current incident on CAP merge 818de493

## Eliminated

## Evidence

- timestamp: 2026-07-29T13:45:49Z
  checked: exact base revision
  found: origin/main and isolated worktree both resolve to merge 818de493a8919da6e369d2a557e29d2c32a6b5c5
  implication: the fix is based on the deployed CAP lineage rather than a stale local branch
- timestamp: 2026-07-29T13:47:31Z
  checked: template deploy call order and signing implementation
  found: template_bootstrap_pubkey_hash and ensure_template_app run before build_signed_deploy_blobs fetches and verifies deployment_context
  implication: keyring registration/upload and app_create can precede release-root failure
- timestamp: 2026-07-29T13:50:26Z
  checked: focused regression before and after the fix
  found: the new source-order test failed on the base and passed after fetch_verified_platform_release was called before both mutating helpers
  implication: the ordering regression is reproducibly guarded
- timestamp: 2026-07-29T13:50:26Z
  checked: local Rust validation
  found: fmt, clippy with warnings denied, 126 CLI binary tests, and two adjacent deployment-context trust tests passed
  implication: the minimal change compiles cleanly and preserves existing CLI behavior

## Resolution

root_cause: platform trust verification is nested in descriptor signing, after template bootstrap and app creation
fix: centralize deployment-context fetch and release-root verification, preflight it before template bootstrap/app creation, and reuse it in descriptor signing
verification: focused red-green regression passed; deployment-context trust tests 2/2 passed; CLI binary unit tests 126/126 passed; stable fmt and clippy passed
files_changed:
  - crates/enclava-cli/src/commands/app.rs
  - crates/enclava-cli/src/commands/app/signing.rs
  - crates/enclava-cli/src/commands/template.rs
