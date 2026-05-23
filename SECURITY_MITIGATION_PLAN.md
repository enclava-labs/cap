# Security Mitigation Plan

This file is the current CAP mitigation checklist. It tracks the supported
production baseline and the checks that must remain true as code changes.

## Supported Baseline

CAP is considered on the supported security path only when all of these are
true:

- API release build starts with production env gates passing.
- Signed platform release verifies against the pinned root key.
- Platform sidecar images are digest-pinned and cosign-verified at API startup.
- Workload image deploys use digest-pinned references and per-app signer
  identity verification.
- Deploy requests include customer descriptor, org keyring, and signed policy
  artifact blobs whenever policy signing or Trustee policy-read mode is enabled.
- `enclava-init` receives workload artifacts and Trustee policy through the
  configured artifact path and verifies the descriptor/keyring/policy chain.
- Tenant app data and TLS state remain separate encrypted volumes.
- User-facing deploy does not require platform-owned env exports.

## Mandatory Gates

| Gate | Enforcement point |
| --- | --- |
| Debug bypass flags rejected in release builds | `crates/enclava-api/src/env_gates.rs` and `crates/enclava-cli/src/main.rs` |
| API-key pepper required in release builds | `crates/enclava-api/src/env_gates.rs` |
| Policy-read mode required in release builds | `crates/enclava-api/src/env_gates.rs` |
| Plain HTTP KBS URL rejected in release builds | `crates/enclava-api/src/env_gates.rs` and `platform_release.rs` |
| Signed platform release validated | `crates/enclava-api/src/platform_release.rs`, `crates/enclava-cli/src/platform_release.rs` |
| Platform sidecar image verification at startup | `crates/enclava-api/src/cosign.rs` |
| App write authorization | `crates/enclava-api/src/auth/scopes.rs` plus route-level calls |
| Signer rotation token verification | `crates/enclava-api/src/routes/apps.rs` |
| Descriptor/keyring/policy artifact validation | `crates/enclava-api/src/routes/deployments.rs`, `signing_service.rs` |
| Runtime verification before seed release | `crates/enclava-init/src/trustee_verify.rs` |

## Regression Checklist

Run this checklist for changes touching deploy, policy, image verification,
runtime manifests, or unlock/config paths:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p enclava-api --lib
cargo test -p enclava-cli
cargo test -p enclava-engine
```

If `enclava-init` dependencies are installed:

```bash
cargo test -p enclava-init --lib
```

Before live testing:

```bash
scripts/nutshell-fast-contract.sh
```

## Operational Checks

| Check | Tooling |
| --- | --- |
| Deployed CAP app proof without cluster access | `scripts/cap_hermes_proof.py` |
| Certificate Transparency monitoring | `runbooks/ct-monitoring.sh` |
| Trustee policy audit | `runbooks/trustee-policy-audit.sh` |

## Current Documentation Policy

Keep this repository focused on current implementation truth. Dated reviews,
phase plans, launch reports, scratch worktrees, and one-off audit evidence do
not belong in the maintained doc set unless they are converted into current
runbooks or tests.
