# Contributing

Thanks for looking at CAP. This file covers how to get a change reviewed.

## Before you start

- For a security problem, follow [SECURITY.md](SECURITY.md) instead of opening
  an issue or pull request.
- For anything larger than a bug fix, open an issue first and describe the
  change. CAP's API, CLI, in-guest sidecar, and signed artifacts are bound
  together by hashes and rollout order, so a change that looks local often is
  not.

## Setup

[DEV.md](../DEV.md) lists the toolchain, native dependencies, and the local
Compose stack. The workspace needs Rust 1.88 or newer.

## Checks

Run these before opening a pull request. CI runs the same commands.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
cargo audit $(bash scripts/cargo-audit-args.sh)
cargo deny check advisories sources
```

Do not pass `--all-features` to the workspace: some feature combinations fail
on purpose. The test suite must stay serialized. If you cannot install
`libcryptsetup`, add `--exclude enclava-init`.

## What reviewers look for

- **A failing test first** when fixing a bug, and tests that exercise runtime
  behavior rather than source text or file layout.
- **Compatibility of signed bytes.** Changing how `cc_init_data`, descriptors,
  or policy artifacts are rendered invalidates artifacts that are already
  signed. Say so in the pull request, and describe how existing deployments
  move forward.
- **Rollout order.** If a change requires the sidecar, the API, and the CLI to
  be deployed in a particular order, document that order in
  [DEPLOYMENT.md](../DEPLOYMENT.md).
- **Migrations are append-only.** Never edit an applied migration file; sqlx
  checksums its bytes.
- **No installation-specific values.** Hostnames, domains, keys, and image
  digests for a particular environment do not belong in new code or defaults.

## Pull requests

Keep one logical change per pull request, and describe what you tested and how.

## License

Contributions are accepted under the repository's [MIT license](../LICENSE).
