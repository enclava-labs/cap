#!/usr/bin/env bash
# check-audit-lockstep.sh — fail unless the cargo audit invocation hardcoded
# in .github/workflows/ci.yml ignores EXACTLY the advisory ids recorded in
# deny.toml [advisories].
#
# Future edits that change one list but not the other now break CI instead
# of silently letting the two dependency gates diverge (Devin review on
# PR #166: "advisory lockstep remains manual" / "required audit policy is
# inconsistent").
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CI_YML="$REPO_ROOT/.github/workflows/ci.yml"

if [[ ! -f "$CI_YML" ]]; then
    echo "check-audit-lockstep: $CI_YML missing" >&2
    exit 1
fi

# Every `cargo audit ... --ignore RUSTSEC-xxxx-xxxx` occurrence in ci.yml.
# If the audit step derives its ignores from cargo-audit-args.sh (deny.toml
# is the single source of truth), the generated step cannot diverge — but a
# stray hardcoded --ignore ANYWHERE in ci.yml (e.g. appended to the
# generated line, or hiding in another job) is still collected and rejected
# below, so the generator fast-path cannot be used to smuggle extra ignores.
generated_step="$(grep -nE '^ *run: cargo audit \$\(bash scripts/cargo-audit-args\.sh\)$' "$CI_YML" || true)"

# Hardcoded ignores are collected from the WHOLE file regardless of the
# generator step, so appending e.g. `--ignore RUSTSEC-XXXX-YYYY` to the
# generated line still fails this check.

expected="$(bash "$SCRIPT_DIR/cargo-audit-args.sh" | sort)"
if [[ -z "$expected" ]]; then
    echo "check-audit-lockstep: no advisory ids parsed from deny.toml — refusing to pass vacuously" >&2
    exit 1
fi

actual="$(grep -o -- '--ignore RUSTSEC-[0-9]\{4\}-[0-9]\{4\}' "$CI_YML" | sort || true)"

if [[ -n "$actual" ]]; then
    echo "check-audit-lockstep: hardcoded --ignore flags in .github/workflows/ci.yml diverge from the deny.toml-generated policy:" >&2
    diff -u <(echo "$expected") <(echo "$actual") >&2 || true
    echo "Fix: remove the hardcoded --ignore flags (the audit step derives them from deny.toml via scripts/cargo-audit-args.sh)." >&2
    exit 1
fi

if [[ -z "$generated_step" ]]; then
    echo "check-audit-lockstep: ci.yml has no 'run: cargo audit \$(bash scripts/cargo-audit-args.sh)' step" >&2
    echo "Fix: update the ci.yml cargo audit step to 'run: cargo audit \$(bash scripts/cargo-audit-args.sh)'." >&2
    exit 1
fi

echo "check-audit-lockstep: ci.yml cargo audit ignores are generated from deny.toml (no hardcoded divergences)"
