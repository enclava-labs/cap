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

# Every `cargo audit ... --ignore RUSTSEC-xxxx-xxxx` line in ci.yml. If the
# audit step derives its ignores from cargo-audit-args.sh (deny.toml is the
# single source of truth), the lists cannot diverge and the check passes;
# otherwise any hardcoded list must match deny.toml exactly.
if grep -q 'cargo audit .*scripts/cargo-audit-args.sh' "$CI_YML"; then
    echo "check-audit-lockstep: ci.yml cargo audit ignores are generated from deny.toml"
    exit 0
fi

expected="$(bash "$SCRIPT_DIR/cargo-audit-args.sh" | sort)"
if [[ -z "$expected" ]]; then
    echo "check-audit-lockstep: no advisory ids parsed from deny.toml — refusing to pass vacuously" >&2
    exit 1
fi

actual="$(grep -o 'cargo audit .*--ignore RUSTSEC-[0-9]\{4\}-[0-9]\{4\}' "$CI_YML" \
    | grep -o -- '--ignore RUSTSEC-[0-9]\{4\}-[0-9]\{4\}' | sort)"

if [[ "$expected" != "$actual" ]]; then
    echo "check-audit-lockstep: cargo audit ignores in .github/workflows/ci.yml diverge from deny.toml [advisories]:" >&2
    diff -u <(echo "$expected") <(echo "$actual") >&2 || true
    echo "Fix: update the ci.yml cargo audit step to 'run: cargo audit \$(bash scripts/cargo-audit-args.sh)' or align both lists." >&2
    exit 1
fi

echo "check-audit-lockstep: ci.yml cargo audit ignores match deny.toml [advisories]"
