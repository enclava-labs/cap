#!/usr/bin/env bash
# cargo-audit-args.sh — print the `--ignore` argument list for cargo audit
# derived from deny.toml [advisories].
#
# deny.toml is the single source of truth for which advisories CAP accepts:
# cargo audit in CI and locally must invoke exactly these ignores so the
# two dependency gates can never diverge (issue #140 follow-up).
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DENY_TOML="$SCRIPT_DIR/../deny.toml"

if [[ ! -f "$DENY_TOML" ]]; then
    echo "cargo-audit-args: $DENY_TOML missing" >&2
    exit 1
fi

grep -o 'id = "RUSTSEC-[0-9]\{4\}-[0-9]\{4\}"' "$DENY_TOML" \
    | sed -E 's/id = "(RUSTSEC-[0-9]{4}-[0-9]{4})"/--ignore \1/' || true
