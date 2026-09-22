#!/usr/bin/env bash
# verify-vendored-rdrand.sh — supply-chain check for vendor/rdrand-0.8.3.
#
# The vendored rdrand is a documented, minimal non-x86 compile fix on top of
# the pristine crates.io tarball (issue #140: "vendored rdrand not diffed").
# This script fails closed unless the working tree delta is EXACTLY the
# reviewed delta recorded in scripts/rdrand-0.8.3-nonx86.patch.
#
# It never trusts the network for the comparison: the tarball is pinned by
# sha256 and can also be supplied offline via RDRAND_TARBALL.
set -Eeuo pipefail

TARBALL_SHA256="d92195228612ac8eed47adbc2ed0f04e513a4ccb98175b6f2bd04d963b533655"
TARBALL_URL="https://static.crates.io/crates/rdrand/rdrand-0.8.3.crate"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$REPO_ROOT/vendor/rdrand-0.8.3"
REVIEWED_PATCH="$SCRIPT_DIR/rdrand-0.8.3-nonx86.patch"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tarball="${RDRAND_TARBALL:-$work/rdrand-0.8.3.crate}"
if [[ ! -f "$tarball" ]]; then
    curl -fsSL "$TARBALL_URL" -o "$tarball"
fi

actual_sha="$(sha256sum "$tarball" | awk '{print $1}')"
if [[ "$actual_sha" != "$TARBALL_SHA256" ]]; then
    echo "verify-vendored-rdrand: tarball sha256 mismatch" >&2
    echo "  expected $TARBALL_SHA256" >&2
    echo "  actual   $actual_sha" >&2
    exit 1
fi

tar -xzf "$tarball" -C "$work"

if [[ ! -d "$VENDOR_DIR" ]]; then
    echo "verify-vendored-rdrand: $VENDOR_DIR missing" >&2
    exit 1
fi

# No file may exist in the vendor dir that is absent from the pristine
# tarball (e.g. a smuggled build.rs) — the vendored tree must be exactly
# the tarball contents plus the reviewed patch.
while IFS= read -r -d '' f; do
    rel="${f#"$VENDOR_DIR"/}"
    if [[ ! -e "$work/rdrand-0.8.3/$rel" ]]; then
        echo "verify-vendored-rdrand: extra file not in pristine tarball: $rel" >&2
        exit 1
    fi
done < <(find "$VENDOR_DIR" -type f -print0)

# The reviewed delta covers only Cargo.toml and src/lib.rs; every other
# vendored file must be byte-identical to the tarball.
for f in src/errors.rs src/changelog.rs LICENSE; do
    if ! diff -q "$work/rdrand-0.8.3/$f" "$VENDOR_DIR/$f" >/dev/null; then
        echo "verify-vendored-rdrand: unexpected delta in $f (must be pristine)" >&2
        diff -u "$work/rdrand-0.8.3/$f" "$VENDOR_DIR/$f" || true
        exit 1
    fi
done

{
    diff -u --label a/Cargo.toml --label b/Cargo.toml \
        "$work/rdrand-0.8.3/Cargo.toml" "$VENDOR_DIR/Cargo.toml" || true
    diff -u --label a/src/lib.rs --label b/src/lib.rs \
        "$work/rdrand-0.8.3/src/lib.rs" "$VENDOR_DIR/src/lib.rs" || true
} > "$work/live.patch"

if ! diff -u "$REVIEWED_PATCH" "$work/live.patch" > "$work/review-delta.diff"; then
    echo "verify-vendored-rdrand: vendored rdrand delta no longer matches the reviewed patch" >&2
    cat "$work/review-delta.diff" >&2
    exit 1
fi

echo "verify-vendored-rdrand: vendored rdrand-0.8.3 matches the reviewed non-x86 patch"
