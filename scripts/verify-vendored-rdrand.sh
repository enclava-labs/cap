#!/usr/bin/env bash
# verify-vendored-rdrand.sh — supply-chain check for vendor/rdrand-0.8.3.
#
# The vendored rdrand is a documented, minimal non-x86 compile fix on top of
# the pristine crates.io tarball (issue #140: "vendored rdrand not diffed").
# This script fails closed unless the working tree delta is EXACTLY the
# reviewed delta recorded in scripts/rdrand-0.8.3-nonx86.patch.
#
# It never trusts the network for the comparison: the tarball is pinned by
# sha256, is committed to the repo as scripts/rdrand-0.8.3.pristine.crate
# (verified against the pinned sha256 below, so the network is never a
# build dependency), and can additionally be overridden via RDRAND_TARBALL.
set -Eeuo pipefail

TARBALL_SHA256="d92195228612ac8eed47adbc2ed0f04e513a4ccb98175b6f2bd04d963b533655"
TARBALL_URL="https://static.crates.io/crates/rdrand/rdrand-0.8.3.crate"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$REPO_ROOT/vendor/rdrand-0.8.3"
REVIEWED_PATCH="$SCRIPT_DIR/rdrand-0.8.3-nonx86.patch"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Preference order: explicit RDRAND_TARBALL override, then the committed
# pristine copy (offline default), then the network as a last resort.
if [[ -n "${RDRAND_TARBALL:-}" && -f "$RDRAND_TARBALL" ]]; then
    tarball="$RDRAND_TARBALL"
elif [[ -f "$SCRIPT_DIR/rdrand-0.8.3.pristine.crate" ]]; then
    tarball="$SCRIPT_DIR/rdrand-0.8.3.pristine.crate"
else
    tarball="$work/rdrand-0.8.3.crate"
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
# the tarball contents plus the reviewed patch. Symlinks and every other
# non-regular entry are rejected outright: a tracked symlink such as
# build.rs -> ../../elsewhere/build.rs is invisible to a regular-files-only
# scan, yet cargo follows it and executes the target as a build script.
while IFS= read -r -d '' f; do
    rel="${f#"$VENDOR_DIR"/}"
    if [[ -L "$f" || ! -f "$f" ]]; then
        echo "verify-vendored-rdrand: non-regular entry (symlink?) not allowed: $rel" >&2
        exit 1
    fi
    if [[ ! -e "$work/rdrand-0.8.3/$rel" ]]; then
        echo "verify-vendored-rdrand: extra file not in pristine tarball: $rel" >&2
        exit 1
    fi
done < <(find "$VENDOR_DIR" -mindepth 1 ! -type d -print0)

# Every vendored file except the two the reviewed patch touches
# (Cargo.toml, src/lib.rs) must be byte-identical to the pristine tarball;
# previously only src/errors.rs, src/changelog.rs and LICENSE were covered,
# leaving every other pristine file unverified.
while IFS= read -r -d '' f; do
    rel="${f#"$VENDOR_DIR"/}"
    if [[ "$rel" == "Cargo.toml" || "$rel" == "src/lib.rs" ]]; then
        continue
    fi
    if ! diff -q "$work/rdrand-0.8.3/$rel" "$f" >/dev/null; then
        echo "verify-vendored-rdrand: unexpected delta in $rel (must be pristine)" >&2
        diff -u "$work/rdrand-0.8.3/$rel" "$f" || true
        exit 1
    fi
done < <(find "$VENDOR_DIR" -type f -print0)

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
