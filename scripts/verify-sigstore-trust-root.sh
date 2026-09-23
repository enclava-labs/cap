#!/usr/bin/env bash
# verify-sigstore-trust-root.sh — pin the bundled sigstore trust root.
#
# crates/enclava-api/trust-roots/sigstore-public-good-1.root.json is the
# trusted_root.json TUF target of the sigstore public-good instance. It was
# extracted from a fully verified TUF checkout (sigstore crate
# SigstoreTrustRoot::new, which chains from the crate's embedded root.json
# and enforces expiration), NOT from an unauthenticated HTTPS fetch. The
# release API image bakes this file in and points SIGSTORE_TUF_ROOT_PATH at
# it, so release cosign verification never bootstraps trust from the
# network (see crates/enclava-api/src/cosign.rs).
#
# This script fails closed unless the bundled file still hashes to the
# pinned value below. Provenance of updates: re-export from a verified TUF
# checkout (see README note in this directory), then update BOTH the file
# and this pin in the same reviewed commit.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_JSON="$REPO_ROOT/crates/enclava-api/trust-roots/sigstore-public-good-1.root.json"

PINNED_SHA256="6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"

if [[ ! -f "$ROOT_JSON" ]]; then
    echo "verify-sigstore-trust-root: missing $ROOT_JSON" >&2
    exit 1
fi

actual="$(sha256sum "$ROOT_JSON" | awk '{print $1}')"
if [[ "$actual" != "$PINNED_SHA256" ]]; then
    echo "verify-sigstore-trust-root: trust root sha256 mismatch" >&2
    echo "  expected $PINNED_SHA256" >&2
    echo "  actual   $actual" >&2
    exit 1
fi

# Structural sanity: it must be the sigstore trusted-root document (not an
# arbitrary JSON blob of the same hash length).
python3 - "$ROOT_JSON" <<'PY'
import json, sys

with open(sys.argv[1], "rb") as fh:
    doc = json.load(fh)

required = {"mediaType", "certificateAuthorities", "ctlogs", "tlogs"}
missing = required - doc.keys()
if missing:
    sys.exit(f"verify-sigstore-trust-root: missing keys: {sorted(missing)}")
if not doc["certificateAuthorities"] or not doc["tlogs"]:
    sys.exit("verify-sigstore-trust-root: empty certificateAuthorities/tlogs")
PY

echo "verify-sigstore-trust-root: bundled sigstore trust root matches pinned sha256 $PINNED_SHA256"
