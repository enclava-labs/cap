#!/usr/bin/env bash
# Fail closed unless ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX is a 32-byte hex
# pubkey that is not the committed dev fixture and that matches the
# signing_pubkey of the platform-release envelope the build will bundle. A
# released binary embeds the root at compile time and falls back to the
# bundled envelope, so the two must rotate together or every published
# artifact fails verification at startup (RootMismatch).
#
# Satisfying the gate in production: generate a root keypair outside the
# repo, sign the payload with (root seed redirected from a protected file,
# never argv: `-- sign payload.json < root-seed.hex`), and set
# BOTH secrets together:
#   ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX  (root pubkey hex)
#   ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON    (signed envelope contents)
# Publishing workflows materialize the envelope secret over
# crates/enclava-cli/platform-release.json before gating or building, so
# this script and the in-Docker gates always read the envelope that will
# ship. Envelope path here: ENCLAVA_PLATFORM_RELEASE_ENVELOPE, default
# crates/enclava-cli/platform-release.json relative to the cwd.
# Local compose / PR debug builds may pass --allow-dev-fixture: the fixture
# root is then accepted only while the bundled envelope is fixture-signed.
set -Eeuo pipefail

FIXTURE="5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd"
ALLOW_DEV_FIXTURE=""
if [[ "${1:-}" == "--allow-dev-fixture" ]]; then
  ALLOW_DEV_FIXTURE=1
fi

root="${ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX:-}"
normalized="${root,,}"

if [[ -z "$root" ]]; then
  echo "secrets.ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be set" >&2
  exit 1
fi
if [[ ! "$normalized" =~ ^[0-9a-f]{64}$ ]]; then
  echo "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must match ^[0-9a-f]{64}$" >&2
  exit 1
fi
if [[ "$normalized" == "$FIXTURE" && -z "$ALLOW_DEV_FIXTURE" ]]; then
  echo "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must not be the committed dev fixture pubkey" >&2
  exit 1
fi

envelope="${ENCLAVA_PLATFORM_RELEASE_ENVELOPE:-crates/enclava-cli/platform-release.json}"
if [[ ! -f "$envelope" ]]; then
  echo "bundled platform-release envelope not found: $envelope" >&2
  exit 1
fi
envelope_key="$(jq -r '.signing_pubkey // empty' "$envelope")"
envelope_key_normalized="${envelope_key,,}"
if [[ ! "$envelope_key_normalized" =~ ^[0-9a-f]{64}$ ]]; then
  echo "bundled platform-release envelope $envelope must carry a 32-byte hex signing_pubkey" >&2
  exit 1
fi
if [[ "$normalized" != "$envelope_key_normalized" ]]; then
  echo "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must match the bundled envelope's signing_pubkey ($envelope); set ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX and ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON together (see scripts/require-platform-release-root.sh)" >&2
  exit 1
fi
