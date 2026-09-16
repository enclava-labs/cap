#!/usr/bin/env bash
# Fail closed unless ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX is a 32-byte hex
# pubkey that is not the committed dev fixture. Publish and tagged-release
# jobs must use this gate; local compose / PR debug builds may still pass the
# fixture explicitly.
set -Eeuo pipefail

FIXTURE="5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd"
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
if [[ "$normalized" == "$FIXTURE" ]]; then
  echo "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must not be the committed dev fixture pubkey" >&2
  exit 1
fi
