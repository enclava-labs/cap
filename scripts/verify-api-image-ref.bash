#!/usr/bin/env bash
set -Eeuo pipefail

unset \
  BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH \
  DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH PYTHONHOME PYTHONPATH \
  RUBYOPT NODE_OPTIONS PERL5LIB

IMAGE_REPOSITORY="ghcr.io/enclava-labs/enclava-api"
IMAGE_REF_PATTERN='^ghcr[.]io/enclava-labs/enclava-api@sha256:[0-9a-f]{64}$'
DEFAULT_SIGNER_SUBJECT="https://github.com/enclava-labs/cap/.github/workflows/api-image.yml@refs/heads/main"
SIGNER_SUBJECT_PATTERN='^https://github[.]com/enclava-labs/cap/[.]github/workflows/api-image[.]yml@refs/(heads/main|tags/v[A-Za-z0-9][A-Za-z0-9._-]*)$'
SIGNER_ISSUER="https://token.actions.githubusercontent.com"
COSIGN_BIN="${COSIGN_BIN:-cosign}"

usage() {
  cat <<'USAGE'
Usage: scripts/verify-api-image-ref.sh [--cosign] [--certificate-identity ID] <image-ref-or-artifact-file>

Validates the official CAP API image reference. The input may be the raw image
reference, a CAP_API_IMAGE= config line, or the downloaded
dist/enclava-api-image.txt artifact.

When an artifact file is used, a sibling enclava-api-signer-identity.txt file
is consumed automatically. Raw references default to the main-branch workflow
identity; tagged raw references must pass their exact official identity with
--certificate-identity.

Options:
  --cosign                  Verify the keyless signature against the selected
                            official GitHub Actions workflow identity.
  --certificate-identity ID Use an exact official main or v* tag workflow
                            certificate identity.
USAGE
}

resolve_executable() {
  local name="$1"
  local command_name="$2"
  local resolved

  if [[ "$command_name" == */* ]]; then
    if [[ "$command_name" != /* ]]; then
      echo "error: COSIGN_BIN must be absolute or a command name without slashes: $command_name" >&2
      return 2
    fi
    if [[ -x "$command_name" && ! -d "$command_name" ]]; then
      printf '%s\n' "$command_name"
      return 0
    fi
  elif resolved="$(command -v "$command_name" 2>/dev/null)"; then
    if [[ "$resolved" == /* && -x "$resolved" && ! -d "$resolved" ]]; then
      printf '%s\n' "$resolved"
      return 0
    fi
    echo "error: $name must resolve to an absolute executable: $command_name -> $resolved" >&2
    return 2
  fi
  echo "error: missing required command: $name ($command_name)" >&2
  return 2
}

read_single_line() {
  local path="$1"
  local description="$2"
  local lines=()

  mapfile -t lines <"$path"
  if (( ${#lines[@]} != 1 )); then
    echo "error: $description must contain exactly one line: $path" >&2
    return 1
  fi
  printf '%s\n' "${lines[0]}"
}

read_image_ref() {
  local input="$1"

  if [[ -f "$input" ]]; then
    read_single_line "$input" "image artifact"
  else
    printf '%s\n' "$input"
  fi
}

artifact_signer_subject() {
  local input="$1"
  local artifact_dir identity_file

  [[ -f "$input" ]] || return 1
  if [[ "$input" == */* ]]; then
    artifact_dir="${input%/*}"
  else
    artifact_dir="."
  fi
  identity_file="$artifact_dir/enclava-api-signer-identity.txt"
  [[ -f "$identity_file" ]] || return 1
  read_single_line "$identity_file" "signer identity artifact"
}

validate_signer_subject() {
  local signer_subject="$1"

  if [[ "$signer_subject" =~ [[:cntrl:]] || "$signer_subject" =~ [[:space:]] ]]; then
    echo "error: signer identity must not contain whitespace or control characters" >&2
    return 1
  fi
  if [[ ! "$signer_subject" =~ $SIGNER_SUBJECT_PATTERN ]]; then
    echo "error: signer identity must be the official CAP API workflow on main or a v* tag" >&2
    return 1
  fi
}

verify_signature() {
  local image_ref="$1"
  local signer_subject="$2"
  local cosign

  cosign="$(resolve_executable cosign "$COSIGN_BIN")" || exit 2
  "$cosign" verify \
    --certificate-identity "$signer_subject" \
    --certificate-oidc-issuer "$SIGNER_ISSUER" \
    "$image_ref" >/dev/null
}

run_cosign=0
input=""
signer_subject=""
while (( $# > 0 )); do
  case "$1" in
    --cosign)
      run_cosign=1
      shift
      ;;
    --certificate-identity)
      if (( $# < 2 )) || [[ -n "$signer_subject" ]]; then
        echo "error: --certificate-identity requires exactly one value" >&2
        exit 64
      fi
      signer_subject="$2"
      shift 2
      ;;
    -h | --help | help)
      usage
      exit 0
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 64
      ;;
    *)
      if [[ -n "$input" ]]; then
        echo "error: expected exactly one image reference or artifact" >&2
        exit 64
      fi
      input="$1"
      shift
      ;;
  esac
done

if [[ -z "$input" ]]; then
  echo "error: missing image reference or artifact" >&2
  usage >&2
  exit 64
fi

image_ref="$(read_image_ref "$input")"
if [[ "$image_ref" =~ [[:cntrl:]] ]]; then
  echo "error: image reference must not contain control characters" >&2
  exit 1
fi
if [[ "$image_ref" =~ [[:space:]] ]]; then
  echo "error: image reference must not contain whitespace" >&2
  exit 1
fi
image_ref="${image_ref#CAP_API_IMAGE=}"

if [[ ! "$image_ref" =~ $IMAGE_REF_PATTERN ]]; then
  echo "error: CAP API image must be $IMAGE_REPOSITORY@sha256:<64 lowercase hex chars>" >&2
  echo "error: got: ${image_ref:-empty}" >&2
  exit 1
fi
digest="${image_ref##*@sha256:}"
if [[ "$digest" =~ ^0+$ || "$digest" =~ ^a+$ ]]; then
  echo "error: CAP API image digest looks like a placeholder" >&2
  exit 1
fi

if [[ -z "$signer_subject" ]]; then
  signer_subject="$(artifact_signer_subject "$input" || printf '%s\n' "$DEFAULT_SIGNER_SUBJECT")"
fi
validate_signer_subject "$signer_subject"

if (( run_cosign )); then
  verify_signature "$image_ref" "$signer_subject"
fi

printf 'CAP_API_IMAGE=%s\n' "$image_ref"
