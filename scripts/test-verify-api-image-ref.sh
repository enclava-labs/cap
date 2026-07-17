#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_SCRIPT="$SCRIPT_DIR/verify-api-image-ref.sh"
IMAGE_REPOSITORY="ghcr.io/enclava-labs/enclava-api"
DIGEST="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
VALID_REF="$IMAGE_REPOSITORY@sha256:$DIGEST"
EXPECTED_OUTPUT="CAP_API_IMAGE=$VALID_REF"

work_dir="$(mktemp -d -t cap-api-image-ref-test.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

assert_output() {
  local expected="$1"
  shift
  local output
  output="$("$@")"
  [[ "$output" == "$expected" ]] || {
    echo "expected: $expected" >&2
    echo "actual:   $output" >&2
    exit 1
  }
}

expect_fail() {
  local name="$1"
  shift
  if "$@" >"$work_dir/$name.out" 2>"$work_dir/$name.err"; then
    echo "expected $name to fail" >&2
    exit 1
  fi
}

artifact="$work_dir/enclava-api-image.txt"
printf '%s\n' "$VALID_REF" >"$artifact"
printf '%s\n' \
  "https://github.com/enclava-labs/cap/.github/workflows/api-image.yml@refs/heads/main" \
  >"$work_dir/enclava-api-signer-identity.txt"
assert_output "$EXPECTED_OUTPUT" "$VERIFY_SCRIPT" "$artifact"
assert_output "$EXPECTED_OUTPUT" "$VERIFY_SCRIPT" "$VALID_REF"
assert_output "$EXPECTED_OUTPUT" "$VERIFY_SCRIPT" "$EXPECTED_OUTPUT"

expect_fail tag "$VERIFY_SCRIPT" "$IMAGE_REPOSITORY:main"
expect_fail wrong_repo "$VERIFY_SCRIPT" "ghcr.io/other/enclava-api@sha256:$DIGEST"
expect_fail uppercase "$VERIFY_SCRIPT" "$IMAGE_REPOSITORY@sha256:${DIGEST^^}"
expect_fail placeholder "$VERIFY_SCRIPT" "$IMAGE_REPOSITORY@sha256:$(printf '0%.0s' {1..64})"

printf '%s\n%s\n' "$VALID_REF" "$VALID_REF" >"$work_dir/multiline"
expect_fail multiline "$VERIFY_SCRIPT" "$work_dir/multiline"
grep -q "exactly one line" "$work_dir/multiline.err"

printf ' %s\n' "$VALID_REF" >"$work_dir/space"
expect_fail whitespace "$VERIFY_SCRIPT" "$work_dir/space"
grep -q "must not contain whitespace" "$work_dir/whitespace.err"

stub_dir="$work_dir/bin"
mkdir -p "$stub_dir"
cat >"$stub_dir/cosign" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >"$COSIGN_ARGS_FILE"
if [[ -n "${COSIGN_ENV_FILE:-}" ]]; then
  {
    printf 'BASH_ENV=%s\n' "${BASH_ENV:-}"
    printf 'ENV=%s\n' "${ENV:-}"
    printf 'CDPATH=%s\n' "${CDPATH:-}"
    printf 'GLOBIGNORE=%s\n' "${GLOBIGNORE:-}"
    printf 'PYTHONPATH=%s\n' "${PYTHONPATH:-}"
    printf 'NODE_OPTIONS=%s\n' "${NODE_OPTIONS:-}"
  } >"$COSIGN_ENV_FILE"
fi
STUB
chmod 0755 "$stub_dir/cosign"

COSIGN_ARGS_FILE="$work_dir/cosign.args" \
  PATH="$stub_dir:$PATH" \
  assert_output "$EXPECTED_OUTPUT" "$VERIFY_SCRIPT" --cosign "$VALID_REF"
grep -Fq -- "--certificate-identity https://github.com/enclava-labs/cap/.github/workflows/api-image.yml@refs/heads/main" "$work_dir/cosign.args"
grep -Fq -- "--certificate-oidc-issuer https://token.actions.githubusercontent.com" "$work_dir/cosign.args"
grep -Fq -- "$VALID_REF" "$work_dir/cosign.args"

ambient_bash_env="$work_dir/ambient.sh"
startup_marker="$work_dir/bash-env-was-sourced"
printf 'printf sourced >%q\n' "$startup_marker" >"$ambient_bash_env"
COSIGN_ARGS_FILE="$work_dir/cosign-scrub.args" \
  COSIGN_ENV_FILE="$work_dir/cosign.env" \
  BASH_ENV="$ambient_bash_env" \
  ENV="/tmp/ambient-env" \
  CDPATH="/tmp" \
  GLOBIGNORE="*" \
  PYTHONPATH="/tmp/pythonpath" \
  NODE_OPTIONS="--no-warnings" \
  PATH="$stub_dir:$PATH" \
  assert_output "$EXPECTED_OUTPUT" "$VERIFY_SCRIPT" --cosign "$VALID_REF"
[[ ! -e "$startup_marker" ]] || {
  echo "BASH_ENV executed before the verifier could scrub it" >&2
  exit 1
}
for expected in "BASH_ENV=" "ENV=" "CDPATH=" "GLOBIGNORE=" "PYTHONPATH=" "NODE_OPTIONS="; do
  grep -Fxq "$expected" "$work_dir/cosign.env" || {
    cat "$work_dir/cosign.env" >&2
    echo "expected scrubbed process-control environment: $expected" >&2
    exit 1
  }
done

tag_identity="https://github.com/enclava-labs/cap/.github/workflows/api-image.yml@refs/tags/v1.2.3"
printf '%s\n' "$tag_identity" >"$work_dir/enclava-api-signer-identity.txt"
COSIGN_ARGS_FILE="$work_dir/tag.args" \
  PATH="$stub_dir:$PATH" \
  assert_output "$EXPECTED_OUTPUT" "$VERIFY_SCRIPT" --cosign "$artifact"
grep -Fq -- "--certificate-identity $tag_identity" "$work_dir/tag.args"
COSIGN_ARGS_FILE="$work_dir/tag-raw.args" \
  PATH="$stub_dir:$PATH" \
  assert_output "$EXPECTED_OUTPUT" "$VERIFY_SCRIPT" --cosign \
    --certificate-identity "$tag_identity" "$VALID_REF"
grep -Fq -- "--certificate-identity $tag_identity" "$work_dir/tag-raw.args"

expect_fail invalid_identity "$VERIFY_SCRIPT" --certificate-identity \
  "https://github.com/other/cap/.github/workflows/api-image.yml@refs/tags/v1.2.3" "$VALID_REF"
grep -q "official CAP API workflow" "$work_dir/invalid_identity.err"

custom_cosign="$work_dir/custom-cosign"
cp "$stub_dir/cosign" "$custom_cosign"
COSIGN_ARGS_FILE="$work_dir/custom.args" \
  COSIGN_BIN="$custom_cosign" \
  assert_output "$EXPECTED_OUTPUT" "$VERIFY_SCRIPT" --cosign "$VALID_REF"

expect_fail missing_cosign env COSIGN_BIN="$work_dir/missing" "$VERIFY_SCRIPT" --cosign "$VALID_REF"
grep -q "missing required command" "$work_dir/missing_cosign.err"
expect_fail relative_cosign env COSIGN_BIN="./cosign" "$VERIFY_SCRIPT" --cosign "$VALID_REF"
grep -q "must be absolute" "$work_dir/relative_cosign.err"

echo "CAP API image reference verification tests passed"
