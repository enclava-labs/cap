#!/usr/bin/env bash
set -Eeuo pipefail

script_path="${BASH_SOURCE[0]}"
case "${script_path}" in
  /*) ;;
  *) script_path="${PWD}/${script_path}" ;;
esac
script_dir="${script_path%/*}"
root_dir="${script_dir%/*}"
workflow="${root_dir}/.github/workflows/ci.yml"
stable_ssh_cli_suite="${root_dir}/scripts/test-stable-ssh-cli.sh"
postgres_image="postgres:16-alpine@sha256:e013e867e712fec275706a6c51c966f0bb0c93cfa8f51000f85a15f9865a28cb"

fail() {
  echo "error: $*" >&2
  exit 1
}

assert_contains() {
  local needle="$1"
  grep -Fq -- "${needle}" "${workflow}" || fail "CI workflow is missing: ${needle}"
}

assert_file_contains() {
  local file="$1"
  local needle="$2"
  local label="$3"
  grep -Fq -- "${needle}" "${file}" || fail "${label} is missing: ${needle}"
}

assert_not_contains() {
  local needle="$1"
  if grep -Fq -- "${needle}" "${workflow}"; then
    fail "CI workflow must not contain: ${needle}"
  fi
}

assert_order() {
  local first="$1"
  local second="$2"
  local first_line second_line

  first_line="$(grep -nF -- "${first}" "${workflow}" | head -n1 | cut -d: -f1 || true)"
  second_line="$(grep -nF -- "${second}" "${workflow}" | head -n1 | cut -d: -f1 || true)"
  [[ -n "${first_line}" && -n "${second_line}" ]] \
    || fail "CI workflow must contain both ordered lines: ${first} before ${second}"
  (( first_line < second_line )) \
    || fail "CI workflow must keep ${first} before ${second}"
}

assert_contains "Run stable SSH CLI contract"
assert_contains "Run CI workflow checks"
assert_contains "run: scripts/test-ci-workflow.sh"
assert_contains "run: scripts/test-stable-ssh-cli.sh"
assert_contains "image: ${postgres_image}"
floating_postgres="$(
  grep -nE '^[[:space:]]+image: postgres:16-alpine$' "${workflow}" || true
)"
if [[ -n "${floating_postgres}" ]]; then
  echo "${floating_postgres}" >&2
  fail "CI Postgres service image must be digest-pinned"
fi
unpinned_uses="$(
  grep -nE '^[[:space:]]+- uses: |^[[:space:]]+uses: ' "${workflow}" \
    | grep -Ev '@[0-9a-f]{40}([[:space:]]+#|[[:space:]]*$)' \
    || true
)"
if [[ -n "${unpinned_uses}" ]]; then
  echo "${unpinned_uses}" >&2
  fail "CI workflow actions must be pinned to 40-character commit SHAs"
fi
assert_not_contains "actions/checkout@v"
assert_not_contains "actions/cache@v"
assert_not_contains "dtolnay/rust-toolchain@stable"
assert_not_contains "taiki-e/install-action@v"
assert_order "run: cargo test --workspace" "run: scripts/test-ci-workflow.sh"
assert_order "run: scripts/test-ci-workflow.sh" "run: scripts/test-stable-ssh-cli.sh"
assert_order "run: cargo test --workspace" "run: scripts/test-stable-ssh-cli.sh"
assert_order "run: scripts/test-stable-ssh-cli.sh" "run: cargo test --doc"

assert_file_contains "${stable_ssh_cli_suite}" "source \"\${cargo_env}\"" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "missing required command: cargo" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "run_cargo_test_with_matches()" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "did not run any passing tests" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo fmt --all -- --check" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo test --locked -p enclava-cli stable_ssh" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo test --locked -p enclava-cli template_instance_idempotency_key_binds_stable_endpoint_request" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo test --locked -p enclava-cli --test api_client_test create_template_instance_posts_hosted_route_with_idempotency_key" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo test --locked -p enclava-cli --test api_contract_test app_response_accepts_phase7_fields_when_server_exposes_them" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo test --locked -p enclava-cli --test api_contract_test deployment_entry_accepts_legacy_deployment_id_field" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo test --locked -p enclava-cli --test api_contract_test template_instance_response_accepts_config_token_and_cap_payload" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo test --locked -p enclava-cli --test api_contract_test create_template_instance_request_sends_stable_endpoint_expectation" "stable SSH CLI suite"
assert_file_contains "${stable_ssh_cli_suite}" "cargo test --locked -p enclava-cli --test api_contract_test ssh_command_response_accepts_pending_and_ready_states" "stable SSH CLI suite"

echo "CI workflow tests passed"
