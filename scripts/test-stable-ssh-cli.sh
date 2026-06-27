#!/usr/bin/env bash
set -Eeuo pipefail

script_path="${BASH_SOURCE[0]}"
case "${script_path}" in
  /*) ;;
  *) script_path="${PWD}/${script_path}" ;;
esac
script_dir="${script_path%/*}"
root_dir="${script_dir%/*}"

cd "${root_dir}"

if ! command -v cargo >/dev/null 2>&1; then
  cargo_env="${HOME:-}/.cargo/env"
  if [[ -n "${HOME:-}" && -f "${cargo_env}" ]]; then
    # shellcheck disable=SC1090
    source "${cargo_env}"
  fi
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "error: missing required command: cargo" >&2
  exit 1
fi

run_cargo_test_with_matches() {
  local label="$1"
  shift
  local output

  if ! output="$("$@" 2>&1)"; then
    printf '%s\n' "${output}"
    return 1
  fi
  printf '%s\n' "${output}"
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed' <<<"${output}"; then
    echo "error: ${label} did not run any passing tests" >&2
    return 1
  fi
}

cargo fmt --all -- --check
run_cargo_test_with_matches "stable SSH CLI filters" \
  cargo test --locked -p enclava-cli stable_ssh
run_cargo_test_with_matches "stable SSH template instance idempotency key binding" \
  cargo test --locked -p enclava-cli template_instance_idempotency_key_binds_stable_endpoint_request
run_cargo_test_with_matches "stable SSH hosted template create route idempotency" \
  cargo test --locked -p enclava-cli --test api_client_test create_template_instance_posts_hosted_route_with_idempotency_key
run_cargo_test_with_matches "stable SSH app response metadata DTO" \
  cargo test --locked -p enclava-cli --test api_contract_test app_response_accepts_phase7_fields_when_server_exposes_them
run_cargo_test_with_matches "stable SSH deployment response metadata DTO" \
  cargo test --locked -p enclava-cli --test api_contract_test deployment_entry_accepts_legacy_deployment_id_field
run_cargo_test_with_matches "stable SSH template instance response metadata DTO" \
  cargo test --locked -p enclava-cli --test api_contract_test template_instance_response_accepts_config_token_and_cap_payload
run_cargo_test_with_matches "stable SSH template instance request metadata DTO" \
  cargo test --locked -p enclava-cli --test api_contract_test create_template_instance_request_can_omit_stable_endpoint_expectation
run_cargo_test_with_matches "stable SSH endpoint command response DTO" \
  cargo test --locked -p enclava-cli --test api_contract_test ssh_command_response_accepts_pending_and_ready_states

echo "Stable SSH CLI tests passed"
