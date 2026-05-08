#!/usr/bin/env bash
set -euo pipefail

CAP_ROOT=${CAP_ROOT:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"}
PLATFORM_ROOT=${PLATFORM_ROOT:-"$(cd "${CAP_ROOT}/.." && pwd)"}
NUTSHELL_ROOT=${NUTSHELL_ROOT:-"${PLATFORM_ROOT}/nutshell"}
POLICY_ROOT=${POLICY_ROOT:-"${PLATFORM_ROOT}/policy-templates"}

require_dir() {
  if [[ ! -d "$1" ]]; then
    echo "missing directory: $1" >&2
    exit 1
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

run() {
  printf '\n==> %s\n' "$*"
  "$@"
}

require_cmd cargo
require_cmd python3
require_dir "${CAP_ROOT}"
require_dir "${NUTSHELL_ROOT}"
require_dir "${POLICY_ROOT}/signing-service"

printf 'CAP_ROOT=%s\n' "${CAP_ROOT}"
printf 'NUTSHELL_ROOT=%s\n' "${NUTSHELL_ROOT}"
printf 'POLICY_ROOT=%s\n' "${POLICY_ROOT}"

printf '\n==> Validate Nutshell CAP contract\n'
python3 - "${NUTSHELL_ROOT}" <<'PY'
import pathlib
import sys

try:
    import tomllib
except ModuleNotFoundError as exc:
    raise SystemExit("python3 must include tomllib; use Python 3.11+") from exc

root = pathlib.Path(sys.argv[1])
config = tomllib.loads((root / "enclava.toml").read_text())
dockerfile = (root / "Dockerfile").read_text()
entrypoint = (root / "docker" / "app-entrypoint.sh").read_text()


def expect(name: str, actual, expected):
    if actual != expected:
        raise SystemExit(f"{name}: expected {expected!r}, got {actual!r}")


app = config.get("app", {})
storage = config.get("storage", {})
expect("app.name", app.get("name"), "nutshell")
expect("app.port", app.get("port"), 3338)
expect("app.command", app.get("command"), ["/usr/local/bin/app"])
expect("storage.paths", storage.get("paths"), [])

required = [
    "APP_SEED_PATH=/state/app/seed",
    "CASHU_DIR=/state/data",
    "HOME=/state/data",
    "MINT_DATABASE=/state/data/mint",
    "MINT_AUTH_DATABASE=/state/data/mint",
    "TMPDIR=/state/data/tmp",
    "XDG_CACHE_HOME=/state/data/.cache",
    "--home-dir /state/data",
    "mkdir -p /state/app /state/data /state/data/tmp",
]
for text in required:
    if text not in dockerfile:
        raise SystemExit(f"Dockerfile missing expected state setting: {text}")

for stale in [
    "CASHU_DIR=/data",
    "HOME=/data",
    "MINT_DATABASE=/data",
    "MINT_AUTH_DATABASE=/data",
    "TMPDIR=/data",
    "XDG_CACHE_HOME=/data",
    "--home-dir /data",
    "mkdir -p /data",
]:
    if stale in dockerfile:
        raise SystemExit(f"Dockerfile still contains stale /data setting: {stale}")

for text in [
    "${MINT_DATABASE:=/state/data/mint}",
    "${MINT_AUTH_DATABASE:=/state/data/mint}",
    "${TMPDIR:=/state/data/tmp}",
]:
    if text not in entrypoint:
        raise SystemExit(f"app-entrypoint.sh missing expected default: {text}")

for stale in [
    "${MINT_DATABASE:=/data/mint}",
    "${MINT_AUTH_DATABASE:=/data/mint}",
    "${TMPDIR:=/data/tmp}",
]:
    if stale in entrypoint:
        raise SystemExit(f"app-entrypoint.sh still contains stale /data default: {stale}")

print("Nutshell descriptor and image defaults match CAP /state contract")
PY

run cargo fmt --all -- --check
run cargo test -p enclava-engine --test manifest_containers_test app_container_
run cargo test -p enclava-cli --test deploy_artifacts_test
run cargo test -p enclava-api deploy::tests

(
  cd "${POLICY_ROOT}/signing-service"
  run cargo fmt --check
  run cargo test genpolicy::tests
)

printf '\nFast Nutshell/CAP contract checks passed. Build and push images only after this gate is green.\n'
