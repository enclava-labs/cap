#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/render-api-release-manifest.sh ghcr.io/enclava-labs/enclava-api@sha256:<64-hex> [output.yaml]

Renders the API Kubernetes manifest with the exact pushed image digest.
The api-secrets Secret must already be supplied by the production environment.
USAGE
}

image_ref="${1:-}"
output="${2:-dist/enclava-api-deploy.yaml}"

if [[ -z "${image_ref}" ]]; then
  usage
  exit 2
fi

if [[ ! "${image_ref}" =~ ^ghcr\.io/enclava-labs/enclava-api@sha256:[0-9a-f]{64}$ ]]; then
  echo "error: image ref must be ghcr.io/enclava-labs/enclava-api@sha256:<64 lowercase hex chars>" >&2
  exit 2
fi

if ! command -v kustomize >/dev/null 2>&1; then
  echo "error: kustomize is required" >&2
  exit 127
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
if [[ "${output}" = /* ]]; then
  output_path="${output}"
else
  output_path="${repo_root}/${output}"
fi

mkdir -p "$(dirname "${output_path}")"

cp -R "${repo_root}/deploy/api/." "${tmp_dir}/"

(
  cd "${tmp_dir}"
  kustomize edit set image "ghcr.io/enclava-labs/enclava-api=${image_ref}"
  kustomize build . > "${output_path}"
)

if ! grep -Fq "image: ${image_ref}" "${output_path}"; then
  echo "error: rendered manifest does not contain the requested digest-pinned image" >&2
  exit 1
fi

if grep -Eq 'image: ghcr\.io/enclava-labs/enclava-api:[^@ ]+' "${output_path}"; then
  echo "error: rendered manifest contains a tag-based API image reference" >&2
  exit 1
fi

for required in \
  "serviceAccountName: enclava-api" \
  "automountServiceAccountToken: true" \
  "name: enclava-api-edge-reconciler" \
  "name: enclava-api-service-reader" \
  "namespace: tenant-envoy"; do
  if ! grep -Fq "${required}" "${output_path}"; then
    echo "error: rendered manifest is missing required Kubernetes access: ${required}" >&2
    exit 1
  fi
done

echo "${output_path}"
