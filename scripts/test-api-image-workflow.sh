#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT_DIR/.github/workflows/api-image.yml"
DOCKERFILE="$ROOT_DIR/crates/enclava-api/Dockerfile"
COMPOSE="$ROOT_DIR/docker-compose.yml"
DEPLOYMENT="$ROOT_DIR/deploy/api/deployment.yaml"
KUSTOMIZATION="$ROOT_DIR/deploy/api/kustomization.yaml"
RBAC="$ROOT_DIR/deploy/api/rbac.yaml"

fail() {
  echo "error: $*" >&2
  exit 1
}

assert_contains() {
  grep -Fq -- "$1" "$WORKFLOW" || fail "workflow is missing: $1"
}

assert_order() {
  local first="$1"
  local second="$2"
  local first_line
  local second_line
  first_line="$(grep -nF -- "$first" "$WORKFLOW" | head -n1 | cut -d: -f1 || true)"
  second_line="$(grep -nF -- "$second" "$WORKFLOW" | head -n1 | cut -d: -f1 || true)"
  [[ -n "$first_line" && -n "$second_line" && "$first_line" -lt "$second_line" ]] \
    || fail "workflow order must keep '$first' before '$second'"
}

job_block() {
  local job="$1"
  local next="$2"
  awk -v start="  $job:" -v stop="  $next:" '
    $0 == start { active = 1 }
    $0 == stop { active = 0 }
    active { print }
  ' "$WORKFLOW"
}

unpinned="$(
  grep -nE '^[[:space:]]+- uses: ' "$WORKFLOW" \
    | grep -Ev '@[0-9a-f]{40}([[:space:]]+#|[[:space:]]*$)' \
    || true
)"
[[ -z "$unpinned" ]] || {
  echo "$unpinned" >&2
  fail "all workflow actions must be pinned to 40-character commits"
}

validate_block="$(job_block validate publish)"
publish_block="$(job_block publish "")"

for required in \
  "workflow_dispatch:" \
  "version_tag:" \
  "validate:" \
  "publish:" \
  "if: github.event_name == 'pull_request'" \
  "if: github.event_name == 'workflow_dispatch' || (github.event_name != 'pull_request' && (github.ref == 'refs/heads/main' || github.ref_type == 'tag'))" \
  "contents: read" \
  "id-token: write" \
  "packages: write" \
  "target: runtime-debug" \
  "push: false" \
  "push: true" \
  "github.ref_type == 'tag' || github.event_name == 'workflow_dispatch'" \
  "target=runtime-release" \
  "target=runtime-debug" \
  "ghcr.io/enclava-labs/enclava-api" \
  "dist/enclava-api-image.txt" \
  "dist/enclava-api-signer-identity.txt" \
  'signer_subject="https://github.com/${{ github.workflow_ref }}"' \
  "cosign sign --yes" \
  "scripts/verify-api-image-ref.sh --cosign dist/enclava-api-image.txt" \
  "name: enclava-api-release-manifest" \
  "scripts/test-api-image-workflow.sh" \
  "scripts/test-verify-api-image-ref.sh" \
  "scripts/verify-api-image-ref.bash" \
  "sh -n scripts/verify-api-image-ref.sh" \
  "bash -n scripts/verify-api-image-ref.bash"; do
  assert_contains "$required"
done

grep -Fq -- '      - "deploy/api/**"' "$WORKFLOW" \
  || fail "API manifest changes must trigger image validation"
grep -Fq -- "serviceAccountName: enclava-api" "$DEPLOYMENT" \
  || fail "API Deployment must use its Kubernetes reconciliation identity"
grep -Fq -- "automountServiceAccountToken: true" "$DEPLOYMENT" \
  || fail "API Deployment must mount Kubernetes credentials"
[[ "$(grep -Fc -- "app.kubernetes.io/name: cap-api" "$DEPLOYMENT")" -ge 2 ]] \
  || fail "API Deployment and pod template must carry the tenant-policy CAP identity"
grep -Fq -- 'CAP_DISABLE_EDGE_RECONCILIATION: "true"' "$COMPOSE" \
  || fail "non-Kubernetes Compose must explicitly disable edge reconciliation"
grep -Fq -- 'CAP_DEPLOYMENT_DISPATCH_ENABLED: "false"' "$COMPOSE" \
  || fail "non-Kubernetes Compose must keep deployment dispatch disabled"
if grep -Fq -- "CAP_DISABLE_EDGE_RECONCILIATION" "$DEPLOYMENT"; then
  fail "release API Deployment must not disable edge reconciliation"
fi
grep -Fq -- "- rbac.yaml" "$KUSTOMIZATION" \
  || fail "API release manifest must include reconciliation RBAC"
if grep -Eq '^namespace:' "$KUSTOMIZATION"; then
  fail "API kustomization must preserve the tenant-envoy Role namespace"
fi
for required in \
  "kind: ServiceAccount" \
  "kind: Role" \
  "kind: RoleBinding" \
  "name: enclava-api-edge-reconciler" \
  "name: enclava-api-service-reader" \
  "namespace: tenant-envoy" \
  'resources: ["services"]' \
  'resources: ["configmaps"]' \
  'resources: ["pods"]' \
  'resources: ["daemonsets"]' \
  'resourceNames: ["haproxy-tenant"]' \
  'verbs: ["list"]' \
  'verbs: ["get", "update"]'; do
  grep -Fq -- "$required" "$RBAC" \
    || fail "API release RBAC is missing: $required"
done

for required in \
  "cargo build --locked --bin enclava-api --bin cap-migrate" \
  "COPY --from=debug-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate" \
  "cargo build --locked --release --bin enclava-api --bin cap-migrate" \
  "COPY --from=release-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate"; do
  grep -Fq -- "$required" "$DOCKERFILE" \
    || fail "API image Dockerfile is missing: $required"
done

if grep -Fq "id-token: write" <<<"$validate_block" \
  || grep -Fq "packages: write" <<<"$validate_block"; then
  fail "pull-request validation must remain read-only"
fi
grep -Fq "id-token: write" <<<"$publish_block" \
  && grep -Fq "packages: write" <<<"$publish_block" \
  || fail "publisher must request package and keyless-signing permissions"

assert_order "- name: Build and push" "- name: Render digest-pinned release artifact"
assert_order "- name: Render digest-pinned release artifact" "- name: Install cosign"
assert_order "- name: Install cosign" "- name: Sign pushed digest"
assert_order "- name: Sign pushed digest" "- name: Verify signed digest"
assert_order "- name: Verify signed digest" "- name: Upload release manifest artifact"

echo "CAP API image workflow tests passed"
