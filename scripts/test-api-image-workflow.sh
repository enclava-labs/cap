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
  "target: runtime-release" \
  "ghcr.io/enclava-labs/enclava-api" \
  "dist/enclava-api-image.txt" \
  "dist/enclava-api-migration.txt" \
  "dist/enclava-api-signer-identity.txt" \
  'signer_subject="https://github.com/${{ github.workflow_ref }}"' \
  "cosign sign --yes" \
  "scripts/verify-api-image-ref.sh --cosign dist/enclava-api-image.txt" \
  "name: enclava-api-release-manifest" \
  "scripts/test-api-image-workflow.sh" \
  "scripts/require-platform-release-root.sh" \
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
grep -A1 -F -- "name: DATABASE_MIGRATION_MODE" "$DEPLOYMENT" \
  | grep -Fq -- "value: verify" \
  || fail "API Deployment must leave migrations to the release Job"
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
  "cargo build --locked --release --bin enclava-api --bin cap-migrate --features prod-strict" \
  "COPY --from=release-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate" \
  "ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX" \
  "COPY scripts/require-platform-release-root.sh scripts/require-platform-release-root.sh" \
  "bash scripts/require-platform-release-root.sh --allow-dev-fixture" \
  "--example platform-release -- verify" \
  "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg"; do
  grep -Fq -- "$required" "$DOCKERFILE" \
    || fail "API image Dockerfile is missing: $required"
done
if grep -Eq '^ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=' "$DOCKERFILE"; then
  fail "API Dockerfile must not default ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX"
fi
[[ "$(grep -cE '^ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX$' "$DOCKERFILE")" -eq 2 ]] \
  || fail "API Dockerfile must declare ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX with no default in both builder stages"
[[ "$(grep -cF 'ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg' "$DOCKERFILE")" -eq 2 ]] \
  || fail "API Dockerfile must fail the build when the platform-release root is empty"
# The release builder must run the gate without the dev-fixture escape hatch.
[[ "$(grep -cE 'bash scripts/require-platform-release-root\.sh$' "$DOCKERFILE")" -eq 1 ]] \
  || fail "API Dockerfile release stage must run the strict root gate exactly once"
[[ "$(grep -cF 'COPY scripts/require-platform-release-root.sh' "$DOCKERFILE")" -eq 2 ]] \
  || fail "API Dockerfile must copy the root gate into both builder stages"

# The release image must ship the pinned sigstore trust root and point
# SIGSTORE_TUF_ROOT_PATH at it (cosign.rs fails closed in release builds
# without a file-backed root).
grep -Fq -- "COPY crates/enclava-api/trust-roots/sigstore-public-good-1.root.json /etc/enclava/sigstore/trusted_root.json" "$DOCKERFILE" \
  || fail "API Dockerfile release stage must bake in the pinned sigstore trust root"
grep -Fq -- "ENV SIGSTORE_TUF_ROOT_PATH=/etc/enclava/sigstore/trusted_root.json" "$DOCKERFILE" \
  || fail "API Dockerfile release stage must set SIGSTORE_TUF_ROOT_PATH"
grep -Fq -- "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66" "$DOCKERFILE" \
  || fail "API Dockerfile builder stages must sha256-gate the bundled trust root"
grep -Fq -- "value: /etc/enclava/sigstore/trusted_root.json" "$DEPLOYMENT" \
  || fail "deployment must restate SIGSTORE_TUF_ROOT_PATH explicitly"

grep -Fq -- "Local-compose-only well-known fixture; must never be a Dockerfile default." "$COMPOSE" \
  || fail "compose must label the fixture as local-compose-only"
grep -Fq -- "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX: 5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" "$COMPOSE" \
  || fail "compose must pass the well-known local fixture as an explicit build-arg"
grep -Fq -- "target: runtime-debug" "$COMPOSE" \
  || fail "compose must build the debug stage, the only stage the fixture root may pin"

grep -Fq -- "Test-only well-known fixture; never a Dockerfile default. PR validation only." <<<"$validate_block" \
  || fail "PR validation must label the fixture as test-only"
grep -Fq -- "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" <<<"$validate_block" \
  || fail "PR validation must pass the test-only fixture as an explicit build-arg"
grep -Fq -- "secrets.ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX" <<<"$publish_block" \
  || fail "publisher must pass secrets.ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX"
grep -Fq -- "secrets.ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON" <<<"$publish_block" \
  || fail "publisher must materialize the production envelope from secrets.ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON"
grep -Fq -- "scripts/require-platform-release-root.sh" <<<"$publish_block" \
  || fail "publisher must run the production platform-release root gate"
# Every pushed image is a prod-strict release build; the fixture-tolerant
# debug stage must never be published.
grep -Fq -- "target: runtime-release" <<<"$publish_block" \
  || fail "publisher must build the release stage"
if grep -Fq -- "runtime-debug" <<<"$publish_block"; then
  fail "publisher must not build or push the debug stage"
fi
if grep -Fq -- "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" <<<"$publish_block"; then
  fail "publisher must not pass the committed fixture as a build-arg"
fi

ROOT_GATE="$ROOT_DIR/scripts/require-platform-release-root.sh"
bash -n "$ROOT_GATE" || fail "scripts/require-platform-release-root.sh is not valid bash"
[[ -x "$ROOT_GATE" ]] || fail "scripts/require-platform-release-root.sh must be executable"
grep -Fq -- '^[0-9a-f]{64}$' "$ROOT_GATE" \
  || fail "root gate must require a 32-byte hex pubkey"
grep -Fq -- "must not be the committed dev fixture pubkey" "$ROOT_GATE" \
  || fail "root gate must reject the committed fixture pubkey"
grep -Fq -- "must match the bundled envelope's signing_pubkey" "$ROOT_GATE" \
  || fail "root gate must reject a root that cannot verify the bundled envelope"

# Gate scenarios run against synthetic envelopes so the root/envelope
# rotation invariant is exercised independently of the committed fixture.
GATE_TMP="$(mktemp -d)"
trap 'rm -rf "$GATE_TMP"' EXIT
prod_key="0000000000000000000000000000000000000000000000000000000000000001"
other_key="0000000000000000000000000000000000000000000000000000000000000002"
write_envelope() {
  printf '{"signing_pubkey": "%s"}\n' "$1" >"$GATE_TMP/envelope.json"
}

# Passes the repo envelope so shape checks run against real bundled state.
repo_env=(ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$ROOT_DIR/crates/enclava-cli/platform-release.json")

gate_rejects() {
  local value="$1"
  local reason="$2"
  if env "${repo_env[@]}" ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="$value" "$ROOT_GATE" \
    >/tmp/platform-release-root-gate.out 2>/tmp/platform-release-root-gate.err; then
    fail "root gate must reject $reason"
  fi
}
gate_rejects "" "an empty root"
gate_rejects "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" "the committed fixture"
gate_rejects "5B9437ADEAFFBE8F41B13D96ED49D2F51CD6C266CD8ECC284B0552EC4912B8DD" "the committed fixture (uppercase)"
gate_rejects "not-a-key" "a non-hex root"
gate_rejects "5b94" "a truncated root"

# A non-fixture root that does not sign the bundled envelope must be
# rejected: otherwise released binaries fail verification of their own
# bundled fallback (RootMismatch) at startup.
write_envelope "$other_key"
if env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="$prod_key" "$ROOT_GATE" \
  >/tmp/platform-release-root-gate.out 2>/tmp/platform-release-root-gate.err; then
  fail "root gate must reject a root that does not match the bundled envelope signing_pubkey"
fi
grep -Fq -- "ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON together" /tmp/platform-release-root-gate.err \
  || fail "root gate mismatch error must explain the two-secret rotation requirement"

# A matching root/envelope pair passes.
write_envelope "$prod_key"
env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="$prod_key" "$ROOT_GATE" \
  || fail "root gate must accept a non-fixture root matching the bundled envelope"
env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="$(echo "$prod_key" | tr 'a-f' 'A-F')" "$ROOT_GATE" \
  || fail "root gate must accept an uppercase root matching the bundled envelope"

# --allow-dev-fixture (debug/PR builds) only tolerates the fixture while the
# bundled envelope is still fixture-signed.
write_envelope "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd"
env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" \
  "$ROOT_GATE" --allow-dev-fixture \
  || fail "root gate must allow the dev fixture for debug builds while the envelope is fixture-signed"
write_envelope "$other_key"
if env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" \
  "$ROOT_GATE" --allow-dev-fixture \
  >/tmp/platform-release-root-gate.out 2>/tmp/platform-release-root-gate.err; then
  fail "root gate --allow-dev-fixture must still reject a fixture root once the envelope is rotated"
fi

if grep -Fq "id-token: write" <<<"$validate_block" \
  || grep -Fq "packages: write" <<<"$validate_block"; then
  fail "pull-request validation must remain read-only"
fi
grep -Fq "id-token: write" <<<"$publish_block" \
  && grep -Fq "packages: write" <<<"$publish_block" \
  || fail "publisher must request package and keyless-signing permissions"

assert_order "- name: Materialize production platform-release envelope" "- name: Require platform-release root"
assert_order "- name: Require platform-release root" "- name: Build and push"
assert_order "- name: Build and push" "- name: Render digest-pinned release artifact"
assert_order "- name: Render digest-pinned release artifact" "- name: Install cosign"
assert_order "- name: Install cosign" "- name: Sign pushed digest"
assert_order "- name: Sign pushed digest" "- name: Verify signed digest"
assert_order "- name: Verify signed digest" "- name: Upload release manifest artifact"

echo "CAP API image workflow tests passed"
