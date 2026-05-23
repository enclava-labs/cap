#!/usr/bin/env bash
set -euo pipefail

# Trustee policy audit wrapper. Run from an operator machine with kubectl,
# CAP_DB_URL, and KBS_ADMIN_TOKEN available.

NS="${KBS_POLICY_NAMESPACE:-trustee-operator-system}"
CM="${KBS_POLICY_CONFIGMAP:-resource-policy}"
KEY="${KBS_POLICY_KEY:-policy.rego}"
OUT_DIR="${1:-trustee-policy-audit-$(date -u +%Y%m%dT%H%M%SZ)}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

need kubectl
need jq
need awk
need grep
need sha256sum
need psql

: "${CAP_DB_URL:?CAP_DB_URL is required}"
: "${KBS_ADMIN_TOKEN:?KBS_ADMIN_TOKEN is required}"

mkdir -p "$OUT_DIR"

kubectl -n "$NS" get cm "$CM" -o yaml > "$OUT_DIR/trustee-cm.snapshot.yaml"
kubectl -n "$NS" get cm "$CM" -o json | jq -r --arg key "$KEY" '.data[$key]' > "$OUT_DIR/live-policy.rego"

KBS_POD="$(kubectl -n "$NS" get pod -l app=kbs -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "$NS" exec "$KBS_POD" -- \
  curl -sf -H "Authorization: Bearer $KBS_ADMIN_TOKEN" \
  http://localhost:8080/kbs/v0/resource-policy \
  > "$OUT_DIR/kbs-list-policies.json"

sha256sum "$OUT_DIR/live-policy.rego" "$OUT_DIR/trustee-cm.snapshot.yaml" \
  > "$OUT_DIR/sha256sums.txt"

python3 - "$OUT_DIR/live-policy.rego" "$OUT_DIR/cap-blocks.rego" "$OUT_DIR/non-cap.rego" <<'PY'
from pathlib import Path
import sys

source, cap_path, non_cap_path = map(Path, sys.argv[1:])
cap_lines = []
non_cap_lines = []
in_cap = False

for line in source.read_text().splitlines(True):
    if "# BEGIN CAP MANAGED" in line:
        in_cap = True
        cap_lines.append(line)
        continue
    if in_cap:
        cap_lines.append(line)
        if "# END CAP MANAGED" in line:
            in_cap = False
        continue
    non_cap_lines.append(line)

cap_path.write_text("".join(cap_lines))
non_cap_path.write_text("".join(non_cap_lines))
PY

psql "$CAP_DB_URL" -At -c \
  "SELECT binding_key FROM kbs_owner_bindings WHERE deleted_at IS NULL
   UNION ALL
   SELECT binding_key FROM kbs_tls_bindings WHERE deleted_at IS NULL
   ORDER BY 1;" > "$OUT_DIR/cap-db-keys.txt"

grep -oE '"[a-z0-9-]+-(owner|tls)"' "$OUT_DIR/cap-blocks.rego" \
  | tr -d '"' \
  | sort -u > "$OUT_DIR/cap-rego-keys.txt"

diff -u "$OUT_DIR/cap-db-keys.txt" "$OUT_DIR/cap-rego-keys.txt" \
  > "$OUT_DIR/cap-binding-key-diff.patch" || true

cat > "$OUT_DIR/README.md" <<EOF
# Trustee Policy Audit

- Namespace: \`$NS\`
- ConfigMap: \`$CM\`
- Key: \`$KEY\`
- KBS pod: \`$KBS_POD\`
- Created: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`

Review:

1. \`cap-binding-key-diff.patch\` must be empty.
2. Classify every rule in \`non-cap.rego\` using
   \`cap/runbooks/trustee-policy-audit.md\`.
3. Confirm CAP-signed artifacts remain the deploy authority.
4. Record any operator-owned rule as intentional baseline or remove it.
EOF

echo "audit artifacts written to $OUT_DIR"
