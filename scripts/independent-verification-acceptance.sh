#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
enclava_bin="${ENCLAVA_BIN:-${repo_root}/target/release/enclava}"
origin="${ORIGIN:?set ORIGIN to the workload HTTPS origin}"
policy="${POLICY:?set POLICY to an independently supplied trust-policy file}"

if [[ -n "${IMAGE:-}" ]]; then
  : "${APP_DIR:?set APP_DIR when IMAGE is set}"
  : "${SIGNER_SUBJECT:?set SIGNER_SUBJECT when IMAGE is set}"
  create_args=(create --signer-subject "$SIGNER_SUBJECT")
  [[ -z "${SIGNER_ISSUER:-}" ]] || create_args+=(--signer-issuer "$SIGNER_ISSUER")
  deploy_args=(deploy --image "$IMAGE")
  [[ -z "${STORAGE_PASSWORD_FILE:-}" ]] || deploy_args+=(--storage-password-file "$STORAGE_PASSWORD_FILE")
  (cd "$APP_DIR" && "$enclava_bin" "${create_args[@]}" && "$enclava_bin" "${deploy_args[@]}")
fi

tmp="$(mktemp -d)"
server_pid=
trap '[[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT

"$enclava_bin" verify "$origin" --policy "$policy" --save-bundle "$tmp/bundle.ce" --json >"$tmp/online.json"
"$enclava_bin" verify --bundle "$tmp/bundle.ce" --policy "$policy" --json >"$tmp/offline.json"
python3 - "$policy" "$tmp/rejected-policy.json" <<'PY'
import json, sys
with open(sys.argv[1], "rb") as source:
    policy = json.load(source)
policy["amd"]["allowed_measurements"] = ["00" * 48]
with open(sys.argv[2], "w", encoding="utf-8") as target:
    json.dump(policy, target, separators=(",", ":"))
PY
if "$enclava_bin" verify --bundle "$tmp/bundle.ce" --policy "$tmp/rejected-policy.json" --json >"$tmp/rejected.json" 2>/dev/null; then
  echo "rejected-measurement policy unexpectedly passed" >&2
  exit 1
fi
python3 - "$tmp/online.json" "$tmp/offline.json" "$tmp/rejected.json" <<'PY'
import json, sys
online, offline, rejected = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:])
if online["verdict"] != "PASS" or offline["verdict"] != "PASS":
    raise SystemExit("native online/offline verification did not pass")
if rejected["verdict"] != "FAIL" or not any(
    check["reason_code"] == "SNP_MEASUREMENT_REJECTED" for check in rejected["checks"]
):
    raise SystemExit("rejected measurement did not produce the expected failure")
PY

chrome="${CHROME_BIN:-}"
for candidate in google-chrome chromium chromium-browser; do
  [[ -n "$chrome" ]] || chrome="$(command -v "$candidate" 2>/dev/null || true)"
done
[[ -n "$chrome" ]] || { echo "set CHROME_BIN to a Chromium-compatible browser" >&2; exit 1; }
ln -s "$repo_root/web" "$tmp/web"
cp "$policy" "$tmp/policy.json"
python3 -m http.server "${VERIFIER_PORT:-8765}" --bind 127.0.0.1 --directory "$tmp" >"$tmp/http.log" 2>&1 &
server_pid=$!
server_ready=
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${VERIFIER_PORT:-8765}/web/verifier/test.html" >/dev/null 2>&1; then
    server_ready=1
    break
  fi
  sleep 1
done
[[ -n "$server_ready" ]] || { cat "$tmp/http.log" >&2; exit 1; }
url="http://127.0.0.1:${VERIFIER_PORT:-8765}/web/verifier/test.html?target=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$origin")&policy=/policy.json"
timeout 45 "$chrome" --headless --no-sandbox --disable-gpu --disable-background-networking \
  --disable-component-update --disable-domain-reliability --no-first-run --disable-sync --virtual-time-budget=30000 \
  --user-data-dir="$tmp/chrome" --dump-dom "$url" >"$tmp/dom.html"
if ! grep -Eq '<pre id="result">PASS [0-9a-f]{64}</pre>' "$tmp/dom.html"; then
  cat "$tmp/dom.html" >&2
  exit 1
fi

if [[ "${ADVERSARIAL:-0}" == "1" ]]; then
  curl -fsS "$origin/" >"$tmp/tenant.html"
  grep -Fq 'Tenant claim: approved image and measurement. This green page is untrusted.' "$tmp/tenant.html"
  curl -fsS "$origin/api/fake-appraiser" >"$tmp/fake-appraiser.json"
  python3 - "$tmp/fake-appraiser.json" <<'PY'
import base64, json, sys
response = json.load(open(sys.argv[1], encoding="utf-8"))
receipt = response.get("receipt", {})
if response.get("verdict") != "PASS" or not receipt.get("key_id"):
    raise SystemExit("dishonest appraiser did not return its PASS opinion")
if len(base64.b64decode(receipt.get("public_key_base64", ""), validate=True)) != 32:
    raise SystemExit("dishonest appraiser receipt public key is malformed")
if len(base64.b64decode(receipt.get("signature_base64", ""), validate=True)) != 64:
    raise SystemExit("dishonest appraiser receipt signature is malformed")
if not isinstance(receipt.get("appraised_at"), int) or not isinstance(receipt.get("expires_at"), int):
    raise SystemExit("dishonest appraiser receipt times are malformed")
PY
  shadow_status="$(curl -sS -o "$tmp/shadow.json" -w '%{http_code}' "$origin/.well-known/confidential/proof-bundle")"
  [[ "$shadow_status" == "400" ]] && ! grep -Fq 'untrusted-tenant' "$tmp/shadow.json"
  if "$enclava_bin" verify "$origin" --policy "$tmp/rejected-policy.json" --json >"$tmp/online-rejected.json" 2>/dev/null; then
    echo "dishonest tenant and appraiser unexpectedly changed the local CLI verdict" >&2
    exit 1
  fi
  python3 - "$tmp/online-rejected.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
if result["verdict"] != "FAIL" or not any(
    check["reason_code"] == "SNP_MEASUREMENT_REJECTED" for check in result["checks"]
):
    raise SystemExit("live CLI collusion check did not reject the measurement")
PY
  timeout 45 "$chrome" --headless --no-sandbox --disable-gpu --disable-background-networking \
    --disable-component-update --disable-domain-reliability --no-first-run --disable-sync --virtual-time-budget=30000 \
    --user-data-dir="$tmp/chrome-rejected" --dump-dom \
    "$url&reject=measurement&expected=FAIL&reason=SNP_MEASUREMENT_REJECTED" >"$tmp/rejected-dom.html"
  if ! grep -Eq '<pre id="result">PASS [0-9a-f]{64}</pre>' "$tmp/rejected-dom.html"; then
    cat "$tmp/rejected-dom.html" >&2
    exit 1
  fi
fi
echo "independent verification acceptance: PASS"
