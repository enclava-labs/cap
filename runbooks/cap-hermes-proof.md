# CAP/Hermes Proof Tooling

Use `scripts/cap_hermes_proof.py` after a CAP app has deployed and the public
app endpoint is reachable. The script stays on the user-facing surface: CAP
API, public app HTTPS, confidential status/attestation endpoints, optional
manifest evidence, and one optional Hermes API request. It does not require
`kubectl`.

## Invocation

```bash
export CAP_API_URL="https://cap.example.com"
export CAP_APP_NAME="your-app"
export CAP_API_TOKEN="session-or-api-key"
export EXPECTED_IMAGE_DIGEST="sha256:..."

# Optional manifest and bundle proof.
export CAP_PROOF_MANIFEST="/path/to/signed-manifest.json"

# Optional Hermes probe.
export API_SERVER_KEY="..."
export HERMES_API_URL="https://your-app.example.com"
export HERMES_API_PATH="/health"

python3 scripts/cap_hermes_proof.py \
  --manifest "$CAP_PROOF_MANIFEST" \
  --require-signed-manifest \
  --require-cosign-verify \
  --cosign-certificate-identity "https://github.com/enclava-ai/hermes-agent/.github/workflows/enclava-build.yml@refs/heads/main" \
  --cosign-certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

If `enclava login` has already populated `~/.enclava/config.toml` and
`~/.enclava/credentials.toml`, `CAP_API_URL` and `CAP_API_TOKEN` can be omitted.

Use `--insecure-tls` only for debug endpoints that intentionally use a test
certificate. Use `--config-ready-optional` only when the app does not expose the
`config_ready` marker.

## Checks

The script verifies:

- CAP API `/health`;
- app status through CAP;
- latest deployment digest against `EXPECTED_IMAGE_DIGEST` or manifest digest;
- public app health;
- confidential status endpoint;
- nonce-bound attestation response and exposed report-data binding;
- optional signed manifest shape;
- optional `cosign verify-blob` bundle check;
- optional Hermes request when `API_SERVER_KEY` is set.

Output is a PASS/WARN/FAIL/SKIP table. Any FAIL exits non-zero.
