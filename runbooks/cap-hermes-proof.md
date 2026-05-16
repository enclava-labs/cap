# CAP/Hermes Proof Tooling

Use `scripts/cap_hermes_proof.py` after a CAP app has been deployed and the app public endpoint is reachable. The script stays in CAP/user-facing territory: it does not read kubeconfig, mutate the cluster, or touch sibling repos.

## Invocation

```bash
export CAP_API_URL="https://cap-test01-enclava.enclava.dev"
export CAP_APP_NAME="your-cap-app-name"
export CAP_API_TOKEN="paste an enclava session token or API key"
export EXPECTED_IMAGE_DIGEST="sha256:..."

# Optional: prove a signed manifest/policy artifact on disk.
export CAP_PROOF_MANIFEST="/path/to/signed-manifest.json"

# Optional: prove one Hermes API call. If HERMES_API_URL is omitted, the script
# calls the CAP app domain with HERMES_API_PATH.
export API_SERVER_KEY="..."
export HERMES_API_URL="https://your-cap-app-name.enclava.dev"
export HERMES_API_PATH="/health"

python3 scripts/cap_hermes_proof.py \
  --manifest "$CAP_PROOF_MANIFEST" \
  --require-signed-manifest
```

If you already ran `enclava login`, `CAP_API_URL` and `CAP_API_TOKEN` can be omitted; the script falls back to `~/.enclava/config.toml` and `~/.enclava/credentials.toml`.

For staging endpoints with temporary certificates, add `--insecure-tls`. For apps that do not expose `config_ready` yet, add `--config-ready-optional`; otherwise missing or false `config_ready` fails the proof.

## What It Proves

- CAP API `/health` is reachable.
- CAP app status is one of `running`, `healthy`, `deployed`, or `ready`.
- The latest CAP deployment digest matches `EXPECTED_IMAGE_DIGEST` or the digest extracted from the manifest.
- Public app `/health` is reachable.
- Confidential `/.well-known/confidential/status` is reachable.
- `config_ready=true` is exposed by confidential status or public health.
- `/.well-known/confidential/attestation` returns a fresh nonce-bound response for the live TLS leaf SPKI, and parseable SNP `report_data` matches when exposed.
- A supplied manifest JSON is parseable, digest-bearing, and signature-bearing when `--require-signed-manifest` is set.
- If `API_SERVER_KEY` is set, one Hermes API request succeeds.

The script prints a demo-readable PASS/WARN/FAIL/SKIP table and exits non-zero on any FAIL.
