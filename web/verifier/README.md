# Local Enclava verifier

Build the static release with `./web/verifier/build.sh`, then serve the repository root with
`python3 -m http.server 8000` and open `http://localhost:8000/web/verifier/`. The page loads only
local assets and fetches the target's reserved proof endpoint directly. Do not run it with
`file://`, whose module and fetch behavior differs between browsers.

Tagged GitHub releases publish the deterministic archive, its hashes, bundled schemas/version, and
a keyless Sigstore signature bundle. Verify it with:

```sh
cosign verify-blob --bundle enclava-verifier-web.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/enclava-labs/cap/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  enclava-verifier-web.tar.gz
```
