# Local Enclava verifier

Build the static release with `./web/verifier/build.sh`, then serve the repository root with
`python3 -m http.server 8000` and open `http://localhost:8000/web/verifier/`. The page loads only
local assets and fetches the target's reserved proof endpoint directly. Do not run it with
`file://`, whose module and fetch behavior differs between browsers.

Publish the generated archive and `SHA256SUMS` through an independently authenticated release
channel. A release operator signs both with the platform release key; private signing keys are not
accepted by this build script.
