#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
cargo build -p enclava-verifier-wasm --release --target wasm32-unknown-unknown
mkdir -p web/verifier/pkg web/verifier/release
wasm-bindgen --target web --out-dir web/verifier/pkg \
  target/wasm32-unknown-unknown/release/enclava_verifier_wasm.wasm
sha256sum web/verifier/index.html web/verifier/app.js web/verifier/style.css \
  web/verifier/pkg/enclava_verifier_wasm.js \
  web/verifier/pkg/enclava_verifier_wasm_bg.wasm > web/verifier/release/SHA256SUMS
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -czf web/verifier/release/enclava-verifier-web.tar.gz \
  web/verifier/index.html web/verifier/app.js web/verifier/style.css web/verifier/pkg \
  web/verifier/release/SHA256SUMS
