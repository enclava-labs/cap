#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
cargo build -p enclava-verifier-wasm --release --target wasm32-unknown-unknown
mkdir -p web/verifier/pkg web/verifier/release
wasm-bindgen --target web --out-dir web/verifier/pkg \
  target/wasm32-unknown-unknown/release/enclava_verifier_wasm.wasm
cp crates/enclava-verifier/tests/fixtures/prove-it-live.policy.json \
  web/verifier/release/example-policy.json
sha256sum web/verifier/SCHEMA_VERSION web/verifier/index.html web/verifier/app.js web/verifier/style.css \
  web/verifier/pkg/* \
  docs/verification/schema/*.json web/verifier/release/example-policy.json \
  > web/verifier/release/SHA256SUMS
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -czf web/verifier/release/enclava-verifier-web.tar.gz \
  web/verifier/SCHEMA_VERSION web/verifier/index.html web/verifier/app.js \
  web/verifier/style.css web/verifier/pkg docs/verification/schema \
  web/verifier/release/SHA256SUMS web/verifier/release/example-policy.json
