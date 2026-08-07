# Public verifier fixtures

`prove-it-live.bundle.b64` is a sanitized proof bundle captured from the disposable Prove-It
deployment on `dev.enclava.work` on 2026-08-04. It contains no workload secret or platform
credential. Its SHA-256 after base64 decoding is
`b62bbdba3f6438a41335fb2323feb9ee5e3fdee545d67259e801a65f36bd32a7`.

`prove-it-live.policy.json` is the independently supplied trust policy for the immutable image,
full 48-byte measurement, platform release, sidecars, AMD root, Sigstore identity, deployment
identity, and target origin in that bundle. `live_bundle.rs` supplies the recorded nonce and trusted
time, proves the fixture passes offline, and mutates every security-critical bundle field and policy
decision. `web/verifier/test.html` runs the same valid and rejected-measurement cases through the
WASM build and pins the valid canonical result hash.

The smaller Genoa files are the AMD chain/report/CRL components used for focused certificate,
signature, VCEK binding, TCB, and revocation-state tests.
