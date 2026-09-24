# Bundled sigstore trust roots

`sigstore-public-good-1.root.json` is the `trusted_root.json` TUF target of
the sigstore public-good instance (Fulcio CAs, Rekor/CT logs). The release
API image bakes it in at `/etc/enclava/sigstore/trusted_root.json` and sets
`SIGSTORE_TUF_ROOT_PATH`; `crates/enclava-api/src/cosign.rs` refuses to
bootstrap cosign trust from the network in release builds.

Provenance: exported from a verified TUF checkout (sigstore crate
`SigstoreTrustRoot::new` chains from the crate's embedded root.json with
expiration enforcement) — not an unauthenticated HTTPS download.

`scripts/verify-sigstore-trust-root.sh` pins its sha256
(`6494e21e…bc0b66`) and runs in CI; any change to the file must update the
pin in the same reviewed commit. To roll to a newer TUF snapshot: re-export
from a fresh verified checkout and update both.
