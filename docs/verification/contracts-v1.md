# Independent verification contracts v1

These contracts separate observed evidence from independently selected policy. A target or
appraiser-provided policy is never selected automatically, and no result may be `PASS` without an
explicit policy whose required security checks all pass.

## Proof endpoint

`GET /.well-known/confidential/proof-bundle?nonce=<base64url-no-pad-32-bytes>` with
`Accept: application/vnd.enclava.proof-bundle.v1` returns that same media type, `Cache-Control:
no-store`, and `Access-Control-Allow-Origin: *`. The endpoint supports GET and credential-free CORS
preflight only.

The body is CE-v1: `label_len:u16be || label || value_len:u32be || value`. It contains these fields
exactly once and in this order:

| Label | Maximum bytes |
|---|---:|
| `purpose` (`enclava-proof-bundle`) | 64 |
| `schema_version` (`1`) | 16 |
| `target_origin` | 2,048 |
| `challenge_nonce` | 32 exactly |
| `created_at_unix_seconds` | 20 |
| `snp_report` | 4,096 |
| `tls_leaf_der` | 16,384 |
| `proxy_receipt_public_key` | 4,096 |
| `amd_endorsements` | 131,072 |
| `cc_init_data_toml` | 196,608 |
| `workload_artifacts_json` | 196,608 |
| `trustee_policy_json` | 49,152 |
| `sigstore_material` | 196,608 |
| `provenance_oci_material` | 311,296 |

The whole bundle is limited to 1,048,576 bytes. The last five fields including CE framing are the
static verification-material blob and are limited to 716,800 bytes. Unknown, missing, duplicated,
reordered, oversized, truncated, unsupported-version, or trailing input is invalid. `bundle_id` is
SHA-256 of the exact response bytes. The creation time is informational and never establishes
freshness.

## Trust policy

Policy is separately supplied JSON with `schema_version: "enclava-trust-policy-v1"`, optional
display-only `label`, and explicit `required_checks`. Version 1 policy constraints cover trusted AMD
roots and TCB/SNP policy/48-byte measurements; Sigstore/Fulcio/Rekor roots and transparency;
source, workflow, issuer, builder and ref; platform, organization and policy-signing roots; target
origin/deployment identity; image digests; runtime/sidecar/artifact relationships; nonce, receipt,
clock-skew and signed revocation-freshness requirements; and whether
`transport.tls_channel_spki` is required. Exact policy bytes are hashed as supplied.

The policy's `amd.measurement` values are always the complete 48-byte SNP launch measurement. A
legacy signed deployment descriptor may carry and compare only its historical 32-byte prefix so
old descriptor signatures remain valid during migration; that compatibility check cannot replace
the full-width policy check required for an independent `PASS`.

`appraiser.keys` independently pins each accepted Ed25519 key by identifier, public key, validity
interval, and revocation status. Receipt lifetime and clock-skew bounds are policy inputs. A
response-carried key is informational and must exactly match an independent pin.

## Appraisal result

The JSON result fields are `verdict`, `bundle_sha256`, `policy_sha256`, `target_origin`,
`challenge_nonce`, `verified_at`, `verifier_version`, ordered `checks`, and ordered `warnings`.
Checks contain `id`, `outcome`, optional `observed`/`expected`, and `reason_code`. Canonical result
hashing uses CE-v1 records in that field order, followed by repeated `check` records (whose values
are CE-v1 check records with explicit presence bits for both optional fields), then repeated
`warning` records.

`PASS` requires every policy-required check to pass. A required mismatch or invalid evidence is
`FAIL`; no policy, insufficient policy, or an unavailable required context fact is `INCONCLUSIVE`.
`transport.tls_channel_spki` is `SKIPPED` with `CHANNEL_SPKI_UNAVAILABLE` when the verifier did not
observe the live TLS connection. A policy requiring it cannot pass in that context.

Machine-readable appraiser/result schemas are in `schema/`; stable codes are listed in
`reason-codes-v1.md`. The canonical Rust receipt verifier is `verify_appraisal_response`.
