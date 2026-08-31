# Appraiser API v1

`POST /v1/appraise` requires `Content-Type:
application/vnd.enclava.appraisal-request.v1+json` and a JSON body:

```json
{
  "bundle_base64": "<standard base64>",
  "policy_base64": "<standard base64>",
  "challenge_nonce_base64url": "<32 bytes, base64url without padding>",
  "expected_target_origin": "https://app.example"
}
```

Supply exactly one of `policy_base64` or `policy_id`. Configured policy IDs map to exact policy
bytes through `ENCLAVA_APPRAISER_POLICIES_JSON`, a JSON object whose values are standard base64.
The service uses its own clock and always appraises uploaded evidence with no observed live-channel
SPKI. Requests are limited to 1,600,000 bytes.

The response media type is `application/vnd.enclava.appraisal-response.v1+json`, with
`Cache-Control: no-store`:

```json
{"result": {}, "result_sha256": "<hex>", "receipt": null}
```

`result` is the canonical v1 result. If `ENCLAVA_APPRAISER_SIGNING_KEY_BASE64` contains a 32-byte
Ed25519 seed, `ENCLAVA_APPRAISER_KEY_ID` is required and `receipt` contains the key ID, appraisal
and expiry times, public key, and signature. The signature covers a CE-v1
`enclava-appraisal-receipt-v1` transcript containing the result, bundle and policy hashes, nonce,
origin, times, verifier version, and key ID. The response public key is informational: consumers
must independently pin the key ID and key with validity/revocation intervals. During rotation,
publish both keys independently for a bounded overlap; never authorize a replacement from a
response alone.

Run `python3 scripts/appraiser-conformance.py https://appraiser.example` against any deployed
implementation. The command checks the public media types, no-store behavior, request context,
fail-closed behavior, stable reason code, and canonical result hash. Repeat it against Enclava's
deployment and a separately deployed instance. Use `--header 'Authorization:Bearer ...'` only when
the independently operated endpoint intentionally requires authentication.

Run `cargo test -p enclava-appraiser` for the reference implementation's local unit checks.

Consumers verify responses with `enclava_verifier::verify_appraisal_response_pinned` and the
independently supplied `appraiser` policy section. The WASM adapter exports the same pinned-only
path. It enforces the exact result hash, signature, validity windows, maximum lifetime, clock skew,
revocation, overlap rotation, and the relying party's policy, nonce, and origin. Stable failures are
documented in `reason-codes-v1.md`.

**Pinning (required):** the appraiser signs results for whatever policy, evidence, nonce, and origin
a requester supplies — it is a public signing oracle by design. A receipt only proves something
when the relying party pinned its own choices. Always verify with
`enclava_verifier::verify_appraisal_response_pinned` and an `ExpectedReceipt` that carries the
sha256 of YOUR policy document, YOUR challenge nonce, and YOUR expected target origin. A
validly-signed `PASS` receipt under an attacker-chosen policy is otherwise indistinguishable from a
genuine one.
