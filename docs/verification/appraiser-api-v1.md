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

Run `cargo test -p enclava-appraiser` as the local conformance check.
