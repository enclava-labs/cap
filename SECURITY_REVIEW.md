# Security Review

This is the current code-grounded security snapshot. It replaces the dated
review documents that described older implementation states.

## Verified Current Controls

| Area | Current control |
| --- | --- |
| API startup | Release builds reject debug bypass flags, require API-key pepper, require policy-read mode, and reject plain HTTP KBS URLs. |
| API keys | New keys use an HMAC format with a 128-bit lookup prefix and 256-bit secret. Creation requires admin role, `org:admin`, and no API-key scope escalation. |
| App writes | App create, deploy, rollback, signer, custom domain, and unlock-mode mutation routes call centralized role/scope checks. |
| Signer identity | Initial set is owner-only. Rotation requires an owner session and a short-lived HMAC token tied to the current and requested identity. |
| Platform release | API and CLI verify signed platform-release metadata against the pinned root key and reject drift in release-owned values. |
| Sidecar images | API startup verifies digest-pinned attestation-proxy and Caddy ingress images with cosign before accepting deploy requests. |
| Workload image | Deploy verifies image signer identity and digest before recording and applying a deployment. |
| Descriptor authority | Deploy requires customer descriptor/keyring/signed policy artifacts when policy signing or Trustee policy-read mode is configured. |
| Agent policy | CLI requests generated agent policy from CAP; CAP validates the returned policy hash and canonical signed policy artifact. |
| In-TEE verification | `enclava-init` verifies descriptor, keyring, policy, and `cc_init_data` bindings before seed release in the supported runtime mode. |
| Tenant storage | App data and TLS state are separate LUKS volumes opened inside the guest by `enclava-init`. |
| Network exposure | Public app traffic and TEE/ownership traffic use separate hostnames. Workload artifact and TLS broker routes validate Trustee attestation. |

## Security-Critical Required Configuration

Production CAP must run with:

- `TRUSTEE_POLICY_READ_AVAILABLE=true`
- signed platform release root key compiled via
  `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX`
- digest-pinned platform sidecar images
- HTTPS Trustee KBS URL and CA material when needed
- `WORKLOAD_ARTIFACTS_URL`, `TRUSTEE_POLICY_URL`,
  `TRUSTEE_ATTESTATION_VERIFY_URL`, and
  `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN`
- policy signing service URL and verification public key
- API signing key, session HMAC key, and API-key HMAC pepper
- non-empty `BTCPAY_WEBHOOK_SECRET`

Release builds refuse the supported production path if these gates are not met
or if debug bypass flags are enabled.

## Current Residual Risks

| Risk | Status |
| --- | --- |
| Static `deploy/api` overlay is minimal | The checked-in overlay is a starting point and does not encode the full production env/RBAC/secrets shape. Production overlays must extend it. |
| KBS and signing-service availability are hard dependencies | Deploy and runtime verification depend on these services being reachable and pinned to the signed release. Operational monitoring must cover them. |
| Billing routes are present but not the security boundary | BTCPay config must be real for billing correctness, but deploy security does not rely on successful billing calls. |
| Development compose can start with ephemeral keys | This is intentional for local work only. Persistent environments must use durable key material. |

## Verification Commands

Use targeted checks while editing security-sensitive paths:

```bash
cargo test -p enclava-api --lib
cargo test -p enclava-cli
cargo test -p enclava-engine
cargo clippy --workspace --all-targets -- -D warnings
```

For live proof of a deployed app without cluster access, use:

```bash
python3 scripts/cap_hermes_proof.py --help
```
