# CAP Security Review Recheck - 2026-05-09

This is the latest verification report for `FULL_REVIEW_2026-04-30.md`.

Date: 2026-05-09
Last updated: 2026-05-13

Scope:
- CAP repo: `/home/lio/s/p/flow/confidential-infrastructure/enclava-platform/cap`
- Policy templates/signing service: `/home/lio/s/p/flow/confidential-infrastructure/enclava-platform/policy-templates`
- Attestation proxy: `/home/lio/s/p/flow/confidential-infrastructure/enclava-platform/attestation-proxy`
- Trustee/KBS fork: `/home/lio/s/p/flow/confidential-infrastructure/enclava-platform/trustee`
- Infra Ansible: `/home/lio/s/p/flow/confidential-infrastructure/enclava-platform/enclava-infra`
- GitOps manifests: `/home/lio/s/p/flow/confidential-infrastructure/enclava-platform/enclava-ops-manifests`
- Live cluster read-only sample via `ssh control1.encl`

The original 2026-05-09 report verified code and configuration with bounded read-only live checks. The 2026-05-13 update includes the P0 mitigation rollout, GHCR image builds, live deployment, and focused E2E probes described below.

## 2026-05-13 P0 Mitigation Addendum

Implemented and deployed:
- CAP commit `92ed3b18a1c7bfbe71f04b05a86f57038584df74`, built by GitHub Actions run `25803717175`.
- Trustee commit `09383ba456a22cf02ad13d031710f7a848db50d2`, built by GitHub Actions run `25803715740`.
- Live CAP API image: `ghcr.io/enclava-ai/enclava-api@sha256:22df6b7ca49d13e9977368c07b0f26aad56bf547148c85e68c8cd648c77fae1a`.
- Live KBS image: `ghcr.io/enclava-ai/trustee-kbs-grpc-as@sha256:e5adaa015a85429cd3eb685bcd67e0f00bd45a1dd7a6d4e7e7f838c6225ddb4c`.
- `ttl.sh` CAP/KBS validation images have been removed from live deployments.

Live E2E evidence from `control1.encl` on 2026-05-13:
- `https://cap-test01-enclava.enclava.dev/health` returned `ok`.
- `https://tuscany.e9cae29e.enclava.dev/health` returned `{"status":"ok"}`.
- `https://tuscany-demo2.e9cae29e.enclava.dev/health` returned `{"status":"ok"}`.
- CAP reads `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN` from `cap-api-secrets/trustee-attestation-verify-bearer-token`.
- KBS reads `KBS_ATTESTATION_VERIFY_BEARER_TOKEN` from `kbs-attestation-verify-auth/token`.
- A pod in `cap-test01` calling KBS `/kbs/v0/attestation/verify` without caller auth received `401 AttestationVerifyAuthRequired`.
- The same pod with the CAP/KBS shared caller bearer reached workload-token verification and received `401 TokenVerifierError` for a fake workload token.
- CAP `/api/v1/workload/artifacts` with a fake workload token returned `403 attestation_denied` with upstream `TokenVerifierError`, proving CAP forwarded internal caller auth and KBS rejected only the fake workload token.
- A pod in a throwaway namespace outside the allowed KBS network path timed out with curl status `000 rc=28`.

Focused regression tests:
- `cargo test -p enclava-api --lib`: 127 passed.
- `AS_FEATURE=coco-as-grpc cargo test -p kbs --lib --features coco-as-grpc --no-default-features`: 98 passed.
- `pytest -q tests/test_trustee_attestation_verify_auth.py tests/test_trustee_network_policy.py`: 4 passed.

## Executive Summary

A large amount of the original review has been materially improved. The biggest architectural improvement is that deployment policy is now customer-signed and CAP requires a `signed_policy_artifact` instead of falling back to platform signing. Trustee/KBS now supports signed policy artifact sets, CAP writes multiple retained policy artifacts for rollout/rollback, and live KBS no longer uses the insecure flags or Kubernetes Secret resource backing that were called out in the review.

The system is still not production-ready. The remaining issues are narrower than the original report, but several are still production blockers because they affect the defensibility of the trust story:

1. Signing-service bootstrap/key-custody is still not a clean production trust boundary.
2. `enclava-init` still trusts mutable ConfigMap content for critical boot decisions.
3. Some API authorization and SSRF findings remain open.
4. Live Trustee still runs `as` and `rvps` with `:latest` tags and no explicit service account.
5. Live ACME configuration still carries a staging directory value, even though current tenant TLS mode is internal.

## Live Read-Only Sample

Sampled from `control1.encl` on 2026-05-09:

```text
KBS config:
  insecure_http = false
  insecure_api = false
  insecure_key = false
  trusted_certs_paths = ["/etc/as-token-signer/ca-cert.pem"]
  trusted_org_owner_public_keys = ["eb05f7af2e1bb98e6ced55ad1e134387a3875fce2f62bb990f715ebfe8e293e4"]
  trusted_descriptor_public_keys = []

KBS resource Secret backing:
  kbsSecretResources: empty
  no flowforge/kbsres legacy resource Secrets returned

Live platform images:
  CAP API:
    ghcr.io/enclava-ai/enclava-api@sha256:22df6b7ca49d13e9977368c07b0f26aad56bf547148c85e68c8cd648c77fae1a
  Signing service:
    ghcr.io/enclava-ai/policy-signing-service@sha256:e993e91c8f7a092b64e73bbb1b13c6a42371041124a33f71da9a8c6fad2f5920
  KBS:
    ghcr.io/enclava-ai/trustee-kbs-grpc-as@sha256:e5adaa015a85429cd3eb685bcd67e0f00bd45a1dd7a6d4e7e7f838c6225ddb4c
  Attestation service:
    ghcr.io/confidential-containers/staged-images/coco-as-grpc:latest
  RVPS:
    ghcr.io/confidential-containers/staged-images/rvps:latest

Live CAP flags:
  REQUIRE_CUSTOMER_SIGNED_POLICY_ARTIFACT=true
  TRUSTEE_KBS_URL=https://kbs-service.trustee-operator-system.svc.cluster.local:8080
  TENANT_CADDY_TLS_MODE=internal
  TENANT_CADDY_ACME_CA=https://acme-staging-v02.api.letsencrypt.org/directory

Live signing service:
  ENABLE_PLATFORM_POLICY_SIGNING=false
  GENPOLICY_VERSION_PIN=kata-containers/genpolicy@3.28.0+660e3bb6535b141c84430acb25b159857278d596
```

## Status Legend

- Closed: code/config now directly mitigates the reviewed issue.
- Partial: the immediate exposure is reduced, but the original production concern is not fully resolved.
- Open: the reviewed issue is still present.
- Replaced: the original mitigation target was superseded by the customer-signed policy model, but still needs production controls around the replacement path.

## Critical Findings

| ID | Status | Evidence | Remaining work |
|---|---|---|---|
| 2.1 SS-C1 signing service had no auth | Closed | Protected routes are behind bearer auth in `policy-templates/signing-service/src/main.rs`; unauthenticated `/agent-policy` returns 401 live. | Move from shared bearer token to mTLS or workload identity before broad production. |
| 2.2 SS-C2 `/bootstrap-org` TOFU and operator-callable | Partial | `/bootstrap-org` is now protected by signing-service bearer auth, but it still first-writes an org owner key into a SQLite store. | Either remove bootstrap from signing-service entirely or require a CAP/customer-signed bootstrap directive plus mTLS and auditable append-only storage. |
| 2.3 SS-C3 signing-service private key in K8s Secret | Partial | Platform signing is disabled live and by default. Raw `POLICY_SIGNING_KEY_B64` requires `ALLOW_RAW_POLICY_SIGNING_KEY_B64=1`. | Do not ship platform policy signing for prod, or put it behind KMS/HSM/external signer with no raw env fallback. |
| 2.4 TR-H1 KBS Secret resource CAS bypass | Closed | Live `kbsSecretResources` is empty and old `flowforge-*`/`kbsres*` Secrets are gone. Infra defaults no longer configure Secret resources. | Keep KBS resources out of Kubernetes Secret backing. Add a regression check in deployment CI. |
| 2.5 TR-H2 `/kbs/v0/attestation/verify` unauthenticated | Closed | KBS now fails closed unless `KBS_ATTESTATION_VERIFY_BEARER_TOKEN` is configured or explicit legacy unauth mode is enabled. CAP sends `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN` as caller auth while keeping the workload token in the JSON body. Live unauth fake token returns `AttestationVerifyAuthRequired`; live authed fake token reaches `TokenVerifierError`; an outside namespace times out. | Replace shared bearer with mTLS/workload identity before broad production. Keep NetworkPolicy and caller-auth regression tests. |
| 2.6 TR-H3 KBS insecure flags | Closed | Live and infra show `insecure_http=false`, `insecure_key=false`, `insecure_api=false`; trusted AS signer cert path is configured. | Add CI/Ansible fail-fast so these cannot be true in production inventory. |
| 2.7 AP-C1/2/3 attestation-proxy HTTP `0.0.0.0:8081` | Partial | Proxy HTTP now defaults to `127.0.0.1`; generated CAP manifests set `ATTESTATION_BIND=127.0.0.1`. | Split public/internal routers or enforce route-level auth. TLS listener still serves the full router. |
| 2.8 E1 legacy bootstrap fallback | Open | `LEGACY_BOOTSTRAP_SCRIPT` still exists in `crates/enclava-engine/src/manifest/containers.rs`. | Remove before production, or compile-gate it behind debug/test-only builds. |
| 2.9 E2 raw TOML construction | Partial | KBS URL/cert escaping was improved, but multiple `cc_init_data` fields are still raw `format!` strings. | Replace hand-built TOML with a TOML serializer or strict field escaping for every interpolated field. |
| 2.10 E4 enclava-init reads critical config from ConfigMap | Partial | Descriptor now binds expected `cc_init_data` hash and in-TEE verification checks local hash, but `config.toml`, trust anchor fields, KBS URLs, and salt still come from ConfigMap. | Move critical trust/config into signed `cc_init_data` or have enclava-init reject any ConfigMap value not chained from the signed descriptor. |
| 2.11 E3 verifier accepted platform fallback signature | Closed | `crates/enclava-init/src/trustee_verify.rs` now documents fallback keys as deprecated and verifies policy artifacts with descriptor signing key. Tests reject platform-signed fallback. | Remove deprecated fields from config once compatibility is no longer needed. |
| 2.12 CLI bootstrap key path traversal | Open | `CliPaths::bootstrap_key_path()` still joins raw `org` and `app`. | Validate/sanitize path components or use opaque IDs/hex encodings for filesystem names. |

## High Findings

| ID | Status | Evidence | Remaining work |
|---|---|---|---|
| 3.1 AP-H2 first-write `seed-encrypted` no signed receipt | Closed | Attestation-proxy now sends signed workload-resource envelopes for create/replace/delete. KBS parses receipt envelope. | Keep negative tests for missing receipt and wrong receipt purpose. |
| 3.2 AP-H3 receipt key not bound into SNP report | Closed | The signed resource-policy template requires `data.request.body.receipt.pubkey_hash_matches` for PUT and DELETE. KBS derives receipt-key binding from claims/report data or verified independent evidence, and tests cover valid binding, missing binding, wrong key, and forged binding. | Run one real workload rekey/rollback exercise before any production claim. |
| 3.3 AP-H1 plaintext proxy to KBS | Closed for live, partial in code defaults | Live CAP passes HTTPS KBS URL and CA. Attestation-proxy supports KBS CA PEM/path. | Change default `KBS_RESOURCE_URL` to HTTPS or require it explicitly in non-debug builds. |
| 3.4 AP-H4 self-signed TLS leaf | Partial | Attestation endpoint binds TLS leaf SPKI into report data. | Complete user-facing verification path for Caddy/public TLS key binding and document pinning semantics. |
| 3.5 AP-M3 inline JWK | Open | Attestation-proxy still verifies AA token using inline JWK from token header. | Verify against trusted JWKS/cert chain or delegate verification to KBS/AS with configured trust anchors. |
| 3.6 SS-H1 genpolicy paths from env | Partial | Genpolicy binary/rules are baked into image and version is pinned live, but env overrides remain. | Remove env override for prod or checksum-verify `GENPOLICY_BIN`, rules, and settings at startup. |
| 3.7 TR-H4 receipt verification fail-open via Rego | Closed | KBS now calls `validate_workload_receipt_hard_gate()` before Rego for workload-resource PUT/DELETE and rejects unless receipt signature, receipt pubkey hash, purpose, resource path, and PUT value hash are valid. Negative tests cover missing receipt, wrong pubkey, wrong purpose, wrong resource path, and wrong value hash. | Keep the Rust hard gate even if Rego templates evolve. |
| 3.8 H2 manifest hash misses `enclava_init_configmap` | Open | `manifest_hash()` still omits `manifests.enclava_init_configmap`. | Add it to the hash and add a regression test. Treat hash as drift detection only, not a security boundary. |
| 3.9 H3 LUKS PVCs operator-readable raw block | Open | Design still relies on in-guest LUKS over operator-visible block devices. | Document threat model honestly; consider dm-integrity/authenticated encryption verification, backup constraints, and customer-managed unlock options. |
| 3.10 CI-H1 Caddy TLS key not bound to REPORT_DATA | Partial | Proxy TLS SPKI is bound for attestation proxy; tenant Caddy/public TLS remains not fully bound. | Bind public Caddy cert/key identity into attestation evidence or expose a clear verification path that chains public TLS to TEE evidence. |
| 3.11 live staging ACME | Partial | Live still has staging ACME URL, but `TENANT_CADDY_TLS_MODE=internal`, so staging ACME is not active for internal mode. | Remove staging value from production overlay or fail startup when production mode uses staging ACME. |
| 3.12 live KBS orphaned K8s Secrets | Closed | Live read-only sample found no `flowforge`/`kbsres` resource secrets. | Add periodic drift/audit check. |
| 3.13 enclava-init panics boot-loop | Open | Panic/expect paths remain in critical init code. | Convert startup panics to structured fatal errors and bounded retry behavior. |
| 3.14 TR-M3 policy body not bound to descriptor hash | Closed | Trustee signed-policy artifact set selection uses `descriptor_core_hash` from attestation claims. | Narrow recursive claim extraction as described in 3.15. |
| 3.15 W-1 recursive claim extraction | Open | KBS still recursively finds `descriptor_core_hash`. | Extract only from explicit trusted claim paths produced by AS/init-data parsing. |
| 3.16a AUTH-H1 Argon2 params not pinned | Open | Email auth still uses `Argon2::default()`. | Pin algorithm/version/memory/time/parallelism and add tests against expected PHC params. |
| 3.16b AUTH-H2 Nostr signup/login body binding | Open | `verify_nip98_event_with_body()` exists, but signup/login routes still call `verify_nip98_event()`. | Use payload-bound helper on mutating auth routes or pass exact raw request body into verification. |
| 3.16c ROUTE-H1 `create_app` scope check | Open | `create_app` validates name/tier but does not require `apps:write` or admin/owner role at entry. | Add `scopes::require_scope(&auth, "apps:write")` and role check. |
| 3.16d ROUTE-H2 namespace/org validation | Open | Namespace is still derived from org/app strings without a combined Kubernetes name cap at derivation. | Validate org slug/app/namespace/service-account length and charset before persistence. |
| 3.16e ROUTE-H3 `rotate_signer` token not verified | Open | Route requires token presence for rotation but TODO says server-side verification does not exist yet. | Implement email confirmation table validation or require old signer/customer key signature over rotation. |
| 3.16f CC-H1 `cosign_verified` hardcoded true | Open | Deployment path still sets `let cosign_verified = true`. | Store actual verification result and fail deploy when verification did not run or did not pass. |
| 3.16g CC-H2 registry SSRF allowlist bypass | Partial | Guarded resolver exists. Deployment path uses guarded client, but registry allowlist is not enforced in `registry::resolve_tag_to_digest`. | Route registry operations through `RegistryClient` or enforce allowlist in `registry_base_url`. |
| 3.16h CC-H3 `tee_http_client` lacks SSRF resolver | Open | `tee_http_client` uses plain `reqwest::Client` with HTTPS-only and optional invalid cert mode. | Use guarded resolver or restrict destinations to CAP-owned tenant domains from DB. |
| 3.16i CC-H4 `SigningServiceClient` lacks SSRF guard/HTTPS | Open | Client allows `http` and uses plain `reqwest::Client`; live URL is in-cluster HTTP. | Pin to exact internal service DNS, disallow arbitrary env host, or use mTLS/Unix socket. For external signer, require HTTPS plus guarded resolver. |
| 3.16j CLI invalid-cert release mode | Open | CLI still allows invalid TEE certs via env/runtime mode in release builds. | Debug-gate invalid-cert support or require explicit `--danger-accept-invalid-certs` with prominent warning. |
| 3.16k CLI silent permission failure | Partial | Some key writes now propagate permission errors. `keyring.rs` still ignores `set_permissions` errors. | Propagate all permission-setting errors and verify final modes with metadata checks. |
| 3.16 TR-M2 `trusted_descriptor_public_keys=[]` | Replaced/partial | Live uses `trusted_org_owner_public_keys` instead of descriptor direct anchors. This is acceptable for customer-rooted artifacts. | Define how per-customer owner roots are provisioned/rotated at scale. Avoid manually editing global KBS config per customer. |

## Medium Findings

| ID | Status | Notes / mitigation |
|---|---|---|
| M-1 SignedPolicyArtifact decoder accepts hex/base64/url-safe | Open | Pick one canonical encoding per field. Keep compatibility decoder only at API edge if needed. |
| M-2 `/healthz` leaks template/genpolicy metadata | Partial | No signing key id is exposed when platform signing is disabled, but template hash/version are still returned. Use opaque health for public/network-wide routes. |
| M-3 Owner DB SQLite on PVC | Open | If owner store remains, add signed append-only event log/HMAC integrity and PVC access controls. Preferred: remove signing-service owner DB from production trust path. |
| M-4 CAP `AppError` raw messages | Open | Map internal errors to opaque client codes; log detail server-side. |
| M-5 Signing-service `AppError` raw messages | Open | Same: opaque external errors, structured internal logs. |
| M-6 Caddyfile renderer adversarial hostnames | Closed | Structured builder validates FQDN/URL/email and adversarial tests exist. |
| M-7 Trustee `as`/`rvps` unpinned latest tags | Open | Live still uses `coco-as-grpc:latest` and `rvps:latest`. Pin both to digests. |
| M-8 Trustee pod default service account | Open | Live Trustee deployment has empty serviceAccountName, which means default SA. Create explicit minimal SA/RBAC. |
| M-9 enclava-init unlock attempt write every loop | Open | Rate limit after real failed derivation only, or isolate unlock socket so co-located pods cannot trigger starvation. |
| M-10 workload binding optional | Partial | Deploy flow sets binding for signed artifacts, but manifest build still allows `None`. Hard-reject when trustee policy read is enabled. |
| M-11 platform-release root fallback fixture | Open | API and CLI still fall back to fixture key if compile-time root is absent. Gate fallback behind `debug_assertions`. |
| M-12 CLI expanded SigningKey zeroize | Open/accepted risk | Use a key type that zeroizes expanded state or document accepted local-client risk. |
| M-13 JWT `typ`/`jti` validator behavior | Open/low | `typ` is post-checked; `jti` is unused. Add validator requirements if revocation is introduced. |
| M-14 org keyring owner check | Closed | `put_keyring` now requires registered signing key for `auth.user_id` and owner role in payload. |
| M-15 Sigstore internal HTTP client not SSRF guarded | Open | Sigstore client still performs its own registry calls. Restrict allowed registries before invoking cosign and prefer explicit allowlist. |
| M-16 KBS ConfigMap apply uses `force()` | Open | CAP KBS policy reconciliation still uses SSA `force()`. Remove force or scope field ownership narrowly. |
| M-17 signing-service pubkey optional | Partial | Current platform-release path supplies/validates pubkey, but legacy env still allows optional. Make mandatory when signing service URL exists. |

## Low / Hygiene Findings

| ID | Status | Notes / mitigation |
|---|---|---|
| L-1 `ALLOW_EPHEMERAL_SIGNING_KEY=1` | Open | Gate behind debug/test feature, not runtime env. |
| L-2 Trustee `init_data` alias | Open/accepted compatibility | Remove only after downstream policy compatibility window. |
| L-3 public query namespace condition param | Open | Rename/internalize the condition parameter or verify all non-workload plugin paths require admin. |
| L-4 owner pubkey in proxy audit logs | Open/low | Hash/truncate public keys in high-volume logs if correlation risk matters. |
| L-5 Mutex poison panics | Open/accepted TEE risk | Document or replace with controlled shutdown errors. |
| L-6 CAP audit logs not durable outside cluster | Open | Ship audit logs to durable append-only storage outside operator-controlled cluster. |

## Production Mitigation Strategy

The right approach is to finish the trust chain first, then clean up platform hardening. The customer-signed policy model is now the core design, so production work should remove or narrow anything that lets CAP/operator infrastructure silently substitute policy, signer, KBS resource bytes, or verification inputs.

### P0 - Must Fix Before Production Claim

1. Enforce receipt public-key binding in both policy and Rust.

Status on 2026-05-13:
- Implemented in Trustee/KBS and the signed resource-policy template.
- KBS Rust hard-rejects invalid workload-resource PUT/DELETE envelopes before Rego.
- Local KBS regression tests cover missing receipt, wrong pubkey, wrong purpose, wrong resource path, wrong value hash, forged binding, and valid binding.

Implemented mitigation:
- Added `data.request.body.receipt.pubkey_hash_matches` to PUT and DELETE workload-resource Rego clauses.
- In KBS Rust, before Rego evaluation for `workload-resource` owner paths, reject unless:
  - receipt exists,
  - receipt signature is valid,
  - receipt pubkey hash matches attested report data,
  - receipt purpose matches method (`rekey` for PUT, `teardown` for DELETE),
  - receipt resource path equals requested path,
  - PUT value hash matches receipt payload.
- Added negative tests for missing receipt, wrong pubkey, wrong purpose, wrong resource path, and wrong value hash.

Remaining validation:
- Run one real workload rekey/rollback exercise before any production claim.

2. Remove production dependence on signing-service owner bootstrap.

Current issue:
- `/bootstrap-org` is authenticated but still TOFU into SQLite.
- Platform signing is disabled, but bootstrap/owner store remains a confusing trust boundary.

Mitigation:
- Preferred: signing service becomes only an agent-policy generator. CAP validates customer auth and customer-signed artifacts. Trustee/KBS verifies org-owner-rooted artifacts. Remove `/sign`, `/bootstrap-org`, `/rotate-owner`, and SQLite owner DB from production deployment.
- If kept short term: require a customer-owner-signed bootstrap directive, mTLS, audit log, and HMAC/signed append-only DB integrity.

3. Finish KBS attestation verification hardening.

Status on 2026-05-13:
- Implemented and deployed in CAP and Trustee/KBS.
- KBS now requires `KBS_ATTESTATION_VERIFY_BEARER_TOKEN` unless explicit legacy unauth mode is enabled.
- CAP now requires `TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN` whenever `TRUSTEE_ATTESTATION_VERIFY_URL` is set, and presents it as caller auth to KBS.
- Infra wires the KBS token from `kbs-attestation-verify-auth/token`; ops wires the CAP token from `cap-api-secrets/trustee-attestation-verify-bearer-token`.
- Live unauthenticated verify returns `AttestationVerifyAuthRequired`; live CAP-authenticated fake workload token reaches `TokenVerifierError`; outside namespace probe times out.

Remaining mitigation:
- Replace the shared bearer with mTLS or workload identity before broad production.
- Keep the live outside-namespace KBS denial probe as a deployment check.

4. Fix `enclava-init` ConfigMap trust.

Current issue:
- Critical init config still comes from a mutable ConfigMap.
- `manifest_hash` does not cover `enclava_init_configmap`.

Mitigation:
- Add `enclava_init_configmap` to `manifest_hash` and tests.
- Move critical fields into signed `cc_init_data`, or have enclava-init compare ConfigMap values against signed descriptor/cc-init-data claims and fail closed on mismatch.
- Treat ConfigMap as convenience transport only, not authority.

5. Remove raw TOML construction risk.

Current issue:
- `cc_init_data.rs` still hand-builds TOML with raw `format!` for several values.

Mitigation:
- Replace with typed TOML serialization or a strict TOML string encoder used for every interpolated field.
- Add adversarial tests for quotes, newlines, CR, triple quotes, backslashes, and delimiter-like values.

### P1 - High Priority Before First Serious Customer

6. Close CAP API authorization gaps.

Mitigation:
- Add `apps:write` and role checks to `create_app`.
- Implement real `email_confirmation_token` validation for `rotate_signer`, or require old signer/customer key signature.
- Use NIP-98 payload binding for signup/login, or remove Nostr auth until body binding is wired.
- Store actual `cosign_verified` result; never write `true` unless the verification path passed.

7. Close SSRF gaps.

Mitigation:
- Route registry digest resolution through `RegistryClient` allowlist.
- Guard or restrict `tee_http_client` to CAP-owned tenant domains.
- Make `SigningServiceClient` accept only pinned internal service DNS in platform mode; for external mode require HTTPS and guarded resolver.
- Add tests proving blocked CIDRs and disallowed registry hosts fail.

8. Pin platform release roots and images.

Mitigation:
- Remove fixture root fallback from API/CLI release builds.
- Pin Trustee `as` and `rvps` to digests.
- Add an explicit Trustee service account and minimal RBAC.
- Make production startup fail if any critical image is tag-only or `:latest`.

9. Clean up live ACME posture.

Mitigation:
- Remove staging ACME URL from production overlays even when internal TLS mode makes it inactive.
- Add config validation: staging ACME allowed only in explicit staging environments.

### P2 - Production Hardening

10. Error handling and audit.

Mitigation:
- Replace raw `anyhow` client responses in CAP/signing-service with opaque error codes.
- Send audit logs to durable storage outside the Kubernetes cluster.
- Normalize health endpoints to avoid unnecessary metadata exposure.

11. Key and local secret hygiene.

Mitigation:
- Propagate all CLI permission-setting failures.
- Verify final file/dir modes after write.
- Consider zeroizing expanded signing-key state or documenting accepted local-machine risk.

12. LUKS/PVC threat model.

Mitigation:
- Document that Kubernetes/storage operators can read raw encrypted blocks.
- Treat LUKS as confidentiality protection against storage visibility, not against malicious rollback/replay by a privileged storage operator unless authenticated rollback controls are added.
- Decide whether customer-managed unlock/password mode is the production default for high-assurance customers.

## Suggested Execution Order

1. Receipt binding hard gate: Rego + KBS Rust + tests.
2. ConfigMap/cc_init_data hardening: TOML serializer, `enclava_init_configmap` hash, init config validation.
3. API auth fixes: `create_app`, `rotate_signer`, Nostr payload binding, `cosign_verified`.
4. SSRF fixes: registry allowlist, signing-service client, TEE client restrictions.
5. Live infra hardening: pin `as`/`rvps`, explicit Trustee service account, remove staging ACME value.
6. Signing-service simplification: remove production `/sign`/bootstrap owner DB or move to signed external trust registry.

## Current Verdict

The platform is much closer to a defensible proof-of-concept than it was on 2026-04-30. The customer-signed policy artifact flow and signed platform release checks are the right direction.

It should not yet be presented as production-ready confidential computing. The most serious remaining gap is not "does the cluster run"; it does. The gap is whether every privileged write and every policy decision is forced through customer-authored, attested, and non-operator-substitutable inputs. Receipt binding and KBS verify exposure now have concrete deployed mitigations; init ConfigMap authority, signing-service ownership/key custody, API authorization, SSRF, and remaining live infra pinning are the remaining line between a strong POC and a production platform.
