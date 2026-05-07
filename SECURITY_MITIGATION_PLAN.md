# Enclava CAP Security Mitigation Plan

Date: 2026-04-30 (rev15)
Source: `SECURITY_REVIEW.md` (2026-04-25)
Scope: Restore the confidentiality chain end-to-end while preserving the "Heroku for confidential applications" UX.

## Current implementation status (2026-04-30)

This file is both the target architecture and the implementation tracker. The
current code no longer requires the platform signing service to be the active
policy authorization boundary:

- CAP CLI can generate a customer/CI-signed `SignedPolicyArtifact` locally from
  the signed platform-release template bytes, pinned Kata `genpolicy` output,
  the customer-signed deployment descriptor, and the owner-signed org keyring.
- CAP API accepts that artifact on deploy and unlock-mode redeploy, verifies
  the descriptor/keyring chain, requires the submitted keyring to match CAP's
  latest stored org keyring, verifies the artifact with
  `descriptor_signing_pubkey`, verifies the Rego hash against
  `descriptor.expected_kbs_policy_hash`, and writes the signed artifact to
  Trustee. `REQUIRE_CUSTOMER_SIGNED_POLICY_ARTIFACT=true` disables the
  transitional platform signing-service fallback.
- `enclava-init` verifies customer-signed artifacts with the
  descriptor-signing key after it proves descriptor and keyring membership; the
  old platform signing-service public keys are optional fallback keys only.
- The local Trustee fork accepts descriptor-key-signed policy artifacts only
  when the descriptor key is independently configured in Trustee's trust-anchor
  allowlist; a configured platform policy key remains a fallback for legacy
  artifacts.

Remaining blockers before the public M5-strict claim are production release-root
custody, production platform-release publishing, broader production rollout of
the patched Trustee/fork, legacy Trustee-policy fate decisions, storage-level
CAS for resource writes, and full Phase 7 raw SNP/VCEK verification hardening.

## Revision history

- **rev1:** initial plan from discussion.
- **rev2:** addressed plan-review findings (SSRF gap, premature C4 deferral, late C1/C2 scheduling, premature C7 deferral, unsafe Phase-4 rollback, attestation evidence precision, hostname/cert clarification, Trustee policy ownership, TEE-signed unlock receipts).
- **rev3:** grounded all assumptions in the actual codebase (CAP, Trustee, caddy-ingress).
- **rev4:** D6 anchored in SNP `init_data_hash` (not self-claim); M3/M4 split; off-cluster signing replaced sealed-secret; D10 customer-signed deployment intent; CAA + CT replaced false token-scoping.
- **rev5 (this revision):** addresses 7 follow-up findings:
  - **Finding 1: Signing-oracle risk in D9.** Rev4's signing service accepted arbitrary Rego from the API. An operator with cluster root could steal the API's signing-service credentials and submit malicious Rego. **Fix:** signing service does **not** accept arbitrary Rego. Inputs are limited to `(app_id, customer-signed deployment intent, platform release version)`; the service independently reconstructs the Rego from code-reviewed templates baked into the service's container image and signs only the reconstructed text. Operator cannot request arbitrary Rego.
  - **Finding 2: Multi-user org keyring under-specified in D10.** Rev4 had "org accepted-signer pubkeys" but treated them as ordinary API data, which the operator can lie about. **Fix:** add an **owner-signed org keyring** — the org owner's CLI signs `{org_id, members:[{user_id, pubkey, role, ...}], updated_at, version}`; non-owner members verify the keyring's owner signature; first-time encounter is TOFU on the owner pubkey with explicit out-of-band verification. New migration `0020_org_keyrings.sql`.
  - **Finding 3: C11 partial in Phase 0.** Rev4 said Phase 0 makes the billing webhook "safe," but billing intent storage is Phase 10 — until then, the webhook still trusts mutable metadata for tier. **Fix:** mark C11 as **partial** in Phase 0 (signature + replay protection); full fix at Phase 10. Optionally pull the intent migration earlier.
  - **Finding 4: Phase 6 seed lifecycle under-specified.** Rev4 said "workload writes its own seeds" but didn't define first-write semantics, overwrite rules, deletion, rekey. **Fix:** Phase 6 now specifies: first-write-wins (resource creation atomic); overwrites require an attestation match **plus** a Phase 10 TEE-signed transition receipt; deletes only via explicit teardown flow with the same gates; rekey is overwrite + receipt.
  - **Finding 5: CAA `validationmethods` missing.** RFC 8657 adds `validationmethods=http-01,tls-alpn-01` as defense-in-depth. **Fix:** Phase 0 adds this to the CAA records (subject to Let's Encrypt support confirmation in the open decision).
  - **Finding 6: Unlock-receipt steady-state component unspecified.** Phase 10's TEE-signed receipts need a long-running in-TEE signer because `enclava-init` exits. **Fix:** **attestation-proxy** is the steady-state in-TEE signing component (already long-lived per D3, already has per-pod ephemeral key bound in `report_data`). Phase 10 uses attestation-proxy's existing key for receipts. D3 updated.
  - **Finding 7: rev4 still references rev3 content for several phases.** "Unchanged from rev3" makes rev4 not standalone. **Fix:** every phase in rev5 has self-contained content; no cross-revision references for the implementer.
- **rev6 (this revision):** addresses 6 follow-up findings:
  - **Finding 1: Phase ordering bug — Phase 6 (M2) depended on Phase 10 receipts, but Phase 10 ships at Week 11 while M2 reaches at Week 8.** Real logical inconsistency. **Fix:** the receipt-signing *primitive* (attestation-proxy's signing endpoint + per-pod ephemeral key) ships in **Phase 5**, not Phase 10. Phase 6 uses it for rekey/teardown receipts. Phase 10 uses the same primitive for unlock-mode transitions. M2 now reaches when Phase 6 lands, with the primitive already in place from Phase 5.
  - **Finding 2: Signing service trusted platform DB for customer pubkeys.** Under operator-root the DB mirror is operator-controlled — operator swaps pubkeys to authorize malicious intent. **Fix:** signing service maintains its own out-of-band-bootstrapped state mapping `org_id → owner_pubkey`. Customer pubkeys are obtained only via the customer-signed org keyring artifact, which the service verifies against its independently-held owner pubkey. The platform DB is never a trust anchor for pubkeys.
  - **Finding 3: CAP "renders" vs "doesn't compose" Rego contradiction.** D9 said CAP never composes Rego; Phase 3 said CAP renders full policy text. **Fix:** signing service is the sole composer of authoritative Rego. CAP API requests `(app_id, deploy_id, customer-signed intent)` from the signing service, receives `{rego_text, signature}`, verifies the signature, writes via Trustee `set_policy`. CAP never authors Rego.
  - **Finding 4: Cryptographic bindings used ambiguous concatenation.** SNP `report_data` and other transcript hashes used plain `\|\|` concatenation, which is ambiguous if any variable-length field shifts. **Fix:** new section D11 specifies a canonical encoding (versioned domain-separation label + length-prefixed fields + fixed-length hashes) for every transcript hash. Use TupleHash-style construction. No plain concat anywhere in the spec.
  - **Finding 5: Owner key compromise/loss left as open decision.** Owner key is the root of org deployer trust — recovery cannot be left undefined. **Fix:** D10 now specifies threshold-of-owners recovery as primary path; recovery contacts as fallback for single-owner orgs; email-only emergency reset with explicit waiting period (30 days) and audit notifications as last resort. Open decision #15 resolved.
  - **Finding 6: API-key storage hardening missing.** The review's Medium finding (16-bit prefix + Argon2 over candidates) was not in any phase. **Fix:** Phase 10 adds the redesign — 128-bit random lookup prefix + HMAC-SHA256 with server-side pepper for stored verification. Migration path documented.
- **rev7 (this revision):** addresses 8 follow-up findings, two of them critical:
  - **Finding 1 (CRITICAL): signed Rego doesn't protect Trustee/KBS under operator-root.** Current Trustee just stores opaque policy bytes (`trustee/kbs/src/api_server.rs:308`) and evaluates them — no signature verification. An operator with cluster root can write `default allow := true` directly to Trustee, bypassing CAP and the signing service entirely. enclava-init's verification stops *honest* workloads from being deceived but does not stop a *malicious* attested workload (deployed under operator control) from getting seeds. **Fix:** Phase 3 adds Trustee-side enforcement — either an upstream patch that verifies signatures before storing/evaluating policy, or an admission proxy in front of Trustee that does the same. New negative test required: writing an unsigned `allow := true` policy must fail at write time, and if injected directly into storage, must fail at evaluation time.
  - **Finding 2 (CRITICAL): Phase 6 requires Trustee features that don't exist.** Trustee's workload-resource policy input has only `method`, `path`, `query` — no body, no body hash, no Ed25519 verification (`trustee/kbs/src/api_server.rs:446`). Storage backends overwrite unconditionally (`trustee/kbs/src/plugins/implementations/resource/kv_storage.rs:35`). So "first-write-wins" and "rekey requires receipt" are unenforceable today. **Fix:** Phase 6 prerequisite work — add to Trustee: conditional writes (check-and-set on resource existence), request body inclusion in policy input, in-policy Ed25519 verification of receipt signatures, delete authorization. This is upstream work; ~1.5 weeks added to Phase 6 calendar.
  - **Finding 3 (HIGH): Phase 0 disables tenant Cloudflare secret generator while pods still mount the secret.** Today Caddy always renders DNS-01 config (`ingress.rs:50`) and the pod always mounts `tls-cloudflare-token` (`volumes.rs:56`). Disabling the generator in Phase 0 without gating Caddy's DNS provider and the volume mount breaks every deploy. **Fix:** the Caddy HTTP-01 cutover (formerly Phase 8) merges into Phase 0. Phase 0 now does the full token-removal path end-to-end. Phase 8 becomes a verification phase only.
  - **Finding 4 (HIGH): Phase 2 / Phase 3 conflict on Rego ownership.** Phase 2 had CAP render Rego locally; Phase 3 then handed authorship to the signing service. **Fix:** signing service is authoritative from Phase 2 onwards. Phase 2 = define the Rego template (committed in the signing-service repo) + add CAP API client to call signing service for artifacts + Kata fail-closed + safe encoding. CAP never renders Rego in any phase.
  - **Finding 5 (HIGH): canonical encoding inconsistent.** D11 says CE-v1 length-prefixed for everything, but Phase 7 said "CBOR with cbor4ii" for intent encoding, and several pseudocode blocks still use `\|\|` concat. **Fix:** CE-v1 is the only encoding in the plan. Remove CBOR references; replace all `\|\|` constructions with `ce_v1_hash(...)` calls.
  - **Finding 6 (MEDIUM): TEE TLS handshake spec is implicit.** Need explicit ordering of: nonce generation, leaf-key creation, cert delivery to CLI, REPORT_DATA encoding into 64 bytes. **Fix:** Phase 5 adds a "Handshake protocol" subsection with step-by-step ordering and the exact REPORT_DATA padding rule (CE-v1 hash → 32 bytes; right-padded with 32 zero bytes to fill SNP's 64-byte field).
  - **Finding 7 (MEDIUM): sigstore-rs `KeylessVerifier` is fictional.** Vendored sigstore 0.13 has `Verifier` with `CertificateSubjectFilter` / `CertificateIssuerFilter` instead. **Fix:** Phase 9 references the actual API path; trust-root setup spelled out.
  - **Finding 8 (MEDIUM): emergency email reset weakens the M5 crypto claim.** D10's email-reset branch lets the signing service accept a new owner key after a 30-day delay — that's a platform/signing-service trust path, not a pure crypto guarantee. **Fix:** M5 description distinguishes "M5-strict" (no email reset enabled) from "M5-with-recovery-reset" (email reset opt-in). Public-facing message clarifies which mode an org is in.
- **rev8 (this revision):** addresses 8 follow-up findings, 2 critical and 3 high. The critical findings collapse to one underlying gap: **not enough deployment metadata is bound by the customer signature**, so the signing service is forced to derive Rego slots from operator-controlled state.
  - **Finding 1 (CRITICAL): Customer-signed intent doesn't bind enough deployment metadata.** D10's intent omits org_id/slug, app name, namespace, service account, TEE domain, KBS resource path, identity hash. The Rego template needs all of these. Without binding them in the signed artifact, the signing service has to take them from somewhere — and the only legitimate source is signed customer data plus release constants. **Fix:** D10 expands `DeploymentIntent` → `DeploymentDescriptor` covering the full app spec; the signing service derives every Rego slot from the verified descriptor + signed `platform-release.json` constants only. New canonical encoding for the descriptor in D11.
  - **Finding 2 (CRITICAL): Same-image malicious spec mutation possible.** Today the customer signs `image_digest` but not the OCI runtime config (command, args, env, mounts, capabilities, ports, securityContext). An operator can run the customer's signed image with attacker-chosen args/env and still satisfy image-digest policy (`crates/enclava-engine/src/manifest/containers.rs:96` already composes command separately from digest). **Fix:** `DeploymentDescriptor` includes the full OCI runtime spec; the **Kata agent policy** validates the actual `CreateContainerRequest` OCI fields byte-for-byte against the signed spec; the **KBS Rego** checks `init_data_claims.oci_spec_hash` matches the signed value. Operator can't substitute args/env even with the right image.
  - **Finding 3 (HIGH): Phase 3 admission-proxy fallback isn't valid for M1/M5.** Firewall/NetworkPolicy is not a security boundary against operator-root. **Fix:** Option A (Trustee patch) is the only path to M1/M5; Option B (admission proxy) is acceptable only as transitional with milestones explicitly marked "not cryptographically enforced."
  - **Finding 4 (HIGH): Phase 6 receipt pubkey not bound to attestation.** Rev7 said `crypto.ed25519.verify(input.tee.snp.receipt_pubkey, ...)` but SNP `report_data` carries a 32-byte hash, not a pubkey. **Fix:** the request envelope carries the receipt pubkey; Rego computes `sha256(receipt_pubkey)` and compares to the hash anchored in `report_data` *before* calling `crypto.ed25519.verify`. Negative test for forged-body-pubkey rejection.
  - **Finding 5 (HIGH): Phase 0 ACME ambiguity.** HTTP-01 needs port 80; TLS-ALPN-01 needs only 443. Plan kept both as options. **Fix:** lock to **TLS-ALPN-01 only**. CAA `validationmethods=tls-alpn-01`. Drops the HAProxy port-80 routing requirement entirely (open decision #11 closed).
  - **Finding 6 (MEDIUM): stale contradictions.** D8 shows plain concatenation; Phase 6 says "no upstream changes needed" before listing patches; Phase 3 header says 2 weeks, footer says 1 week. **Fix:** all three reconciled inline.
  - **Finding 7 (MEDIUM): Phase 9 sigstore-rs API still wrong.** Vendored sigstore 0.13 doesn't have `CertSubjectEqualVerifier` / `CertIssuerEqualVerifier`. Real types: `CertSubjectUrlVerifier`, `CertSubjectEmailVerifier`, `CertificateVerifier`, `PublicKeyVerifier`. **Fix:** use `CertSubjectUrlVerifier { url, issuer }` for GitHub Actions OIDC.
  - **Finding 8 (MEDIUM): enclava-init can't read active policy text.** Trustee's `GET /resource-policy` returns `list_policies()`, not the policy body. **Fix:** the Trustee signed-policy patch (Phase 3) must add a `GET /resource-policy/<id>/body` endpoint returning the signed envelope, OR the enclava-init in-TEE verification requirement is dropped (and we rely on the write-time + evaluation-time enforcement only).
- **rev9 (this revision):** addresses 6 follow-up findings, 1 critical:
  - **Finding 1 (CRITICAL): receipt pubkey binding was unrecoverable.** Rev8 packed both `leaf_spki_sha256` and `receipt_pubkey_sha256` into a single CE-v1 hash that filled REPORT_DATA[0..32]. That's a one-way function — Trustee cannot extract `receipt_pubkey_sha256` from it, so the Phase 6 receipt-verification chain (which compares `sha256(body.receipt_pubkey)` to an attested pubkey hash) had nothing to compare against. **Fix:** new layout puts `receipt_pubkey_sha256` directly in REPORT_DATA[32..64] (recoverable) and the transcript hash in REPORT_DATA[0..32] (binds domain/nonce/leaf_spki only). Trustee SNP-claim patch exposes `receipt_pubkey_sha256` as a structured claim. CLI verification updated to re-derive transcript hash and compare bytes 0..32, then compare receipt_pubkey_sha256 against bytes 32..64.
  - **Finding 2 (HIGH): enclava-init's policy-read endpoint required admin auth.** Workload pods cannot carry Trustee admin credentials. **Fix:** the new `GET /resource-policy/<id>/body` endpoint is **workload-attested and resource-scoped** — accepts the same attestation token Trustee already uses for workload-resource reads, and returns the policy body only for resources whose Rego policy the workload's attestation actually satisfies (i.e., the workload can read its own policy and nothing else).
  - **Finding 3 (HIGH): DeploymentDescriptor not threaded through later phases.** D9, Phase 2, and Phase 7 still reference `customer_intent_blob` / `DeploymentIntent` in places. **Fix:** descriptor terminology and field references propagated through every interface and verifier.
  - **Finding 4 (HIGH): OCI validation in Kata policy was hand-wave.** Rev8 said "Rego canonicalizes CreateContainerRequest" — that's not a real implementation strategy. **Fix:** use **kata-containers/genpolicy** as the established mechanism. The signing service runs `genpolicy` against the customer-signed `oci_runtime_spec` to produce a complete agent policy that compares specific fields directly (no Rego-side canonicalization needed). The generated policy is signed and shipped in cc_init_data. Plain Rego field comparisons at runtime; no custom built-ins.
  - **Finding 5 (MEDIUM): receipt envelope contract inconsistent.** Text said the envelope carries `receipt_pubkey` but the JSON shape didn't include it; `body_canonical_bytes` was referenced but not defined. **Fix:** envelope now explicitly: `{operation, receipt:{pubkey:<32B>, payload_canonical_bytes:<CE-v1>, signature:<64B>}, value?:<bytes>}`.
  - **Finding 6 (MEDIUM): stale rev7/rev8 text.** Phase 8 still mixed HTTP-01/TLS-ALPN; Rollout still labeled rev7; sigstore pseudocode used `client.verify_constraints` (method) but in sigstore 0.13 it's a free function. **Fix:** all three corrected inline.
- **rev10 (this revision):** addresses 6 follow-up findings, 2 high. Rev9 inadvertently introduced new specification gaps; rev10 closes them.
  - **Finding 1 (HIGH): Phase 6 Rego depended on undefined builtins (`sha256`, `ce_v1_extract_field`).** Trustee's workload-policy input is currently just `{method, path, query}` with no extensions. Rev9 wrote Rego rules that called `sha256(...)` and `ce_v1_extract_field(...)` which don't exist as `regorus` builtins. **Fix:** all the heavy lifting moves into Trustee Rust code — Trustee parses the request body JSON, extracts `body.receipt.{pubkey, payload_canonical_bytes, signature}`, computes `sha256(receipt.pubkey)`, computes `sha256(value)` for rekey, performs Ed25519 verification, and exposes typed booleans/fields as policy-input. Rego then uses simple `==` comparisons. The only Rego built-in needed is `crypto.ed25519.verify` (already in the Phase 6 patch list); even that may not be needed since Trustee can pre-compute the verification result and expose `input.request.body.receipt.signature_valid: bool`.
  - **Finding 2 (HIGH): public-key hash encoding inconsistent.** `leaf_spki_sha256` and `receipt_pubkey_sha256` are referenced in different sections with different implied byte representations (PEM text vs DER vs raw 32-byte). **Fix:** lock the encodings:
    - `leaf_spki_sha256` = `SHA256(DER-encoded SubjectPublicKeyInfo)` — the standard "SPKI fingerprint" used by HPKP, certificate transparency, etc. The TLS leaf cert's SPKI is extracted via `webpki` or `rustls`'s parsed cert.
    - `receipt_pubkey_sha256` = `SHA256(raw 32-byte Ed25519 public key)` — the canonical Ed25519 encoding (RFC 8032 §5.1.5) is exactly 32 bytes.
    - Bundle fields are renamed: `tls_pubkey_pem` → `tls_pubkey_spki_der` (DER bytes); `receipt_pubkey_pem` → `receipt_pubkey_raw` (32 raw bytes). These are now what's hashed.
  - **Finding 3 (MEDIUM): descriptor's `expected_cc_init_data_hash` not enforced.** The verifier checks `HOST_DATA == SHA256(cc_init_data_toml)` (anchors attestation→bytes) but never compares the result to the customer's signed `descriptor.expected_cc_init_data_hash`. **Fix:** add `require_eq!(descriptor.expected_cc_init_data_hash, snp.host_data)` — chains customer's authorized hash to the attested hash. Phase 2's cc_init_data does NOT include `oci_spec_hash` as a self-referential field; instead, **genpolicy alone owns OCI enforcement at runtime**: cc_init_data carries the genpolicy-rendered agent policy, the SNP HOST_DATA chains attestation to that policy text, and the policy itself enforces field-by-field comparisons against the actual `CreateContainerRequest`. The descriptor's `oci_spec_hash` field is removed (was redundant with the genpolicy text being included in cc_init_data — cc_init_data_hash already commits to it transitively).
  - **Finding 4 (MEDIUM): in-TEE policy verification too narrow.** `enclava-init` verified signed policy text only against `(image_digest, init_data_hash, signer_identity)`; the rev9 descriptor binds many more fields (namespace, SA, identity hash, sidecars, runtime class, KBS resource path). **Fix:** the signed policy envelope now includes `(app_id, descriptor_hash, descriptor_signing_pubkey, signed_at)` as authenticated metadata. `enclava-init` reads the signed policy, verifies the signing-service signature, then verifies that the metadata's `descriptor_hash` matches the descriptor it was launched with (descriptor reference + its signature + the org-keyring fingerprint are part of cc_init_data so enclava-init can independently verify the chain). End-to-end: descriptor signed by deployer → signing service verifies + renders policy → policy envelope binds back to descriptor_hash → enclava-init verifies both.
  - **Finding 5 (MEDIUM): stale "intent" references in normative sections.** Multiple executable sections still say "intent" where rev9 requires "descriptor." Replaced throughout; only the DB table name (`deployment_intents`) is left as legacy migration detail.
  - **Finding 6 (LOW): rollout total conflict.** Rollout said ~13–14 weeks / M5 at Week 11; Effort Summary said ~12–13 weeks / M5 at Week 10. **Reconciled:** authoritative numbers are **~13 weeks single engineer; M5 reaches end of Week 11.** Phase 0 Weeks 1–2, then Phase 1 Week 3, etc. (See updated Rollout Strategy table.)
- **rev11 (this revision):** addresses 5 follow-up findings from review of rev10 (3 high, 2 medium):
  - **Finding 1 (HIGH): cc_init_data ↔ descriptor hash cycle.** Rev10 had the descriptor sign `expected_cc_init_data_hash` AND had cc_init_data carry `descriptor_hash` + `descriptor_signature`. The descriptor's hash (over its full canonical bytes) depends on `expected_cc_init_data_hash`, which equals `SHA256(cc_init_data_toml)`, which contains `descriptor_hash` and `descriptor_signature`. Self-referential and unrenderable. **Fix:** introduce a **`descriptor_core_hash`** = CE-v1 hash over the descriptor's canonical bytes **excluding** `expected_cc_init_data_hash` and `expected_kbs_policy_hash`. cc_init_data carries `descriptor_core_hash` (cycle-free), `descriptor_signing_pubkey`, and `org_keyring_fingerprint` — but **not** the descriptor's full signature. enclava-init reads the active descriptor + its signature out-of-band from the platform DB at unlock; verifies `compute_descriptor_core_hash(read_descriptor) == cc_init_data.descriptor_core_hash` (operator can't substitute different core fields), then verifies the full descriptor signature against the cc_init_data-bound signing pubkey. Two unidirectional chains: forward (descriptor.expected_*_hash → cc_init_data + KBS policy) and backward (cc_init_data → descriptor_core); no field commits in both directions.
  - **Finding 2 (HIGH): Phase 6 still contained the rev9 impossible-Rego path.** Rev10's bullet 3 correctly moved hashing/Ed25519 verification into Trustee Rust, but the receipt-envelope-contract bullet (5) still said Rego runs `crypto.ed25519.verify` and `sha256(...) == ce_v1_extract_field(...)` — undefined `regorus` builtins, directly contradicting bullet 3 and reopening the issue rev10 was supposed to close. **Fix:** rewrite bullet 5 to match bullet 3. Trustee Rust parses the body JSON, computes all hashes, performs Ed25519 verification, and exposes only typed fields plus pre-computed booleans (`pubkey_hash_matches`, `signature_valid`, `value_hash_matches`) to Rego. Rego rules use `==` only. Remove `crypto.ed25519.verify` from the Trustee patch list — no longer needed.
  - **Finding 3 (HIGH): cc_init_data claims missing fields the Phase 7 verifier requires.** Phase 2's `[data]` table listed only `image_digest`, `signer_identity`, `sidecar_digests`, `runtime_class`, but the Phase 7 verifier (line 1046–1048 of rev10) checks `claims.namespace`, `claims.service_account`, and `claims.identity_hash`. Either the verifier asserts on undefined fields or those values are sourced from operator-controlled state. **Fix:** add `namespace`, `service_account`, and `identity_hash` to cc_init_data's `[data]` table. The Phase 2 Rego template already references them via `input.kubernetes.{namespace, service_account}` and `input.identity_hash`; cc_init_data now provides them so the SNP `init_data_hash` anchor extends to those fields too. M4 needs them anchored to attestation, not fetched from API.
  - **Finding 4 (MEDIUM): Trustee SNP claim path not locked.** Plan references `input.snp.init_data_hash` throughout, but local Trustee at `trustee/deps/verifier/src/snp/mod.rs:623` exposes the claim as `init_data` (mapped from `report.host_data`). Every Rego rule referencing `input.snp.init_data_hash` evaluates to `undefined`, and `default allow := false` then denies silently — looks like correct behavior in negative tests but actually means *no policy ever passes*. **Fix:** add an explicit Trustee SNP-claim patch to Phase 3's patch list — alias or rename the claim to `init_data_hash` so the field path the plan uses actually exists at evaluation time. Adds ~half a day to the Phase 3 Trustee work.
  - **Finding 5 (MEDIUM): "intent" terminology in normative sections.** Despite rev9/rev10 mandating "descriptor," normative implementation text still said "intent" in: M4 milestone definition, Phase 7 heading and goal, CLI unlock-flow steps, Phase 7 test list, Phase 12 integration test list, Rollout table, and "5 hard interfaces" list. The old thin intent shape was the source of two prior CRITICAL findings (rev8 #1 and #2). **Fix:** replace throughout. Reserved for legacy use only: the `deployment_intents` DB table name (kept for migration compatibility), the unrelated "billing intent" concept (Phase 0/10 webhook tier), and historical revision-log entries documenting how the term evolved.
- **rev12 (this revision):** addresses 5 follow-up findings from review of rev11 (2 high, 2 medium, 1 low):
  - **Finding 1 (HIGH): Rego still reads `input.kubernetes.{namespace, service_account}` and `input.identity_hash` despite rev11 putting those values in cc_init_data.** Local Trustee's token-transform broker (`trustee/attestation-service/src/ear_token/broker.rs:459`) exposes verified init data via `init_data_claims`, not via Kubernetes-attested claims. Rego rules that reference `input.kubernetes.*` evaluate against an empty/operator-influenceable structure, not against attestation. **Fix:** the Phase 2 Rego template references `input.init_data_claims.{namespace, service_account, identity_hash}` (single anchor: SNP `init_data_hash` → cc_init_data → `init_data_claims`). The `input.kubernetes.*` path is dropped from the plan; if Trustee's k8s-evidence claim path is desired later as defense-in-depth, it ships as a separate explicit Trustee transform with its own tests, not implicitly.
  - **Finding 2 (HIGH): the signed policy envelope's authenticated metadata is not actually signed.** Phase 3 enclava-init verifies metadata `(app_id, descriptor_core_hash, descriptor_signing_pubkey, signed_at)` against the cc_init_data values, but D9 and Phase 3 still define the signed artifact as `{rego_text, signature, key_id, signed_at}` — the signature is over the Rego text only, so the metadata could be swapped at rest by the operator without breaking the signature. **Fix:** define the artifact explicitly:
    ```
    SignedPolicyArtifact {
        metadata: {
            app_id: UUID,
            deploy_id: UUID,
            descriptor_core_hash: 32 bytes,
            descriptor_signing_pubkey: 32 bytes,
            platform_release_version: String,
            signed_at: RFC3339,
            key_id: String,                    // signing-service key version
        },
        rego_text: String,                    // the rendered policy
        signature: 64 bytes,                  // Ed25519 over CE-v1(metadata, sha256(rego_text))
    }
    ```
    The signing service builds `sign_input = ce_v1_hash([("purpose","enclava-policy-artifact-v1"), ("metadata", canonical_metadata_bytes), ("rego_sha256", sha256(rego_text))])` and signs that. Verifiers (CAP API, Trustee, enclava-init) reconstruct `sign_input` from the wire-format and check the signature. New CE-v1 binding listed in D11; rev10/rev11 references to bare `{rego_text, signature, key_id, signed_at}` updated.
  - **Finding 3 (MEDIUM): enclava-init does not independently verify the forward descriptor → cc_init_data hash.** Rev11's chain relied on the Phase 7 CLI verifier to check `descriptor.expected_cc_init_data_hash == SHA256(cc_init_data_toml)`. But CLI verification is for the unlock channel; the seed-release decision is made by enclava-init inside the TEE, where the CLI's check has no force. Without an in-TEE forward-chain check, an operator-substituted descriptor with mismatched `expected_cc_init_data_hash` would still satisfy enclava-init's backward-chain check (`descriptor_core_hash` would still match). **Fix:** add an explicit step to the in-TEE verification list — after verifying the full descriptor signature, enclava-init also asserts `descriptor.expected_cc_init_data_hash == SHA256(cc_init_data_toml_local)`. This closes the chain *inside* the TEE rather than relying on the CLI.
  - **Finding 4 (MEDIUM): D3 and D5 still describe Caddy as ACME HTTP-01 despite rev8/rev9 locking to TLS-ALPN-01 only.** Phase 0 says TLS-ALPN-01 only; D3 pod-layout diagram and D5 TLS-strategy split still say HTTP-01. Implementer following the architecture decisions would build an HTTP-01 path that contradicts the rest of the plan. **Fix:** D3 and D5 updated to TLS-ALPN-01.
  - **Finding 5 (LOW): stale rev/index text.** Header said `(rev10)`; verification index claimed Trustee exposes `init_data_hash` while rev11 correctly recorded that local Trustee exposes `init_data` (the rename is part of the Phase 3 Trustee patch); Rollout table row for the Trustee-receipts patch still listed "Ed25519 in Rego" even though rev11 moved Ed25519 verification into Trustee Rust. **Fix:** header updated to `(rev12)`; verification index annotates the current `init_data` exposure with the rename plan; Rollout row reads "body-in-policy + receipt verification in Trustee Rust."
- **rev13 (this revision):** addresses 5 follow-up findings from review of rev12 (1 high, 3 medium, 1 low):
  - **Finding 1 (HIGH): KBS policy-template provenance not pinned end-to-end.** Rev12 has the customer's CLI compute `expected_kbs_policy_hash` by rendering the same Rego template as the signing service, but never defines how the CLI obtains a signed, versioned, hash-pinned copy of that template. The signing service could substitute a different template version that hashes the same way for a given descriptor (collision-search domain) or simply use a different template than the customer rendered against; the customer signature would still verify. **Fix:** add `policy_template_id` (string) and `policy_template_sha256` (32 bytes) to:
    - The signed `platform-release.json` artifact bundled with the CLI (canonical bytes signed by the platform-release signing key; CLI verifies on first read and pins).
    - `descriptor_core_canonical_bytes` (deployer commits to which template the platform must use).
    - `SignedPolicyArtifact.metadata` (signing service confirms it used that exact template version).
    - In-TEE verification additionally asserts `descriptor.policy_template_id == metadata.policy_template_id` and `descriptor.policy_template_sha256 == metadata.policy_template_sha256`, and that the same `policy_template_sha256` matches the signed `platform-release.json` value the workload booted under.
  - **Finding 2 (MEDIUM): enclava-init artifact-retrieval path underspecified.** Phase 3 said the TEE reads the active descriptor, descriptor signature, and org keyring "from the platform DB," but the workload pod has no DB credentials and shouldn't carry admin tokens. **Fix:** define a **read-only workload artifact endpoint** on CAP API: `GET /api/v1/workload/artifacts/<app_id>` returning `{descriptor_payload, descriptor_signature, descriptor_signing_key_id, org_keyring_payload, org_keyring_signature, signed_policy_artifact}` as opaque blobs. **No authentication required** — every blob is signed and verified locally inside the TEE; an operator who tampers with the response only causes verification failure (deny-of-service, not bypass). The endpoint is reachable from the tenant pod via the cluster-internal Service. Adds one route to Phase 3's CAP API surface.
  - **Finding 3 (MEDIUM): SignedPolicyArtifact metadata compared to the wrong anchor.** Rev12's Phase 3 step 5 said `metadata.{app_id, descriptor_core_hash, descriptor_signing_pubkey}` must match cc_init_data, but cc_init_data carries `descriptor_core_hash`, `descriptor_signing_pubkey`, `org_keyring_fingerprint` — not `app_id`. Also `deploy_id` and `platform_release_version` are signed metadata but never explicitly compared. **Fix:** correct the comparison sources:
    - `metadata.app_id == descriptor.app_id` (against the verified descriptor, which carries app_id)
    - `metadata.deploy_id == descriptor.deploy_id` (likewise)
    - `metadata.descriptor_core_hash == cc_init_data.descriptor_core_hash`
    - `metadata.descriptor_signing_pubkey == cc_init_data.descriptor_signing_pubkey`
    - `metadata.platform_release_version == descriptor.platform_release_version` (new descriptor-core field; rev13 adds it so the customer signs over which platform release they targeted, allowing this check to be meaningful)
    - `metadata.policy_template_id == descriptor.policy_template_id` and `metadata.policy_template_sha256 == descriptor.policy_template_sha256` (rev13 finding #1)
  - **Finding 4 (MEDIUM): seed DELETE authorization wording inconsistent.** Phase 6's lifecycle table said delete requires "API admin role + Trustee Rego attestation match," but the actual Trustee patch later in the same phase (and the receipt envelope contract) requires DELETE to be authorized by the workload's attestation token plus a TEE-signed teardown receipt — not by API admin. **Fix:** rewrite the lifecycle row: "CAP admin **initiates** teardown via the API (orchestrates pod state transitions, marks app `teardown_pending`); Trustee `DELETE /workload-resource/...` itself is authorized only by attested workload identity + TEE teardown receipt — admin tokens cannot bypass the workload-attested gate."
  - **Finding 5 (LOW): SignedPolicyArtifact signing-input bytes ambiguous.** Rev12's prose said "Ed25519 over CE-v1(metadata, sha256(rego_text))" but the pseudocode wrote `sign_input = ce_v1_hash(...)`. `ce_v1_hash` returns the 32-byte SHA-256 of the CE-v1 records — not the records themselves — so signer and verifier could disagree on whether Ed25519 is signing the variable-length raw bytes or the 32-byte hash output. **Fix:** specify exactly. **Ed25519 signs the raw CE-v1 bytes** (the TLV-encoded records, NOT the 32-byte SHA-256 hash). RFC 8032 PureEd25519 internally hashes with SHA-512; pre-hashing with SHA-256 would be wasteful and ambiguous. Add a new D11 helper `ce_v1_bytes(records) -> Vec<u8>` that returns the raw encoded message; `ce_v1_hash` remains defined as `sha256(ce_v1_bytes(records))` for cases where a 32-byte hash is needed (e.g., for embedding in REPORT_DATA). All Ed25519 signatures in the plan (descriptor signature, receipt signatures, policy-artifact signature, recovery directives, keyring signatures) sign the **raw CE-v1 bytes**. Phase 3 acceptance criteria adds: signer + verifier reference test vectors committed to the policy-templates repo.
- **rev14 (this revision):** addresses 5 follow-up findings from review of rev13 (1 high, 2 medium, 2 low):
  - **Finding 1 (HIGH): rev13 pinned the template hash but never shipped the template bytes.** The CLI is supposed to render the Rego template to compute `expected_kbs_policy_hash`, but rev13 only made `policy_template_sha256` available — a hash cannot render a template. **Fix:** ship the **canonical template bytes** alongside the hash, in two places:
    - The signed `platform-release.json` artifact (bundled with the CLI) gains a `policy_template_text: String` field. The platform-release signature commits to it, so the CLI can verify `sha256(platform_release.policy_template_text) == platform_release.policy_template_sha256` on first read and refuse to use mismatched releases.
    - The signing service performs the same self-check at startup against its baked-in template (loaded from the `policy-templates` repo at image build time): `sha256(baked_template_text) == release_pin.policy_template_sha256`. Mismatch → service refuses to start.
    - The descriptor's `policy_template_sha256` field, the `SignedPolicyArtifact.metadata.policy_template_sha256` field, and the platform-release's hash all chain to the same template bytes. CLI, signing service, and enclava-init all reach the same `expected_kbs_policy_hash` because they all see the same canonical text.
  - **Finding 2 (MEDIUM): unauthenticated workload artifact endpoint creates cross-tenant disclosure risk.** Rev13's `GET /api/v1/workload/artifacts/<app_id>` returned descriptor + keyring + signed policy artifact without auth. Signatures protect integrity, not confidentiality, and the descriptor's OCI runtime spec contains env vars, mount paths, custom domains, app names — disclosure to anyone with an app_id is a real risk (env vars in particular often hold non-secret-but-sensitive config like database hostnames, feature flags, ratio knobs). **Fix:** make the endpoint **workload-attested and scoped by `descriptor_core_hash`**:
    - Endpoint: `GET /api/v1/workload/artifacts` (no path-segment app_id; the app_id leaks tenant identifiers cross-cluster otherwise).
    - Required header: `Authorization: Attestation <kbs_attestation_token>` — the SAME token the workload presents to Trustee for KBS resource reads. CAP API delegates token validation to a Trustee callback (`POST /kbs/v0/attestation/verify`) and receives back the attested SNP claims, including the parsed `init_data_claims` from cc_init_data.
    - CAP API extracts `init_data_claims.descriptor_core_hash` from the validated attestation; looks up the artifacts row whose `descriptor_core_hash` matches; returns that bundle and only that bundle. An attacker without an actual TEE workload booted with the matching cc_init_data cannot fetch — there is no way to forge `init_data_claims` without an SNP signature.
    - Standard rate-limit middleware still applied (per-IP + per-attestation-fingerprint).
    - Effect: only the attested workload that booted with descriptor X can fetch descriptor X's artifacts. Cross-tenant disclosure becomes cryptographic, not organizational.
  - **Finding 3 (MEDIUM): in-TEE org-keyring trust anchor wording was wrong.** Step 4 said the keyring's owner-signature is "anchored separately by org-keyring TOFU." TOFU is a CLI concept — `enclava-init` is an ephemeral container with no persistent state and no out-of-band channel; it cannot perform TOFU. The actual in-TEE anchor is different and stronger:
    - Step 4a: enclava-init computes the CE-v1 fingerprint of the received keyring bytes and asserts `fingerprint == cc_init_data.org_keyring_fingerprint`. This pins the **exact keyring bytes** to attestation — anchored via SNP `HOST_DATA`, not via TOFU.
    - Step 4b: the `SignedPolicyArtifact` (whose signature was already verified in step 5 against the platform-release-pinned signing-service pubkey) implicitly proves the signing service accepted the keyring against its own sovereign owner-pubkey state — the signing service refuses to issue a `SignedPolicyArtifact` for any descriptor whose deployer pubkey isn't in a keyring that owner-signature-verifies against its bootstrapped owner key. So if the policy artifact verifies, the keyring was acceptable to the signing service.
    - There is no TOFU step in enclava-init, and the owner pubkey itself is never directly trusted in the TEE — only the (keyring fingerprint) → (signing service authorization) chain. **Fix:** replace step 4's wording.
  - **Finding 4 (LOW): metadata canonicalization naming is misleading.** D9 prose says `canonical_metadata_bytes` (suggesting raw bytes); D11 defines `canonical_policy_metadata_bytes` (rev12) as a 32-byte CE-v1 hash used as a record value. Both names suggest raw bytes; the value is actually a hash. Implementer reading the pseudocode could pass raw bytes and break interop. **Fix:** rename throughout to **`canonical_policy_metadata_hash`** (it's a hash, not raw bytes); D11 row updated.
  - **Finding 5 (LOW): footer sections still labeled rev10/rev9.** Rollout Strategy header, Open Decisions header, Effort Summary header, and Confidence statement header all still say "(rev10)" or reference rev9 in column headings. **Fix:** bump to rev14 throughout (and add brief notes for any meaningful change since rev10).
- **rev15 (this revision):** implements the pragmatic customer/CI-signed policy-artifact path. The descriptor signing key can now sign the final Trustee artifact directly after local `genpolicy` and template rendering. CAP verifies the keyring/descriptor chain and Rego/agent-policy hashes before writing to Trustee. `enclava-init` verifies descriptor-key signatures first and keeps platform keys as compatibility fallbacks; Trustee accepts descriptor-key signatures only when that descriptor key is independently configured as a Trustee trust anchor. This removes the platform signing service from the steady-state authorization boundary while keeping `/sign` available for transition and test environments.

## Implementation Status (living section — update on every PR merge)

**Last updated:** 2026-04-30 — PRs #2/#3/#4 merged; follow-up implementation closed the signed-policy write path, explicit cc_init_data claims, CAP/CLI runtime descriptor parity, attestation-proxy REPORT_DATA binding, tenant well-known routing, workload teardown, unlock-mode receipt verification/persistence, signed platform-release consumption, generated Kata agent-policy wiring, and the pragmatic customer/CI-signed policy-artifact path. The signing service exposes `/agent-policy`, signed artifacts carry `agent_policy_text` plus its hash/version pin, the CLI can sign final `SignedPolicyArtifact` envelopes with the descriptor key, CAP API accepts those artifacts on deploy and unlock-mode redeploy, and enclava-init verifies descriptor-key signatures before platform fallbacks. cap-test01 is cut over to the signed-policy/artifact path with `TRUSTEE_POLICY_READ_AVAILABLE=true`, signed-policy enforcement in Trustee, a CAP-managed signed `resource-policy` artifact, sidecar cosign verification over GitHub Actions OIDC-signed GHCR sidecar digests, tenant Flux removed, ops Flux controllers scaled to zero, and repo-owned GHCR images instead of `ttl.sh`. The live CAP API is `ghcr.io/enclava-ai/enclava-api@sha256:8ae3bb73369c974dd1b9ff8a5b8b54a7bdcf7078f5e2aae2cc04e2b73fbd3b0f`, the live enclava-init image env is `ghcr.io/enclava-ai/enclava-init@sha256:1505f3095e0b677a1a85db1faebea96233837ec4822f3265d3745e2440c16e5e`, the live Trustee KBS image is `ghcr.io/enclava-ai/trustee-kbs-grpc-as@sha256:f874e261992243f35cd3d1740ed38ab78d116cf827d13844c60acacf1eadb4af`, and the off-cluster validation signer at `http://10.0.0.2:18080` is `ghcr.io/enclava-ai/policy-signing-service@sha256:1f812ee51303313fef97506a1eec2316b55cd555783f7802c82f4d849d15a11b`. The signer health reports Kata `genpolicy` 3.28.0 commit pin `kata-containers/genpolicy@3.28.0+660e3bb6535b141c84430acb25b159857278d596`. Remaining production blockers are release-root custody, production platform-release publishing, durable signer key custody/deployment target or full customer/CI `/agent-policy` replacement, Trustee upstream/fork ownership, production policy for customer descriptor keys as Trustee trust anchors, legacy policy fate decisions, and storage-level CAS hardening.

PR #1 shipped Phases 0/1/4/9 plus pre-merge review fixes. PR #2 shipped Phase 11 + Phase 7 CLI groundwork. PR #3 shipped the Phase 5 `enclava-init` fresh pass. PR #4 shipped the post-review Phase 5/11 fixes. **M0 partial + M3 reached; cap-test01 validates the M1/M2/M4 plumbing, but durable production claims still need release provenance, key custody, upstream/fork ownership, template fate decisions, and CAS hardening.**

### Phase status

| Phase | Status | What's done | What's left |
|---|---|---|---|
| 0 | PARTIAL | env-var gates, SSRF-defended outbound HTTP, SA automount disabled, JWT iss/aud/typ/jti, webhook MAC + replay (`processed_webhooks`), server-side billing intent fields, NIP-98 payload-tag helper, trusted-proxy rate limiter, env-driven CORS allowlist, tenant TLS-ALPN-only Caddyfile, no tenant Cloudflare secret path, no-DNS-plugin `caddy-ingress`, tenant-manifest template cutover, CT monitoring script/runbook, legacy `flowforge-1` overlay retired, stale legacy CAP/flowforge namespaces deleted | **Production cutover ops:** publish CAA records (`accounturi` + `validationmethods=tls-alpn-01`), roll the signed GHCR no-DNS caddy-ingress path beyond cap-test01, and schedule CT monitoring. |
| 1 | DONE | Migrations 0010–0020, CE-v1 helpers (D11), validators, hostname helpers, identity hash migrated to CE-v1 | — |
| 2 | PARTIAL | Local sibling `../policy-templates` now has a v1 Rust signing service: CE-v1 bytes, descriptor/keyring canonicalization, durable SQLite owner store, `/agent-policy`, `/sign`, signed metadata, artifact verification, deterministic vector, docs, CI, and a real Kata `genpolicy` adapter. The signing-service image bakes checksum-verified `kata-tools-static-3.28.0-amd64.tar.zst`, passes explicit `rules.rego`/settings paths, refuses unpinned genpolicy labels at startup, and runs `genpolicy` before signing the KBS artifact. Signed artifacts now include the generated Kata agent policy text, hash, and genpolicy version pin. CAP deploy and unlock-mode redeploy paths require `customer_descriptor_blob` + `org_keyring_blob` whenever signed-policy/signing-service infrastructure is configured, and can now accept customer/CI-generated `signed_policy_artifact` envelopes signed by the descriptor key. CAP verifies descriptor/keyring authority, matches the submitted keyring to CAP's latest org keyring, verifies the artifact signature with `descriptor_signing_pubkey`, verifies KBS Rego and generated-agent-policy hashes, persists descriptor/keyring/policy artifacts in `workload_artifacts`, carries explicit descriptor/keyring/identity claims into cc_init_data, and renders `policy.rego` from the signed generated-agent-policy artifact instead of the legacy CAP fallback. CLI deploy preflights `/agent-policy`, anchors `expected_agent_policy_hash`, signs the final policy artifact locally, then computes `expected_cc_init_data_hash` over cc_init_data containing that exact policy text. Auto-unlock enable/disable also require a digest-pinned `--image` so the mode-transition redeploy has a fresh signed descriptor and artifact. cap-test01 is promoted to the public, keyless-signed signing-service digest `sha256:1f812ee51303313fef97506a1eec2316b55cd555783f7802c82f4d849d15a11b`, CAP API digest `sha256:8ae3bb73369c974dd1b9ff8a5b8b54a7bdcf7078f5e2aae2cc04e2b73fbd3b0f`, and enclava-init digest `sha256:1505f3095e0b677a1a85db1faebea96233837ec4822f3265d3745e2440c16e5e`. | Still left: production platform-release signing-root custody and release process; publish production release verify pubkey; replace the transitional `/agent-policy` dependency with a fully customer/CI-local generator or pick durable signing-service key custody/deployment target; keep cap-test01 monitored before broader production rollout. |
| 3 | PARTIAL | Local sibling `../trustee` now has SNP `init_data_hash`, signed-policy write/evaluation enforcement, workload-attested policy body read, body/receipt policy inputs, required `If-None-Match`/`If-Match` preconditions, insert-if-absent storage backends, and `POST /kbs/v0/attestation/verify`. CAP API has workload-attested `GET /api/v1/workload/artifacts` with Trustee callback validation and init-data-hash cross-check. Signed deployment apply writes the verified signed policy artifact envelope to Trustee and skips local Rego reconciliation. cap-test01 runs the patched GHCR Trustee KBS image with `require_signed_policy=true`; an unsigned raw Rego negative test fails closed before KBS serves policy. | Decide upstream-vs-fork; add per-resource version/ETag CAS after v1; classify legacy/operator policy lines into the signing-service template or documented deprecations before broader production rollout. |
| 4 | DONE | Two-hostname routing (`<app>.<orgSlug>.enclava.dev` + `.tee.`), atomic DNS pair creation with rollback, **HAProxy advisory lock fix (multi-replica bug)**, TXT-challenge custom domain verification with `hickory-resolver` + Cloudflare-fallback, structured Caddyfile builder rejecting injection, signer-identity columns wired into create_app, idempotent `migrate-two-hostnames` binary | — |
| 5 | PARTIAL | PR #3/#4 merged plus local follow-up: real `libcryptsetup-rs` LUKS open, two block PVCs (`state`, `tls-state`), `enclava-init-config` ConfigMap, app/caddy decrypted mountpoints, runtime ownership fixes, KBS autounlock/password inputs, owner seed resource path parity (`default/<owner-type>/seed-encrypted`), full in-TEE Trustee verification chain gated by `trustee_policy_read_available`, and CAP follow-up config that renders Trustee URLs/pubkeys + local `cc-init-data.toml` only when enabled. `attestation-proxy` local repo now rejects caller-supplied runtime_data, serves internal HTTP on 8081 plus external TLS on 8443, and constructs SNP REPORT_DATA as `transcript_hash || receipt_pubkey_sha256`; receipt signing primitives are in place. CAP and tenant manifests expose Service port 8081 to the proxy TLS listener while keeping KBS/CDH and Caddy loopback traffic on HTTP 8081. Live `kata-qemu-snp` validation passes after fixing the actual Kata config path, removing the bad `kernel_modules` setting, and changing CAP to the verified static wait-exec + long-running mounter-sidecar contract. cap-test01 has Trustee Phase 3 endpoints deployed, `TRUSTEE_POLICY_READ_AVAILABLE=true`, repo-owned GHCR CAP/API/proxy/caddy/enclava-init/KBS image refs, and a CLI-bundled development platform release for those sidecar anchors. | Keep broader production rollout gated until production release metadata, raw SNP/VCEK verification, and signing-service deployment/key custody are finalized. |
| 6 | PARTIAL | Trustee local repo exposes receipt/body verification fields, required workload-resource preconditions, and insert-if-absent first-write; `attestation-proxy` local repo now uses `If-None-Match: *` for first write, `If-Match: *` + signed rekey envelope for overwrite, and `If-Match: *` + signed teardown envelope for delete; CAP removed `kbs-resource-writer`, removed writer env gates, stops writing KBS Secret/KbsConfig fallbacks, and calls workload teardown before namespace deletion. Signing-service template now requires receipt pubkey binding/signature/value-hash checks for rekey/delete. cap-test01 is promoted to patched GHCR Trustee KBS and signed attestation-proxy images. | Per-resource version/ETag CAS remains a post-v1 hardening gap. |
| 7 | PARTIAL | PR #2 merged CLI key/keyring/descriptor groundwork; local follow-up wires `enclava deploy` to require a digest-pinned `--image` and include `customer_descriptor_blob` + `org_keyring_blob` on every deploy. Auto-unlock enable/disable also require a digest-pinned `--image`, build a descriptor for the requested target mode, and send descriptor/keyring blobs with the unlock-mode transition request. Local attestation verifier plumbing checks HOST_DATA, descriptor cc-init hash, firmware measurement, explicit cc-init claims, TLS transcript hash, and receipt pubkey hash. `enclava ownership claim/unlock/recover/change-password/auto-unlock` now attests the TEE endpoint, validates evidence `report_data` against nonce + TLS SPKI + receipt key, builds a rustls SPKI-pinned client, and sends sensitive payloads only over that client. Unlock-mode transition receipts use the D11 shape (`purpose`, UUID `app_id`, `from_mode`, `to_mode`, `attestation_quote_sha256`, `timestamp`) and CAP verifies the receipt key hash against the attestation binding. CLI now has a signed bundled development platform-release artifact and deterministic generator; CAP API consumes the same signed release anchors for signed-policy-mode signing-service and sidecar config. | Add full raw AMD SNP report parsing/VCEK chain validation instead of the current evidence-JSON `report_data` check; full keyring CLI subcommands; design customer/CI-signed policy artifacts to remove the platform signer from the authorization path |
| 8 | PARTIAL | Local dead-code cleanup for the legacy tenant DNS-01 / Cloudflare-token path is complete: no `CADDY_DNS_PROVIDER` code path, no tenant token Secret/mount, and caddy-ingress builds without DNS-provider plugins. Tenant GitOps no longer includes the legacy `flowforge-1` static overlay, stale legacy tenant/CAP namespaces were deleted during live cleanup, and cap-test01 now references the GHCR caddy-ingress digest signed by the repo workflow. | Production CAA publication and scheduled CT monitoring remain before this is a production-release claim. |
| 9 | DONE | Per-app `VerificationPolicy` (Fulcio URL/Email/PublicKey), real sigstore 0.13 API, TUF root pin, `PATCH /apps/:name/signer` rotation endpoint (initial-set bypasses email confirmation), `SKIP_COSIGN_VERIFY` runtime branch removed, hardcoded `cosign_verified=true` removed, **CLI `--signer-subject`/`--signer-issuer` on create + `enclava signer set/rotate` subcommands + GitHub workflow signer step**. **M3 reached.** | — |
| 10 | PARTIAL | API-key HMAC redesign implemented: new `enclava_<base32-128-bit-prefix>_<base32-256-bit-secret>` keys store `hash_format='hmac_v1'`, use `API_KEY_HMAC_PEPPER` / `_BASE64`, and keep legacy `enc_` Argon2 lookup for migration. Centralized role/scope helpers are in place; removed memberships are ignored by auth; soft-remove expires org API keys; server-side billing intent fields are used by webhooks instead of mutable BTCPay metadata; API-issued TEE tokens now include `instance_id` for proxy verification. Unlock-mode changes now require a TEE-signed D11 transition receipt plus transition attestation metadata, verify CE-v1 payload/signature/app UUID/from-to modes/timestamp, reject timestamp replay, bind the receipt pubkey hash to the CLI-attested TEE key, and persist receipts in `unlock_transition_receipts`. cap-test01 is running the GHCR CAP API and signed attestation-proxy image carrying this contract. | Full customer-facing keyring CLI subcommands |
| 11 | DONE | PR #2/#4 merged: NetworkPolicy egress allowlist (per-app `EgressRule`), SSA `force()` gating, sidecar cosign at API startup (`SidecarPin` + `verify_sidecars_at_startup`), runtime-install removal, and Phase 5 manifest integration fixes. Live Kata runtime validation now passes through `runbooks/validate-kata-dm-crypt.yml`. | — |
| 12 | PARTIAL | CI now runs fmt, clippy, workspace tests, doctests, build, `cargo audit`, and `cargo deny check advisories sources`; `deny.toml` documents the temporary RSA advisory exception, lockfile updates clear current `rustls-webpki`/`rand` advisories, manifest snapshot checks are committed, and `prod-strict` feature gates reject debug/test-only features. | Broader live/integration scaffolding beyond the current API health DB test |

### Milestones

| Milestone | Status | Notes |
|---|---|---|
| M0 — loud-noise removed | PARTIAL | Phase 0 code paths are locally implemented, including server-side billing intent and tenant TLS-ALPN/no-Cloudflare-secret rendering; production CAA publication, CT scheduler wiring, and no-DNS-plugin image rollout still need ops execution. |
| M1 — policy boundary intact | PARTIAL | cap-test01 is wired for and running the signed-policy/artifact path (`TRUSTEE_POLICY_READ_AVAILABLE=true`, Trustee policy/artifact URLs, signing-service pubkey envs, patched Trustee KBS with `require_signed_policy=true`, CAP-managed signed `resource-policy`). Tenant GitOps keeps the Trustee namespace but no longer owns the policy ConfigMap, and tenant Flux controllers remain scaled to zero. cap-test01 now uses repo-owned GHCR image digests for CAP API, enclava-init, sidecars, Trustee KBS, and the off-cluster validation signing service, with sidecar/signing-service cosign verification pinned to GitHub Actions OIDC identities. CLI now bundles a signed development platform-release artifact for the cap-test01 sidecar/template/genpolicy anchors, CAP API refuses release-anchor env drift in signed-policy mode, and the validation signing-service image runs real pinned Kata `genpolicy` before signing. Generated Kata agent policy is now locally wired into descriptor hashes, signed artifacts, `cc_init_data`, and enclava-init verification. Trustee no longer self-authenticates descriptor-key-signed artifacts; descriptor keys are accepted only when configured in `trusted_descriptor_public_keys` as independent trust anchors. Blocked on durable signing-service key custody or full customer/CI local policy generation, production platform-release publishing, upstream-vs-fork ownership, production descriptor-key trust-anchor policy, and production legacy-policy template fate decisions. |
| M2 — operator out of seed loop | PARTIAL | Receipt signer + Trustee receipt inputs + receipt-gated template rules exist locally; CAP no longer ships `kbs-resource-writer`, and the active cap-test01 kustomization removed the writer plus token Secret. Proxy write/rekey/delete uses workload-resource preconditions and receipt envelopes; cap-test01 validates the no-writer path with signed GHCR Trustee/proxy image refs. Blocked on storage-level versioned CAS hardening. |
| M3 — tenant-bound image trust | **DONE** | Phase 9 in PR #1 |
| M4 — CLI proves real TEE | PARTIAL | Phase 5 code path, REPORT_DATA binding, the live CLI sensitive-payload path, and the bundled signed development platform-release artifact now cover the cap-test01 validation anchors. Still blocked on wiring all deploy flows to the bundled release instead of env fallbacks, full raw AMD SNP report/VCEK validation, keyring UX completion, and broader production rollout beyond cap-test01. |
| M5-strict — confidentiality chain holds | BLOCKED | M0 + M1 + M2 + M3 + M4 + email-reset disabled at org creation |
| M5-with-recovery-reset | BLOCKED | Same as M5-strict + customer opted into 30-day-delayed email reset |

### Active worktrees / PR state

- PR #2 (`security/phase-11-and-7-cli`) merged.
- PR #3 (`worktree-agent-ab6f4d3186c6e5f19`) merged.
- PR #4 follow-up fixes merged.
- No open CAP PRs remain. Cross-repo follow-up for signed GHCR images has been pushed; remaining work is tracked as external prerequisites below.

### Open decisions delta vs rev14

- #4 (Let's Encrypt CAA `validationmethods` support) — **resolved YES** by `runbooks/investigations/B1-letsencrypt-caa-support.md`. Plan caveat removable.
- #5 (LUKS in Kata SEV-SNP) — **resolved with design pivot**. The actual `kata-qemu-snp` config path is `/opt/kata/share/defaults/kata-containers/configuration-qemu-snp.toml`; removing `[agent.kata] kernel_modules` restores new sandbox startup. Inside the SNP guest, LUKS format/open/mount succeeds. Creating workload containers after the mount exists fails with `EINVAL`, so CAP now starts app/caddy under a static `enclava-wait-exec` helper, waits for their sentinels, then `enclava-init` mounts and stays alive as the propagation source. `runbooks/validate-kata-dm-crypt.yml` passes this live contract.
- #14 (CI/CD signing infra for D9) — **partially implemented, not production-final**. `../policy-templates/signing-service` exists; CI publishes/signs public `ghcr.io/enclava-ai/policy-signing-service`, and the off-cluster validation service at `http://10.0.0.2:18080` now runs the verified GHCR digest with checksum-pinned Kata 3.28.0 `genpolicy` baked into the image. The signing-service manifest is still not included by the cap-test01 kustomization because durable key custody/deployment target remain unresolved. See `runbooks/external-tracks.md` item 1.
- #10 (existing Trustee policy state audit) — **completed; no longer blocks cap-test01 signed-policy validation**. Artifacts are committed under `runbooks/audits/trustee-policy-audit-20260427T194217Z/`; fate decisions remain for 1,156 lines of legacy/operator-owned policy before those behaviors can be carried forward or intentionally dropped in the durable signing-service template. See `runbooks/external-tracks.md` item 4.

### External (non-CAP-repo) prerequisites

The remaining critical-path work splits between in-repo phases (above) and **out-of-repo platform/infra tracks** that are gating M5. Tracked separately in `runbooks/external-tracks.md`.

2026-04-28 external-track execution pass:

- Track 1 locally implemented: `../policy-templates/signing-service` now verifies descriptors/keyrings against a durable owner DB, renders/signs artifacts, runs checksum-pinned Kata 3.28.0 `genpolicy`, has a deterministic CE-v1/Ed25519 vector, receipt-gated Rego rules, docs, CI, tests, clippy, and a GHCR publish/sign workflow. CAP consumer wiring exists, CAP now bundles a signed development `platform-release.json` with cap-test01 sidecar/template/genpolicy anchors and consumes it in signed-policy mode, and the off-cluster validation signing service is promoted to the public signed GHCR digest. Generated Kata agent policy is now wired locally into `cc_init_data`, descriptor hash flow, signed artifacts, and in-TEE verification. Remaining work: durable key custody, production deployment target, production release publishing, and promotion of the new CAP/signing-service images.
- Track 2 implemented and live-validated in cap-test01: `../trustee` now has signed-policy enforcement, workload-attested policy body read, body/receipt inputs, attestation verify callback, SNP `init_data_hash`, required write/delete preconditions, and insert-if-absent storage writes. `key-value-storage` tests pass locally; KBS/verifier focused tests are blocked on this workstation by missing Intel DCAP quote verifier headers (`sgx_dcap_quoteverify.h`). cap-test01 runs the patched GHCR KBS image with signed-policy enforcement. Remaining work: upstream-vs-fork decision and per-resource version/ETag CAS.
- Track 3 resolved for the current runtime: `../enclava-infra/ansible` now renders the actual Kata config paths, repairs shim aliases, removes stale `kernel_modules`, rejects future module overrides, and adds preflight/recover/validate playbooks. Syntax checks pass, host preflight passes on `worker-1`, and the live smoke passes with the app-starts-first + mounter-sidecar contract. Do not re-add `io.katacontainers.config.agent.kernel_modules` on this runtime.
- Track 4 completed via `ssh control1.encl`: audit artifacts are in `runbooks/audits/trustee-policy-audit-20260427T194217Z/`. Live pre-cutover ConfigMap and KBS-loaded policy matched except for a trailing newline, and CAP DB binding keys matched CAP-managed Rego keys. cap-test01 has now moved to a CAP-managed signed policy artifact; the old 1,156 lines of legacy/operator-owned policy are no longer in the live `resource-policy` ConfigMap. Fate decisions are still required before those legacy behaviors are either folded into the durable template or intentionally deprecated. The KBS admin metadata endpoint could not be queried because production KBS admin is configured as `DenyAll` and returns 401.

2026-04-28 live-manifest reconciliation pass:

- cap-test01 CAP now points at the signed-policy/artifact path: `PLATFORM_SIGNING_SERVICE_URL=http://10.0.0.2:18080`, `SIGNING_SERVICE_PUBKEY_HEX`, `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX`, `WORKLOAD_ARTIFACTS_URL`, `TRUSTEE_ATTESTATION_VERIFY_URL`, `TRUSTEE_POLICY_URL`, and `TRUSTEE_POLICY_READ_AVAILABLE=true` are present in `../enclava-ops-manifests/overlays/cap-test01/cap-api.yaml`.
- The active cap-test01 kustomization no longer includes `kbs-resource-writer.yaml`, and the old writer token Secret is patched out. The stale YAML file still exists in the ops repo but is not referenced by the active overlay.
- Tenant Flux/GitOps has been retired on cap-test01; CAP now owns tenant resources and the signed Trustee policy write. This is the live Trustee signed-policy cutover on the manifest side; full M1 remains blocked by durable release/provenance, key custody, upstream/fork ownership, and legacy-policy fate decisions.
- Tenant GitOps commit `4c28cf0` retired the legacy `flowforge-1` static overlay because its dirty rewrite still contained placeholder cc-init-data/salt values. The live `flowforge-1` namespace and stale legacy CAP app namespaces were deleted; only `cap-test01`, Trustee, and platform/system namespaces remain relevant to validation.
- Former rollout caveat resolved for cap-test01: the live CAP/API, attestation-proxy, caddy-ingress, Trustee KBS, enclava-init, and off-cluster validation signing-service refs have been promoted from `ttl.sh` validation refs to repo-owned GHCR digests, with sidecar/signing-service images signed by their repo workflows. cap-test01 still points at the off-cluster validation signing-service URL, but that service now runs the public signed GHCR digest while durable key custody/deployment target are finalized.
- Main rollout blocker: production release publishing and platform-release distribution. CAP now has a signed development platform-release artifact carrying cap-test01 sidecar image digests, signing-service pubkey, policy template text/hash, and Kata 3.28.0 genpolicy pin, and CAP API consumes those signed anchors in signed-policy mode. Generated-agent-policy wiring is implemented locally; the production path still needs release-root custody, signing-service deployment/key custody, image promotion, and full production release publishing before M1/M4/M5 can be claimed broadly. Tenant Flux is removed; ops Flux remains a platform/ops-only concern.

---

## Verification index

| Claim | Source |
|---|---|
| KBS empty allowlists are rendered today | `cap/crates/enclava-engine/src/manifest/kbs_policy.rs:32-34, 50-123`; `cap/crates/enclava-api/src/kbs.rs:688-689` |
| Kata agent policy is generated by signed `genpolicy` artifacts on signed deploys, with a legacy CAP fallback only for unsigned/dev paths | `cap/crates/enclava-engine/src/manifest/cc_init_data.rs`; `cap/crates/enclava-api/src/signing_service.rs`; `policy-templates/signing-service/src/main.rs` |
| Trustee stores policy as opaque blob, evaluates only `data.policy.allow` | `trustee/kbs/src/api_server.rs:308-341, 39`; `trustee/deps/policy-engine/src/policy/rego.rs:39-100` |
| Trustee SNP claims expose `init_data` (raw `report.host_data` hex); rename to `init_data_hash` is part of the Phase 3 Trustee patch (rev11/rev12) | `trustee/deps/verifier/src/snp/mod.rs:621-623` |
| Trustee has attestation-gated workload-resource write API for `*-owner` resources | `trustee/kbs/src/api_server.rs:457-600, 495, 481` |
| `replace_bindings_block` preserves operator-written policy outside CAP markers | `cap/crates/enclava-api/src/kbs.rs:615-679` |
| Cosign verifier uses platform pubkey only | `cap/crates/enclava-api/src/cosign.rs:114, 179` |
| Tenant pod is StatefulSet, replicas=1; attestation-proxy is a regular sidecar; app/caddy start under `/usr/local/bin/enclava-wait-exec` supplied by their images; `enclava-init` is the long-running LUKS mounter sidecar; the stateful Block PVC path uses no initContainers | `cap/crates/enclava-engine/src/manifest/{statefulset.rs,containers.rs,volumes.rs}`; `cap/crates/enclava-wait-exec/src/main.rs` |
| App container drops privileged + SYS_ADMIN and waits on `/run/enclava/init-ready` before execing the workload argv | `cap/crates/enclava-engine/src/manifest/containers.rs`; `cap/crates/enclava-wait-exec/src/main.rs` |
| Caddy drops privileged + SYS_ADMIN, keeps only NET_BIND_SERVICE, and waits on `/run/enclava/init-ready` before execing Caddy | `cap/crates/enclava-engine/src/manifest/containers.rs`; `cap/crates/enclava-wait-exec/src/main.rs` |
| Attestation-proxy non-root by default, internal HTTP on 8081, external TLS on 8443 | `cap/crates/enclava-engine/src/manifest/containers.rs`; `attestation-proxy/src/main.rs` |
| Service exposes 443 (Caddy) + 8081 (attestation), with attestation targetPort 8443 | `cap/crates/enclava-engine/src/manifest/service.rs` |
| `bootstrap_script.sh` 646 lines, two unlock paths | `cap/crates/enclava-engine/src/manifest/bootstrap_script.sh:84-141, 143-240, 354-443, 463-565, 567-606, 618-646` |
| Tenant Caddy uses TLS-ALPN-01 without a Cloudflare DNS plugin or tenant token | `caddy-ingress/Dockerfile`; `cap/crates/enclava-engine/src/manifest/ingress.rs`; `cap/crates/enclava-engine/src/manifest/containers.rs` |
| HAProxy is L4 SNI passthrough | `cap/crates/enclava-api/src/edge.rs:189-193` |
| HAProxy lock is process-local mutex; API has `replicas: 2` | `cap/crates/enclava-api/src/edge.rs:16, 91-92`; `cap/deploy/api/deployment.yaml:7` |
| HAProxy does not route port 80 to tenant pods | `cap/crates/enclava-engine/src/manifest/network_policy.rs:116-117` |
| DNS records created are A/AAAA only | `cap/crates/enclava-api/src/dns.rs:16-22, 103, 172-178` |
| Cloudflare DNS:Edit is zone-wide, not record-type-scoped | Cloudflare API token UI; `/user/tokens/verify` returns status only |
| RFC 8657 defines CAA `accounturi` and `validationmethods` parameters | RFC 8657 §3, §4 |
| CAP CLI validates SNP `report_data` binding from attestation evidence JSON; full raw SNP report/VCEK validation is still open | `cap/crates/enclava-cli/src/tee_client.rs`; `cap/crates/enclava-cli/src/attestation.rs` |

## Goals

1. Restore the confidentiality chain — operator cannot read tenant data, secrets, or memory even with cluster root.
2. Fix every CRITICAL finding and HIGHs that affect tenant isolation or attestation integrity.
3. Preserve developer UX — single password input per unlock, customers bring their own image and own its signature, the URL still looks like Heroku.
4. Make the architecture extensible — adding a sidecar later does not require new attestation flows or KBS resources.

## Confidentiality Status Milestones

| Milestone | After | What is restored |
|---|---|---|
| **M0 — Loud-noise removed** | Phase 0 | No production env-var foot-guns; Cloudflare token removed from tenant namespaces *and* its manifest generator disabled; SSRF surface closed; billing webhook has signature + replay protection (intent-tier still trusted from webhook metadata until Phase 10 — **C11 partial**); CAA records (with `accounturi` + `validationmethods`) anchor ACME issuance; CT log monitoring detects unauthorized issuance. |
| **M1 — Policy boundary intact** | Phase 2 + Phase 3 | KBS releases gated by Rego that anchors in attested SNP `init_data_hash` and explicitly checks workload digest, signer identity, k8s namespace/SA. Kata agent fail-closed. Trustee policy text owned by CAP and signed by an off-cluster signing service that **independently reconstructs Rego from code-reviewed templates** (not arbitrary text from the API). KBS write path is still operator-domain. |
| **M2 — Operator out of the seed loop** | Phase 6 | Workload writes its own seed via Trustee's attestation-gated `workload-resource` API. `kbs-resource-writer` deleted. Seed lifecycle defined: first-write-wins, overwrites require attestation + receipt, deletes via teardown flow. **The receipt-signing primitive ships in Phase 5** (attestation-proxy's per-pod ephemeral key + signing endpoint), so Phase 6 has everything it needs without waiting for Phase 10 — Phase 10 only adds another *consumer* of the same primitive. |
| **M3 — Tenant-bound image trust enforced** | Phase 9 | Each app's signature verified against its registered Fulcio identity. Operator can no longer sign a malicious image and pass verification. |
| **M4 — CLI proves it's talking to a real, customer-deployed TEE** | Phase 7 + Phase 9 | CLI's TLS verifier is attestation-pinned. Expected attestation values come from a customer-signed deployment descriptor (D10), with the org keyring itself owner-signed (not operator-controlled). |
| **M5-strict — Confidentiality chain holds end-to-end (cryptographic)** | M0 + M1 + M2 + M3 + M4, **with email-reset disabled at org creation** | All five together AND no operator-reachable trust path. The README claim "operator cannot read user data, secrets, or memory" is enforced cryptographically. |
| **M5-with-recovery-reset** | Same as M5-strict but with the org's emergency email-reset opt-in enabled | The crypto chain holds *between resets*, but a 30-day-delayed operator-influenceable reset path exists for orgs that opted in. Customer chose this trade at org creation; CLI displays the org's current mode at every unlock. Public-facing language: "operator cannot read user data, secrets, or memory unless the customer's email-reset path is exercised, observed for 30 days, and unchallenged." |

## Architectural Decisions

### D1. Two-hostname model
- App traffic: `<app>.<orgSlug>.enclava.dev`
- TEE-direct: `<app>.<orgSlug>.tee.enclava.dev`
- `orgSlug` = 8 hex chars, generated at org creation, immutable, globally unique
- HAProxy SNI-routes both hostnames to ports 443 and 8081 of the same Service (already exposed)
- Customer-visible URL is the app hostname; the TEE hostname is a CLI implementation detail

### D2. Single owner_seed inside the TEE
- One root secret per app; HKDF-derived per component
- Distributed via well-known paths on the LUKS-encrypted volume
- Adding a sidecar = one new HKDF context + one new path

### D3. Pod layout (rev5: attestation-proxy is also the steady-state receipt signer)
```
Pod (StatefulSet, replicas=1)
├── attestation-proxy   (regular sidecar container)
│                        listens HTTP 8081 for in-pod sidecars and TLS 8443
│                        for the Service's external attestation port;
│                        self-signed cert, SPKI bound in SNP report_data;
│                        long-lived; OWNS THE RECEIPT-SIGNING ROLE for Phase 10
├── caddy               (regular container, drops privileged + SYS_ADMIN)
│                        starts under /usr/local/bin/enclava-wait-exec,
│                        signals it is running, then waits for /run/enclava/init-ready
│                        listens 443, ACME TLS-ALPN-01, reads /state/caddy/seed
├── app                 (regular container, drops privileged + SYS_ADMIN)
│                        starts under /usr/local/bin/enclava-wait-exec,
│                        signals it is running, then waits for /run/enclava/init-ready
│                        reads /state/app/seed
└── enclava-init        (long-running mounter sidecar)
                         waits for caddy/app sentinels, opens LUKS,
                         derives + writes seeds, marks ready, stays alive
```

attestation-proxy holds a per-pod ephemeral signing keypair (Ed25519); the public key's hash is bound into the SNP `report_data` of every quote. Phase 10 unlock-mode transition receipts are signed by this keypair. The CLI verifies the receipt signature against the pubkey it extracted during the original attested-TLS handshake — same trust anchor as the unlock channel. In-pod consumers (`KBS_CDH_ENDPOINT`, Caddy well-known proxying, readiness probes) continue to use loopback HTTP 8081; external `.tee.` traffic reaches the TLS listener through Service port 8081 → targetPort 8443.

### D4. Customer-controlled signing
- Per-app `signer_identity` = (Fulcio OIDC subject, issuer)
- Default: GitHub Actions OIDC keyless cosign
- Platform never holds customer signing keys
- Identity stored at app creation; rotation requires owner role + email confirmation
- Verified at every deploy and bound into the per-app KBS-release Rego

### D5. TLS strategy split
- App hostnames + BYO custom domains: Caddy + WebPKI / ACME TLS-ALPN-01 only (rev8/rev9 locked this in; rev12 syncs D5 to match Phase 0). HTTP-01 is intentionally not used — the platform does not route port 80 to tenant pods, and CAA `validationmethods=tls-alpn-01` blocks any other method even if a pod tried.
- TEE-direct hostname: attestation-proxy + self-signed cert with SPKI in SNP `report_data`. Never ACME, never CA-issued.
- CLI's custom rustls verifier kicks in only for `.tee.` hostnames

### D6. KBS Rego anchors in SNP-attested `init_data_hash`

The trust chain:
1. SNP signature commits `HOST_DATA` (host-set, AMD-signed)
2. Trustee verifies `SHA256(received_init_data) == HOST_DATA`; exposes the result as the SNP claim `init_data_hash`
3. Once anchored, parsed `init_data_claims` is implicitly trusted

Rendered Rego template:
```rego
package policy
default allow := false

allow {
    input.tee == "snp"
    input.snp.init_data_hash == "ABC123..."   # SHA-256 of cc_init_data, set by CAP at deploy

    # Trusted only because init_data_hash anchored above
    input.init_data_claims.image_digest == "sha256:def..."
    input.init_data_claims.signer_identity.subject == "repo:me/myapp:ref:refs/heads/main"
    input.init_data_claims.signer_identity.issuer == "https://token.actions.githubusercontent.com"

    # k8s placement, anchored via cc_init_data → init_data_claims (rev12 — was input.kubernetes.*,
    # which doesn't exist in local Trustee's broker token transform; see broker.rs:459)
    input.init_data_claims.namespace == "cap-..."
    input.init_data_claims.service_account == "cap-..."
    input.init_data_claims.identity_hash == "..."
}
```

`cc_init_data_hash` does **not** appear in the cc_init_data `[data]` table (would be a self-claim). The hash is only in the Rego literal, compared against the SNP claim.

**SNP claim path (rev11):** local Trustee at `trustee/deps/verifier/src/snp/mod.rs:623` currently exposes this claim as `init_data` (the raw `report.host_data` hex). The plan references `input.snp.init_data_hash` throughout — that field path does **not** exist today, so every rule referencing it would evaluate to `undefined` (and `default allow := false` would mask the bug as if it were a deny). The Phase 3 Trustee patch list adds a small claim-rename: expose the same value as `init_data_hash` (semantically correct — it is the SHA-256 of the user-supplied init_data, anchored via SNP HOST_DATA). Until that patch lands, every Rego rule the signing service emits is silently no-op.

### D7. Kata agent policy default-deny
`AllowRequestsFailingPolicy` flips to `false`. Explicit allow rules for boot/start. Bind runtime class.

### D8. Attestation evidence the CLI verifies

| Field | Source | Bound to |
|---|---|---|
| AMD root signing chain | SNP report header (CLI parses via `sev` crate) | AMD VCEK / VLEK |
| `MEASUREMENT` | SNP report | Expected platform firmware digest |
| `HOST_DATA` | SNP report | SHA-256 of bundled cc_init_data (CLI re-derives) |
| `REPORT_DATA` | SNP report (64 bytes) | **rev9/rev10 layout (recoverable, encoding-locked):** `report_data[0..32] = transcript_hash`, `report_data[32..64] = receipt_pubkey_sha256` where `transcript_hash = ce_v1_hash([("purpose","enclava-tee-tls-v1"), ("domain", domain), ("nonce", nonce_32B), ("leaf_spki_sha256", spki_32B)])`. **Encoding lock:** `leaf_spki_sha256 = SHA256(DER-encoded SubjectPublicKeyInfo)` (extracted via webpki/rustls); `receipt_pubkey_sha256 = SHA256(raw 32-byte Ed25519 public key)` (RFC 8032 §5.1.5). |
| Workload image digest | `init_data_claims.image_digest` | Customer-signed deployment descriptor |
| Sidecar image digests | `init_data_claims.sidecar_digests` | Customer-signed deployment descriptor |
| Runtime class | `init_data_claims.runtime_class` | Customer-signed deployment descriptor |
| Signer identity | `init_data_claims.signer_identity` | Customer-signed deployment descriptor |

### D9. Trustee policy ownership and signing (rev15: customer/CI artifacts are the preferred authorization path)

**Threat:** rev4 had API submit arbitrary Rego to the signing service (signing oracle). Rev5 fixed by having the service reconstruct from templates, but still verified customer pubkeys against a "read-only DB mirror" — operator-controlled, so operator could swap pubkeys to authorize malicious intent.

**Rev15 model — two artifact producers, same signed envelope:**

The steady-state path is customer/CI-signed. The customer-controlled deploy
key that signs the `DeploymentDescriptor` also signs the final
`SignedPolicyArtifact` after rendering the signed platform-release template and
running the pinned Kata `genpolicy` adapter. CAP verifies the artifact, stores
it, and transports it to Trustee; CAP API still never authors Rego.

The off-cluster signing service remains as a transitional producer for
environments that have not moved policy artifact generation into customer CI.
It signs the same envelope and is verified by the same code paths, but
`REQUIRE_CUSTOMER_SIGNED_POLICY_ARTIFACT=true` disables that fallback.

**Rev6 transitional model — signing service is sovereign when used:**

The off-cluster signing service is the **sole author** of CAP-managed Trustee policy text. It maintains:
1. **Rego templates** baked into its container image (from a separate platform-controlled repo, code-reviewed)
2. **Per-org owner-pubkey state** in its own database, bootstrapped out-of-band at org creation (not from any platform DB)
3. **Private signing keypair** in its own CI/HSM environment

CAP API does **not** compose, render, or author Rego. Inputs to the signing service are minimal:
- `app_id` (UUID)
- `deploy_id` (UUID)
- `customer_descriptor_blob` (rev9: full DeploymentDescriptor from D10, with signature — replaces the rev6/7/8 "intent_blob" references throughout)
- `org_keyring_blob` (from D10, with owner signature)
- `platform_release_version` (string)

The signing service:
1. Verifies the **org keyring's owner signature** against its independently-held owner pubkey for that `org_id`. If the keyring's signature doesn't verify, hard reject — the operator is trying to substitute a fake keyring.
2. Verifies the **deployment descriptor's signature** against a deployer pubkey from the verified keyring (and that the deployer has appropriate role).
3. Looks up the Rego template for the requested platform release (baked into the service's image).
4. Substitutes verified-descriptor values (`image_digest`, `signer_identity`, etc.) into the template deterministically.
5. Signs the reconstructed Rego with the service's private key, or in the
   customer/CI path verifies locally and signs with `descriptor_signing_pubkey`.
6. Returns a **`SignedPolicyArtifact`** (rev13 — adds `policy_template_id` / `policy_template_sha256` to metadata so the customer-pinned template version is bound through the artifact; rev12 introduced the explicit shape):
   ```
   SignedPolicyArtifact {
       metadata: {
           app_id: UUID,
           deploy_id: UUID,
           descriptor_core_hash: 32 bytes,
           descriptor_signing_pubkey: 32 bytes,
           platform_release_version: String,
           policy_template_id: String,            // (rev13) which template was rendered
           policy_template_sha256: 32 bytes,      // (rev13) hash of the template text
           agent_policy_sha256: 32 bytes,         // (rev15) generated Kata policy hash
           genpolicy_version_pin: String,         // (rev15) pinned generator identity
           signed_at: RFC3339,
           key_id: String,                        // signing-service key version or customer CI key id
       },
       rego_text: String,
       rego_sha256: 32 bytes,                     // diagnostic; signer still signs computed hash
       agent_policy_text: String,                 // generated Kata agent policy carried into cc_init_data
       signature: 64 bytes,                       // Ed25519 PureEdDSA over RAW CE-v1 message bytes (rev13 finding #5 — NOT the 32-byte hash)
       verify_pubkey_b64: String,                 // diagnostic key hint; verifiers use anchored expected keys
   }
   ```
   The signing service builds `sign_message = ce_v1_bytes([("purpose","enclava-policy-artifact-v1"), ("metadata", canonical_policy_metadata_hash), ("rego_sha256", sha256(rego_text))])` (raw TLV-encoded record stream — note `canonical_policy_metadata_hash` is the 32-byte CE-v1 hash of the metadata fields, embedded as a record value here; rev14 finding #4 renamed from rev12/rev13 `canonical_metadata_bytes` / `canonical_policy_metadata_bytes` to make explicit that it's a hash, not raw bytes) and signs **those bytes** with Ed25519 (RFC 8032 PureEd25519 — internal SHA-512 in Ed25519 handles compression). Verifiers reconstruct `sign_message` from the wire-format and call `ed25519_verify(pubkey, sign_message, signature)`. The Phase 3 acceptance criteria require committing reference test vectors (signer + verifier) to the policy-templates repo so cross-implementation interop is mechanical.

CAP API:
- Receives the signed artifact, verifies the descriptor/keyring chain, verifies
  the signature against `descriptor_signing_pubkey` for customer/CI artifacts
  or against the configured signing-service pubkey for transitional artifacts,
  verifies `rego_sha256 == SHA256(rego_text)`, verifies
  `descriptor.expected_kbs_policy_hash == SHA256(rego_text)`, verifies the
  generated agent policy hash, then writes it to Trustee via `set_policy`.
- **Never composes, modifies, or re-renders Rego.**

**Bootstrap of the signing service's owner-pubkey state:**
- Org creation flow at the customer's CLI generates the owner keypair, posts the public key directly to the signing service's bootstrap endpoint (separate from the platform API; signing-service URL is in the CLI's bundled `platform-release.json`)
- The signing service records `(org_id, owner_pubkey, bootstrapped_at)` in its own DB
- Subsequent owner rotations follow D10's threshold-of-owners or recovery-contact flow, all signed by existing owner key(s) and verified by the signing service against its cached state
- Platform DB is never queried for pubkeys

**Why this matters:** every input to the signing service is either:
- Bound by a customer-signed artifact (descriptor, keyring), verified against pubkey state the signing service holds independently, or
- An immutable identifier (`app_id`, `deploy_id`, `platform_release_version`) that the signing service's logic doesn't trust — they only select which template to use and which app the result is for.

A stolen API credential cannot ask for arbitrary Rego because the input space is bounded by what customers actually signed and what the signing service's own owner-pubkey state authorizes. The worst-case operator action is *replay* of a previous signed artifact — which already matches the workload's attestation, so it's a no-op.

**Verification (in API, Trustee, and `enclava-init`):**
- Customer/CI artifacts verify against `descriptor_signing_pubkey`, after the
  verifier proves the descriptor signature and org-keyring membership chain.
- Transitional signing-service artifacts verify against the signing-service
  public key published with the CAP release artifact.
- `enclava-init` tries the descriptor key first and treats platform keys as
  fallback compatibility keys only.
- Key rotation: org keyring rotation for customer keys; append-only platform
  public-key list with `since` timestamps for transitional platform keys.

**Operational requirement:** before Phase 3 starts, set up the signing service container image + CI/CD pipeline + private signing key + owner-pubkey storage in a separate platform-controlled repo + deployment. Signing service has its own DB (small — one row per org). ~1.5 weeks of platform-eng work; can run in parallel with Phase 0.

### D10. Customer-signed deployment descriptor + owner-signed org keyring (rev5: org keyring is signed)

**The trust anchor problem:** the CLI verifier needs known-good values for image digest, signer identity, etc. Under operator-root, the API is operator-controlled. Rev4 fetched expectations as API data — operator could lie. Rev5: the customer signs the deployment intent and the org keyring, the CLI verifies signatures, the API is just opaque storage.

**Per-user keypair:**
- CLI maintains an Ed25519 keypair per user, generated on first use, stored in `~/.enclava/keys/<user_id>.priv` (mode 0600)
- Public key registered with platform via `POST /users/me/public-keys`
- Stored in `user_signing_keys` (Phase 1 migration)

**Owner-signed org keyring (rev5):**
- The org owner's CLI maintains a signed keyring per org:
  ```
  OrgKeyring {
      org_id: UUID,
      version: u64,
      members: [
          { user_id, pubkey, role: "owner"|"admin"|"deployer", added_at },
          ...
      ],
      updated_at: <timestamp>,
  }
  ```
- Owner signs with their private Ed25519 key
- Stored on the platform in `org_keyrings` (new `0020_org_keyrings.sql`); platform treats it as opaque bytes
- Updates: each new version signed by an owner; old versions kept for audit
- **Bootstrap (TOFU on owner pubkey):** when a member's CLI first interacts with an org, the platform returns the keyring; the CLI prompts the user to verify the owner's pubkey out-of-band (Slack, email, fingerprint comparison). On confirmation, owner pubkey is cached in `~/.enclava/state/<org_id>/owner_pubkey`. Subsequent fetches are verified against the cached pubkey.
- **Owner rotation:** old owner signs a "rotation receipt" naming the new owner's pubkey; non-owner members verify the chain on their next fetch.

**Deployment Descriptor (rev8 — replaces the prior thin DeploymentIntent):**

The customer-signed artifact is now a **full deployment descriptor** that binds every field the Rego references and every OCI runtime field the Kata agent policy validates. The signing service derives every Rego slot from this descriptor + signed `platform-release.json` constants only — no operator-controlled state ever influences a Rego value.

```
DeploymentDescriptor {
    // Identity
    schema_version: "v1",
    org_id: UUID,
    org_slug: String,                  // 8-hex
    app_id: UUID,
    app_name: String,                  // DNS-1123
    deploy_id: UUID,
    created_at: RFC3339,
    nonce: 32 bytes,

    // Network
    app_domain: String,                // <app>.<orgSlug>.enclava.dev
    tee_domain: String,                // <app>.<orgSlug>.tee.enclava.dev
    custom_domains: [String],          // owner-verified BYO

    // Kubernetes binding (constrained by Rego)
    namespace: String,                 // cap-<orgSlug>-<app>
    service_account: String,
    identity_hash: 32 bytes,           // CE-v1 from Phase 1

    // Workload identity (cosign verifies; Rego references)
    image_digest: String,              // sha256:...
    signer_identity: { subject: String, issuer: String },

    // OCI runtime spec (rev8 — full binding to prevent same-image mutation)
    oci_runtime_spec: {
        command: [String],             // exact argv[0]
        args: [String],                // exact argv[1..]
        env: [{ name, value }],        // sorted by name; canonical ordering
        ports: [{ container_port, protocol }],
        mounts: [{ source, destination, type, options }],
        capabilities: { add: [...], drop: [...] },
        security_context: {
            run_as_user, run_as_group,
            read_only_root_fs,
            allow_privilege_escalation: false,    // hard-required
            privileged: false,                    // hard-required (post-Phase 5)
        },
        resources: { requests, limits },
        liveness_probe?, readiness_probe?, startup_probe?,
    },

    // Sidecar binding (the customer pins what they're running with)
    sidecars: {
        attestation_proxy_digest: String,
        caddy_digest: String,
        // platform release constants; CLI fills from platform-release.json
    },

    // Platform binding (constants from platform-release.json, but signed by customer to acknowledge)
    expected_firmware_measurement: 32 bytes,
    expected_runtime_class: String,    // kata-qemu-snp

    // KBS resource path (so signing service can render the Rego target)
    kbs_resource_path: String,         // default/cap-<orgSlug>-<app>-tls-owner

    // Hash anchor for cc_init_data — chains attestation FORWARD to descriptor.
    // Customer's CLI computes this by running the same renderer the platform will run
    // (rendering the genpolicy-generated agent policy + cdh.toml + aa.toml + identity.toml)
    // and SHA256'ing the result. CLI uses the platform-release.json to know the renderer version.
    // (rev11) These two `expected_*_hash` fields are EXCLUDED from descriptor_core_canonical_bytes
    // to break the rev10 cc_init_data ↔ descriptor cycle (see "Hash chain" note below).
    expected_cc_init_data_hash: 32 bytes,

    // Hash anchor for the rendered KBS Rego policy — chains in-TEE policy verification to descriptor.
    // (rev10 — replaces rev8/rev9's oci_spec_hash, which was redundant with cc_init_data binding.)
    // CLI runs the same template the signing service will run; SHA256s the result; signs.
    // enclava-init reads the active policy via Trustee's workload-attested endpoint, verifies
    // platform signature, then verifies SHA256(policy_text) == descriptor.expected_kbs_policy_hash.
    expected_kbs_policy_hash: 32 bytes,

    // Policy-template provenance (rev13 finding #1) — pins which Rego template version the
    // customer rendered against, so the signing service must use the same one. Both fields
    // are also present in the signed `platform-release.json` bundled with the CLI; CLI
    // verifies they match the release pin before computing `expected_kbs_policy_hash`.
    policy_template_id: String,        // e.g. "kbs-release-policy-v3"
    policy_template_sha256: 32 bytes,  // SHA-256 of the canonical template text

    // Platform release the deployer targeted (rev13 finding #3). Bound here so the
    // SignedPolicyArtifact's metadata.platform_release_version can be checked against
    // the customer-signed value; without this, the signing service could claim any release.
    platform_release_version: String,  // e.g. "platform-2026.04"
}
```

**Hash chain (rev11 — breaks the rev10 cycle):**

There are two derived hashes over the descriptor:

| Hash | Inputs | Used by | Direction |
|---|---|---|---|
| `descriptor_core_hash` | All descriptor fields **except** `expected_cc_init_data_hash` and `expected_kbs_policy_hash` (CE-v1 encoded; see D11 for the exact record list) | Embedded in cc_init_data as `descriptor_core_hash`; enclava-init re-computes from the read descriptor and compares | cc_init_data → descriptor (backward) |
| `descriptor_full_signature` | The deployer's Ed25519 signature over **all** descriptor fields' canonical bytes (CE-v1) | Stored in the platform DB next to the descriptor; enclava-init reads it out-of-band and verifies against `cc_init_data.descriptor_signing_pubkey` | independent (covers the full signed object) |

**Crucially, the descriptor's full signature is NOT inside cc_init_data.** That was the rev10 cycle source: the signature commits to `expected_cc_init_data_hash`, which equals `SHA256(cc_init_data_toml)`, which contained the signature itself. By moving the signature to platform-DB-only storage and putting only `descriptor_core_hash` in cc_init_data, both directions of the chain are well-defined:

- **Forward (cc_init_data follows descriptor):** at sign time the deployer computes `expected_cc_init_data_hash` over a cc_init_data shape that contains `descriptor_core_hash` (computed from the cycle-free subset). The customer's signature commits to that. The Phase 7 CLI verifier checks `descriptor.expected_cc_init_data_hash == SHA256(cc_init_data_toml)` — chains attestation to the descriptor's authorized hash.
- **Backward (descriptor follows cc_init_data):** enclava-init reads cc_init_data, reads the candidate descriptor + signature out-of-band, computes `descriptor_core_hash` from the candidate, and asserts equality with `cc_init_data.descriptor_core_hash`. The operator cannot substitute a descriptor with different core fields. The full signature is then verified against the cc_init_data-bound signing pubkey.

The `expected_*_hash` fields chain forward only; `descriptor_core_hash` chains backward only. No field commits in both directions.

The descriptor is canonical-encoded per D11 (CE-v1), signed by the deployer's Ed25519 key, and submitted to:
1. **The platform API** as opaque bytes (stored in `deployment_intents` for the workload to read at unlock)
2. **The signing service** alongside the org keyring; the signing service verifies signatures, then renders the Rego deterministically using only descriptor fields and signed release constants
3. **The Kata agent policy generation:** `expected_cc_init_data_hash` is computed by the customer's CLI to mirror what the platform will render; the customer signs over it; if the platform renders something different, the deployment is rejected at attestation time

**At unlock:**
- CLI fetches the latest signed descriptor + signed org keyring
- Verifies keyring signature against TOFU-cached owner pubkey
- Verifies descriptor's signing pubkey is in the keyring's `members` with `deployer` or higher role
- Verifies descriptor signature
- Uses descriptor's values as the SNP attestation expectations (per Phase 7 verifier)

**For multi-device CLI use:** users with multiple devices register multiple keys (each device its own keypair). Org owner adds each one to the keyring. Future v1.1: HSM/FIDO2-backed keys replace per-device keyfiles.

**Owner-key compromise / loss recovery (rev6):**

Owner key is the root of org deployer trust. Recovery cannot be left undefined or rely on email alone — an operator who can read email at the platform side could forge a reset.

Three-tier recovery:

1. **Threshold-of-owners (primary path).** Multi-owner orgs default to a recovery threshold M-of-N (default: ceil(N/2) + 1, i.e. simple majority over half). When one owner's key is compromised:
   - Other owners' CLIs collectively sign a `RecoveryDirective { org_id, revoked_owner_pubkey, replacement_owner_pubkey, signed_at, reason }`
   - M owner signatures required
   - Directive is committed to the org keyring as a `recovery_event` entry, increments the keyring version
   - Signing service verifies the M-of-N signatures against its cached owner pubkeys before accepting the new owner pubkey for that role
   - Old owner pubkey is permanently revoked (recorded in the keyring history)
2. **Recovery contacts (single-owner orgs).** During org creation, owner can designate 2–5 recovery-contact pubkeys (typically other senior team members or personal backup keys held offline). Recovery requires M-of-N from this set (default 2-of-N). Same directive shape; signing service verifies against bootstrapped recovery-contact pubkeys (also stored in signing-service's own DB at org creation).
3. **Emergency email reset (last resort).** Only available if the org has neither multiple owners nor designated recovery contacts. Triggered by submitting a fresh owner pubkey to the signing service via a special endpoint, which:
   - Sends an email confirmation to the registered owner email
   - Imposes a **30-day waiting period** during which the org cannot deploy or unlock
   - Sends daily audit notifications to the email and to a webhook URL the org has registered
   - After 30 days, accepts the new pubkey as owner; old pubkey permanently revoked
   - Customer must explicitly opt into "no-recovery-contacts mode" at org creation; this is the only way emergency reset becomes available, and the consent is logged

The 30-day waiting period exists so an attacker who somehow triggered an emergency reset cannot immediately take over — legitimate owner has time to detect via audit notifications and cancel.

Configuration is per-org. The default for new orgs prompts the user to set up at least 2 recovery contacts even for single-owner orgs; CLI nudges them away from emergency-reset-only mode. Email-reset is opt-in, not default.

### D11. Cryptographic bindings: canonical encoding (rev6 — new)

Every transcript hash in this plan uses an unambiguous, domain-separated, length-prefixed encoding. Plain `\|\|` concatenation is forbidden — a variable-length field shifting boundaries can change the meaning of a hash.

**Canonical encoding rule (CE-v1):**

A hash input is built by concatenating tagged TLV-style records:
```
record = label_len:u16_be || label_bytes || value_len:u32_be || value_bytes
```
- `label_bytes` is the field name in ASCII (e.g. `"domain"`, `"nonce"`, `"leaf_spki"`)
- Each transcript hash starts with a fixed `purpose_label` record whose value is the versioned domain-separation string (e.g. `"enclava-tee-tls-v1"`)
- Records appear in a fixed order documented per binding; renderers and verifiers MUST emit/expect the same order
- Fixed-size fields (32-byte hashes, 32-byte nonces, AMD report fields) still carry their length prefix — never omitted, never implicit
- Hash function: SHA-256 unless otherwise specified

Equivalent in code form:
```rust
// (rev13) The raw CE-v1 message — used wherever we sign with Ed25519.
fn ce_v1_bytes(records: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (label, value) in records {
        out.extend_from_slice(&(label.len() as u16).to_be_bytes());
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

// 32-byte hash — used wherever a fixed-length identifier is needed
// (e.g., REPORT_DATA, descriptor_core_hash, sub-canonicalizations embedded as
// values in another CE-v1 record). NOT used as an Ed25519 sign input.
fn ce_v1_hash(records: &[(&str, &[u8])]) -> [u8; 32] {
    Sha256::digest(&ce_v1_bytes(records)).into()
}
```

**Ed25519 signing convention (rev13 finding #5):** every Ed25519 signature in this plan signs the **raw `ce_v1_bytes(...)` message**, not the 32-byte `ce_v1_hash(...)` output. Ed25519's RFC 8032 PureEd25519 mode internally hashes the message with SHA-512; pre-hashing with SHA-256 would be wasteful and ambiguous. The 32-byte hash is reserved for use as a record value or as a fixed-length anchor (e.g., `report_data[0..32]`, `descriptor_core_hash`). Reference test vectors (signer + verifier) live in the policy-templates repo and are exercised by both the signing-service tests and the CLI/enclava-init verification tests.

**Bindings using CE-v1:**

| Binding | Records (in order) |
|---|---|
| SNP `report_data[0..32]` transcript hash (Phase 5/7) | `("purpose","enclava-tee-tls-v1")`, `("domain", domain_utf8)`, `("nonce", nonce_32B)`, `("leaf_spki_sha256", spki_hash_32B)` |
| SNP `report_data[32..64]` (rev9: directly carries `receipt_pubkey_sha256`, NOT inside the transcript hash, so Trustee can extract it) | raw 32-byte SHA-256 of the receipt-signing pubkey; placed verbatim in bytes 32..64 of REPORT_DATA |
| Deployment Descriptor canonical bytes (rev13 — adds rev13 fields; Phase 7, signed by deployer) | `("purpose","enclava-deployment-descriptor-v1")`, `("schema_version", "v1")`, `("org_id", uuid_16B)`, `("org_slug", slug_utf8)`, `("app_id", uuid_16B)`, `("app_name", name_utf8)`, `("deploy_id", uuid_16B)`, `("created_at", rfc3339_utf8)`, `("nonce", nonce_32B)`, `("app_domain", domain_utf8)`, `("tee_domain", tee_domain_utf8)`, `("custom_domains", canonical_string_list_bytes)`, `("namespace", ns_utf8)`, `("service_account", sa_utf8)`, `("identity_hash", hash_32B)`, `("image_digest", digest_utf8)`, `("signer_identity", canonical_signer_bytes)`, `("oci_runtime_spec", canonical_oci_spec_bytes)`, `("sidecars", canonical_sidecar_map_bytes)`, `("expected_firmware_measurement", measurement_32B)`, `("expected_runtime_class", class_utf8)`, `("kbs_resource_path", path_utf8)`, `("policy_template_id", id_utf8)`, `("policy_template_sha256", hash_32B)`, `("platform_release_version", version_utf8)`, `("expected_cc_init_data_hash", hash_32B)`, `("expected_kbs_policy_hash", hash_32B)` |
| `descriptor_core_canonical_bytes` (rev11 — cycle-free subset; embedded in cc_init_data as `descriptor_core_hash`) | Identical record list to "Deployment Descriptor canonical bytes" above **with only `("expected_cc_init_data_hash", ...)` and `("expected_kbs_policy_hash", ...)` removed** AND the purpose label changed to `"enclava-deployment-descriptor-core-v1"` for domain separation from the full descriptor signature input. The rev13 fields (`policy_template_id`, `policy_template_sha256`, `platform_release_version`) ARE in core, so they propagate to cc_init_data via `descriptor_core_hash` and are anchored to attestation. Hash function: SHA-256. Result is 32 bytes. |
| `canonical_oci_spec_bytes` (rendered through kata-containers/genpolicy at sign time, so the descriptor commits to the rendered policy bytes themselves rather than a separate hash) | CE-v1 hash of: `("command", canonical_string_list_bytes)`, `("args", canonical_string_list_bytes)`, `("env", canonical_env_bytes)` (sorted by name), `("ports", canonical_ports_bytes)`, `("mounts", canonical_mounts_bytes)`, `("capabilities_add", canonical_string_list_bytes)`, `("capabilities_drop", canonical_string_list_bytes)`, `("security_context", canonical_secctx_bytes)`, `("resources", canonical_resources_bytes)` — list/map sub-canonicalizations sort their entries lexicographically; integer fields are u32_be |
| The previous rev8 `oci_spec_hash` field is removed in rev10 — the same binding is achieved transitively: the OCI spec is in the descriptor → genpolicy renders an agent policy → cc_init_data contains that policy → `expected_cc_init_data_hash` chains the agent policy to the descriptor. No separate hash needed. |
| Org keyring canonical bytes (signed by owner) | `("purpose","enclava-org-keyring-v1")`, `("org_id", uuid_16B)`, `("version", version_u64_be)`, `("members", canonical_members_bytes)`, `("updated_at", rfc3339_utf8)` |
| Recovery directive (signed by M owners or recovery contacts) | `("purpose","enclava-recovery-v1")`, `("org_id", uuid_16B)`, `("revoked_pubkey", pubkey_32B)`, `("replacement_pubkey", pubkey_32B)`, `("signed_at", rfc3339_utf8)`, `("reason", reason_utf8)` |
| Unlock-mode transition receipt (Phase 10, signed by attestation-proxy) | `("purpose","enclava-unlock-receipt-v1")`, `("app_id", uuid_16B)`, `("from_mode", mode_utf8)`, `("to_mode", mode_utf8)`, `("timestamp", rfc3339_utf8)`, `("attestation_quote_sha256", quote_hash_32B)` |
| Rekey receipt (Phase 6, signed by attestation-proxy) | `("purpose","enclava-rekey-v1")`, `("app_id", uuid_16B)`, `("resource_path", path_utf8)`, `("new_value_sha256", hash_32B)`, `("timestamp", rfc3339_utf8)` |
| Teardown receipt (Phase 6) | `("purpose","enclava-teardown-v1")`, `("app_id", uuid_16B)`, `("resource_path", path_utf8)`, `("timestamp", rfc3339_utf8)` |
| Signed policy artifact (rev12/rev13/rev14 — Phase 3 / D9; signing service signs the **raw CE-v1 bytes** of these records, not the hash) | `("purpose","enclava-policy-artifact-v1")`, `("metadata", canonical_policy_metadata_hash)`, `("rego_sha256", sha256_of_rego_text_32B)` — **Ed25519 signs `ce_v1_bytes(records)`, the raw TLV-encoded message; verifiers reconstruct the same byte stream and pass it directly to `ed25519_verify`.** |
| `canonical_policy_metadata_hash` (rev15 — includes generated-agent-policy fields) | 32-byte CE-v1 **hash** of: `("app_id", uuid_16B)`, `("deploy_id", uuid_16B)`, `("descriptor_core_hash", hash_32B)`, `("descriptor_signing_pubkey", pubkey_32B)`, `("platform_release_version", version_utf8)`, `("policy_template_id", id_utf8)`, `("policy_template_sha256", hash_32B)`, `("agent_policy_sha256", hash_32B)`, `("genpolicy_version_pin", pin_utf8)`, `("signed_at", rfc3339_utf8)`, `("key_id", key_id_utf8)` |

**Sub-canonicalizations:**
- `canonical_signer_bytes` for `signer_identity` = CE-v1 hash of `[("subject", utf8), ("issuer", utf8)]` (32 bytes)
- `canonical_sidecar_map_bytes` for sidecar digests = CE-v1 hash of records sorted lexicographically by sidecar name (32 bytes)
- `canonical_members_bytes` for keyring members = CE-v1 hash of records, members sorted by `user_id`, each member encoded as `[("user_id", uuid_16B), ("pubkey", pubkey_32B), ("role", role_utf8), ("added_at", rfc3339_utf8)]` then hashed (32 bytes per member, then full set hashed)

**Why this matters:** ambiguous concatenation has been the vector for collision attacks against signature schemes (e.g. SAML, JWT alg confusion, length-extension). CE-v1 makes domain separation explicit and length-shift attacks impossible. The encoding is defined once here and referenced by every binding-specific section.

**Versioning:** if any binding's record set changes, bump the purpose label to `-v2`. Old verifiers reject `-v2` artifacts; old artifacts continue to verify under `-v1` until aged out.

---

## Phased Implementation

Every phase below is self-contained. No cross-revision references.

### Phase 0 — Production Stopgaps + Caddy TLS-ALPN-01 cutover (~2 weeks)

**Goal:** Close easiest exploits; remove operator-readable tenant secrets; disable their generator; eliminate SSRF; set up CAA + CT monitoring. **Reaches M0.**

**Findings addressed:** C5 (partial), C7 (partial — transitional hardening; full fix Phase 6), **C11 (partial — signature + replay only; full fix Phase 10)**, C12 (full), C4 (tenant-secret removal + manifest-gen disable + CAA + CT), Highs around runtime TLS modes, JWTs, CORS.

**Changes:**

A. **Production env-var gates** (`crates/enclava-api/src/main.rs`, `crates/enclava-cli/src/main.rs`): refuse to start in `cfg(not(debug_assertions))` if any of these are set: `SKIP_COSIGN_VERIFY`, `COSIGN_ALLOW_HTTP_REGISTRY`, `ALLOW_EPHEMERAL_KEYS`, `TENANT_TEE_ACCEPT_INVALID_CERTS`, `ENCLAVA_TEE_ACCEPT_INVALID_CERTS`, or empty `BTCPAY_WEBHOOK_SECRET`. Insecure-TLS modes only with `cfg(debug_assertions)`. `KBS_RESOURCE_WRITER_TOKEN` is removed with Phase 6 rather than gated.

B. **C12 SSRF dedicated outbound HTTP clients** (`crates/enclava-api/src/clients.rs` — new): `RegistryClient` with `redirect::Policy::none()`, `https_only(true)`, response-body size limits, custom `reqwest` resolver via `hickory-resolver` rejecting loopback/link-local/RFC1918/cluster-pod/cluster-service CIDRs; registry hostname allowlist (`ghcr.io`, `docker.io`, `quay.io`, `gcr.io`, `*.pkg.dev`). Replace `reqwest::Client::new()` at `cosign.rs:198-258` and `registry.rs:73-80`. Same client for BTCPay webhook callbacks.

C. **C4 Cloudflare strategy (rev5 with RFC 8657 validationmethods):**
- Tenant-secret removal: generated tenant manifests no longer create or mount tenant Cloudflare token Secrets. Existing tenant-namespace Secrets matching the legacy token name are operator cleanup items.
- **Caddy TLS-ALPN-01 cutover (rev8: locked to TLS-ALPN-01 only):**
  - `crates/enclava-engine/src/manifest/secrets.rs` — deleted; no tenant Cloudflare Secret is emitted
  - `crates/enclava-engine/src/manifest/ingress.rs` — Caddyfile renders **TLS-ALPN-01 only**. No HTTP-01 path, no DNS-01 path, and no `caddy-dns/cloudflare` plugin reference.
  - `crates/enclava-engine/src/manifest/containers.rs` — no tenant `CF_API_TOKEN` env injection
  - `crates/enclava-engine/src/manifest/volumes.rs` — no `tls-cloudflare-token` volume or mount
  - `caddy-ingress` image: rebuild a no-DNS-plugin variant tagged `enclava/caddy-ingress:tls-alpn-01`; CAP defaults to this image
  - **No HAProxy DaemonSet changes needed.** TLS-ALPN-01 runs entirely on port 443, which HAProxy already SNI-passes through. Open decision #11 (HAProxy port-80 routing) is closed: not needed.
- **CAA records (rev8: locked to `validationmethods=tls-alpn-01`):**
  ```
  enclava.dev.       CAA  0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<id>; validationmethods=tls-alpn-01"
  enclava.dev.       CAA  0 issuewild ";"
  tee.enclava.dev.   CAA  0 issue ";"
  tee.enclava.dev.   CAA  0 issuewild ";"
  ```
  Binds issuance to the platform's Let's Encrypt account AND restricts to TLS-ALPN-01 — DNS-01 issuance from this account is impossible even with Cloudflare TXT-write. Per RFC 8657 §4 and Let's Encrypt's challenge-types docs ([https://letsencrypt.org/docs/challenge-types/](https://letsencrypt.org/docs/challenge-types/)). Effectiveness depends on Let's Encrypt honoring `validationmethods` for the issuing account; confirm in first 2 days of Phase 0 (open decision #4).
- **CT log monitoring:** subscribe to certstream or run a watcher that alerts on any cert issued for `*.enclava.dev` or `*.tee.enclava.dev` not by the platform's account. Document runbook in `runbooks/ct-monitoring.md`.
- **Residual risk:** operator with cluster root *plus* a CA that ignores CAA can still issue. Documented; CT monitoring is the detection layer.

D. **`kbs-resource-writer` retirement path:** the original Phase 0 transitional hardening was superseded by the Phase 6 local implementation. `kbs-resource-writer` is deleted from CAP, and the workload-owned Trustee `workload-resource` path is now the only local seed write/delete path.

E. **ServiceAccount automount disabled** on every generated SA + PodSpec (`crates/enclava-engine/src/manifest/service_account.rs`).

F. **JWT hardening** (`auth/jwt.rs`): add `iss`, `aud`, `typ`, `jti`. Separate validators for session vs config tokens.

G. **C11 partial fix** (`routes/billing.rs`): replace `==` with `mac.verify_slice()` after hex-decoding; new table `processed_webhooks (delivery_id, event_id PK)`; reject duplicates. **Note:** webhook still trusts `tier` from the payload metadata. Full fix (server-side billing intent) lands in Phase 10. **C11 is partial in M0.**

H. **NIP-98 payload tag verification** on mutating endpoints with bodies.

I. **Rate limiter:** stop trusting `X-Forwarded-For` from arbitrary peers; trusted-proxy config bound to platform HAProxy.

J. **CORS:** per-environment allowlist, not `Any/Any/Any`.

**Migration:** `0010_processed_webhooks.sql`.

**Investigation tasks (parallel, ~3 days work distributed across team):**
- Confirm Let's Encrypt honors CAA `accounturi` and `validationmethods` extensions (open decision #4).
- Validate the app-starts-first wait-exec + mounter-sidecar LUKS contract on live Kata SEV-SNP (open decision #5).
- Confirm platform CI/CD signing infrastructure for D9 (open decision #14).

**Tests:**
- API refuses to start with debug-only env var in production builds
- Manifest generator never emits tenant `CF_API_TOKEN`, Cloudflare Secret, DNS-01 Caddyfile, or token volume/mount (snapshot)
- CAA records present and correct on startup; refuse to start otherwise
- SSRF: registry client refuses private/cluster CIDRs and metadata endpoints
- JWT missing `iss`/`aud` rejected
- Webhook replay → no-op on second delivery_id
- Caddy TLS-ALPN-01 cutover: testcontainer with Pebble ACME → cert issued without Cloudflare token
- Manifest snapshot: no `CF_API_TOKEN` env var, no Cloudflare Secret, no token volume mount
- Existing tenant pods continue to operate during cutover (cert renewals via TLS-ALPN-01 succeed)

**Effort:** ~2 weeks (rev7: was 4–5 days; +1 week for Caddy/Caddyfile/volume gating + image rebuild + cert continuity testing).

---

### Phase 1 — Foundations: schema, hostnames, validation (1 week)

**Goal:** Land DB schema and validation primitives every later phase depends on. No customer-visible behavior change yet.

**Findings addressed:** C8, Highs around weak validation, ImageRef parsing, CLI path traversal.

**Migrations** (rev5: adds `0020_org_keyrings.sql`):
```
0011_org_slug.sql                  -- adds orgs.cust_slug (UNIQUE), backfill
0012_app_signer_identity.sql       -- adds apps.signer_identity_subject/issuer/set_at
0013_kbs_binding_columns.sql       -- adds kbs_tls_bindings.image_digest/init_data_hash/signer_identity_*
0014_custom_domain_verification.sql -- adds custom_domain_challenges table
0019_user_signing_keys.sql         -- adds user_signing_keys + deployment_intents tables
0020_org_keyrings.sql              -- rev5: adds org_keyrings table
```

`0020_org_keyrings.sql`:
```sql
CREATE TABLE org_keyrings (
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    keyring_payload BYTEA NOT NULL,    -- canonical-encoded keyring
    signature BYTEA NOT NULL,           -- Ed25519 signature by owner
    signing_key_id UUID NOT NULL REFERENCES user_signing_keys(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version)
);
CREATE INDEX org_keyrings_org_id_version ON org_keyrings(org_id, version DESC);
```

**Validation helpers** (`crates/enclava-common/src/validate.rs` — new):
- `validate_dns_label`, `validate_org_slug`, `validate_app_name`, `validate_fqdn`, `validate_image_digest`

**Hostname helpers** (`crates/enclava-common/src/hostnames.rs` — new): `app_hostname`, `tee_hostname`.

**Identity hash canonicalization** (`crates/enclava-engine/src/crypto.rs`): replace colon-concatenated SHA-256 with **CE-v1** encoding (D11): `ce_v1_hash([("purpose","enclava-identity-v1"), ("tenant_id", t), ("instance_id", i), ("bootstrap_owner_pubkey", pk)])`. No `\|\|` concatenation.

**Apply validation** at `routes/orgs.rs`, `routes/apps.rs`, `routes/domains.rs`, `crates/enclava-cli/src/config.rs` (path-traversal guard via `Path::components()`).

**Tests:** property tests on validators with malicious inputs (`..`, NUL, newlines, RTL Unicode, double `@`, oversized labels, IDN homograph); identity hash collision (`("a","bc")` ≠ `("ab","c")`); migration concurrency under advisory lock.

**Effort:** 1 week.

---

### Phase 2 — Rego template (in signing-service repo) + CAP signing-service client + Kata fail-closed (rev7: 1 week)

**Goal:** Define the Rego template in the **signing-service repo** (CAP never composes Rego — finding #4 fix); CAP API gets a thin client that requests signed artifacts. Flip Kata agent fail-closed. Eliminate raw `format!` from cc_init_data. **Reaches half of M1.**

**Findings addressed:** C1 (full), C2 (full), C9 (full), rev7 finding #4 (Rego ownership).

**Changes:**

**Rego template (in `enclava-platform/policy-templates` repo, NOT in CAP):**
- Template per D6 — anchors in `input.snp.init_data_hash`; references `input.init_data_claims.{image_digest, signer_identity.{subject,issuer}, sidecar_digests, runtime_class, namespace, service_account, identity_hash}` (rev12: single anchor, all values flow through cc_init_data → init_data_claims; the rev10/rev11 `input.kubernetes.*` and `input.identity_hash` paths are removed because local Trustee's broker doesn't populate them)
- Template substitutions are deterministic; the signing service unit-tests the template's output against a fixed golden file
- Code-reviewed in the policy-templates repo; signing service rebuilds when template changes

**CAP API signing-service client** (`crates/enclava-api/src/signing_client.rs` — new, replaces `kbs_policy.rs`):
- `request_signed_policy(app_id, deploy_id, customer_descriptor_blob, org_keyring_blob, platform_release_version) → SignedPolicyArtifact` (rev9: descriptor not intent)
- HTTP client with mTLS or bearer auth to the signing service (URL from `PLATFORM_SIGNING_SERVICE_URL`)
- Caches signed artifacts by `(app_id, deploy_id, content_hash)` — no re-signing on reconcile, only on content change
- Verifies the artifact signature against the compiled-in `PLATFORM_TRUSTEE_POLICY_PUBKEY` before accepting it (defense-in-depth)
- **Delete** `crates/enclava-engine/src/manifest/kbs_policy.rs` entirely — CAP no longer composes Rego

**CAP API kbs.rs**:
- Before `ensure_tls_binding`, compute SHA-256 of rendered cc_init_data; persist on deployment row; pass to signing service as part of the customer-descriptor verification chain
- Replace local Rego rendering with a call to `signing_client.request_signed_policy(...)`
- Write the returned signed artifact to Trustee via `set_policy`

**cc_init_data shape** (`crates/enclava-engine/src/manifest/cc_init_data.rs`):
- `[data]` includes (rev11):
  - `image_digest`, `signer_identity` (subject + issuer), `sidecar_digests`, `runtime_class` — fields the Phase 2 read-side Rego anchors (already in rev10)
  - `namespace`, `service_account`, `identity_hash` — added in rev11 (finding #3) so the Phase 7 verifier can check `claims.namespace`, `claims.service_account`, `claims.identity_hash` against attestation. Without these the verifier was asserting on undefined fields or sourcing them from operator-controlled state. Both the Phase 7 CLI verifier and the Phase 2 Rego template (rev12 — corrected from `input.kubernetes.*` to `input.init_data_claims.*`) read these values from `init_data_claims`, so the SNP `init_data_hash` anchor extends to them.
  - `descriptor_core_hash` (rev11) — 32-byte CE-v1 hash over the descriptor's canonical bytes EXCLUDING `expected_cc_init_data_hash` and `expected_kbs_policy_hash` (the cycle-free subset; see D10/D11). Replaces rev10's `descriptor_hash`, which created the cc_init_data ↔ descriptor cycle.
  - `descriptor_signing_pubkey` — 32 raw bytes; the Ed25519 pubkey enclava-init uses to verify the out-of-band-read full descriptor signature.
  - `org_keyring_fingerprint` — 32 bytes; fingerprint of the org keyring at deploy time, so enclava-init can confirm the signing pubkey is in that exact keyring version.
- Does NOT include:
  - `cc_init_data_hash` (would be self-claim)
  - The descriptor's full Ed25519 signature (rev10 had this; rev11 removes it because the signature commits to `expected_cc_init_data_hash` which equals SHA256(cc_init_data_toml) — putting the signature inside cc_init_data made it self-referential. The signature is read from the platform DB at unlock time and verified against the cc_init_data-bound `descriptor_signing_pubkey`.)
- All TOML rendering via `toml_edit` (no raw `format!`)

**Kata agent policy** (`cc_init_data.rs:45-55`):
- Default-deny. Explicit allow rules for `CreateContainerRequest`, `StartContainerRequest`, `RemoveContainerRequest`. Explicit deny tests for `ExecProcessRequest`, `CopyFileRequest`, `WriteStreamRequest` to user containers, mount changes, env mutations. Bind runtime class.
- **OCI spec validation against signed descriptor (rev9 — uses kata-containers genpolicy, not custom Rego canonicalization):** the rev8 plan said "Rego canonicalizes CreateContainerRequest, computes CE-v1 hash, compares" — that's the highest-risk part of the plan and not how Kata-CC actually does this in practice. Rev9 uses the established mechanism:
  - **kata-containers/genpolicy** is the upstream tool that generates an agent policy from a Kubernetes deployment manifest, embedding expected per-container OCI fields directly into the policy text (each field becomes a `data.policy.*` constant the agent compares with `==`)
  - At sign time, the **signing service** runs `genpolicy` against the customer-signed `oci_runtime_spec` from the DeploymentDescriptor (after rendering it into a Kubernetes-equivalent shape). The output is a complete agent policy that compares specific fields directly: `data.policy.containers[i].process.args == input.req.OCI.Process.Args`, etc.
  - The signing service signs the generated policy and ships it inside cc_init_data; the agent at runtime evaluates plain Rego field comparisons. **No custom canonicalization in Rego, no Rego built-ins, no hash recomputation in policy.**
  - Because the `oci_runtime_spec` is in the customer-signed descriptor, the operator cannot mutate args/env/mounts before genpolicy runs — the signing service derives genpolicy input only from verified-signed bytes
  - The signing service publishes the genpolicy version it ran; CLI's `enclava-init` (or platform release notes) pin a specific genpolicy version per platform release, so customer and platform agree on policy semantics
  - Negative test fixtures (rendered through genpolicy in the test harness): spec with mutated `command`, `args`, `env` (added/removed/reordered), `mounts`, `capabilities`, `securityContext.privileged: true` → all denied at agent policy level
  - **Open decision (added):** if customer wants a feature genpolicy doesn't model (e.g., GPU device mounts, special seccomp profiles), a custom Rego built-in *may* eventually be needed, but v1 ships genpolicy-only. Document the supported field set in `platform-release.json`.

**Tests:**
- Signing-service-side unit: template renders byte-identically for golden inputs
- Signing-service-side unit: malicious identifiers (quotes, braces, newlines, `'''`, NUL) safely-escaped
- `opa eval` against the rendered Rego: tampered evidence → deny; correct → allow
- **Critical:** if `input.snp.init_data_hash` missing/wrong, request denied even if `init_data_claims.image_digest` matches — proves anchor works
- CAP-side unit: signing-client correctly forwards descriptor + keyring; rejects artifact with bad signature
- Snapshot: signed artifact's Rego always references `input.snp.init_data_hash` against non-empty literal

**Migration:** Backfill `kbs_tls_bindings` columns for existing deployments by requesting fresh signed artifacts and re-applying KBS resources, audit-logged.

**Rollback (fail-closed):** buggy template or signing service → pause new deploys via `DEPLOY_GATE=closed`, leave existing Trustee policies. Per-app `enforcement_paused=true` leaves binding at previous value, never empty.

**Effort:** 1 week.

---

### Phase 3 — Trustee-side signed-policy enforcement + delete `replace_bindings_block` (rev7: 2 weeks)

**Goal:** Trustee itself rejects unsigned or invalid policy artifacts at write time AND at evaluation time. Without this, an operator with cluster root can write `default allow := true` directly to Trustee and bypass everything CAP-side. **Completes M1.**

**Effort raised from 1 week to 2 weeks (rev7)** for the Trustee patch / admission-proxy work — this was the critical gap that made rev6's M1 claim aspirational.

**Findings addressed:** review's `kbs.rs:615-679` finding, rev5 finding #1, rev6 findings #2 and #3, **rev7 finding #1 (CRITICAL)** — Trustee-side enforcement.

**Changes:**

**Trustee-side signed-policy enforcement (rev7 — the load-bearing critical fix):**

The fundamental issue: Trustee at `trustee/kbs/src/api_server.rs:308` accepts arbitrary policy bytes from any admin-authorized caller and at `:513` evaluates whatever's stored. An operator with cluster root can `curl -X POST` an `allow := true` policy and KBS will release every secret to every workload. CAP-side signing means nothing if Trustee evaluates unsigned bytes.

**Trustee SNP claim path patch (rev11 finding #4):** local Trustee at `trustee/deps/verifier/src/snp/mod.rs:623` exposes `report.host_data` as the JSON claim `init_data` (not `init_data_hash`). The plan's Rego templates reference `input.snp.init_data_hash` — currently undefined, so every rule using it would silently evaluate to `undefined` and fall through to `default allow := false`. Add a small claim-rename to the Phase 3 Trustee patch set: extend `parse_tee_evidence` to expose the value as `init_data_hash` (semantically: SHA-256 of the user-supplied init_data, anchored via SNP HOST_DATA). Effort: ~half a day; same patch surface as the signed-policy enforcement work below.

Two viable shapes; pick before Phase 3 starts:

**Option A — patch Trustee directly (REQUIRED for M1/M5; ~1.5 weeks):**
- Fork `trustee/kbs` or upstream a feature flag `KBS_REQUIRE_SIGNED_POLICY=true`
- New code path in `api_server.rs::set_policy`: parse the incoming policy as the rev15 `SignedPolicyArtifact` envelope (D9 — `{metadata, rego_text, signature}`); reconstruct `sign_message = ce_v1_bytes([("purpose","enclava-policy-artifact-v1"), ("metadata", canonical_policy_metadata_hash), ("rego_sha256", sha256(rego_text))])` (rev13 finding #5 — raw CE-v1 message bytes, NOT the 32-byte hash; rev15 — metadata includes `agent_policy_sha256` and `genpolicy_version_pin`). Verification must use an independent Trustee trust anchor: either the configured platform `signed_policy_public_key` for transitional platform-signed artifacts or a configured allowlist entry matching `metadata.descriptor_signing_pubkey` for customer/CI-signed artifacts. **Never accept `metadata.descriptor_signing_pubkey` as self-authenticating input.** Reject with 400 if missing/invalid.
- New code path in policy evaluation: only evaluate policies whose stored envelope verifies; refuse to load any legacy unsigned policy
- At least one policy-signing trust anchor is configured at Trustee startup; fail if `require_signed_policy=true` with no `signed_policy_public_key` and no trusted descriptor-pubkey allowlist
- Storage backend stores the full envelope; on read, the evaluator unwraps and verifies before passing the Rego text to `regorus`
- **New endpoint** `GET /resource-policy/<id>/body` (rev8 finding #8 / rev9 finding #2 — workload-attested, NOT admin auth). `enclava-init` needs to read the active policy text to verify it; current Trustee `GET /resource-policy` returns only `list_policies()` (`trustee/kbs/src/api_server.rs:345`) and requires admin auth — workload pods cannot carry Trustee admin credentials. Rev9 endpoint:
  - Accepts the same workload attestation token already used for `GET /resource/...` (KBS resource read)
  - Trustee evaluates the resource's own Rego against the workload's attestation claims; if the workload would be authorized to *read* the resource, it is authorized to read its policy body
  - Returns 403 if the workload's attestation doesn't satisfy the resource's policy (i.e., a workload can read its own policy and nothing else)
  - Returns the full `SignedPolicyArtifact` envelope (rev12 — `{metadata, rego_text, signature}` per D9; the metadata is what enclava-init checks against cc_init_data)
  - This way the in-TEE verification step in `enclava-init` works without ever holding admin credentials
- Negative tests in Trustee's own test suite:
  - `POST /resource-policy` with unsigned bytes → 400
  - `POST /resource-policy` with `{rego, signature_for_different_rego}` → 400
  - Direct DB injection of unsigned policy → evaluation refuses, request denied
  - Configured-but-tampered policy → evaluation refuses
  - `GET /resource-policy/<id>/body` returns the envelope with verified signature

**Option B — admission proxy in front of Trustee (rev8: NOT a path to M1/M5; transitional only):**
- Small Rust proxy sits between API and Trustee; verifies signatures before forwarding writes
- Trustee admin endpoint firewalled to allow only the proxy
- **Under operator-root, NetworkPolicy is not a security boundary** — an operator with cluster root can disable the NetworkPolicy or bypass the CNI layer. So Option B does not enforce signed-policy under the threat model.
- Acceptable only as a **transitional** model during deployment, with milestones explicitly marked "M1/M5 not cryptographically enforced — using transitional admission proxy." When Option A lands, Option B is removed.

**M1 and M5 cannot be claimed without Option A.** If Trustee upstream patches stall, the milestone definitions revert to "not cryptographically enforced for orgs deployed under transitional admission proxy."

**CAP API role — request artifacts only, never author Rego** (`crates/enclava-api/src/kbs.rs`):
- Delete `replace_bindings_block` (`kbs.rs:615-679`)
- Delete `kbs_policy.rs` entirely (this work moved to Phase 2's signing-client)
- Use the signing-service client (Phase 2) to fetch signed artifacts; write the envelope to Trustee via `set_policy`
- On reconcile: if Trustee's stored policy differs from the latest signed artifact, CAP requests a fresh artifact and overwrites — never modifies, merges, or re-renders Rego locally
- **(rev13 + rev14 finding #2) Add workload-attested artifact endpoint** (`crates/enclava-api/src/routes/workload.rs` — new): `GET /api/v1/workload/artifacts` (no path-segment app_id; the `descriptor_core_hash` from validated attestation claims selects the row). Required header `Authorization: Attestation <kbs_attestation_token>` — the SAME token the workload presents to Trustee for KBS resource reads. CAP API delegates token validation to a Trustee callback (`POST /kbs/v0/attestation/verify`), receives back the parsed SNP claims including `init_data_claims.descriptor_core_hash`, looks up the artifacts row whose `descriptor_core_hash` matches, returns `{descriptor_payload, descriptor_signature, descriptor_signing_key_id, org_keyring_payload, org_keyring_signature, signed_policy_artifact}`. Anyone without a valid SNP attestation token bound to the matching cc_init_data cannot fetch — no operator-trust path. Rate-limit middleware: per-IP + per-attestation-fingerprint. Reachable from tenant pods via the cluster-internal Service. This replaces the rev13 unauthenticated shape (which had a cross-tenant disclosure risk because descriptor OCI runtime spec contains env vars, mount paths, and custom domains).

**Signing service architecture** (per D9 — separate platform-controlled repo `enclava-platform/policy-templates`):
- Hosts Rego templates baked into the service's container image (the *only* source of authoritative Rego shapes)
- Maintains its own per-org owner-pubkey state, bootstrapped out-of-band at org creation (NOT from platform DB)
- Verifies inputs: org keyring signature against held owner pubkey → deployer pubkey is in verified keyring → descriptor signature against deployer pubkey → all-or-nothing
- Signs reconstructed Rego with private key in CI/HSM
- Worst case (replay of prior signed artifact for same deploy): no-op since the artifact matches the workload's attestation

**In-TEE verification (in `enclava-init`)** (rev13 — corrects the metadata-comparison anchors and pulls all artifacts from a workload-readable endpoint):
- Reads the policy currently in effect from Trustee (workload-attested `GET /resource-policy/<id>/body` from rev9 finding #2)
- Verifies the policy envelope's signature against `descriptor_signing_pubkey` after proving the descriptor/keyring chain; compiled-in platform keys are fallback compatibility keys for transitional platform-signed artifacts
- Reads cc_init_data, which carries `(descriptor_core_hash, descriptor_signing_pubkey, org_keyring_fingerprint)` — but **not** the descriptor's full signature (rev11 cycle fix)
- Fetches the bundle from CAP API's workload-attested artifact endpoint **`GET /api/v1/workload/artifacts`** (rev14 finding #2 — workload-attested, scoped by `descriptor_core_hash` from validated SNP claims). Workload presents its KBS attestation token; CAP API validates it via Trustee callback and returns the artifacts whose `descriptor_core_hash` matches `init_data_claims.descriptor_core_hash`. Returns `{descriptor_payload, descriptor_signature, descriptor_signing_key_id, org_keyring_payload, org_keyring_signature, signed_policy_artifact}`. Then verifies, in order:
  1. Computes `descriptor_core_canonical_bytes` from the read descriptor (purpose label `"enclava-deployment-descriptor-core-v1"`, all fields EXCEPT `expected_cc_init_data_hash` and `expected_kbs_policy_hash`); CE-v1 hashes it; asserts `result == cc_init_data.descriptor_core_hash`. If the operator substituted a descriptor with different core fields (image, signer, namespace, template id, release version, …), this fails.
  2. Computes `descriptor_full_canonical_bytes` (purpose label `"enclava-deployment-descriptor-v1"`, all fields including `expected_*_hash`); calls `ed25519_verify(cc_init_data.descriptor_signing_pubkey, descriptor_full_canonical_bytes, descriptor_signature)`. The signing pubkey is itself anchored to attestation via cc_init_data → SNP `HOST_DATA`. (rev13 finding #5 — Ed25519 signs the raw CE-v1 bytes, not the 32-byte hash.)
  3. **(rev12) Forward-chain check, performed in the TEE:** asserts `descriptor.expected_cc_init_data_hash == SHA256(local_cc_init_data_toml)` where `local_cc_init_data_toml` is the cc_init_data bytes the workload actually booted with (the same bytes that hashed to SNP `HOST_DATA`). Closes the chain inside the TEE rather than relying on the Phase 7 CLI verifier — necessary because the seed-release decision is made here, not at the CLI.
  4. (rev14 finding #3 — corrected: enclava-init has no TOFU channel and never directly trusts the owner pubkey.) Verifies the org keyring in two anchored steps:
     - **4a.** Computes the CE-v1 fingerprint of the received keyring bytes; asserts `fingerprint == cc_init_data.org_keyring_fingerprint`. This pins the **exact keyring bytes** to attestation via SNP `HOST_DATA` — nothing TOFU-style.
     - **4b.** The signing service's authorization is implicit: the `SignedPolicyArtifact` (whose signature is verified in step 5 against the platform-release-pinned signing-service pubkey) is only ever issued by the signing service if the deployer pubkey was a verified member of the org keyring under the signing service's sovereign owner-pubkey state. So a verifying artifact in step 5 transitively proves that the keyring (whose fingerprint we just pinned) was acceptable to the signing service.
     - Asserts `cc_init_data.descriptor_signing_pubkey` is a member of the keyring with `deployer` role or higher (the structural in-keyring check).
     - The keyring's owner-Ed25519 signature inside the payload is **not** verified inside the TEE (no anchor for the owner pubkey) — that's the signing service's job, transitively trusted via 4b.
  5. **(rev13 finding #3) `SignedPolicyArtifact` metadata comparison — corrected anchors:** verifies the artifact's signature per finding #5 (Ed25519 over the raw CE-v1 message), then asserts:
     - `metadata.app_id == descriptor.app_id` (descriptor is the authoritative source — cc_init_data does not carry app_id)
     - `metadata.deploy_id == descriptor.deploy_id` (likewise)
     - `metadata.descriptor_core_hash == cc_init_data.descriptor_core_hash`
     - `metadata.descriptor_signing_pubkey == cc_init_data.descriptor_signing_pubkey`
     - `metadata.platform_release_version == descriptor.platform_release_version` (rev13 — descriptor field added so this comparison is meaningful)
     - `metadata.policy_template_id == descriptor.policy_template_id` (rev13 finding #1)
     - `metadata.policy_template_sha256 == descriptor.policy_template_sha256` (rev13 finding #1)
  6. Verifies `SHA256(envelope.rego_text) == descriptor.expected_kbs_policy_hash` — the customer-authorized policy hash, now trustworthy because the descriptor's full signature was verified in step 2 against an attestation-anchored pubkey, AND the template version that produced it is pinned by step 5.
- Two unidirectional chains both validated inside the TEE: forward (descriptor → expected_cc_init_data_hash → cc_init_data) at step 3, backward (cc_init_data → descriptor_core) at step 1. The Phase 7 CLI verifier independently re-checks the same forward chain for unlock-channel trust, but seed release does not depend on it.
- Mismatch on any step → refuses to release seeds; structured error returned to CLI

**Operational variants:** if a full signing service is too much for v1, an acceptable transitional model is "templates committed signed to a versioned git repo by maintainers; CAP API fetches the signed template, fills only specific slots from a customer-signed descriptor, doesn't re-author the Rego structure, writes to Trustee." Same security property if the slot-filling is byte-deterministic and the descriptor supplies all values; worse ergonomics. Decide before starting.

**Audit task (must complete before Phase 3 cutover):** dump current production Trustee policy state across all CAP-managed resources; identify operator-added rules outside CAP markers; either roll them into the rendered template or document why they should be dropped.

**Effort:** 2 weeks (rev7/rev8: header and footer reconciled — was inconsistent in earlier draft. 1.5 weeks for the Trustee patch + signed-policy read endpoint + negative tests; ~3 days for CAP-side cleanup, audit, and rollout).

---

### Phase 4 — Two-hostname routing + HAProxy distributed lock (1 week)

**Goal:** Cut over to two-hostname model. Fix the broken process-local HAProxy lock under multi-replica API.

**Findings addressed:** C8 (full), C13 (TXT verification), Highs around HAProxy/Caddy injection, the multi-replica HAProxy lock bug.

**Changes:**

App creation (`routes/apps.rs`):
- Compute both hostnames via Phase 1 helpers
- Atomic two-record DNS creation; roll back on partial failure
- Insert two HAProxy SNI map entries

Service still exposes 443 (Caddy) and 8081 (TEE attestation), but the attestation service port targets the proxy's TLS listener:
- HAProxy SNI route `<app>.<orgSlug>.enclava.dev` → `service:443`
- HAProxy SNI route `<app>.<orgSlug>.tee.enclava.dev` → `service:8081` → pod `targetPort:8443`

HAProxy distributed lock (`crates/enclava-api/src/edge.rs`):
- Replace process-local `Mutex` with PostgreSQL advisory lock: `SELECT pg_advisory_xact_lock(<haproxy_lock_id>)` inside the transaction that reads ConfigMap, mutates, writes back
- Lock held for read-modify-write duration; released on commit/rollback
- Correct under `replicas: 2` (verified at `cap/deploy/api/deployment.yaml:7`)

Custom domain verification (`routes/domains.rs`):
- TXT challenge required before A/AAAA record creation
- FQDN parser (e.g. `addr` or `publicsuffix` crate); reject anything inside `enclava.dev` zone unless explicitly assigned

Caddy/HAProxy config: structured builders, no `format!` of validated user input.

**Tests:**
- Concurrent app creates from two API pods → both routes appear, no lost writes
- Custom domain TXT verification: pass / fail / missing / wrong
- Custom domain inside `enclava.dev` rejected
- Caddyfile + HAProxy snapshot tests with realistic + adversarial inputs

**Migration of existing apps:** one-shot binary computes new hostname pair, creates DNS records, adds HAProxy entries. Old hostnames stay live one release cycle.

**Effort:** 1 week.

---

### Phase 5 — In-TEE unlock model: enclava-init + attestation-proxy with TLS (2.5–3 weeks)

**Goal:** Replace the 646-line `bootstrap_script.sh` with Rust `enclava-init` unlock/mount logic. Run attestation-proxy as a regular sidecar that terminates its own TLS with the attestation-bound self-signed cert. On the current Kata SNP runtime, app/caddy must start before the LUKS mount exists, so Phase 5 uses an argv-preserving static wait-exec helper from the app/caddy images and a long-running `enclava-init` mounter sidecar.

**Findings addressed:** Highs around privileged root containers + SYS_ADMIN, runtime install, shell-interpolated user command.

**Changes:**

New crate `crates/enclava-init`:
- Single Rust binary, sync, no async runtime needed
- Modules:
  - `socket.rs` — unix socket on `/run/enclava/unlock.sock` for password mode
  - `unlock.rs` — Argon2id derivation, retry loop, rate limit (5/60s)
  - `kbs_fetch.rs` — autounlock-mode KBS read of wrap key
  - `luks.rs` — `cryptsetup luksOpen` via `libcryptsetup-rs`
  - `seeds.rs` — HKDF-SHA256 derivation; atomic file writes via tmp+rename
  - `trustee_verify.rs` — verify Trustee policy signature against compiled-in pubkey; verify policy text matches templates for current digest
  - `chown.rs` — replicates `resolve_exec_identity` + chown logic
  - `main.rs` — wire it together; exit 0 on success
- Memory hygiene: `Zeroize` on every secret type

attestation-proxy enhancements (separate `attestation-proxy` repo):
- Add TLS termination on 8443 with self-signed cert generated on each pod boot while keeping internal HTTP on 8081 for KBS/CDH, Caddy loopback proxying, and health checks.
- Generate **two** Ed25519 keypairs on boot:
  - **TLS keypair** for the self-signed cert (leaf SPKI bound in attestation)
  - **Receipt-signing keypair** (per-pod ephemeral; pubkey bound in attestation alongside the TLS SPKI)
- Bind keys into SNP `report_data` via the **rev9 split layout**:
  - `report_data[0..32]` = `transcript_hash = ce_v1_hash([("purpose","enclava-tee-tls-v1"), ("domain", domain), ("nonce", nonce), ("leaf_spki_sha256", spki)])` — binds the TLS leaf
  - `report_data[32..64]` = raw `receipt_pubkey_sha256` — directly recoverable by Trustee/CLI
- Endpoints:
  - `GET /v1/attestation?nonce=<base64>&domain=<tee-host>&leaf_spki_sha256=<hex>` and `GET /.well-known/confidential/attestation?...` — returns SNP evidence plus `runtime_data_binding` for domain, leaf SPKI hash, and receipt pubkey hash
  - `POST /unlock` — forwards password to enclava-init via unix socket
  - `POST /receipts/sign` (rev6 — moved here from Phase 10): accepts a typed receipt request, performs in-TEE validation specific to the receipt type (e.g., for rekey, verifies the requesting workload's identity matches the bound resource), signs the receipt body using D11 CE-v1 encoding with the receipt-signing key, returns the signed receipt. Receipt types defined here for use by Phase 6 and Phase 10:
    - `rekey` (Phase 6 consumer): allows overwriting an existing KBS resource the workload owns
    - `teardown` (Phase 6 consumer): allows deletion of an existing KBS resource on app destruction
    - `unlock_mode_transition` (Phase 10 consumer): allows changing the app's unlock mode in the platform DB

This makes the receipt-signing primitive ship in Phase 5. Phase 6 uses it for rekey/teardown. Phase 10 uses it for unlock-mode transitions. The same per-pod ephemeral key signs all three receipt types; CE-v1's `purpose` label provides domain separation between them.

Pod manifest (`crates/enclava-engine/src/manifest/`):
- `statefulset.rs`: render all stateful workload components as regular containers (app, attestation-proxy, caddy, long-running `enclava-init` mounter); the Block PVC/LUKS path intentionally has no initContainers
- `containers.rs`: app/caddy drop `privileged: true` and `SYS_ADMIN`; they start under `/usr/local/bin/enclava-wait-exec` supplied by their images, signal `/run/enclava/containers/<name>`, wait for `/run/enclava/init-ready`, then `exec` the original argv
- `containers.rs`: `enclava-init` waits for app/caddy sentinels, opens/mounts LUKS, writes seeds, marks ready, and stays alive as the mount propagation source
- `volumes.rs`: add `emptyDir { medium: Memory }` `unlock-socket` mounted in attestation-proxy, app, caddy, and enclava-init at `/run/enclava`; keep startup ConfigMap only as a fallback for app images that provide no argv

Bootstrap script remnants:
- Most of `bootstrap_script.sh` deleted
- `SECURE_PV_ALLOW_RUNTIME_INSTALL` removed entirely (High finding)

**Runtime finding:** LUKS format/open/mount succeeds inside the Kata SEV-SNP guest. The failed assumption was creating workload containers after the mount exists: the runtime returns `EINVAL`. The live-passing contract starts workload containers first, has them wait, then starts the LUKS mount via the long-running mounter sidecar.

**Tests:**
- Argon2id and HKDF vectors
- Wrong password loops; rate limit at 6th attempt within 60s
- Atomic write: kill -9 between write and rename → no partial file
- Zeroize: heap-trace test that owner_seed bytes wiped on drop
- Integration via testcontainers: write password → seeds appear at expected paths
- Snapshot: rendered pod manifest has no `privileged: true` on caddy or app

**TEE TLS handshake protocol (rev7 — explicit ordering, fixes finding #6):**

The handshake binds an attested SNP report to a TLS leaf cert. Every step is ordered to prevent ambiguity between implementations.

1. **Pod boot, attestation-proxy starts:**
   - Generates two Ed25519 keypairs in TEE memory: `tls_keypair` and `receipt_keypair`
   - Generates a self-signed X.509 cert from `tls_keypair` (CN = `<app>.<orgSlug>.tee.enclava.dev`, SAN = same, validity = pod lifetime)
   - Stores `tls_pubkey_spki_sha256` (32 bytes) and `receipt_pubkey_sha256` (32 bytes)
   - Listens on internal HTTP 8081 for in-pod CDH/Caddy/readiness traffic and external TLS 8443 for the Service's `attestation` target port.
2. **CLI initiates unlock:**
   - CLI generates fresh 32-byte `nonce` (CSPRNG, per-unlock)
   - CLI opens a one-time TLS connection to `https://<app>.<orgSlug>.tee.enclava.dev:8081/.well-known/confidential/attestation?...` to capture the presented leaf SPKI, then immediately switches to a rustls client that accepts only that SPKI.
3. **attestation-proxy responds:**
   - Reads `nonce` from query string
   - Computes `transcript_hash` via D11 CE-v1 with records in fixed order (rev9: receipt_pubkey_sha256 is NOT in the transcript — placed directly in REPORT_DATA[32..64] so Trustee can extract it):
     ```
     ("purpose","enclava-tee-tls-v1"),
     ("domain", "<app>.<orgSlug>.tee.enclava.dev"),
     ("nonce", nonce_32B),
     ("leaf_spki_sha256", tls_pubkey_spki_sha256_32B)
     ```
   - `report_data` (64 bytes) is built as **`report_data[0..32] = transcript_hash`, `report_data[32..64] = receipt_pubkey_sha256`** — the receipt-signing pubkey hash sits directly in bytes 32..64, not inside any one-way function
   - Calls into the SNP attestation-report device (`/dev/sev-guest`) with this report_data; receives the AMD-signed report bytes
   - Returns JSON bundle with `runtime_data_binding` plus evidence payload. The current CAP CLI validates the evidence JSON's SNP `report_data` against the expected D11 bytes and then pins the TLS client to the attested leaf SPKI. Full raw report/VCEK validation remains the remaining Phase 7 hardening item.
   - Caches the SNP report keyed by `nonce` (refresh on next quote request with a new nonce)
4. **CLI verifies the bundle (per Phase 7 algorithm):**
   - Parses SNP report via `sev` crate; verifies AMD chain (current local code validates `report_data` from the evidence JSON; raw report/VCEK validation remains open)
   - Re-derives `transcript_hash` using the same CE-v1 input the proxy used; checks `report.report_data[0..32] == transcript_hash`
   - Computes `sha256(bundle.receipt_pubkey_raw)` (the 32-byte Ed25519 public key) and checks it equals `report.report_data[32..64]` — anchors the receipt pubkey directly
   - Verifies `report.measurement` matches `expected_firmware_measurement` (from customer-signed deployment descriptor)
   - Verifies `SHA256(cc_init_data_toml) == report.host_data` (anchors `init_data_claims`)
   - Parses `cc_init_data_toml`; checks all `init_data_claims.*` fields against the customer-signed descriptor
   - Confirms `tls_pubkey_spki_sha256` (computed from the bundle's TLS PEM) matches what the transcript_hash bound
5. **CLI builds a pinned TLS client:**
   - rustls custom verifier: accept the server cert iff `SHA256(cert.spki) == tls_pubkey_spki_sha256`; ignore CA chain entirely
   - Re-fetches the attestation endpoint over verified TLS before sending sensitive payloads
6. **CLI sends sensitive payloads** (password for unlock, transition requests) over the pinned TLS connection
7. **Receipt verification** (post-unlock, for Phase 6 / Phase 10 receipts):
   - CLI uses `receipt_pubkey_sha256` (already trust-anchored via the transcript) to verify Ed25519 receipt signatures
   - The same trust anchor covers TLS, unlock, rekey, teardown, and unlock-mode transition

**Why this ordering matters:**
- Nonce comes from CLI, not the proxy → replay protection without trusting the proxy's clock
- `transcript_hash` (bytes 0..32) commits to `(domain, nonce, leaf_spki)` in one CE-v1 shot
- `receipt_pubkey_sha256` lives in bytes 32..64 directly, not inside the transcript hash, so Trustee's SNP-claim parser can expose it as a structured claim and Rego can compare against it. Putting it inside the transcript would have made the receipt-verification chain in Phase 6 impossible — that was the rev9 critical fix.
- The 64-byte SNP REPORT_DATA field is fully consumed: 32 bytes transcript + 32 bytes receipt-pubkey hash = 64. No padding ambiguity.
- CLI never has to trust the cert's CA chain — only its SPKI hash, which is attested

**Effort:** 3 weeks (rev7: was 2.5–3 weeks; +receipt-signing API endpoint and TEE TLS handshake spec already accounted in rev6 estimate; finalized as 3 weeks).

---

### Phase 6 — Workload writes its own seeds via Trustee's existing API + Trustee patches for receipt-gated writes (rev7: 2.5 weeks)

**Goal:** Eliminate the operator-domain `kbs-resource-writer`. Workload writes its own seed material via Trustee's attestation-gated `workload-resource` API. **Reaches M2.**

**Findings addressed:** C7 (full), rev5 finding #4 (seed lifecycle).

**Trustee landscape:** Trustee already exposes `PUT/DELETE /kbs/v0/workload-resource/{repo}/{type}/{tag}` for resources whose type ends in `-owner` (`trustee/kbs/src/api_server.rs:457-600, 495, 481`). Workload presents its attestation token; Rego policy on the resource gates the write. **However, the existing API is insufficient for first-write-wins, body-aware policy, and Ed25519 receipt verification — those require upstream Trustee patches listed below (rev8 corrected wording — earlier "no upstream needed" was wrong).**

**Changes:**

Resource naming: each app's seed material at `default/cap-<orgSlug>-<app>-tls-owner` (the `-owner` suffix is required by Trustee).

Rego policy on each resource:
- Same template style as Phase 2 read-side Rego: anchor in `input.snp.init_data_hash`; check `input.init_data_claims.{image_digest, signer_identity, namespace, service_account, identity_hash}` (rev12: single-anchor; no `input.kubernetes.*`)
- Read and write are gated by the same Rego — only the same attested workload can read what it wrote

`enclava-init` enrollment flow (`crates/enclava-init/src/enrollment.rs`):
- On first boot:
  1. Generate `autounlock_wrap_key` locally (random, in-TEE)
  2. SNP attestation, obtain Trustee attestation token
  3. PUT wrap key to `/kbs/v0/workload-resource/default/cap-<orgSlug>-<app>-tls-owner/0` with attestation token
  4. Trustee evaluates Rego against workload claims; on success, stores wrap key
  5. App row marked `enrolled` (DB)
- On subsequent boots: standard attested KBS read of the same resource

Password-mode apps:
- `owner_seed = Argon2id(password, app_salt)` derived directly in `enclava-init`
- KBS not used for owner_seed at all

**Seed lifecycle semantics (rev5):**

| Operation | When allowed | Who/what gates |
|---|---|---|
| **First write** | At first attested boot, when no resource exists at the path | Trustee Rego; `enclava-init` enrollment is the writer |
| **Read** | At every attested boot | Trustee Rego (same as write — must match attestation) |
| **Overwrite** | Only via explicit rekey flow (e.g. unlock-mode change, key rotation) | Trustee Rego attestation match **plus** a TEE-signed `rekey` receipt (issued by attestation-proxy's `POST /receipts/sign` endpoint, primitive ships in Phase 5) embedded in the request body. Without the receipt, the write fails. |
| **Delete** | Only via explicit teardown flow (app destruction) | (rev13 finding #4 — clarified: admin tokens cannot bypass the workload-attested gate.) **CAP admin initiates** teardown via the API (orchestrates pod state transitions, marks the app `teardown_pending`, schedules the workload to issue the `DELETE`). The Trustee `DELETE /workload-resource/...` call itself is authorized **only** by attested workload identity + a TEE-signed teardown receipt — Trustee never accepts admin-bearer DELETEs against `*-owner` resources. So the operator can stop the app but cannot directly delete its KBS material; the deletion is performed by the attested workload presenting a teardown receipt signed by attestation-proxy's per-pod ephemeral key. |
| **Concurrent writes** | First-write-wins | Trustee atomically rejects writes when a non-empty resource already exists, unless the request carries a valid rekey receipt |

**Trustee-side prerequisites (rev7 finding #2 — CRITICAL).** Today's Trustee cannot enforce any of the lifecycle table above:
- `workload-resource` policy input has only `method`, `path`, `query` (`trustee/kbs/src/api_server.rs:446`); no body, no body hash, no Ed25519 verification
- KV storage backend (`trustee/kbs/src/plugins/implementations/resource/kv_storage.rs:35`) overwrites unconditionally — no check-and-set
- No "delete authorization" beyond the standard admin path

Phase 6 is gated on these upstream patches landing first:

1. **Conditional writes (check-and-set).** Add `If-Match: <expected-version>` and `If-None-Match: *` semantics to `PUT /kbs/v0/workload-resource/...`. Backed by a version column in storage; first-write-wins is `If-None-Match: *` returning 412 if the resource exists.
2. **Body hash in policy input.** Extend the policy input to include `request.body_sha256` (32-byte hex) so Rego can reference it: `input.request.body_sha256 == "..."`.
3. **Receipt verification done in Trustee Rust (rev10 — closes finding #1).** The earlier draft asked Rego to call `sha256(...)` and `ce_v1_extract_field(...)`, neither of which exist as `regorus` builtins. Doing the heavy lifting in Rego is a non-starter without a custom-builtin path that's effectively new infrastructure. **Rev10:** all parsing, hashing, and signature verification happen in Trustee Rust before policy evaluation. Trustee then exposes pre-computed typed fields/booleans to Rego.

   **Trustee-side Rust pipeline (Phase 3/6 patch — runs before Rego eval on `PUT/DELETE workload-resource`):**
   - Parse the request body JSON; extract `body.operation`, `body.receipt.{pubkey, payload_canonical_bytes, signature}`, optional `body.value`
   - Extract `receipt_pubkey_sha256` from SNP `report_data[32..64]` (per D8 layout)
   - Compute `pubkey_hash_matches := sha256(body.receipt.pubkey) == report_data[32..64]`
   - Compute `signature_valid := ed25519_verify(body.receipt.pubkey, body.receipt.payload_canonical_bytes, body.receipt.signature)`
   - Parse `body.receipt.payload_canonical_bytes` as CE-v1 records; expose individual fields as `input.request.body.receipt.payload.{purpose, app_id, resource_path, new_value_sha256, timestamp}` (rekey shape) or analogous for teardown/transition
   - For rekey: compute `value_hash_matches := sha256(body.value) == receipt.payload.new_value_sha256`

   **Exposed policy input** (rev10):
   ```
   input.request.body.operation                              : string  # "rekey"|"teardown"|"unlock_mode_transition"
   input.request.body.receipt.pubkey_hash_matches            : bool
   input.request.body.receipt.signature_valid                : bool
   input.request.body.receipt.payload.purpose                : string
   input.request.body.receipt.payload.app_id                 : string
   input.request.body.receipt.payload.resource_path          : string
   input.request.body.receipt.payload.timestamp              : string  # RFC3339
   input.request.body.receipt.payload.new_value_sha256       : string  # rekey only
   input.request.body.value_hash_matches                     : bool    # rekey only
   ```

   **Rego rules become trivial `==` comparisons:**
   ```rego
   allow {
       input.request.method == "PUT"
       input.request.body.operation == "rekey"
       input.request.body.receipt.pubkey_hash_matches
       input.request.body.receipt.signature_valid
       input.request.body.receipt.payload.purpose == "enclava-rekey-v1"
       input.request.body.receipt.payload.resource_path == data.bound.resource_path
       input.request.body.value_hash_matches
       # ...plus the standard image_digest/signer_identity/namespace constraints from Phase 2
   }
   ```

   No new Rego builtins are strictly required — Trustee's Rust does the work, Rego does the policy. (The `crypto.ed25519.verify` builtin is no longer needed; remove from the patch list.) This avoids the rev9 problem entirely: no undefined Rego functions, no symmetry-with-CLI canonicalization issue (canonicalization is in Trustee), and Rego stays simple and auditable.
4. **Delete authorization.** `DELETE` operations evaluate the same Rego as `PUT` and require a teardown receipt in the request body.
5. **Receipt envelope contract (rev11 — aligned with bullet 3's Rust pipeline; the rev9 "Rego runs ed25519.verify and ce_v1_extract_field" wording was an internal contradiction with bullet 3 and is removed).** The wire-format request body is:
   ```json
   {
     "operation": "rekey" | "teardown" | "unlock_mode_transition",
     "receipt": {
       "pubkey":                 "<base64 of 32-byte Ed25519 pubkey>",
       "payload_canonical_bytes": "<base64 of CE-v1 receipt payload>",
       "signature":              "<base64 of 64-byte Ed25519 signature>"
     },
     "value": "<base64 of new-resource-bytes>"   // present for "rekey" only; absent for "teardown" / "unlock_mode_transition"
   }
   ```
   - `payload_canonical_bytes` is the receipt's canonical form per D11 (e.g., for rekey: CE-v1 of `[("purpose","enclava-rekey-v1"), ("app_id", uuid), ("resource_path", path), ("new_value_sha256", sha256(value)), ("timestamp", rfc3339)]`)
   - **All parsing, hashing, and Ed25519 verification happen in Trustee Rust** (per bullet 3 above) before policy evaluation. Trustee parses the body JSON; reads the three fields plus optional `value`; CE-v1-decodes `payload_canonical_bytes` to extract the typed receipt fields (`purpose`, `app_id`, `resource_path`, `timestamp`, `new_value_sha256` for rekey); computes `pubkey_hash_matches := sha256(receipt.pubkey) == report_data[32..64]`; computes `signature_valid := ed25519_verify(receipt.pubkey, payload_canonical_bytes, receipt.signature)`; for rekey, computes `value_hash_matches := sha256(value) == decoded_payload.new_value_sha256`.
   - **Rego sees only typed fields and pre-computed booleans** (the exact policy-input shape from bullet 3): `input.request.body.operation`, `input.request.body.receipt.pubkey_hash_matches`, `input.request.body.receipt.signature_valid`, `input.request.body.receipt.payload.{purpose,app_id,resource_path,timestamp,new_value_sha256}`, `input.request.body.value_hash_matches`. Rego rules are `==` comparisons only. **No `crypto.ed25519.verify`, no `sha256(...)`, no `ce_v1_extract_field(...)` calls in Rego** — those were the rev9 undefined-builtin issue this bullet originally introduced.
   - Removed from the patch list: the `crypto.ed25519.verify` Rego built-in. The CE-v1 decoder is a Trustee-Rust function, not a Rego built-in.
6. **Trustee tests.** Each of the above gets unit tests in Trustee's own suite; CAP integration tests don't ship until upstream lands.

Estimated upstream effort: ~1.5 weeks. Run in parallel with Phase 5 (where attestation-proxy adds the receipt-signing primitive). Owner: same engineer / repo as Phase 3's signed-policy enforcement work, since both touch `kbs/src/api_server.rs`.

Implementation details (assuming the upstream patches land):
- `enclava-init`'s first-write uses `If-None-Match: *`; on 412 (resource exists), reads the existing resource instead — no race window
- Rekey: API initiates → attestation-proxy `POST /receipts/sign { type:"rekey", ... }` → workload bundles `{operation, receipt:{pubkey, payload_canonical_bytes, signature}, value}` in the envelope → PUT to Trustee → Trustee Rust pipeline computes `pubkey_hash_matches`, `signature_valid`, `value_hash_matches`, exposes them as policy inputs → Rego asserts all booleans true plus standard policy constraints. Forged pubkey rejected because `sha256(forged) != report_data[32..64]` so `pubkey_hash_matches = false`.
- Teardown: same pattern with `type:"teardown"` and DELETE method

Service removal:
- Delete `crates/enclava-api/src/bin/kbs-resource-writer.rs`
- Delete its NetworkPolicy and Service in `deploy/`
- Delete `KBS_RESOURCE_WRITER_TOKEN` env var and all callers
- Delete `ensure_tls_seed_resource` in `kbs.rs`

Migration:
- Existing apps with KBS resources written by old `kbs-resource-writer` continue to work for *reads*
- For writes (e.g. rekey), apps must re-enroll via a controlled pod restart in attested-write mode
- Operator runbook: `runbooks/migrate-kbs-resources.md`

**Tests:**
- Workload with wrong attestation → write rejected by Trustee Rego
- First write succeeds; second write without rekey receipt → rejected
- Rekey with valid receipt → succeeds
- Rekey with stale receipt (signed by old pod's keypair, replayed against new pod) → rejected (receipt's signing key doesn't match current pod's SNP-bound pubkey)
- Teardown without receipt → rejected
- Password-mode app boots and unlocks with no Trustee resource at all
- `kbs-resource-writer` binary gone from the build

**Migration:** `0017_app_enrollment_state.sql` (status: `pending_enrollment`/`enrolled`/`teardown_pending`).

**Dependencies:** Phase 2 (Rego template), Phase 3 (full-policy ownership + Trustee-side signed-policy enforcement), Phase 5 (`enclava-init` exists + attestation-proxy receipt-signing API), **Trustee upstream patches above (the gating dependency)**.

**Effort:** 2.5 weeks (rev7: was 1 week; +1.5 weeks for Trustee upstream patches landing in parallel with Phase 5 — net schedule unchanged because parallelization).

---

### Phase 7 — CLI attestation-pinned TLS + customer-signed deployment descriptor + signed org keyring (2 weeks)

**Goal:** CLI verifies SNP attestation chain + init_data_claims + SPKI binding; expectations come from customer-signed deployment descriptor (D10); the descriptor's signing pubkey is verified against an owner-signed org keyring. **Reaches M4.**

**Findings addressed:** C3, rev4 finding #4 (CLI trust anchor), rev5 finding #2 (org keyring trust).

**Changes:**

CLI keypair (`crates/enclava-cli/src/keys.rs` — new):
- Ed25519 generation on first use (`enclava login` triggers if none exists)
- Stored at `~/.enclava/keys/<user_id>.priv` (mode 0600)
- Public key registered via `POST /users/me/public-keys`
- `enclava users rotate-key`: email confirmation + owner role + old-key-signed transition certificate

Org keyring (`crates/enclava-cli/src/keyring.rs` — new, rev5):
- `OrgKeyring` struct (per D10) — owner-signed list of members + roles + pubkeys
- Owner-signed updates; non-owner CLIs verify against locally-cached owner pubkey
- `enclava org keyring init` (owner-only): creates v1 keyring, signs, uploads
- `enclava org keyring add-member` (owner-only): adds entry, increments version, signs, uploads
- `enclava org keyring trust` (member's first encounter): TOFU prompt with owner pubkey fingerprint; user confirms out of band; cached at `~/.enclava/state/<org_id>/owner_pubkey`
- Subsequent fetches verify keyring signature against cached owner pubkey; refuse on mismatch with explicit error and rotation instructions

Deployment Descriptor (`crates/enclava-cli/src/descriptor.rs` — new, rev9: replaces "intent.rs"):
- `DeploymentDescriptor` struct with full D10 fields (org/app identity, k8s binding, signer identity, full `oci_runtime_spec`, sidecars, platform binding, kbs_resource_path, etc.)
- Canonical encoding: **CE-v1 from D11** (length-prefixed TLV records). No CBOR. Deterministic by construction; same encoder used in CLI, API, and signing service.
- OCI spec builder: takes the customer's `enclava.toml` + `docker inspect` of the resolved image digest + platform release defaults; produces the canonical `oci_runtime_spec` field
- Sign/verify helpers; local cache at `~/.enclava/state/<app_id>/descriptor.json`

CLI `enclava deploy`:
- Resolves image digest via cosign
- Reads platform sidecar digests + firmware measurement + supported genpolicy version + **`policy_template_id`, `policy_template_sha256`, `policy_template_text`, and `platform_release_version`** (rev13 + rev14 finding #1) from CLI-bundled `platform-release.json` (shipped with each CLI release, signed by the platform-release signing key, verified by CLI on first read; **not** fetched at runtime from API). The CLI:
  1. Verifies the platform-release artifact signature.
  2. Asserts `sha256(policy_template_text) == policy_template_sha256` — proves the bytes shipped match the pinned hash. Mismatch → CLI refuses the release and does not deploy.
  3. Renders the Rego template using `policy_template_text` against descriptor field values, producing the same byte stream the signing service will produce.
  4. Computes `expected_kbs_policy_hash = sha256(rendered_rego_text)` and signs it as part of the descriptor.
- The signing service performs the same `sha256(baked_template_text) == release_pin.policy_template_sha256` self-check at startup; mismatch refuses to start. Customer, signing service, and enclava-init therefore all see the same template bytes — the hash is a tag, not the trust anchor.
- Inspects the customer's image to populate the OCI spec defaults; merges with `enclava.toml` overrides
- Builds descriptor, signs, POSTs `{descriptor_payload, signature, signing_key_id}` to API
- API stores in `deployment_intents` (table name kept for migration compatibility; rows now hold descriptor blobs)

CLI `enclava unlock`:
- Fetches latest signed descriptor + current org keyring
- Verifies keyring signature against TOFU-cached owner pubkey
- Verifies the descriptor's signing pubkey is in keyring with `deployer` role or higher
- Verifies descriptor signature
- Uses verified descriptor values as attestation expectations
- Local TOFU pin against last-known descriptor signing pubkey for the app; pubkey change → refuse with explicit rotation instructions

SNP verifier (`crates/enclava-cli/src/attestation.rs`):
```rust
fn verify_quote(bundle: &AttestationBundle, exp: &AttestationExpectations) -> Result<SpkiHash> {
    verify_amd_chain(&bundle.snp_report)?;
    require_eq!(bundle.snp_report.measurement, exp.expected_firmware_measurement);

    // Anchor cc_init_data to attestation: HOST_DATA == SHA256(received cc_init_data)
    let derived_init_data_hash = sha256(&bundle.cc_init_data_toml);
    require_eq!(bundle.snp_report.host_data, derived_init_data_hash);

    // rev10: chain customer-authorized hash to attested hash
    require_eq!(exp.descriptor.expected_cc_init_data_hash, derived_init_data_hash);

    // Now init_data_claims is trusted (its hash chains: AMD signature -> HOST_DATA -> cc_init_data bytes)
    let claims = parse_cc_init_data(&bundle.cc_init_data_toml)?;
    require_eq!(claims.image_digest, exp.descriptor.image_digest);
    require_eq!(claims.runtime_class, exp.descriptor.expected_runtime_class);
    require_eq!(claims.signer_identity, exp.descriptor.signer_identity);
    require_eq!(claims.namespace, exp.descriptor.namespace);
    require_eq!(claims.service_account, exp.descriptor.service_account);
    require_eq!(claims.identity_hash, exp.descriptor.identity_hash);
    for (name, digest) in &exp.descriptor.sidecars {
        require_eq!(claims.sidecar_digests[name], *digest);
    }

    // rev10 encoding-locked SPKI/raw hashing
    let leaf_spki_hash = sha256(&bundle.tls_pubkey_spki_der);   // SHA256 of DER SubjectPublicKeyInfo
    let receipt_pubkey_hash = sha256(&bundle.receipt_pubkey_raw); // SHA256 of raw 32-byte Ed25519 pubkey
    let transcript = ce_v1_hash(&[
        ("purpose", b"enclava-tee-tls-v1"),
        ("domain", exp.domain.as_bytes()),
        ("nonce", &exp.nonce),
        ("leaf_spki_sha256", &leaf_spki_hash),
    ]);
    // SNP REPORT_DATA layout:
    //   bytes 0..32  = transcript_hash
    //   bytes 32..64 = receipt_pubkey_sha256 (raw, recoverable)
    let mut expected_report_data = [0u8; 64];
    expected_report_data[..32].copy_from_slice(&transcript);
    expected_report_data[32..].copy_from_slice(&receipt_pubkey_hash);
    require_eq!(bundle.snp_report.report_data, expected_report_data);

    Ok(SpkiAndReceiptKey { leaf_spki_hash, receipt_pubkey_hash })
}
```

`SpkiPinnedVerifier` (rustls), production build gates: `TENANT_TEE_TLS_MODE`, `TENANT_TEE_ACCEPT_INVALID_CERTS` honored only with `cfg(debug_assertions)`. `--insecure` flag is no-op in release builds.

**Tests:**
- Tampered AMD signature → reject
- Wrong firmware measurement / image digest / sidecar digest / runtime class / signer identity → reject
- HOST_DATA doesn't match cc_init_data → reject (binding chain broken)
- SPKI mismatch → reject
- Replayed quote (stale nonce) → reject
- Customer signature: tampered descriptor payload → reject; revoked signing key → reject; unknown key → TOFU prompt
- Org keyring: tampered keyring → reject; owner pubkey mismatch with TOFU cache → reject; member tries to deploy without `deployer` role → reject

**Effort:** 2 weeks.

---

### Phase 8 — Verification of Phase 0 cutover + dead-code removal (rev9: 2 days)

The substantive Caddy TLS-ALPN-01 cutover work moved into Phase 0 (rev7 finding #3 — couldn't disable secret generation without breaking pods; rev8 locked the challenge method to TLS-ALPN-01 only). Phase 8 is now a verification + cleanup phase only.

**Goal:** Confirm the Phase 0 cutover holds in steady state; delete any residual code paths around the legacy DNS-01 / Cloudflare token flow.

**Changes:**
- Remove the `CADDY_DNS_PROVIDER` feature flag entirely; supporting tenant DNS-01 is unnecessary
- Delete dead code paths in `secrets.rs`, `containers.rs`, `volumes.rs`, `ingress.rs` around the tenant Cloudflare token
- caddy-ingress image: keep only the no-DNS-plugin TLS-ALPN variant; deprecate the DNS-01 variant from the image registry
- Update `caddy-ingress/scripts/smoke.sh` to assert the Cloudflare DNS module is absent

**Tests:**
- Manifest snapshot: no `CF_API_TOKEN` env in any tenant pod across all platform releases since Phase 0 cutover (regression check)
- CI: build fails if `CADDY_DNS_PROVIDER` env var is read anywhere in the codebase

**Dependencies:** Phase 0 local cutover is complete; production verification still depends on image rollout, manifest reconciliation, CAA publication, and CT monitoring schedule.

**Effort:** 2 days.

---

### Phase 9 — Customer-controlled signing via Fulcio identity (1.5 weeks)

**Calendar:** runs Weeks 5–6 in parallel with Phase 5. **Reaches M3.**

**Goal:** Replace platform-wide cosign verification with per-app Fulcio identity. Customers sign in their own GitHub Actions runners.

**Findings addressed:** C5 (full), C6.

**Changes:**

Cosign verifier rewrite (`crates/enclava-api/src/cosign.rs`) — rev8 corrected sigstore-rs API:

The vendored `sigstore` 0.13 crate exports (per `sigstore-0.13.0/src/cosign/verification_constraint/mod.rs:69`):
- `CertSubjectUrlVerifier { url, issuer }` — exact-match URL subject (GitHub Actions OIDC subjects are URL-shaped: `https://github.com/me/myapp/.github/workflows/build.yml@refs/heads/main`)
- `CertSubjectEmailVerifier { email, issuer }` — for OIDC issuers using email subjects (Google, etc.)
- `CertificateVerifier` — generic certificate-based verifier
- `PublicKeyVerifier` — for offline-signed images (the current code's path)

There is no `CertSubjectEqualVerifier` or `CertIssuerEqualVerifier`. (Earlier drafts named these incorrectly.)

Concrete verifier wiring for keyless GitHub Actions:
```rust
use sigstore::cosign::verification_constraint::{
    CertSubjectUrlVerifier, VerificationConstraintVec,
};
use sigstore::cosign::ClientBuilder;
use sigstore::trust::sigstore::SigstoreTrustRoot;

let trust_root = SigstoreTrustRoot::new(None).await?;     // pulls TUF metadata; pin in production
let client = ClientBuilder::default()
    .with_trust_repository(&trust_root)?
    .build()?;

let constraints: VerificationConstraintVec = vec![
    Box::new(CertSubjectUrlVerifier {
        url: policy.fulcio_subject_url,        // exact URL match
        issuer: policy.fulcio_issuer,          // e.g. https://token.actions.githubusercontent.com
    }),
];

let (cosign_signature_layers, _) = client.trusted_signature_layers(...).await?;
// rev9: in sigstore 0.13, verify_constraints is a free function in
// sigstore::cosign, NOT a method on Client.
sigstore::cosign::verify_constraints(&cosign_signature_layers, constraints.iter())?;
```

- Per-app `VerificationPolicy` enum:
  - `FulcioUrlIdentity { fulcio_subject_url: String, fulcio_issuer: String }` — for GitHub Actions OIDC. Exact URL match. If the customer wants pattern matching across branches (e.g., "any branch in this repo"), they register multiple identities or we add a custom `VerificationConstraint` wrapping `CertSubjectUrlVerifier` with prefix matching. v1 ships exact match only.
  - `FulcioEmailIdentity { email: String, fulcio_issuer: String }` — for OIDC providers with email subjects
  - `PublicKey { pem: String }` — uses `PublicKeyVerifier` for advanced offline-signing users
- Trust root: pin to a specific TUF metadata snapshot in production; update via signed CAP releases (avoids runtime fetches that operator could intercept)
- Rekor inclusion proof verification: `sigstore` 0.13 checks Rekor when the trust root has Rekor pubkeys configured; verify integration in tests
- Remove `SKIP_COSIGN_VERIFY` runtime path (replace with `cfg(test)` test helper)
- Remove hardcoded `verified_signer = true` audit value

App creation (`routes/apps.rs`):
- New required field `signer_identity` (subject + issuer)
- Default subject pattern for GitHub Actions: `repo:<org>/<repo>:ref:refs/heads/<branch>`
- Default issuer: `https://token.actions.githubusercontent.com`
- Stored on `apps` row (Phase 1 columns)

Identity rotation:
- `PATCH /apps/:id/signer` — owner role + email confirmation token
- Audit log every rotation

KBS Rego integration: render `signer_identity` into the Phase 2 Rego template's slot.

Tooling (optional for v1): `enclava init-ci --provider github` generates `.github/workflows/build-and-sign.yml`.

**Tests:**
- Verify image signed by known GitHub Actions OIDC identity → accept
- Same image signed by wrong identity → reject
- Same identity but wrong issuer → reject
- Rekor inclusion missing → reject
- Rotated identity: deploy with new identity succeeds; deploy with old identity fails

**Effort:** 1.5 weeks.

---

### Phase 10 — Authorization centralization + role hardening + billing intent + unlock-mode receipt consumer + API-key storage hardening (1 week)

**Goal:** Centralize authorization helpers. Close admin-promotes-to-owner loophole. Store billing intent server-side (full C11 fix). Wire the unlock-mode transition flow to consume the TEE-signed receipt primitive that already shipped in Phase 5. Redesign API-key storage (rev6 finding #6).

**Findings addressed:** C10, **C11 (full — completes the partial fix from Phase 0)**, unlock-mode TEE-receipt requirement, rev6 finding #6 (API-key storage hardening — review's Medium on Argon2-over-prefix).

**Changes:**

Authorization centralization (`crates/enclava-api/src/auth/scopes.rs` — new):
- `require_member`, `require_admin`, `require_owner`, `require_scope`, `require_owner_to_modify_owner`
- Apply to: `DELETE /apps/:id` (admin), `PATCH /apps/:id/unlock-mode` (owner), `POST/DELETE /apps/:id/domains` (admin), `POST /apps/:id/config-tokens` (admin), org member invite (admin), member role change (owner if changing to/from owner; admin otherwise)

Owner invariant:
- Transactional check: at least one owner per org after every role change
- Reject changes that would leave zero owners
- Self-demotion as last owner returns clear error

Billing intent (`crates/enclava-api/src/routes/billing.rs`) — full C11 fix:
- New columns on `payments`: `requested_tier TEXT`, `expected_amount_msat BIGINT`, `purpose TEXT`
- Set at invoice creation from authenticated user's request, never from the webhook
- Webhook handler: verify signature (Phase 0), look up `payment` by invoice ID, fetch invoice state from BTCPay server-side (don't trust webhook body for amount/state), update org tier only if `payment.status = 'pending'` (idempotent), record in `processed_webhooks` (Phase 0 dedup)

Session/membership lifecycle:
- `org_members.removed_at` column
- Auth middleware: check current membership against accessed org; deny if `removed_at IS NOT NULL`
- API keys created by removed members marked inactive at remove time

Account-level rate limiting (`tower-governor` with custom keyer): per-email and per-account-id, in addition to per-IP.

Auth error normalization: don't leak which credential was wrong.

**Unlock-mode transition receipts (consumer of Phase 5 primitive):**

The receipt-signing primitive (attestation-proxy's `POST /receipts/sign` + per-pod ephemeral key + SNP-bound pubkey) ships in Phase 5. Phase 10 only wires the unlock-mode transition use case to that primitive.

Flow:
1. User initiates: `POST /apps/:id/unlock-mode { from_mode, to_mode, new_recovery_material? }` — owner role required (centralized auth from this phase)
2. API forwards to attestation-proxy: `POST /receipts/sign { type: "unlock_mode_transition", app_id, from_mode, to_mode, ... }`
3. attestation-proxy validates legality (e.g. cannot enable autounlock without recovery material), performs in-TEE work via the existing small helper binary, signs the receipt body using D11 CE-v1 encoding with the per-pod ephemeral key
4. API receives `{ receipt_payload, signature, attestation_quote_at_transition }`; verifies signature against the receipt-signing pubkey extracted from the bundled SNP report
5. DB update conditional: `UPDATE apps SET unlock_mode = $new WHERE id = $id AND last_transition_receipt_timestamp < $receipt.timestamp`
6. Receipt persisted in `unlock_transition_receipts` for audit

CLI verification (symmetric): after a transition, CLI fetches receipt, verifies against pinned pubkey from most recent unlock; if pubkey changed (pod restart), CLI re-attests first.

**API-key storage hardening (rev6 finding #6 — review's Medium):**

Current code uses a 16-bit lookup prefix and Argon2 over all candidates sharing that prefix (`auth/api_key.rs:70-72, 116-145` per review). Argon2 is computationally expensive; iterating it per candidate is a DoS surface.

Replace with HMAC-pepper construction:
- New format: `enclava_<base32(prefix:16B)>_<base32(secret:32B)>` (16-byte prefix gives 2^128 search space; 32-byte secret is the verifier input)
- DB stores: `(prefix BYTEA PRIMARY KEY, hmac_sha256_of_secret BYTEA, ...metadata)`
- Verification: `HMAC-SHA256(server_pepper, secret) == stored_hmac` — constant-time, no Argon2 iteration
- Server pepper is in env var `API_KEY_HMAC_PEPPER`, mounted from Kubernetes Secret at startup; rotation via append-only list of accepted peppers with `since` timestamps
- Lookup is a single B-tree probe on the 128-bit prefix → no candidate iteration

Migration path:
- New column `api_keys.hash_format VARCHAR DEFAULT 'argon2_legacy'`
- New keys minted with `hash_format = 'hmac_v1'` and the new shape
- Verification handler dispatches on `hash_format`: legacy keys still verify via Argon2 over candidates with the 16-bit prefix; new keys via HMAC
- After 90-day deprecation window: legacy keys disabled with a clear error message asking the user to rotate
- CLI gets `enclava api-keys rotate` that creates a new key and revokes the old one in one step

Migration: `0021_api_key_hash_format.sql` adds the column, indexes the new prefix.

**Note:** `API_KEY_HMAC_PEPPER` is operator-readable at runtime (it has to be — the API process needs it to verify keys). This is an acceptable operator-trust assumption for *authentication* (operator can already deny service); the confidentiality threat model only requires the operator cannot read tenant *data*. Pepper compromise lets the operator forge API keys, which is a denial-of-confidentiality only via creating a new tenant under their control — a much narrower attack than reading existing tenant data.

**Migrations:** `0015_billing_intent.sql`, `0016_member_removed_at.sql`, `0027_unlock_transition_receipts.sql`, `0021_api_key_hash_format.sql`.

**Tests:**
- Admin cannot promote self/anyone to owner
- Last owner cannot demote self
- Removed member cannot use stale session or API key
- Webhook with metadata `tier=enterprise` but invoice was for `pro` → org gets `pro`
- Webhook replay (same event ID) → no-op
- Unlock-mode transition without receipt → rejected
- Receipt with bad attestation chain → rejected
- Receipt signed by stale pod's pubkey → rejected
- Replayed receipt (timestamp older than `last_transition_receipt`) → no-op
- Owner role required for transition (in addition to receipt requirement)
- API key new format: HMAC verification accepts correct secret, rejects modified
- API key legacy format: Argon2 path still works during deprecation window
- API key prefix lookup: 128-bit prefix returns at most one row (no iteration)
- API key pepper rotation: keys verified under both old and new pepper during overlap

**Dependencies:** Phase 5 (attestation-proxy with per-pod signing key + receipt-signing API), Phase 7 (CLI attestation pinning for symmetric verification).

**Effort:** 1 week.

---

### Phase 11 — Kubernetes hardening + remaining Highs (3–5 days)

**Goal:** Sweep remaining High findings around runtime hardening.

**Findings addressed:** Highs around NetworkPolicy egress, SSA `force()`, drift detection, runtime install, sidecar digest verification.

**Changes:**

NetworkPolicy (`crates/enclava-engine/src/manifest/network_policy.rs`):
- Replace `world` egress on TCP 80/443 with per-app egress allowlist (default: no egress)
- Tighten ingress: reference exact gateway service account or use Cilium identities

Server-Side Apply (`crates/enclava-engine/src/apply/`):
- Use `force()` only where genuinely needed (initial create, recovery from conflict)
- Record managed fields; on conflict log structured warning
- For attestation-critical fields (image digest, init_data_hash, signer identity, policy refs): verify-then-apply with no force; refuse to overwrite if conflict was set by an operator outside the control plane

Drift detection: treat manifest-hash annotations as advisory only until an attested controller can sign and verify desired state.

Runtime install removal: `SECURE_PV_ALLOW_RUNTIME_INSTALL` already removed in Phase 5; this phase removes any residual references.

Sidecar cosign verification at startup (uses Phase 9 Fulcio machinery): verify `ATTESTATION_PROXY_IMAGE` and `CADDY_INGRESS_IMAGE` against platform-controlled signer identities at API startup; bind their digests into `cc_init_data` and KBS Rego.

cc_init_data binds runtime class — fail if pod's `runtimeClassName` is absent.

**Tests:**
- NetworkPolicy snapshot: no `world` egress entry by default
- SSA conflict: log + warning, no silent overwrite of attestation-critical fields
- API startup fails if a configured sidecar image cannot be cosign-verified

**Effort:** 3–5 days.

---

### Phase 12 — Verification gates + integration tests (continuous + final hardening week)

**Goal:** Build test scaffolding that proves the confidentiality chain holds; add CI gates.

**Tests across phases:**
- Unit: every validator (Phase 1), every crypto primitive (Phase 5), every parser (Phases 1, 8)
- Manifest snapshot: KBS Rego always anchors in `input.snp.init_data_hash` against non-empty literal (Phase 2); no `CF_API_TOKEN` in tenant spec (Phase 8); no `privileged: true` on caddy/app (Phase 5); `automountServiceAccountToken: false` (Phase 0); NetworkPolicy default-deny egress (Phase 11)
- Negative policy: OPA / Trustee evaluator runs against rendered Rego with malicious inputs (Phase 2); Kata agent denies exec/cp/logs/attach (Phase 2)
- Integration:
  - Wrong image digest cannot read KBS resource (Phase 2)
  - Wrong init_data_hash cannot read KBS resource (Phase 2)
  - CLI refuses valid public CA cert without matching attestation (Phase 7)
  - Customer-signed descriptor verification (Phase 7)
  - Org keyring TOFU + verification (Phase 7)
  - Admin cannot promote to owner; last owner cannot demote (Phase 10)
  - Webhook intent (Phase 10): metadata-tier ≠ payment-tier rejected
  - Duplicate platform hostname rejected (Phase 4)
  - Custom domain requires TXT proof (Phase 4)
  - First-write-wins on KBS resource; rekey requires receipt (Phase 6)
  - Unlock-mode transition without receipt rejected (Phase 10)
- Deployment readiness: platform-side health check verifies kubectl can `get` StatefulSet, replicas Ready, image digest matches deployment row — not just DB row inserted

CI gates:
- `cargo clippy -- -D warnings`, `cargo audit --ignore RUSTSEC-2023-0071`, `cargo deny check advisories sources`
  - Temporary RSA advisory exception is documented in `deny.toml`: transitive via `jsonwebtoken`/`sigstore`, no fixed upstream `rsa` release yet, and CAP does not perform RSA private-key operations.
- Manifest snapshots committed and diff-checked
- `cargo build --release --features prod-strict` fails to compile if any debug-only path is reachable

**Effort:** continuous + 1 dedicated final week.

---

## Database Migrations Summary (rev8)

```
0010_processed_webhooks.sql              (Phase 0)
0011_org_slug.sql                        (Phase 1)
0012_app_signer_identity.sql             (Phase 1)
0013_kbs_binding_columns.sql             (Phase 1)
0014_custom_domain_verification.sql      (Phase 1)
0015_billing_intent.sql                  (Phase 10)
0016_member_removed_at.sql               (Phase 10)
0017_app_enrollment_state.sql            (Phase 6)
0027_unlock_transition_receipts.sql      (Phase 10)
0019_user_signing_keys.sql               (Phase 1)
0020_org_keyrings.sql                    (Phase 1)
0021_api_key_hash_format.sql             (Phase 10)  -- rev6
```

## Configuration Changes Summary (rev8)

**Removed (debug/test only after this work):**
- `SKIP_COSIGN_VERIFY`, `COSIGN_ALLOW_HTTP_REGISTRY`, `ALLOW_EPHEMERAL_KEYS`
- `TENANT_TEE_ACCEPT_INVALID_CERTS`, `ENCLAVA_TEE_ACCEPT_INVALID_CERTS`
- `TENANT_TEE_TLS_MODE`, `ENCLAVA_TEE_TLS_MODE` (insecure modes)
- `SECURE_PV_ALLOW_RUNTIME_INSTALL`
- `KBS_RESOURCE_WRITER_TOKEN` (Phase 6)

**Required in production:**
- `BTCPAY_WEBHOOK_SECRET` (non-empty)
- `CLOUDFLARE_API_TOKEN` (zone-wide; security control is CAA + CT, not token scope)
- `TRUSTEE_POLICY_READ_AVAILABLE=true` only after Phase 3 endpoints are deployed.
- `WORKLOAD_ARTIFACTS_URL`, `TRUSTEE_POLICY_URL`, `TRUSTEE_ATTESTATION_VERIFY_URL`
- `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX`, `SIGNING_SERVICE_PUBKEY_HEX` — Ed25519 public keys for in-TEE verification (non-secret)
- `PLATFORM_SIGNING_SERVICE_URL` + auth — points at off-cluster signing service (D9)
- `PLATFORM_FIRMWARE_MEASUREMENT` — published with each platform release; CLI bundles via `platform-release.json`
- `API_KEY_HMAC_PEPPER` (rev6) — server-side pepper for HMAC verification of API keys; rotated via append-only list with `since` timestamps; operator-readable (acceptable for auth; see Phase 10 note)

**New:**
- `PLATFORM_DOMAIN`, `TEE_DOMAIN_SUFFIX`
- `CLUSTER_POD_CIDR`, `CLUSTER_SERVICE_CIDR` (SSRF denylist)
- `REGISTRY_ALLOWLIST`

## Rollout Strategy (rev14)

| Phase | Confidentiality milestone | Calendar | Notes |
|---|---|---|---|
| 0 | M0 (with C11 partial) | Weeks 1–2 | Stopgaps + Caddy TLS-ALPN-01 cutover (rev9: locked to TLS-ALPN-01 only) + CAA + CT |
| 1 | — | Week 3 | Schema + helpers + org keyring table |
| 2 | M1 half | Week 4 | Rego template (in signing-service repo) + CAP signing-client + Kata fail-closed |
| 3 | M1 complete | Weeks 5–6 | **Trustee-side signed-policy enforcement (rev7 critical fix)** + delete `replace_bindings_block` |
| 4 | — | Week 5 (parallel) | Two-hostname routing + HAProxy advisory lock |
| 5 | — | Weeks 6–8 | enclava-init refactor + attestation-proxy TLS + receipt-signing API + handshake spec |
| 9 | **M3** | Weeks 6–7 (parallel with P5) | Customer Fulcio signing (rev7 corrected sigstore-rs API) |
| Trustee patches for receipts | — | Weeks 6–7 (parallel) | Conditional writes + body-in-policy + receipt verification in Trustee Rust (rev10/rev11: hashing + Ed25519 verification moved into Rust; Rego sees only typed fields and pre-computed booleans) + SNP claim rename `init_data` → `init_data_hash` (rev11) |
| 6 | **M2** | Week 9 | Workload-resource enrollment + lifecycle (uses Trustee patches above) |
| 7 | **M4** | Weeks 10–11 | CLI attestation + signed descriptor + signed org keyring |
| 8 | — | Week 11 | Verification + dead-code removal (was full cutover; moved to P0) |
| 10 | — | Weeks 11–12 | Auth + billing intent (full C11) + receipt consumer + API-key HMAC |
| 11 | — | Week 12 | K8s hardening sweep |
| 12 | — | Week 13 | Final CI gates + audit |

**Total (rev14 reconciled — same numbers as rev10; rev11–rev14 added no new phases or schedule weeks):** ~13 weeks single engineer; ~10 weeks two-engineer; ~8 weeks three-engineer. **M5 reaches end of Week 11.**

**Public-facing message until M5-strict:** "CAP is in active hardening for confidential workloads. Until vX.Y (Week 11), production deployments rely on the platform's operational controls in addition to hardware attestation. After vX.Y, the operator-out-of-trust-boundary property is enforced cryptographically — for orgs that have not opted into emergency email recovery. Orgs with email-recovery enabled have a 30-day-delayed reset path; this is documented per-org and visible in the CLI."

## Parallel Execution Tracks

(unchanged shape from rev4; recap)

**Critical path to M5:** `0 → 1 → 2 → 3 → 5 → 6 → 7`, with Phase 9 joining 7 as co-blocker.

**3-engineer split (recommended):**
- Track A — Confidentiality core: 0, 1, 2, 3, 5, 6, 7
- Track B — Image trust + verification: 9 (after P2), helps land P7, owns P12
- Track C — Edge / Auth / K8s: 4, 8 (after P0+P4), 10 auth/billing parts, 11

**5 hard interfaces** that all decompositions share:
1. Phase 1 schema lock (now includes `0020_org_keyrings.sql`)
2. Phase 2 Rego template shape (slot names + `init_data_claims` JSON)
3. Phase 5 attestation-proxy `/v1/attestation` / `/.well-known/confidential/attestation` JSON contract (includes per-pod receipt-signing pubkey hash and TLS SPKI binding)
4. D10 deployment descriptor + org keyring canonical encoding (one-time spec)
5. Customer signing identity flow (DB → Rego → cosign → CLI verify)

## Open Decisions (rev14 status)

1. ~~Trustee write-API support~~ Resolved.
2. ~~Platform Trustee policy signing key custody~~ Resolved by rev4 + rev5 — off-cluster signing service with templates baked into the service image.
3. ~~Cloudflare scoped-token capabilities~~ Resolved by rev4 — CAA + CT.
4. **Let's Encrypt support for CAA `accounturi` and `validationmethods` (RFC 8657).** Confirm in first 2 days of Phase 0. If `validationmethods` not supported, rely on `accounturi` alone and document the gap.
5. ~~Kata LUKS device-mapper persistence after init-container exit.~~ Resolved by live test with design pivot: app/caddy start first and wait; `enclava-init` mounts second and stays alive. The one-shot/native-sidecar-before-app handoff is not viable on the current runtime.
6. **Native Kubernetes sidecar with Kata SEV-SNP.** Confirm with platform team.
7. **Customer-visible org slug (D1).** Confirm shown in CLI/UI.
8. **GitHub Actions OIDC as default signer.** v1 ships GitHub-only.
9. **Existing-customer migration window (Phase 4).** One release cycle sufficient?
10. **Existing Trustee policy state audit (Phase 3 prerequisite).** Dump production policies.
11. ~~**HAProxy DaemonSet repo location**~~ **Resolved by rev8: TLS-ALPN-01 lock-in eliminates port-80 routing requirement; HAProxy unchanged.**
12. ~~CLI trust anchor for expected attestation values~~ Resolved by rev4 D10.
13. **Multi-user org signer-list semantics (rev5: now resolved as owner-signed keyring with TOFU on owner pubkey).** Confirm UX for owner-pubkey verification (Slack? email? print + QR?). Default: prompt user with hex fingerprint and ask for explicit confirmation.
14. **CI/CD signing infrastructure for D9.** Need a separate `enclava-platform/policy-templates` repo with maintainer-owned signing key. ~1 week of platform-eng work; can run parallel with Phase 0.
15. ~~**Owner-pubkey rotation UX**~~ **Resolved by rev6 D10**: three-tier — threshold-of-owners (default M-of-N) → recovery contacts (M-of-N from owner-designated set) → emergency email reset (30-day waiting period, opt-in only at org creation, with daily audit notifications). All three follow the CE-v1 RecoveryDirective shape from D11. Customer chooses configuration at org creation.
16. **API-key migration window (rev6 finding #6).** Default 90-day deprecation for legacy Argon2 keys after Phase 10 ships. Confirm timeline with customer base — if any customer has long-lived automation that can't rotate quickly, may need extended window.

## Out of Scope

- Multi-region / geo-replication of KBS or platform DNS
- Customer-managed encryption keys (CMEK)
- Hardware-token-backed unlock (FIDO2, YubiKey) — strong v1.1 candidate; replaces per-CLI Ed25519 file with HSM-backed key
- Audit log streaming to customer SIEM
- Replacement of HAProxy with an in-TEE L4 router

---

## Effort Summary (rev14)

| Phase | rev9 | rev14 | Why changed |
|---|---|---|---|
| 0 | ~2 weeks | ~2 weeks | unchanged |
| 1 | 1 week | 1 week | unchanged |
| 2 | **1 week** | 1 week | rev9: switch from "Rego canonicalizes CreateContainerRequest" to **kata genpolicy** (existing tool); rev11–rev14 spec-only refinements no schedule impact |
| 3 | 2 weeks | 2 weeks | unchanged effort; rev11/rev14 add: SNP claim rename `init_data` → `init_data_hash`, `SignedPolicyArtifact` envelope verify path, workload-attested artifacts endpoint with Trustee-callback validation, signed-template-bytes self-check at signing-service startup. All small additions to the same patch. |
| 4 | 1 week | 1 week | unchanged |
| 5 | 3 weeks | 3 weeks | unchanged effort; rev9 split REPORT_DATA layout corrected (rev9 critical finding #1) |
| 6 | 2.5 weeks | 2.5 weeks | unchanged effort; rev10/rev11 receipt verification moved into Trustee Rust (no new Rego builtins) — same patch surface, simpler implementation |
| 7 | 2.5 weeks | 2.5 weeks | unchanged effort; descriptor terminology threaded; CLI verifier updated; rev13/rev14 add `policy_template_text` + `policy_template_*` to descriptor and platform-release.json |
| 8 | 2 days | 2 days | unchanged; HTTP-01 references purged (rev9 finding #6) |
| 9 | 1.5 weeks | 1.5 weeks | unchanged effort; sigstore-rs free-function call corrected (rev9 finding #6) |
| 10 | 1.5 weeks | 1.5 weeks | unchanged |
| 11 | 3–5 days | 3–5 days | unchanged |
| 12 | continuous + 1 week | continuous + 1 week | unchanged |

**Total (rev14 reconciled): ~13 weeks single engineer; ~10 weeks two-engineer; ~8 weeks three-engineer.** **M5 reaches end of Week 11.** rev11–rev14 added no new phases or schedule weeks; all changes are spec tightening.

---

## Confidence statement (rev14)

Rev9 surfaced 1 critical (the receipt-pubkey-binding-was-unrecoverable bug — I had bound it inside a one-way hash) and 5 implementation-detail issues. Rev10 closed two contradictions inside Phase 6 (Rego built-ins) and finalized the descriptor↔cc_init_data binding. Rev11 closed the cc_init_data↔descriptor cycle (`descriptor_core_hash` introduced), added namespace/SA/identity_hash to cc_init_data, and locked the SNP claim path. Rev12 split forward/backward chain checks and made the signed-policy artifact metadata actually-signed. Rev13 pinned policy-template provenance, defined a workload-readable artifacts endpoint, and locked Ed25519 sign-input bytes. Rev14 ships the template *bytes* (not just hash), tightens the artifacts endpoint to be workload-attested, and corrects the in-TEE keyring trust anchor to the structural (fingerprint + signing-service authorization) chain rather than the impossible "TOFU." Overall confidence: ~88% (up from rev10's 84% as the cycle and the multiple-anchor confusion are now closed; the only remaining HIGHs through rev11–rev14 were spec-tightening, not redesigns).

- Architecture direction: 93%
- Phase 0 (TLS-ALPN-01 locked in): 82%
- Phase 2 (genpolicy-based OCI validation): **88%** (genpolicy is upstream and proven; signing service running it is straightforward; symmetry-with-CLI problem disappears because Rego doesn't canonicalize at runtime)
- Phase 3 (Trustee signed-policy enforcement + workload-attested policy read + workload-attested artifacts endpoint + SNP claim rename): 78% (up from rev10's 75%; rev14 gave Phase 3 a fully concrete, credential-free path for the in-TEE bundle)
- Phase 5 (split REPORT_DATA layout): 88%
- Phase 6 (receipt envelope explicit; pubkey extractable; receipt verification in Trustee Rust): 90% (up from rev10's 88%; rev10 simplified by moving Ed25519 + hashing into Rust)
- Phase 7 (full DeploymentDescriptor + descriptor.rs + signed `policy_template_text`): 87% (up from rev10's 85%; the template-bytes-shipped fix removes the rev13 "render from a hash" gap)
- Phase 9 (sigstore-rs free-function corrected): 88%
- Phase 10: 88%
- D11 CE-v1 + descriptor canonicalization (now with explicit `ce_v1_bytes` vs `ce_v1_hash`): 94% (up from 92%; the sign-input ambiguity is closed)

Biggest remaining unknowns:
- **Trustee upstream cooperation** for signed-policy enforcement (Phase 3), receipt-gated writes (Phase 6), workload-attested policy read (rev9 finding #2), `receipt_pubkey_sha256` SNP-claim exposure (rev9 critical-fix consequence), SNP claim rename `init_data` → `init_data_hash` (rev11 finding #4), and the `POST /kbs/v0/attestation/verify` callback for the workload artifacts endpoint (rev14 finding #2). Six upstream patches stacked — the schedule risk continues to be Trustee maintainer coordination, not plan design.
- **kata-containers/genpolicy version pinning** — platform release must pin a specific genpolicy version so customer descriptor → policy is reproducible across CLI and signing service
- Phase 5 live Kata SNP LUKS/mount propagation is verified with app/caddy-starts-first + mounter-sidecar ordering; customer/platform images that CAP wraps must include the static `enclava-wait-exec` helper
- Let's Encrypt `validationmethods=tls-alpn-01` support for the platform's account (open decision #4)
- Platform CI/CD signing infrastructure existence (open decision #14)
- Existing operator-added rules in production Trustee policies (Phase 3 audit)

Each review round has surfaced real correctness issues (rev2: 9, rev3: 6, rev4: 5, rev5: 7, rev6: 6, rev7: 8 with 2 critical, rev8: 8 with 2 critical, rev9: 6 with 1 critical, **rev10: 6, rev11: 5, rev12: 5, rev13: 5, rev14: 5**). The find-rate flattened at ~5/round across rev10–rev14, and severities trended down: rev11 had 3 highs, rev12 had 2 highs, rev13 had 1 high, rev14 had 1 high. None of rev11–rev14's HIGHs were structural — they were specification-completeness gaps (cycle, missing fields, ambiguous bytes, missing template text) that systematic spec-vs-code review caught.

Find-rate trend: stabilizing at the level of pure spec-tightening. The plan is approaching steady state — one more pass to spot-check rev14's changes (the workload-attested endpoint Trustee callback in particular) is prudent, but further iteration is competing with the value of starting Phase 0 implementation and learning from real code. The Trustee upstream coordination is now the dominant schedule risk; it's an external dependency rather than a plan-design issue.
