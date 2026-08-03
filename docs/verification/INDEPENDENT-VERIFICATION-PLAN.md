# Independent End-to-End Verification Plan

Status: proposed platform architecture authority; supersedes `demo-apps/prove-it/docs/FULL-VERIFICATION-PLAN.md` for further planning and implementation

This plan makes a raw proof bundle and an independently run verifier the authority. CAP owns and supplies the complete verification implementation. When Enclava PaaS is deployed, it is the hosted product connection point and must expose CAP-backed verification APIs, but it does not implement verification or become a trust root.

The old Prove-It plan is explicitly marked superseded, and Prove-It keeps only a pointer to this document. Do not maintain a second active verification architecture in the demo repository.

## 1. Outcome

A user must be able to answer this question without trusting the tenant application or an Enclava verdict:

> Does this fresh, nonce-bound set of evidence satisfy a trust policy I selected independently of the target application and the appraiser?

The minimum supported CAP-only flow is:

```text
independent policy -----------+
                              |
target reserved endpoint ---> raw proof bundle ---> canonical verifier ---> PASS / FAIL
                                                         ^
                                                         |
                              independently obtained verifier artifact
```

The canonical verifier has three delivery surfaces, all executing the same Rust implementation:

1. `enclava verify` for tenants, auditors, and advanced users.
2. WebAssembly loaded by a small local HTML verifier for application end users.
3. A stateless appraiser service that anyone, including Enclava or a third party, can run.

Only the first two provide an independent local verdict. An appraiser response is a signed opinion whose signer must be trusted separately.

CAP is the implementation boundary for verification. A standalone CAP installation must be able to deploy a workload, expose its reserved proof endpoint, publish the verifier artifacts, and complete both CLI and browser verification without PaaS source code, APIs, templates, configuration, credentials, identity, DNS, or availability.

`CAP-only` describes the software and runtime dependency boundary, not the source of trust. The verifier still requires independently selected policy and external cryptographic roots such as AMD and Sigstore; sourcing all expected values from CAP would make CAP the appraiser authority again.

When PaaS is present, it is the required product-facing gateway for discovery, bundle download, and convenience appraisal. Its handlers call CAP-owned endpoints or services and preserve CAP's bytes and result contracts. Standalone CAP verification remains a release gate so hosted-product integration cannot become an accidental implementation dependency.

## 2. Non-negotiable trust boundaries

### 2.1 The target is untrusted

The tenant workload may return arbitrary HTML, JavaScript, headers, badges, verifier results, expected measurements, policies, and appraiser responses. None of these are authoritative.

The public proof endpoint must be owned by the platform's reserved ingress route, before the workload catch-all. CAP already routes `/.well-known/confidential/*` to the attestation proxy; extend that route rather than adding another proxy or ingress mechanism.

### 2.2 Evidence and policy are different inputs

The proof bundle reports observed facts and carries signed artifacts needed to validate them. It must not select the expected facts against which it is judged.

The trust policy is supplied independently by the verifier user, organization, or configured appraiser. In particular, never accept any of these solely because they appear in the bundle, target page, or appraiser response:

- expected SNP measurements or minimum TCB;
- accepted workload image digest, source repository, workflow, or builder identity;
- trusted AMD, Fulcio, Rekor, CAP, organization, or policy-signing roots;
- accepted workload domain or deployment identity;
- required sidecars, runtime class, egress policy, or other platform invariants;
- freshness limits or clock-skew allowances;
- an appraiser public key.

The bundle may contain the observed form of these values. The verifier compares them with independently selected policy.

If no explicit policy is supplied, the verifier may inspect and report the evidence but must return `INCONCLUSIVE`, never `PASS`.

### 2.3 Enclava is not the verdict authority

The local verifier must not call an Enclava service to finish verification. Enclava may publish:

- verifier releases;
- suggested policy files;
- the public proof endpoint implementation;
- a convenience appraiser.

Users must be able to obtain the verifier and policy independently, pin their hashes or signing keys, and run entirely local verification over bundle bytes fetched from the target.

Enclava remains capable of withholding service or evidence. This design removes its ability to convert invalid evidence into a valid local verdict; it does not remove denial-of-service risk.

### 2.4 What the verdict does and does not prove

A passing verdict proves that the evidence is cryptographically valid, fresh, bound together, and accepted by the selected policy. It can establish source-to-image-to-confidential-runtime identity.

It does not by itself prove:

- that the application is bug-free, safe, or honest;
- the exact bytes of an arbitrary HTTP response;
- that browser-rendered content came from code whose digest was verified;
- that a browser's current TLS connection used the leaf key bound into the attestation report;
- protection from a compromised independently trusted root.

Proving exact application responses would require a separate response-signing protocol bound to a key held inside the attested workload. That is out of scope for this plan.

The native CLI can retain normal Web PKI validation while recording the peer leaf certificate from its TLS connection and comparing its SPKI with the attested SPKI. Rustls exposes the authenticated peer certificate chain through [`peer_certificates`](https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html#method.peer_certificates). The browser [Fetch `Response` interface](https://fetch.spec.whatwg.org/#response-class) does not expose the peer certificate to JavaScript or WASM. The browser can therefore validate only the internal relationship between the leaf certificate carried in the bundle and the SPKI hash in `REPORT_DATA`; it cannot bind that key to the connection over which it fetched the bundle.

The canonical check `transport.tls_channel_spki` is context-dependent. It is `PASS` when an observed channel SPKI is present and matches, `FAIL` when present and mismatched, and `SKIPPED` with reason `CHANNEL_SPKI_UNAVAILABLE` when the surface cannot observe it. A policy that requires live channel binding cannot produce overall `PASS` from a browser result with this check skipped. Browser UI must label any otherwise passing result: `Evidence valid; live TLS channel binding was not checked. Use the CAP CLI for that stronger check.`

## 3. Foundational public contracts

Freeze these contracts before implementing product UI. They are the public interface; CLI, HTML, appraisers, and integrations are adapters.

### 3.1 Proof endpoint

```http
GET /.well-known/confidential/proof-bundle?nonce=<base64url-encoded-32-bytes>
Accept: application/vnd.enclava.proof-bundle.v1
```

Successful response:

```http
Content-Type: application/vnd.enclava.proof-bundle.v1
Access-Control-Allow-Origin: *
Cache-Control: no-store
```

Requirements:

- accept exactly one 32-byte nonce;
- support `GET` and CORS preflight only, without credentials;
- apply strict response size and generation time limits;
- enforce a per-source request rate, a global request rate, and a global quote-generation concurrency limit before touching `/dev/sev-guest`;
- derive the source only from the socket peer or explicitly trusted ingress metadata, return `429` with `Retry-After` when throttled, and bound the pending queue;
- derive the target HTTPS origin from the reserved ingress request, not a caller-supplied expected domain;
- compare that host with the signed deployment descriptor's allowed domains;
- obtain the proxy TLS identity internally; do not accept a caller-supplied SPKI hash;
- return deterministic binary bytes or a typed error, never a verdict;
- keep the existing workload-shadowing protection: the reserved route must win even when the tenant implements the same path.

The CAP-authenticated internal PaaS adapter in §3.7 is the only origin-handling exception. It accepts an origin because it does not receive the public target's ingress request; CAP resolves the named deployment and accepts the origin only when it is present in that deployment's signed descriptor. This supports product relay and offline appraisal but does not claim to prove current live routing.

### 3.2 Proof bundle v1

Use the existing CE-v1 length-prefixed transcript encoding in `enclava-common`:

```text
label_len:u16be || label || value_len:u32be || value
```

Add a strict decoder and a versioned, fixed field schema. Do not introduce JSON canonicalization, a second envelope format, or a manifest that recursively hashes its own container.

`bundle_id = SHA-256(exact_response_body_bytes)`.

Required fields, in fixed order:

1. purpose and bundle schema version;
2. target HTTPS origin;
3. raw verifier nonce;
4. producer-reported bundle creation time, informational and display-only;
5. raw AMD SEV-SNP attestation report;
6. exact proxy TLS leaf certificate in DER form, from which the verifier derives the SPKI;
7. proxy receipt public key;
8. AMD ARK, ASK, VCEK, TCB information, and revocation material needed for offline appraisal;
9. exact `cc-init-data.toml` bytes used for the deployment;
10. exact `workload-artifacts.json` bytes used for the deployment;
11. exact `trustee-policy.json` bytes used for the deployment;
12. exact portable Sigstore/Cosign verification material for the image;
13. exact signed build provenance and the referenced OCI manifest/blob material required to recompute the image identity.

The creation-time field is not in `REPORT_DATA` and is not attested. No freshness, expiry, or policy check may trust it. Online freshness comes from the verifier-generated nonce and authenticated quote; offline verification is explicitly historical. The field exists only for diagnostics and display.

Proof bundle v1 limits are part of the wire contract:

- complete bundle: `1,048,576` bytes;
- static verification-material blob stored in the pod ConfigMap: `716,800` bytes (700 KiB), including CE framing;
- `cc-init-data.toml`: `196,608` bytes (192 KiB);
- `workload-artifacts.json`: `196,608` bytes (192 KiB);
- `trustee-policy.json`: `49,152` bytes (48 KiB);
- Sigstore/Cosign material: `196,608` bytes (192 KiB);
- provenance plus required OCI material: `311,296` bytes (304 KiB);
- AMD endorsements and revocation material: `131,072` bytes (128 KiB);
- TLS leaf certificate: `16,384` bytes;
- SNP report: `4,096` bytes;
- proxy receipt public key: `4,096` bytes.

The five static fields plus CE framing must fit the 700 KiB static-blob limit; individual maxima are not an allowance to exceed that total. CAP rejects deployment evidence that exceeds a field, static-blob, or bundle limit rather than truncating it or silently falling back to online retrieval. The 700 KiB bound leaves room for ConfigMap object metadata and base64 expansion below Kubernetes' documented [1 MiB ceiling](https://kubernetes.io/docs/concepts/configuration/configmap/#motivation).

The decoder must reject:

- missing, duplicate, unknown, or reordered fields;
- non-canonical lengths or encodings;
- values exceeding per-field and total-size limits;
- unsupported versions;
- trailing bytes.

The bundle is self-contained for cryptographic verification. Trust anchors and expected measurements remain outside it.

### 3.3 Attestation binding

Retain the existing CE-v1 report-data binding, which binds the fresh quote to:

- the target domain/origin;
- the raw verifier nonce;
- the proxy TLS leaf SPKI hash;
- the proxy receipt public-key hash.

The SNP `REPORT_DATA` contains the lowercase ASCII hex encoding currently used by the proxy. Document it as part of v1 and validate it byte-for-byte. A format migration, if later needed, requires a new version and explicit compatibility tests.

### 3.4 Trust policy v1

Define a separate `enclava-trust-policy-v1` document. JSON is acceptable here because policy bytes are hashed as supplied; signatures cover those exact bytes. Do not reuse the proof-bundle encoding unless it materially reduces existing code.

The policy can express:

- trusted AMD root fingerprints, minimum TCB, allowed SNP policy bits, and complete 48-byte measurements;
- trusted Fulcio/Rekor/Sigstore roots and required transparency properties;
- accepted source repository, GitHub workflow, issuer, builder, and source-ref constraints;
- accepted CAP/platform release and organization/policy signing roots;
- accepted deployment domain or identity constraints;
- accepted workload image digests when a fixed release is required;
- required runtime class, sidecars, policy constraints, and artifact relationships;
- online nonce requirements, appraisal-receipt lifetime, and clock skew;
- maximum revocation-data age measured from signed `thisUpdate`, rejection after signed `nextUpdate`, and required handling when those timestamps are absent;
- whether `transport.tls_channel_spki` is required for a passing verdict;
- required verification checks by stable check identifier.

Every result records `policy_sha256` and an optional display-only policy label. A policy embedded in or linked by the target is never auto-selected.

### 3.5 Canonical appraisal result v1

All verifier surfaces return the same serializable result:

```text
verdict: PASS | FAIL | INCONCLUSIVE
bundle_sha256
policy_sha256
target_origin
challenge_nonce
verified_at
verifier_version
checks[]: { id, outcome: PASS | FAIL | SKIPPED, observed?, expected?, reason_code }
warnings[]
```

Rules:

- `PASS` requires every policy-required check to pass;
- malformed, invalid, mismatched, revoked, stale, or unsupported required evidence produces `FAIL`;
- `INCONCLUSIVE` applies when no policy was supplied, or when the supplied policy requires no checks sufficient to reach a security verdict;
- a policy-required context check that is `SKIPPED` prevents `PASS` and produces `INCONCLUSIVE`; an observed mismatch remains `FAIL`;
- machines consume stable reason codes; prose is non-authoritative;
- canonical result hashing uses one documented byte encoding and identical golden vectors across native and WASM builds when the complete inputs, including `VerificationContext`, are identical.

Revocation freshness uses the verifier's trusted `now`, never the producer-reported bundle creation time. The stable check `amd.revocation.freshness` fails with `REVOCATION_DATA_EXPIRED` after signed `nextUpdate`, `REVOCATION_DATA_STALE` when signed `thisUpdate` exceeds the policy maximum age, and `REVOCATION_TIME_MISSING` when required signed time fields are absent. Offline verification never refreshes revocation data over the network.

### 3.6 Appraiser API v1

Define one stateless compatibility API:

```http
POST /v1/appraise
Content-Type: application/vnd.enclava.appraisal-request.v1+json
```

The request contains bundle bytes and either policy bytes or an independently configured policy identifier. The response contains the canonical appraisal result and may contain a signed receipt.

An appraiser receipt covers at least:

- result hash;
- bundle hash;
- policy hash;
- nonce and target origin;
- appraisal and expiry times;
- verifier version;
- appraiser key identifier.

The receipt proves what that appraiser said. It does not make the verdict independently true. Consumers choose and pin acceptable appraiser keys outside both the target and the response.

Publish the API schema, bundle fixtures, policy fixtures, result fixtures, and conformance command so third parties can implement or run compatible appraisers.

### 3.7 Hosted PaaS gateway contract

PaaS exposes the hosted product surface while delegating all security-sensitive work to CAP. Add versioned public routes equivalent to:

```http
GET  /api/verification/v1/apps/{verification_id}
GET  /api/verification/v1/apps/{verification_id}/proof-bundle?nonce=<base64url-32B>&origin=<https-origin>
POST /api/verification/v1/appraise
```

The public `verification_id` maps server-side to one hosted CAP application and its allowed origins. It is an identifier, not a secret. Do not accept an arbitrary upstream URL or CAP path from the caller.

The discovery response supplies product navigation data: allowed target origins, supported bundle version, the public proof route, local-verifier release metadata, and optional suggested policy references. These values are untrusted hints to an independent verifier; they never become policy merely because PaaS returned them.

The bundle route calls a CAP-owned internal route such as:

```http
GET /internal/paas/orgs/{org_id}/apps/{app_name}/proof-bundle?nonce=...&origin=...
```

CAP resolves the application, validates that the origin belongs to its signed deployment descriptor, and invokes the same bundle producer used by the direct reserved endpoint. PaaS must:

- use its existing authenticated CAP client and raw-response path;
- stream or copy the exact body bytes without parsing or re-encoding;
- preserve the bundle content type and `Cache-Control: no-store`;
- apply public rate, size, and timeout limits;
- expose CORS without browser credentials when end users need local verification;
- map errors to bounded public errors without inventing a bundle or verdict.

The appraisal route forwards the caller's exact bundle and explicit policy selection to the CAP reference appraiser, then returns CAP's canonical result and optional receipt. PaaS does not execute verification logic, amend checks, choose a hidden policy, or translate `FAIL`/`INCONCLUSIVE` into `PASS`.

The hosted UI uses these APIs for bundle download and the clearly labeled convenience appraisal. Its `Verify locally` action opens the CAP HTML/WASM verifier with the target origin visible. For the strongest live remote-page check, that local verifier fetches the target's reserved endpoint directly; a PaaS-relayed bundle is useful for download and offline appraisal but cannot independently demonstrate that PaaS is currently routing the target origin to the same deployment.

PaaS transport is not trusted for validity: it may alter bytes only by causing signature, binding, or policy failure, and it may deny service. Tests must prove byte preservation for an honest relay and local rejection after a one-byte relay mutation.

### 3.8 Signing-key lifecycle

The proxy receipt key is authenticated per bundle by its hash in `REPORT_DATA`; its key identifier is not a trust root. Rotating that key requires a fresh SNP report and bundle binding the replacement key. Previously saved bundles remain historical evidence under the policy and time context applicable to them.

Appraiser keys are trusted only through independently distributed policy. Policies give each accepted key an identifier, public key, validity interval, and optional revocation status. Rotation uses an overlap window in which old and new keys are both independently authorized; after the old key's expiry or revocation, its new receipts fail with a stable key-expired or key-revoked reason. A key or rotation statement carried only in an appraisal response is never trusted.

## 4. One canonical verifier

Create `crates/enclava-verifier` as the only implementation of verification semantics.

Its top-level API should have the shape:

```rust
verify(
    bundle_bytes: &[u8],
    policy_bytes: &[u8],
    context: VerificationContext,
) -> AppraisalResult
```

`VerificationContext` supplies only facts that cannot safely come from evidence:

```rust
struct VerificationContext {
    challenge_nonce: [u8; 32],
    expected_target_origin: String,
    now_unix_seconds: u64,
    observed_channel_spki_sha256: Option<[u8; 32]>,
}
```

Native online adapters populate `observed_channel_spki_sha256` from the peer leaf certificate observed on the same TLS connection that returns the bundle, while retaining normal Web PKI hostname and chain validation. Browser and offline adapters set it to `None` because they did not observe such a channel.

An appraiser that receives uploaded bundle bytes also sets the field to `None`. An appraiser fetch mode may populate it only when that same appraiser opened the target TLS connection and observed the peer leaf certificate; the `transport.tls_channel_spki` outcome makes the difference explicit.

The crate must be:

- deterministic;
- free of filesystem, network, environment, random-number, and global-clock access;
- compilable for native Rust and `wasm32-unknown-unknown`;
- responsible for parsing, cryptography, chain validation, binding validation, policy evaluation, and result construction;
- tested with the exact same bundle, policy, context, and expected result bytes on both targets.

Transport adapters own nonce generation, HTTP fetching, file loading, clocks, optional channel-SPKI observation, UI, and output formatting. The core owns the `transport.tls_channel_spki` outcome so adapters cannot reinterpret the missing or mismatched value.

Do not wrap the existing CLI verifier wholesale. It currently mixes network retrieval and OpenSSL-backed SEV parsing, and its SNP parser truncates a 48-byte measurement to 32 bytes. Extract or replace only the portable primitives needed by the core.

The first implementation gate is a walking skeleton that validates one real AMD chain/report fixture and one real Sigstore/provenance fixture under `wasm32-unknown-unknown`. The target intentionally provides no browser filesystem or network APIs, so any dependency that assumes them must remain outside the core. For direct browser loading, package the thin binding with `wasm-bindgen --target web`; no JavaScript bundler is required. See the official [Rust target notes](https://doc.rust-lang.org/stable/rustc/platform-support/wasm32-unknown-unknown.html) and [wasm-bindgen deployment guide](https://wasm-bindgen.github.io/wasm-bindgen/reference/deployment.html).

If current `sev`, `sigstore`, or OpenSSL-dependent paths do not compile, use their portable parsing/cryptographic components where possible or the already selected RustCrypto/X.509 dependencies. Do not create a browser-specific verification implementation.

## 5. Repository responsibilities

### `cap`

- owns proof-bundle, trust-policy, and result schemas;
- owns `enclava-verifier`, CLI adapter, WASM adapter, and reference appraiser;
- retains exact deployment verification material rather than only a boolean/summary;
- emits verification material to the workload pod through a read-only, non-secret volume available to the attestation proxy but not the application;
- preserves compatibility during the 48-byte SNP measurement migration;
- publishes signed, reproducible verifier and appraiser artifacts.

### `attestation-proxy`

- extends the existing reserved well-known route with the proof-bundle endpoint;
- obtains fresh SNP evidence for the caller nonce;
- reads immutable deployment verification material;
- assembles canonical bundle bytes without appraising them;
- serves CORS-safe binary responses with strict limits.

### `enclava-ops-manifests`

- pins and rolls out `enclava-init`, attestation-proxy, CAP API, and optional appraiser images;
- mounts verification material only where required;
- updates `platform-release.json` and validates the live pre-production workload manifests.

This repository deploys Enclava's hosted CAP instance but is not required by the CAP verification protocol or verifier. A third-party CAP operator can deploy the same CAP artifacts using its own release process.

### `demo-apps/prove-it`

- demonstrates the end-user explanation and adversarial scenario after the CAP-owned acceptance suite passes;
- hosts no authoritative expected values inside the tenant workload;
- can link to the local verifier download, but the link alone is not an independent distribution channel;
- demonstrates that a dishonest application and appraiser cannot make the local verifier pass.

### `enclava-paas`

- is the required product-facing connection point whenever PaaS is deployed;
- exposes public discovery, raw proof-bundle, and convenience-appraisal endpoints backed by CAP;
- reuses `CapInternalHttpClient::raw_response` for binary bundles rather than routing them through JSON proxy helpers;
- maps public verification IDs to authorized CAP org/app paths server-side;
- preserves exact CAP bundle bytes and canonical appraisal results;
- provides bundle download, convenience appraisal, and `Verify locally` product actions with honest labeling;
- contains no evidence parsing, cryptographic verification, policy evaluation, or hidden expected values;
- maintains cross-repository contract tests against the pinned CAP API revision.

PaaS integration is required for the hosted product release, but it is not required to build, run, or verify with standalone CAP.

## 6. Implementation sequence

Each phase ends with runnable evidence. Do not begin PaaS product integration before the CAP-only contracts and portable verifier gate pass.

### Phase 0 — Freeze contracts and prove portability

Dependencies: none.

Primary CAP locations:

- `crates/enclava-common/src/canonical.rs`
- new `crates/enclava-verifier/`
- new `docs/verification/`
- workspace `Cargo.toml`

Work:

1. Specify proof bundle v1, policy v1, result v1, reason codes, the exact byte limits in §3.2, direct-endpoint rate/concurrency defaults, and appraiser v1.
2. Add a strict CE-v1 decoder beside the existing encoder.
3. Create the I/O-free verifier crate with parsing and result scaffolding.
4. Check in sanitized real fixtures for AMD SNP, Sigstore/Cosign, provenance, descriptors, and policies, including corrupt variants.
5. Compile and execute the walking-skeleton fixture on native Rust and WASM.
6. Produce identical canonical result bytes and hashes on both targets.
7. Record dependency decisions; reject any dependency that forces separate native and browser semantics.
8. Build a maximum-size static verification-material fixture, serialize it through the exact ConfigMap `binaryData` representation, mount it in a test pod, and compare the mounted bytes with the source fixture.

Exit criteria:

- schemas are versioned and reviewed as public interfaces;
- malformed CE-v1 inputs fail closed under fuzz/property cases;
- one valid and one invalid AMD fixture have the same native/WASM outcomes;
- one valid and one invalid Sigstore/provenance fixture have the same native/WASM outcomes;
- the maximum-size ConfigMap fixture stays below the Kubernetes object limit and round-trips byte-for-byte;
- no verifier-core dependency performs I/O or reads ambient state.

### Phase 1 — Correct the measurement and finish verifier semantics

Dependencies: Phase 0.

Primary CAP locations:

- `crates/enclava-common/src/descriptor.rs`
- `crates/enclava-cli/src/attestation.rs`
- `policy-templates/signing-service/src/descriptor.rs`
- `crates/enclava-verifier/`

Work:

1. Change SNP measurement handling from the current truncated 32 bytes to the complete 48-byte measurement.
2. Introduce a versioned descriptor representation and dual readers for the migration window; emit the new form only after readers are deployed.
3. Move all pure attestation, descriptor, KBS artifact, Sigstore, provenance, and policy checks into `enclava-verifier`.
4. Validate the full AMD certificate chain, report signature, chip/TCB relationship, revocation state and signed revocation freshness, SNP policy bits, and full measurement.
5. Validate descriptor and organization signatures, policy artifact relationships, cc-init/report-data binding, the context-dependent `transport.tls_channel_spki` check, image identity, transparency material, and signed provenance.
6. Give every check a stable ID and fail-closed reason code.
7. Add mutation tests that flip every security-relevant field independently.
8. Add a proxy receipt-key rotation fixture proving that only a fresh report binding the replacement key is accepted.

Exit criteria:

- no code path truncates an SNP measurement;
- the CLI no longer owns independent verification logic;
- all required chains terminate in policy-selected roots;
- bundle-provided roots or expectations cannot turn a failing vector into `PASS`;
- stale, expired, or undated required revocation data fails with its defined stable reason code;
- identical native/WASM contexts yield identical result hashes, while a native context with an observed channel SPKI intentionally yields the additional channel-binding outcome;
- same-context native/WASM fixture parity remains exact.

Rollout constraint:

If KBS policy/artifact parsing changes, deploy compatible `enclava-init` readers first, verify the new digest in live CAP workload manifests, and only then deploy the CAP API writer. Include `policy-templates/signing-service` in the compatibility migration.

### Phase 2 — Produce a raw, self-contained bundle

Dependencies: Phase 1 contracts; implementation can proceed in parallel with the latter part of verifier completion.

Primary CAP locations:

- `crates/enclava-api/src/cosign.rs`
- deployment routes and persistence models
- `crates/enclava-engine/src/manifest/`
- `crates/enclava-init/`

Primary proxy locations:

- attestation state and route modules
- proxy container/configuration manifests

Work:

1. Change CAP deployment verification to retain the exact portable signed artifacts needed for replay, not merely `cosign_verified`, signer summaries, or decoded provenance JSON.
2. Preserve OCI manifest/blob identity, Sigstore/Cosign signature material, Fulcio certificate, Rekor inclusion/checkpoint material, and signed provenance in a bounded verification-material artifact.
3. Encode a single static verification-material blob capped at 700 KiB in a separate read-only ConfigMap `binaryData` entry instead of expanding the existing init ConfigMap past Kubernetes size limits.
4. Mount it into the attestation proxy only. Do not mount it into the tenant application.
5. Retain any public TLS certificate material needed for the bundle.
6. Extend the existing reserved proxy route to accept the nonce, derive target origin and TLS identity, obtain a fresh quote/endorsements, and encode the proof bundle.
7. Add CORS, cache, method, nonce, size, timeout, canonical-order, trusted-source rate, global rate, bounded-queue, and quote-concurrency enforcement.
8. Keep bundle assembly separate from appraisal: the endpoint never returns `PASS` or expected values.

Exit criteria:

- an arbitrary byte-for-byte bundle can be saved and appraised offline;
- no verifier network request is needed after bundle acquisition;
- tenant code cannot read or replace the mounted static verification material;
- CAP rejects over-limit evidence before deployment, and the exact 700 KiB boundary fixture survives ConfigMap creation and pod mounting without truncation or mutation;
- the target cannot shadow the reserved proof route;
- a load test that exceeds per-source and global limits receives bounded `429` responses while quote concurrency stays within the configured cap and the tenant workload remains responsive;
- changing any static artifact without updating its authenticated relationship causes local failure;
- missing endorsements or portable supply-chain proof produce an explicit non-pass result, not a network fallback.

### Phase 3 — Make the CAP CLI the canonical native adapter

Dependencies: Phases 1 and 2.

Primary CAP locations:

- `crates/enclava-cli/src/main.rs`
- `crates/enclava-cli/src/tee_client.rs`
- `crates/enclava-verifier/`

Add:

```text
enclava verify <https-origin> --policy <path> [--save-bundle <path>] [--json]
enclava verify --bundle <path> --policy <path> [--json]
```

Online flow:

1. validate and normalize an HTTPS origin;
2. generate a cryptographically random 32-byte nonce;
3. fetch the reserved binary endpoint directly with normal Web PKI validation while recording the peer leaf certificate from that same TLS connection;
4. derive the observed channel SPKI hash and pass it with exact bytes, nonce, origin, time, and selected policy to the core;
5. render the canonical result and return a stable success/failure exit code;
6. optionally save the unmodified bundle.

Offline flow is useful for audit and reproducibility. It must label freshness as historical and must not imply that replayed evidence proves current liveness.

Exit criteria:

- the command performs no Enclava appraiser call;
- `--json` matches the canonical result schema;
- changing only the target page's claimed result has no effect;
- a matching observed TLS channel SPKI passes `transport.tls_channel_spki`, while a mismatch fails before an overall `PASS`;
- valid, stale, wrong-origin, wrong-nonce, wrong-measurement, wrong-image, revoked, malformed, and missing-policy cases have integration tests;
- the CLI and verifier fixture suite return identical result hashes.

### Phase 4 — Ship the same verifier as local HTML/WASM

Dependencies: Phases 1 and 2.

Primary CAP locations:

- new `crates/enclava-verifier-wasm/`
- new `web/verifier/` or equivalent static release directory

Work:

1. Add a thin `wasm-bindgen` wrapper over `enclava-verifier`; it contains no verification decisions.
2. Build with `wasm-bindgen --target web` and publish static HTML, JavaScript glue, WASM, schema version, hashes, and release signatures.
3. Implement one accessible local page using native browser APIs only:
   - target HTTPS origin input;
   - policy file input;
   - Verify button;
   - clear PASS/FAIL/INCONCLUSIVE result and per-check details;
   - bundle download for audit.
4. Generate the nonce in the browser, fetch the target's reserved endpoint directly, and provide nonce/origin/current time plus `observed_channel_spki_sha256: None` to WASM.
5. Keep cryptography, parsing, policy evaluation, and result creation out of JavaScript.
6. Document running the static archive from localhost, for example `python3 -m http.server`, because `file://` behavior is inconsistent across browsers.
7. Publish deterministic release archives and signatures so users can obtain and pin the verifier independently of the target tenant.
8. Display the mandatory channel-binding limitation beside the verdict whenever `transport.tls_channel_spki` is `SKIPPED`; link to the CLI for the stronger live-channel check.

Exit criteria:

- the page works from a local static server without an Enclava backend;
- browser network capture shows only local asset loads and the target proof endpoint;
- the page performs no appraiser request;
- native and browser builds produce the same result hash for the same bundle, policy, and `VerificationContext` fixture;
- a live browser result reports `transport.tls_channel_spki=SKIPPED`, never silently `PASS`, and a policy requiring that check produces overall `INCONCLUSIVE`;
- the UI visibly distinguishes `PASS` with an optional skipped channel check from the stronger CLI result in which that check passed;
- tampering with HTML presentation cannot change the WASM result object;
- CORS and preflight behavior work against a live reserved endpoint.

Deferred:

A browser extension may package the same WASM and policy flow later if distribution, origin permissions, or update UX justify it. The local HTML satisfies the initial end-user requirement without creating a second product.

### Phase 5 — Add optional Enclava and third-party appraisers

Dependencies: Phase 1. Phase 2 is needed for live target acquisition but not fixture conformance.

Primary CAP locations:

- new `crates/enclava-appraiser/`
- `docs/verification/appraiser-api-v1.*`
- public conformance fixtures/command

Work:

1. Implement a small stateless service that invokes `enclava-verifier` directly.
2. Run it as an optional CAP component, separate from tenant processes and secrets.
3. Support caller-supplied policy bytes or a server-configured policy selected by an independently meaningful ID.
4. Return the canonical result and optionally a signed receipt.
5. Publish a digest-pinned container and a one-command conformance suite.
6. Run the same suite against Enclava's deployment and at least one separately deployed instance.
7. Label service responses and any CAP example UI: `Convenience appraisal by <operator>; verify locally for an independent verdict.`
8. Publish and test the appraiser key overlap, expiry, and revocation procedure from §3.8.

Exit criteria:

- a third party can run the reference image with its own key and policy;
- an independently written client can call the documented API;
- appraiser output matches native/WASM canonical results for all fixtures;
- an invalid or untrusted appraiser signature never changes a local verdict;
- old and new appraiser keys work only during their independently authorized validity windows, and response-supplied replacement keys are rejected;
- the appraiser can be entirely unavailable while CLI and local HTML verification still work.

### Phase 6 — Prove CAP-only operation, integrate PaaS, and run adversarial acceptance

Dependencies: Phases 2 through 5.

Work:

1. Add a CAP-owned end-to-end harness that deploys and verifies a test workload using only CAP APIs/CLI and CAP runtime components.
2. Run it with all PaaS endpoints, credentials, and configuration absent or blocked.
3. Verify a valid deployment through both `enclava verify` and the local HTML/WASM release.
4. Add the CAP internal PaaS bundle handler as a thin adapter over the same bundle-production function used by the reserved endpoint.
5. Add PaaS discovery, raw bundle relay, and convenience-appraisal routes using the existing CAP client; keep bundle transport binary and byte-preserving.
6. Add the PaaS product UI actions and explain the two choices accurately:
   - independent local verification with the downloaded HTML/WASM or CLI;
   - optional convenience appraisal by a named operator.
7. Publish an independently signed example policy and its hash outside the tenant application.
8. Add end-to-end tests against a standalone CAP deployment and the complete PaaS-to-CAP hosted path.
9. Add the required collusion scenario below as a release blocker.
10. Update ops image references only after standalone and hosted-product integration tests pass.

#### Required CAP-only acceptance test

Start a clean CAP deployment with no PaaS services, routes, credentials, templates, or configuration available. Deploy a test workload through the CAP CLI/API, then verify it using the CAP CLI and local CAP HTML/WASM verifier.

Required assertions:

- deployment and proof-material creation complete without PaaS;
- the reserved proof endpoint returns a self-contained bundle;
- browser and CLI network logs contain zero PaaS requests;
- a valid bundle and independent policy produce matching local `PASS` results;
- a policy-rejected mutation produces matching local `FAIL` results;
- stopping every optional appraiser does not affect either local result.

#### Required PaaS integration acceptance test

Deploy PaaS connected to the candidate CAP release and exercise verification only through the public product APIs and UI.

Required assertions:

- public discovery maps only to the registered hosted CAP application and allowed origins;
- the proof route forwards nonce and origin to CAP without accepting arbitrary upstream URLs or CAP paths;
- a fixed binary CAP fixture emerges from the PaaS relay byte-for-byte identical, with the correct media type and no-store headers;
- the convenience-appraisal result and receipt match the CAP appraiser response without PaaS-owned verification fields;
- PaaS supplies no implicit trust policy or expected measurement;
- the hosted UI labels the appraiser verdict as a convenience opinion and offers raw-bundle download plus local verification;
- a one-byte mutation in the PaaS relay makes the canonical local verifier return `FAIL`;
- when CAP is unavailable, PaaS returns a bounded unavailable error and never a cached or fabricated verdict;
- the local verifier's independent mode fetches the target reserved endpoint directly and continues to work when PaaS is stopped.

#### Required collusion acceptance test

Set up all of the following simultaneously:

1. The tenant workload serves a fake green `Verified` page.
2. The tenant implements a fake `/.well-known/confidential/proof-bundle` endpoint and claims an approved image/measurement.
3. The real workload evidence contains a policy-rejected image digest or SNP measurement.
4. The configured Enclava test appraiser deliberately returns `PASS` and a syntactically valid receipt from its test key.
5. The local HTML verifier and CLI receive their policy independently and fetch the target reserved endpoint directly.

Required assertions:

- Caddy routes the reserved path to the attestation proxy, not tenant code;
- the raw bundle exposes the authenticated observed image/measurement, not the tenant claim;
- browser and CLI network logs contain zero requests to the Enclava appraiser;
- browser and CLI network logs contain zero requests to PaaS;
- the local verifier rejects the evidence with the expected stable reason code;
- the malicious appraiser's `PASS` is displayed only as that appraiser's opinion if shown at all;
- substituting the appraiser response, target HTML, or target-provided policy cannot change the local `FAIL`;
- native and WASM both report the same policy-rejection reason; their live result hashes may differ only because the CLI observed `transport.tls_channel_spki` and the browser skipped it;
- replaying both builds with the same recorded `VerificationContext` fixture produces the same canonical result hash.

This test passes only when both dishonest parties fail to influence the independently run verifier. Merely detecting that one party lied is insufficient.

Exit criteria:

- the CAP-only acceptance test passes with PaaS absent;
- the PaaS integration acceptance test passes through the public hosted-product API and UI;
- collusion test passes in CI and pre-production;
- a fresh valid deployment passes locally under the independently pinned policy;
- changing every security-critical link individually causes local failure;
- all user-facing language distinguishes evidence, local verdicts, and appraiser opinions;
- verifier artifacts, policy artifacts, and appraiser receipts show distinct issuers and hashes.

## 7. Verification matrix

| Case | Local expected result | Appraiser relevance |
|---|---:|---|
| Valid fresh bundle + matching independent policy | PASS | Optional |
| No policy | INCONCLUSIVE | Cannot supply trust implicitly |
| Target supplies permissive policy | FAIL or ignored | None |
| Appraiser supplies permissive policy unexpectedly | Local result unchanged | Appraiser opinion only |
| Wrong nonce or origin | FAIL | None |
| Stale or replayed quote | FAIL | None |
| Invalid AMD chain/report signature | FAIL | None |
| Revoked or insufficient TCB | FAIL | None |
| Stale, expired, or undated required revocation data | FAIL | No online refresh |
| Wrong full 48-byte SNP measurement | FAIL | None |
| TLS SPKI/report-data mismatch | FAIL | None |
| Observed CLI channel SPKI mismatches bundle leaf SPKI | FAIL | None |
| Browser cannot observe channel SPKI; policy makes check optional | PASS with mandatory warning | Weaker than CLI |
| Browser cannot observe channel SPKI; policy requires it | INCONCLUSIVE | Use CLI |
| Descriptor, KBS policy, or artifact signature mismatch | FAIL | None |
| Image digest/provenance mismatch | FAIL | None |
| Invalid Fulcio/Rekor/Sigstore chain | FAIL | None |
| Missing required self-contained evidence | FAIL | No network fallback |
| PaaS relays exact CAP bundle bytes | Same result as CAP bytes | Transport only |
| PaaS mutates one bundle byte | FAIL | Cannot manufacture validity |
| Tenant and appraiser both claim PASS for bad evidence | FAIL | Local verifier ignores both claims |

Run every applicable vector through:

- the Rust library;
- `enclava verify`;
- WASM in a headless browser;
- the reference appraiser;
- a third-party appraiser conformance target.

For deterministic inputs, require identical check outcomes, reason codes, and canonical result hashes.

## 8. Release and rollout order

1. Merge contract specifications, fixtures, and the portable verifier gate.
2. Build digest-pinned candidate `enclava-init`, CAP API, attestation-proxy, CLI, WASM, and optional appraiser artifacts from the same tested source set.
3. In a standalone CAP environment, deploy dual-reading `enclava-init` and signing-service compatibility first if artifact schemas change, then verify the init digest in workload manifests.
4. Deploy the backward-compatible CAP API writer, PaaS adapter routes, and attestation-proxy bundle producer in the standalone test environment. Expose every required operation directly through CAP.
5. Run the CAP-only acceptance test with PaaS absent using the candidate CLI and local HTML/WASM artifacts.
6. Publish the signed CLI and local HTML/WASM release artifacts only after that test passes.
7. Deploy the optional appraiser only after local verification works end to end.
8. Implement and test the PaaS public discovery, bundle, appraisal, and UI integration against the pinned candidate CAP contract. If an existing CAP internal response shape changes, update and test PaaS before deploying that CAP API change.
9. For Enclava's hosted product, update `enclava-ops-manifests` with the candidate digests and volume mounts, preserving the init-before-API rollout order.
10. Deploy or enable the matching PaaS routes and verify readiness against the live CAP internal endpoints.
11. Run the PaaS integration acceptance test, including byte-preserving relay and CAP-unavailable behavior.
12. Verify the target reserved route against a live tenant pod and run the independent local-verifier path with PaaS stopped.
13. Run the tenant-plus-appraiser collusion acceptance test in pre-production.
14. Update `platform-release.json`, then promote only the exact verified digests.

The standalone CAP release gate proves ownership of the core. The PaaS integration gate proves the hosted product exposes that core correctly. Both must pass before the combined Enclava product release is promoted.

## 9. Required checks

In addition to phase-specific native/WASM, fixture, conformance, browser, and adversarial tests, CAP changes must pass:

```bash
rustup run stable cargo fmt --all -- --check
rustup run stable cargo clippy --workspace --all-targets -- -D warnings
rustup run stable cargo test --workspace
rustup run stable cargo test --doc
rustup run stable cargo audit --ignore RUSTSEC-2023-0071
rustup run stable cargo deny check advisories sources
rustup run stable cargo build --workspace
ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release --bin enclava-api
ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release --bin enclava
ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release -p enclava-init --features prod-strict
sudo docker build -f crates/enclava-init/Dockerfile -t enclava-init:local .
sudo docker build -f crates/enclava-api/Dockerfile -t enclava-api:local .
```

Also require:

```bash
rustup target add wasm32-unknown-unknown
cargo build -p enclava-verifier --target wasm32-unknown-unknown
cargo test -p enclava-verifier
# Run the checked-in WASM fixture harness in a supported browser runtime.
# Run the appraiser conformance suite against Enclava and third-party endpoints.
```

Repository-specific tests must cover:

- CAP manifest generation and volume isolation;
- exact-limit ConfigMap creation/mount round-trip and over-limit deployment rejection;
- existing reserved-route precedence in Caddy;
- proxy bundle endpoint parsing, CORS, size, timeout, canonical bytes, per-source/global rate limits, and quote-concurrency limits;
- channel-SPKI match, mismatch, and unavailable contexts across native and WASM;
- fresh, stale, expired, missing-time, and revoked AMD revocation fixtures;
- standalone CAP deployment and verification with PaaS unavailable;
- PaaS public discovery, raw bundle relay, appraiser forwarding, rate limits, and CAP error handling;
- cross-repository tests pinned to the matching CAP API contract;
- byte-for-byte relay fixtures and local failure after relay mutation;
- ops digest rollout and live pod inspection;
- Prove-It valid, tamper, and tenant-plus-appraiser-collusion paths.

## 10. Definition of done

This work is complete only when all of the following are true:

- the raw proof bundle is documented and shipped as the foundational public interface;
- it contains sufficient portable evidence for offline cryptographic verification;
- a standalone CAP installation can produce and verify it with no PaaS dependency;
- no CAP verifier code or standalone CAP release test requires PaaS source, APIs, templates, configuration, credentials, identity, DNS, or availability;
- when PaaS is deployed, its public discovery, proof-bundle, appraisal, and UI surfaces work end to end against CAP;
- PaaS contains no duplicate verifier or policy-decision implementation and preserves exact CAP bytes/results;
- policy is a separate, explicit input and target/appraiser-provided expectations cannot produce `PASS`;
- CAP has one I/O-free verifier implementation used by library, CLI, WASM, and reference appraiser;
- the CLI binds the bundle to its observed TLS channel, while browser/appraiser/offline results explicitly report when that check was unavailable;
- the local HTML verifier works without an Enclava backend, labels its weaker TLS-channel assurance, and is distributed as a signed, independently pinnable artifact;
- stale, expired, or undated required revocation material fails from trusted verifier time rather than producer creation time;
- bundle/field/ConfigMap limits and direct-endpoint rate/concurrency limits are enforced at their boundaries;
- the Enclava appraiser is explicitly labeled optional and replaceable;
- third parties can run the reference appraiser or implement the published compatibility API;
- full 48-byte SNP measurements are checked end to end;
- native and WASM outcomes are byte-for-byte compatible for golden vectors with identical `VerificationContext` inputs;
- the tenant-plus-Enclava-appraiser collusion test returns local `FAIL` for invalid evidence;
- rollout compatibility rules and all required repository checks pass.
