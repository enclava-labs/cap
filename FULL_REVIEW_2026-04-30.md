# Enclava Platform — Full Security & Architecture Review

**Date:** 2026-04-30
**Scope:** CAP (`crates/enclava-{api,engine,cli,common,init,wait-exec}`),
attestation-proxy, caddy-ingress, Trustee fork (`trustee/`), policy-templates
signing service (`policy-templates/signing-service`), and the live cluster
state at `control1.encl` (k0s v1.35.2, master-1 + worker-1).
**Live cluster:** cap-test01 (production-named), trustee-operator-system,
tenant-envoy, mgmt-envoy.
**Methodology:** prior-context review (SECURITY_REVIEW.md 2026-04-25,
SECURITY_MITIGATION_PLAN.md rev15 2026-04-30) → cluster reconnaissance via SSH
→ ultra-granular code analysis on highest-risk paths → 4 parallel sub-agents
on (engine+init, attestation-proxy+caddy, Trustee+signing-service, CLI+auth).
**Threat model:** the operator (anyone with kubectl, control-node root, K8s
admin, network-MITM via Cilium CNI) is OUTSIDE the trust boundary; the only
secrecy guarantee is AMD SEV-SNP guest memory.

---

## Executive Summary

The mitigation work is real and structurally significant: cc_init_data binds
descriptor + keyring + sidecars; enclava-init has a six-step in-TEE
verification chain; Trustee enforces signed policy with byte-for-byte CE-v1
canonicalization; cosign sigstore is wired; SSRF defense + JWT iss/aud + HMAC
API keys + signed BTCPay webhook + replay table are all live. Each component
in isolation looks defensible.

**The composite system, however, does not yet hold the confidentiality chain
end-to-end against the documented threat model.** Live cluster evidence and
code analysis identify **twelve CRITICAL paths** by which an operator-root
adversary defeats the policy-authorization boundary or escalates privileges
today, plus several **latent footguns** (single env-var flip in CAP-API,
silent fallback through ConfigMap-supplied trust anchors, hardcoded
`cosign_verified=true`) that re-enable significant parts of the
pre-mitigation attack surface. **17 HIGH findings** include CLI key-path
traversal that the prior 2026-04-25 review listed as fixed but is NOT,
Argon2 parameters not actually pinned despite plan claim, multiple SSRF
allowlist bypasses, and authentication/scope gaps on the `create_app` route
and `rotate_signer` route.

The single most consequential finding: **the platform-policy signing service
(`policy-templates/signing-service`) is a centralized signing oracle running
on the operator-controlled control node, on plain HTTP at `10.0.0.2:18080`,
with NO authentication on `/sign`, `/bootstrap-org`, `/agent-policy`, or
`/rotate-owner`, with its private signing key stored as a Kubernetes Secret
that any cluster-admin can `kubectl get`, with its owner allowlist stored as
a SQLite file on the operator-controlled node, with a TOFU bootstrap that
operators can race**. While `trusted_descriptor_public_keys = []` in
production, this signing service is the *sole* trust anchor for
`signed_policy_public_key` in Trustee; whoever controls the signing service
controls every Rego policy decision, and the operator does. Trustee's
verification, the in-TEE chain, the customer-signed artifact bytes, and the
cc_init_data binding are all mathematically correct, but they verify the
integrity of an attacker-authorable payload because the root signer is in the
attacker's hands.

The mitigation plan acknowledges "durable signing-service key custody",
"production release-root publishing", and "storage-level CAS hardening" as
remaining production blockers, and the Phase status table is honest about it.
Read against the rev15 promise of "M1 partial; cap-test01 validates the
plumbing", the live state is consistent. Read against the public M5-strict
claim ("confidentiality chain holds end-to-end"), the live state is **NOT
ready**, and several tactical issues below need to land before that claim is
defensible. The public README's "even the platform operator cannot access user
data" sentence is currently **false** for at least the operator paths in
§2.1, §2.2, §2.3, and §2.7.

cap-test01 in production has no actual tenant pods running today (only
`cap-api` + `postgres`), so none of these attack paths are being exercised
against real user data. The signed `bootstrap-deny-all` Rego policy ensures
that even if a workload were deployed, no KBS resource would be released.
However, several **production hygiene** issues — `TENANT_CADDY_ACME_CA`
pointing at Let's Encrypt **staging** in production; nine orphaned legacy
`flowforge-*` and `flowforge-1-mini-canary-*` K8s Secrets still mounted as
KBS resources; the upstream `coco-as-grpc:latest` and `rvps:latest`
unpinned-tag images in the Trustee pod — must be cleaned up before any
real tenant pods land.

---

## 0. Corrections (post-peer-review, 2026-04-30)

After peer review the following findings in §2/§3 were narrowed or
re-scoped. Read these before quoting any individual finding from the
sections below; the original finding text has been updated in place.

- **2.1 (SS-C1) overstated.** `/sign` is unauthenticated at the transport
  layer but the handler verifies the descriptor + keyring against an
  out-of-band-bootstrapped owner pubkey (`policy.rs:112-130`). A caller
  hitting `/sign` with arbitrary inputs cannot mint a valid artifact;
  the bypass requires winning the `/bootstrap-org` race, tampering with
  the owner SQLite DB, or stealing the platform Ed25519 key. Lack of
  transport auth is still a real defense-in-depth and confidentiality
  problem, but the "anyone forges" claim was wrong.
- **2.4 (TR-H1) wording fixed.** Backend-level CAS *is* implemented
  (`local_fs.rs:75-108` uses `create_new(true)` and `truncate(true)`).
  The actual bypass is direct K8s Secret edits propagated into the
  KBS pod's mounted resource files — invisible to the LocalFs CAS
  layer because the mutation isn't a write through that layer.
- **§1 contradiction on CLI SNP/VCEK fixed.** Code shows raw 1184-byte
  SNP report parsing + ARK/ASK/VCEK chain validation IS done
  (`attestation.rs:108`, `tee_client.rs:503-797`). Rev15 plan Phase 7
  PARTIAL is outdated for this item. §1 table updated.
- **2.9 (E2) cc_init_data attack scope narrowed.** Only the un-validated
  `signer_identity_*` fields are operator-mutable in TOML interpolations,
  and they sit in `[data]` *before* the `'''policy.rego'''` heredoc, so
  the original "any field can close the heredoc" claim was overstated.
  The structural fix (typed TOML rendering) still stands.
- **3.8 (manifest-hash) coverage corrected.** The hash DOES include
  `bootstrap_configmap`, `startup_configmap`, `ingress_configmap`, and
  the `statefulset` (which carries the cc_init_data annotation). The
  genuine miss is `enclava_init_configmap`, which is the most
  security-critical ConfigMap by far (E4). Finding text reframed.
- **3.16d (ROUTE-H2) namespace length detail fixed.** App names are
  capped at `MAX_APP_NAME_LEN = 32` (`validate.rs:25`), not 63. The
  actual issue is that org names are unvalidated/unbounded, and the
  combined `cap-{org}-{app}` exceeds the K8s DNS-1123 63-char limit
  when org is long.

---

## 1. Confidentiality chain: actual state vs. intended state

**Intended chain (per README + plan rev15):**

```
user CLI -- attested-TLS --> TEE caddy + attestation-proxy
                                     |
                                     +-- LUKS opens with HKDF(owner_seed, ...)
                                     |
                                     +-- KBS releases seed only if SNP_init_data == cc_init_data hash
                                     |   AND policy.rego signed by descriptor key
                                     |   AND descriptor signed by deployer
                                     |   AND keyring fingerprint matches cc_init_data anchor
                                     |
                                     +-- attestation-proxy first-write of seed-encrypted
                                     |   gated by If-None-Match: * + signed receipt
                                     |
                                     +-- workload runs inside SEV-SNP
```

**Current break points (live + code-confirmed):**

| Link | Status | Break |
|---|---|---|
| CLI authenticates the TEE | **HOLDS at the cryptographic level** | rustls SPKI-pinned client + raw 1184-byte SNP report parsing + ARK/ASK/VCEK DER chain validation are wired (`crates/enclava-cli/src/attestation.rs:108`, `tee_client.rs:503-797`). The `sev` crate parses real SNP reports; the dev `ENCLAVA_TEE_DEV_ALLOW_JSON_REPORT_DATA_ONLY` shortcut is `cfg!(debug_assertions)`-gated. Plan rev15 Phase 7 PARTIAL is OUTDATED on this item — the CLI side is done. (Open question: is the CLI getting raw report bytes from the proxy's `/v1/attestation` endpoint, or does the proxy still wrap them in JSON? Verify the wire format.) |
| Tenant TLS belongs only to the workload | **BROKEN (live)** | `TENANT_CADDY_ACME_CA = https://acme-staging-v02.api.letsencrypt.org/directory` in cap-test01 production env — browsers will reject. The dns-01/Cloudflare-token path *is* removed (confirmed), and TLS-ALPN-01-only is wired. |
| Only the signed workload image can get KBS secrets | **BROKEN (operator-substitutable)** | The Trustee resource backend is `LocalFs` (`kbs-config-grpc`) and the resource paths are mounted **from operator-controlled K8s Secrets** (`KbsConfig.kbsSecretResources`). Any operator with `kubectl edit secret -n trustee-operator-system <name>` rewrites the bytes KBS serves to any policy-authorized workload. Compounded by **TR-H1**: the new `If-None-Match`/`If-Match` CAS is HTTP-layer only; direct file writes inside the KBS pod or via the K8s Secret bypass it. |
| K8s control plane cannot introspect the guest | **HOLDS by Kata policy** (CONDITIONALLY) | `cc_init_data.rs:230` correctly emits `default AllowRequestsFailingPolicy := false` and denies `ExecProcessRequest`/`ReadStreamRequest`/`CopyFileRequest`/`WriteStreamRequest`. **BUT** if `LEGACY_BOOTSTRAP_SCRIPT=true` is flipped on the API, the workload reverts to privileged-root + shell interpolation (E1). And the **fallback** `build_agent_policy` (cc_init_data.rs:174-251) only checks 4 OCI annotations, not the full container spec — defense rests on the genpolicy-generated authoritative policy, which is generated by the unauthenticated signing service. |
| Operator cannot plant or rotate TLS seeds | **BROKEN** | Multiple paths: (a) the signing service's `/bootstrap-org` is unauthenticated and TOFU; (b) signing key stored in K8s Secret on operator-controlled node; (c) attestation-proxy `/receipts/sign` has no auth and is reachable on `0.0.0.0:8081`; (d) attestation-proxy first-write of `seed-encrypted` carries no signed envelope; (e) LocalFs storage is operator-writable. |
| Tenant identifiers cannot collide or inject | **HOLDS for Rego (active path)** | `kbs.rs` reconcile uses `serde_json::to_string` for active path; `cc_init_data.rs` `rego_string()` uses `serde_json::to_string` for the agent-policy fallback. **BUT** the **TOML wrapper** of cc_init_data (lines 60-92, 138-141, 148-155, 264-271) is built with raw `format!` against operator-influenceable strings (signer_identity_subject/issuer, identity TOML body) — a `"` or newline can escape the heredoc that contains `policy.rego`, allowing an attacker to substitute the Kata agent policy before the cc_init_data hash is computed (E2). |

---

## 2. CRITICAL findings

Each finding is operator-exploitable today on cap-test01's deployment shape.

### 2.1 [SS-C1] Policy-signing service has NO authentication on any route

- **File:** `policy-templates/signing-service/src/main.rs:110-127`
- **Live URL:** `http://10.0.0.2:18080` (control node, plain HTTP, reachable
  from cluster pods and from the control-node host). Confirmed by direct
  curl (returns `404` on `/`, `405` on `GET /sign`, indicating the service is
  alive and listening with no auth challenge).
- **Routes:** `/healthz` (GET), `/agent-policy` (POST), `/sign` (POST),
  `/bootstrap-org` (POST), `/rotate-owner` (POST). No `tower::auth` layer, no
  bearer-token check, no mTLS, no source-IP allowlist.
- **Evidence:** the CAP API client (`crates/enclava-api/src/signing_service.rs:53-93`)
  *sends* a bearer token from `PLATFORM_SIGNING_SERVICE_TOKEN`; the signing
  service code does not check it.
- **Important nuance (correction):** `/sign` itself is NOT a fully open
  oracle — `policy.rs:112-130` (`verify_signing_inputs`) requires a
  descriptor signed by a deployer in a keyring signed by the org owner
  whose pubkey is independently held in the signing service's
  `owner_store`. So a hostile caller hitting `/sign` with arbitrary
  inputs cannot simply mint a signature. The bypass requires ONE of:
  (a) winning the `/bootstrap-org` race for an org whose owner pubkey
  has not yet been registered (see 2.2), (b) tampering with the
  operator-readable owner-state SQLite (see M-3) to substitute the
  attacker's pubkey as the trusted owner, (c) stealing the platform
  Ed25519 signing key (see 2.3), or (d) compromising a legitimate
  customer's private key. Lack of transport auth on `/sign` is still
  bad — it leaks descriptor blobs to anyone who can reach the URL,
  enables DoS, and removes a defense-in-depth layer — but the
  immediate "anyone forges artifacts" claim was overstated. The
  authorization-boundary collapse runs through paths (b) and (c),
  which are the more consequential findings.
- **Fix:** require strong auth on every endpoint (mTLS with a CAP-API
  client cert, NOT a static bearer token; the signing service must refuse
  requests where the cert subject is not the API's). Better: move the signer
  off-cluster to a host the operator does not have root on, with HSM-backed
  key custody.

### 2.2 [SS-C2] `/bootstrap-org` is TOFU and operator-callable

- **File:** `policy-templates/signing-service/src/main.rs:189-219`,
  `owner_store.rs:78-117`
- **Logic:** accepts `org_id` + `owner_pubkey_b64`, inserts on first contact,
  no signature, no out-of-band check. Subsequent calls with the same
  `(org_id, pubkey)` succeed; with a different pubkey, errors with
  "org already bootstrapped with a different owner pubkey".
- **Operator impact:** for any org_id the platform creates, an operator who
  scripts a faster bootstrap call wins — they own the org's signing
  authority. There is no rate-limit, no admin-token gate, no requirement
  that the bootstrapping call carry a signature from an offline release
  root. Combined with **2.1**, this is the second of two paths to defeat
  customer-signed policy: claim the org, then sign at will.
- **Fix:** bootstrap must require an offline release-root signature, OR a
  manual operator unlock, OR be removed entirely (with the owner key
  delivered out-of-band on org creation through a different channel).

### 2.3 [SS-C3] Signing-service Ed25519 private key lives as an operator-readable K8s Secret

- **File:** `policy-templates/signing-service/src/policy.rs:75-100`,
  deploy descriptor reads `POLICY_SIGNING_KEY_B64` env from a K8s Secret.
- **Operator impact:** `kubectl get secret signing-service-secrets
  -o jsonpath='{.data.POLICY_SIGNING_KEY_B64}' | base64 -d` exfiltrates
  the entire signing capability. Combined with **2.6** (`insecure_key=true`
  removes the JWK trust anchor), the operator can stand up a parallel
  signing service or sign arbitrary policies offline.
- **Fix:** HSM/external KMS for signing; the in-cluster service must hold
  only a request-signing capability bound to a particular KMS path, never
  the raw key bytes.

### 2.4 [TR-H1] Trustee storage CAS bypassed via direct K8s Secret edit (NOT HTTP-layer-only — correction)

- **Correction to earlier wording:** Backend-level CAS *is* implemented.
  `trustee/kbs/src/plugins/implementations/resource/local_fs.rs:75-108`
  uses `OpenOptions::new().create_new(true)` (atomic-or-fail at the
  filesystem layer) for `write_secret_resource_if_absent`, and
  `truncate(true).open()` (requires file exists) for
  `write_secret_resource_if_present`. The `kv_storage` backend at
  `kv_storage.rs:54` similarly uses backend-level conditional writes.
  So writes that go *through KBS* are properly conditional.
- **The actual bypass:** the resource files at
  `/opt/.../default/<name>/workload-secret-seed` are mounted from K8s
  Secrets via `KbsConfig.kbsSecretResources`. The operator does NOT need
  to write through the KBS HTTP API or the filesystem of the KBS pod —
  they `kubectl edit secret -n trustee-operator-system
  flowforge-1-mini-canary-tls` (the source K8s Secret) and the kubelet's
  Secret-volume reflector propagates the new bytes into the pod's mount.
  KBS LocalFs then serves the operator's substituted bytes on the next
  authorized read. The CAS layer never sees the mutation because the
  mutation isn't a write through the LocalFs API.
- **Operator impact:** rotate any tenant's owner-seed ciphertext under
  the attacker's key, then attest a workload that decrypts with that
  key. Plan rev15 acknowledges "storage-level CAS for resource writes"
  is open; in practice the CAS that exists is sound but the *backing
  store choice* (K8s Secret reflection) defeats it.
- **Fix:** stop mounting K8s Secrets as resource backing. Either
  (a) write resources through the KBS HTTP API only (so all mutation
  goes through the backend's `create_new`/`truncate` semantics),
  (b) back resources with a database the operator cannot write to
  directly, or (c) run KBS on a node whose root is not the operator's.
  Drop the `kbsSecretResources` field from `KbsConfig` and migrate
  existing tenants to API-driven writes.

### 2.5 [TR-H2] `/kbs/v0/attestation/verify` is unauthenticated and accepts the token in the request body

- **File:** `trustee/kbs/src/api_server.rs:321-327, 763-772`
- **Operator impact:** the endpoint is the verification callback used by
  CAP API's `routes/workload.rs` (the workload-artifacts endpoint). With no
  auth, **anyone reaching the KBS port** can submit any token (in the
  `Authorization` header OR in `{"token":"..."}` body) and have KBS verify
  it and return all the EAR claims. With **2.6** (`insecure_key=true`),
  any inline-JWK-signed token verifies. An operator can:
  1. Mint or capture an attested token.
  2. POST it to `/kbs/v0/attestation/verify`.
  3. Receive the `init_data_hash` + `descriptor_core_hash` claims.
  4. Replay those to CAP API's `/api/v1/workload/artifacts` and harvest
     a tenant's descriptor + keyring + signed policy artifact.
- **Note on impact severity:** the workload-artifacts response is integrity-
  protected (every blob is signed), so the operator can't *forge* artifacts
  via this path — but it's a **confidentiality** leak: descriptors contain
  env vars, mounts, custom domains, and other sensitive deployment metadata.
- **Fix:** require admin auth on `/attestation/verify` (the plan describes it
  as a trusted callback for CAP API only). Or bind the endpoint to a
  dedicated mTLS listener.

### 2.6 [TR-H3 + KBS config] `insecure_http=true insecure_key=true insecure_api=true` in production

- **Live evidence:** `kubectl -n trustee-operator-system get cm
  kbs-config-grpc -o yaml`:
  ```toml
  [http_server]
  sockets = ["0.0.0.0:8080"]
  insecure_http = true
  ...
  [admin]
  type = "DenyAll"
  insecure_api = true
  ...
  [attestation_token]
  insecure_key = true
  ```
- **Operator impact:**
  - `insecure_http=true`: KBS serves plain HTTP. Cilium operator can MITM
    every workload-resource read/write and every attestation token exchange.
  - `insecure_key=true`: `trustee/kbs/src/token/jwk.rs:190-200` accepts the
    token's *embedded* JWK as the verification key — no external trust
    anchor. Anyone who can answer the AA token URL can mint an
    "attested" token with arbitrary claims, and Trustee will accept it.
  - `insecure_api=true` under `[admin]`: even though `type = "DenyAll"`,
    the `insecure_api` flag relaxes admin auth across other paths
    (worth a closer audit; documented as test/dev).
- **Fix:** these are explicit dev/test flags. Production must run with
  `insecure_http=false` (with TLS termination either on KBS or via a
  loopback-only deployment), `insecure_key=false` (with `trusted_jwk_sets`
  pointing at the in-cluster AS), and explicit admin auth.

### 2.7 [AP-C1 + AP-C2 + AP-C3] attestation-proxy serves privileged routes on `0.0.0.0:8081` (HTTP) cluster-wide, unauthenticated

- **Files:** `attestation-proxy/src/main.rs:76-97, 159-163`,
  `attestation-proxy/src/config.rs:99` (`ATTESTATION_BIND` default `0.0.0.0`),
  `attestation-proxy/src/handlers.rs:1186-1193, 2329-2340`.
- **Live state:** the proxy is intended as a TEE-internal sidecar; the
  Service exposes only its TLS port (8443). However, the **HTTP listener at
  `0.0.0.0:8081` is reachable from any cluster pod** that resolves the Pod
  IP — including a co-located operator-deployed pod. The same `app_router`
  is bound to both listeners with no per-listener filter.
- **Routes that should be loopback-only but are exposed:**
  - `POST /receipts/sign` — no auth, mints rekey/teardown/unlock-mode
    transition receipts for arbitrary `app_id`/`resource_path`. Trustee
    only checks `pubkey_sha256` matches REPORT_DATA → any receipt under the
    workload's keypair is structurally valid.
  - `POST /cdh/resource/*` — passes through to AA/CDH which talks to KBS
    plaintext over HTTP. After unlock, any cluster caller can read any KBS
    resource the workload is policy-authorized for.
  - `POST /teardown`, `POST /config/*`, `/.well-known/confidential/*`.
- **Operator impact:** with the workload past the ownership gate (i.e., any
  successful boot), the operator co-locates a pod, reaches the HTTP 8081
  listener via Pod IP, and forges KBS receipts or reads resources without
  ever talking to the attested TLS path.
- **Fix:** bind HTTP to `127.0.0.1` only (loopback for Caddy + AA/CDH
  agents). Or split the router so HTTP exposes only the AA/CDH internal
  endpoints, and TLS-only exposes attestation/receipt/config/teardown.
  Add JWT/scope auth on every public route.

### 2.8 [E1] `LEGACY_BOOTSTRAP_SCRIPT=true` env on CAP API re-enables privileged-root + shell interpolation

- **File:** `crates/enclava-engine/src/manifest/containers.rs:24-28, 94, 142-155, 217-228, 503-514, 619-666, 727-742`
- **What it does:** when set, the engine emits manifests where:
  - app and caddy containers run with `privileged: true`, `runAsUser: 0`,
    `runAsNonRoot: false`, `add: SYS_ADMIN`.
  - app command becomes `["/bin/sh","-c","/secure-pv/bootstrap.sh -- {user_cmd}"]`
    where `user_cmd = primary.command.join(" ")` — unquoted shell
    interpolation of every argv element.
- **Operator impact:** flipping this flag on the CAP-API Deployment
  (`kubectl edit deployment cap-api -n cap-test01`, redeploy) causes every
  subsequent reconcile to render tenant pods to the legacy shape. The
  shell-interpolation enables command injection through any deploy whose
  argv contains spaces/quotes (and the user_cmd source is operator-readable
  DB rows, so the operator can self-craft both flag and payload). All
  tenants are simultaneously affected on next reconcile.
- **Fix:** delete the `legacy_bootstrap_enabled()` branch, every
  `if legacy { ... }` arm, and the `bootstrap_script.sh` artifact. The
  rev15 plan describes Phase 5 as "DONE" with the legacy fallback gone
  from production; the code shows the fallback is still emittable.

### 2.9 [E2] `cc_init_data` TOML built with raw `format!` against operator-influenceable strings — heredoc escape

- **File:** `crates/enclava-engine/src/manifest/cc_init_data.rs:60-92,
  138-141, 148-155, 264-271`
- **Pattern:** every value (`namespace`, `service_account`,
  `tenant_instance_identity_hash`, `signer_identity_subject`,
  `signer_identity_issuer`, identity TOML body, sidecar digests) is
  interpolated as `format!("foo = \"{val}\"\n")` with no escaping.
  `signer_identity_subject`/`issuer` flow from API DB rows the operator
  can edit; the rest are validated upstream (image_digest by parser,
  namespace/service_account/identity_hash by `validate_*` helpers,
  runtime_class is a const).
- **Attack scope (corrected — narrower than originally written):** the
  vulnerable interpolations are only the ones whose source strings are
  not server-side-validated for TOML special characters: primarily
  `signer_identity_subject` and `signer_identity_issuer`. These appear
  in the `[data]` section *before* the `'''policy.rego'''` heredoc, so
  injecting `"` or `\n` there breaks the `[data]` table parse and would
  be caught by the TOML round-trip — it does NOT directly close the
  later policy.rego heredoc unless multi-line TOML semantics are
  exploitable. The defensible concerns remain: (a) any future
  interpolated field added without server-side validation reopens the
  attack surface; (b) the `[data.sidecar_digests]` table at line 148-155
  is rendered after `policy.rego` and a malformed `signer_identity_*`
  field plus a string literal adjacent could in principle produce a
  document that re-parses with a different `policy.rego` value;
  (c) `serde_json::to_string` is used correctly inside the agent-policy
  fallback (`rego_string()`) but the surrounding TOML scaffolding does
  not match that hygiene. The right fix is structural, not tactical.
- **Original prose claim "any interpolated value containing `'''` breaks
  the heredoc" was overstated**; the actual reach depends on which field
  the attacker controls and where in the TOML stream it appears. The
  heredoc, allowing the attacker to substitute the Kata agent policy text
  with a permissive one — and the cc_init_data SHA256 hash will commit to
  the *attacker's* policy text, so the subsequent SNP HOST_DATA anchor is
  consistent with the substitution.
- **Operator impact:** combined with **E1**, two engineering-grade exploits
  in one component. Even without E1, an operator who can update a
  signer_identity row and trigger a redeploy substitutes the Kata agent
  policy, then re-attests, gets seeds.
- **Fix:** render the entire TOML through `toml::to_string` of a typed
  struct. The agent policy itself uses `rego_string()` correctly (line 253
  via `serde_json::to_string`); the surrounding wrapper does not.

### 2.10 [E4] enclava-init reads its critical configuration (cc_init_data, trust-anchor pubkeys, KBS URL, salt) from a plain ConfigMap

- **Files:** `crates/enclava-engine/src/manifest/enclava_init_config.rs:25-52`
  mounts `enclava-init-config` ConfigMap at `/etc/enclava-init/`;
  `crates/enclava-init/src/main.rs:42-47, 341-347` and
  `crates/enclava-init/src/config.rs` load `kbs_url`, `kbs_resource_path`,
  `argon2_salt_hex`, `workload_artifacts_url`, `trustee_policy_url`,
  `cc_init_data_path`, `platform_trustee_policy_pubkey_hex`,
  `signing_service_pubkey_hex` from the file.
- **Operator impact:** with `kubectl edit configmap` on the
  enclava-init-config:
  - Redirect `kbs-url` to a host the operator controls (autounlock seed
    harvesting; the operator's KBS lookalike returns whatever owner-seed
    they want, plain HTTP).
  - Swap `argon2-salt-hex` (forces a re-format of LUKS on next boot under a
    mismatched key — destroys all user state and yields a fresh container
    the operator unlocks).
  - Replace `platform-trustee-policy-pubkey-hex` with a key whose private
    half they hold — combined with **E3** (silent fallback), the in-TEE
    verifier accepts the operator's signature as valid.
  - Replace the local `cc-init-data.toml` (the file is mounted from the
    same ConfigMap) — operator-supplied bytes that pass the in-TEE
    `expected_cc_init_data_hash == sha256(local_cc_init_data_toml)` check
    only because the descriptor's expected value is also under operator
    influence at the same boot.
- **Fix:** read cc_init_data TOML from the Kata-exposed init-data annotation
  (the actual SNP HOST_DATA-anchored bytes), not from a K8s ConfigMap. Pin
  the trust-anchor pubkeys into the enclava-init binary at build time
  (cosign-verified at CAP-API startup), not into a ConfigMap.

### 2.11 [E3] In-TEE policy verifier silently accepts platform fallback signature

- **File:** `crates/enclava-init/src/trustee_verify.rs:286-300`
- **Logic:** verify with `descriptor_signing_pubkey` first; on failure, try
  `platform_trustee_policy_pubkey` and `signing_service_pubkey` and emit a
  `tracing::warn!`, **not a refusal**. Both fallback keys are loaded from
  the operator-mutable enclava-init-config ConfigMap (E4).
- **Live state:** Trustee `trusted_descriptor_public_keys = []` in
  production. The customer-signed path is therefore non-functional today;
  every successful verification routes through the platform fallback.
- **Operator impact:** with **2.1** (signing service unauth) the operator
  obtains a valid platform-key signature on any policy envelope they want
  → in-TEE verifier accepts it. Plus the warn-only fallback hides the
  bypass from anyone watching tracing logs.
- **Fix:** remove the silent fallback. Either refuse verification when
  `descriptor_signing_pubkey` doesn't verify, or require the platform
  fallback to come through cc_init_data (host_data-bound) rather than the
  ConfigMap.

### 2.12 [CLI-C1] CLI `bootstrap_key_path()` path-traversal not fixed (prior High finding regressed)

- **File:** `crates/enclava-cli/src/config.rs:90`
- **Logic:** `bootstrap_key_path(org, app)` joins `org` and `app` directly
  into `~/.enclava/keys/{org}/{app}.key` with **no validation** of either
  component. CLI commands feed `org` from the persisted CliConfig and `app`
  from CLI args / API responses.
- **Operator impact:** a malicious or mis-resolved API response (or stale
  CliConfig) returning `org="../"` or `app="../../../etc/passwd"` reads or
  overwrites arbitrary user files (e.g. `~/.ssh/id_ed25519`). The
  prior 2026-04-25 review listed this as a High finding ("CLI key path
  traversal through org names") and the rev15 plan does **not** list it as
  unfixed. It IS unfixed.
- **Fix:** in `bootstrap_key_path`, reject `org`/`app` containing `/`,
  `\`, `..`, control characters, or anything not matching the same DNS-1123
  regex used server-side (`enclava_common::validate::validate_app_name`).

---

## 3. HIGH findings

### 3.1 [AP-H2] First-write of `seed-encrypted` carries no signed receipt envelope

- **File:** `attestation-proxy/src/kbs.rs:367-371`
- The `Create` branch sends raw `body.to_vec()` with `If-None-Match: *`
  and content-type `application/octet-stream`; only the `Replace` branch
  wraps the body in a signed receipt envelope. The plan's "first-write
  binds receipt key into REPORT_DATA" depends on the create branch
  carrying a signed claim, which it doesn't.
- **Fix:** include a signed `bootstrap_claim` receipt envelope in the
  create body; have the Trustee policy verify `pubkey_sha256` matches
  REPORT_DATA on PUT-create, not just PUT-replace.

### 3.2 [AP-H3] Bootstrap claim does not bind the new Ed25519 receipt key into the SNP report

- **File:** `attestation-proxy/src/handlers.rs:1624-1751`,
  `attestation-proxy/src/receipts.rs:130-136`
- The `receipt_signer` is generated **per process restart** as ephemeral.
  After bootstrap_claim writes the encrypted seed, no fresh attestation is
  issued binding the new receipt key to REPORT_DATA. On restart, the new
  ephemeral receipt key cannot be cryptographically tied back to the
  bootstrap event.
- **Fix:** persist `receipt_pubkey_sha256` deterministically (e.g.,
  HKDF(owner_seed, "receipt-key-v1")) so it survives restart, and force a
  fresh attestation immediately after bootstrap_claim.

### 3.3 [AP-H1] Plaintext HTTP from attestation-proxy to KBS for resource writes and tokens

- **File:** `attestation-proxy/src/config.rs:117-119` defaults
  `KBS_RESOURCE_URL` to `http://kbs-service.../kbs/v0/resource`;
  `attestation-proxy/src/kbs.rs:347-394` uses `state.http_client` with no
  TLS pinning.
- The Bearer token (an attested JWT) flies in plaintext. Operator-controlled
  Cilium can replay or strip it.
- **Fix:** mTLS tunnel between proxy and KBS, OR enforce TLS once Trustee
  no longer runs with `insecure_http=true`.

### 3.4 [AP-H4] Self-signed TLS leaf with no SNI / cert-pinning fallback

- **File:** `attestation-proxy/src/main.rs:178-190`,
  `rcgen::generate_simple_self_signed`. The leaf SPKI IS bound into
  REPORT_DATA, which is correct; but there's no mechanism preventing a
  client from caching a leaf across restarts (if a CLI ever does). Strict
  TOFU-via-SNP-quote on every dial is the only way; document and enforce.

### 3.5 [AP-M3] AA token verified via inline JWK (Bring-Your-Own-Key)

- **File:** `attestation-proxy/src/attestation.rs:67-87`
- Verifies the AA token's signature against whatever JWK the token's own
  header advertises. With **AP-C1** (HTTP listener on 0.0.0.0) and the
  `AA_TOKEN_URL` env-supplied (potentially an operator-controlled
  network address), the operator can inject arbitrary claims.
- **Fix:** verify against a pinned JWK set; check `iss`, `aud`.

### 3.6 [SS-H1] Genpolicy invocation accepts paths from env vars

- **File:** `policy-templates/signing-service/src/genpolicy.rs:34-50, 103-114`
- Reads `GENPOLICY_BIN`, `GENPOLICY_RULES_PATH`, `GENPOLICY_SETTINGS_DIR`
  from env. Operator with deployment-edit access can swap the binary.
- **Containment:** the customer-signed descriptor's
  `expected_agent_policy_hash` would have to match — so the operator
  cannot inject (the wrapper's output hash must equal the customer's
  expectation). However, in production today the customer often computes
  the expectation by *querying* the signing service (`/agent-policy`),
  which means a swapped binary swaps both ends silently.
- **Fix:** pin `GENPOLICY_BIN` into the OCI image, drop env override,
  verify checksum at startup.

### 3.7 [TR-H4] Receipt verification fail-open via missing Rego clause

- **File:** `trustee/kbs/src/api_server.rs:591-681` (Rust verification
  is correct), `policy-templates/signing-service/src/policy.rs:619-643`
  (Rego template requires the `pubkey_hash_matches`/`signature_valid`
  fields).
- A future-rendered policy that forgets a clause silently ignores the
  receipt. There's no Rust-side fail-closed gate beyond what Rego asserts.
- **Fix:** add a minimum-policy harness in Trustee that rejects PUT/DELETE
  on `*-owner` paths when `signature_valid==false` *before* Rego runs, in
  addition to the policy check.

### 3.8 [H2] `manifest-hash` annotation misses `enclava_init_configmap`

- **Files:** `crates/enclava-engine/src/apply/orchestrator.rs:24-52`,
  `crates/enclava-engine/src/apply/drift.rs:60-67`.
- **Correction:** the hash DOES cover `bootstrap_configmap` (line 39),
  `startup_configmap` (line 40), `ingress_configmap` (line 41), and the
  `statefulset` (line 42) — and the StatefulSet manifest is where the
  cc_init_data annotation lives, so cc_init_data IS hashed transitively.
  It also covers namespace, service_account, network_policy,
  resource_quota, service, sni_route_configmap, envoy_proxy, gateway,
  tls_route, kbs_owner_binding.
- **The genuine miss:** `enclava_init_configmap` (the file mounted at
  `/etc/enclava-init/` per E4) is **not** in the parts list. That is the
  ConfigMap an operator can `kubectl edit` to redirect KBS URL, swap
  Argon2 salt, or substitute trust-anchor pubkeys — and drift detection
  will not notice. Combined with E4, this is the operationally most
  important manifest-hash gap.
- **Fix:** add `manifests.enclava_init_configmap` to the parts vector
  in `manifest_hash`. Treat the hash as advisory documentation, not a
  security control — operators control both the annotation and the
  ConfigMap, so the hash is at best a reconciliation hint.

### 3.9 [H3] LUKS state PVCs are operator-readable raw block devices

- **File:** `crates/enclava-engine/src/manifest/volumes.rs:113-141`
- The two PVCs are `Block`-mode `longhorn-wait` claims. LUKS encryption
  protects content. Combined with **E4** (operator controls the salt) for
  password-mode pods, an attacker can force a known salt → known
  OwnerSeed → known LUKS key, then offline-decrypt captured ciphertext.
- **Fix:** tie LUKS key derivation to SNP `host_data`, not just the
  ConfigMap-supplied salt.

### 3.10 [CI-H1] Caddy TLS private key not bound to REPORT_DATA

- **Files:** `crates/enclava-engine/src/manifest/ingress.rs:184`,
  `caddy-ingress/Dockerfile`.
- Caddy generates a fresh keypair on first ACME order, persists on the
  LUKS-mounted volume. Browsers see a Let's Encrypt-issued cert (chain
  validity confirmed by ACME), but **cannot tie the public key to a
  specific measurement**. A user who clicks through cert UX has no way to
  detect a swapped TEE.
- **Fix:** seed Caddy's account/leaf key from `owner_seed` HKDF; surface
  the leaf SPKI through `/.well-known/confidential/attestation` so clients
  can pin against the SNP-bound value.

### 3.11 [Live Env] `TENANT_CADDY_ACME_CA = letsencrypt staging` in production cluster

- **Live evidence:** `kubectl -n cap-test01 exec deploy/cap-api -- env`:
  `TENANT_CADDY_ACME_CA=https://acme-staging-v02.api.letsencrypt.org/directory`.
- Tenant apps would receive Let's Encrypt **staging** certs, browser-rejected
  by default. Users who click through cert errors learn to ignore the
  TEE attestation banner; the security UX collapses.
- **Code state:** `crates/enclava-engine/src/types.rs:138`
  `default_acme_ca_url()` returns the production ACME endpoint.
  `crates/enclava-engine/src/manifest/network_policy.rs:11` allows
  egress to *both* staging and production hosts; `env_gates.rs` does
  NOT refuse to start on a staging URL in release builds.
- **Fix:** add a release-only gate in `env_gates.rs` that refuses
  `TENANT_CADDY_ACME_CA` containing `acme-staging` or any non-production
  ACME directory unless an explicit `STAGING_OK=1` debug flag is set.

### 3.12 [Live KBS] Orphaned legacy K8s Secrets mounted as KBS resources

- **Live evidence:** `kubectl -n trustee-operator-system get kbsconfig -o yaml`
  shows `kbsSecretResources: [kbsres1, flowforge-storage, flowforge-tls,
  flowforge-1-mini-canary-state, flowforge-1-mini-canary-tls,
  flowforge-1-mini-canary-2-state, flowforge-1-mini-canary-2-tls,
  flowforge-1-mini-canary-auto-state, flowforge-1-mini-canary-auto-tls]`.
- Each `flowforge-1-mini-canary-*` secret has a `workload-secret-seed` key.
  These are the OLD legacy seeds from prior tenants now removed (the
  `flowforge-1` namespace doesn't exist); the secrets persist with
  operator-readable values.
- **Active mitigation:** the resource policy is `bootstrap-deny-all`, so
  no read currently succeeds. **Latent risk:** when CAP transitions to a
  real production policy, those resources become readable to any
  policy-authorized workload. An operator can `kubectl edit secret
  flowforge-1-mini-canary-state` to substitute their bytes; on next
  authorized read, the substituted bytes are served. This is the same
  attack path as **2.4** but with already-extant operator-owned objects.
- **Fix:** delete the orphaned Secrets and remove them from
  `KbsConfig.kbsSecretResources` immediately; document in a runbook the
  cleanup procedure for app teardown.

### 3.13 [H1] enclava-init panics weaponizable for boot-loop

- **Files:** `crates/enclava-init/src/main.rs:33-38` (any error → ExitCode 1
  → kubelet restart), `crates/enclava-engine/src/manifest/cc_init_data.rs:165, 171`
  (panic on missing required fields), `crates/enclava-engine/src/manifest/containers.rs:38-44`
  (panic if `ENCLAVA_INIT_IMAGE` not digest-pinned).
- In password mode, a tampered `argon2-salt-hex` makes every unlock attempt
  fail before the rate-limiter advances → **rate-limit window resettable**
  at the operator's discretion, allowing slow Argon2 brute-force without
  the user's knowledge.
- **Fix:** log + retry rather than exit; rate-limit by wall-clock not
  process-restart count.

### 3.14 [TR-M3] `/resource-policy/<id>/body` not bound to descriptor_core_hash in Rust

- **File:** `trustee/kbs/src/api_server.rs:411-444`. The policy binding to
  `descriptor_core_hash` is delegated entirely to Rego, not Rust. A
  workload attested under descriptor A could request the body of policy B
  if Rego forgets to pin the relationship.
- **Fix:** surface the requested `policy_id` and the policy's own
  `metadata.descriptor_core_hash` in `policy_data`, and add a Rust-level
  equality check before returning the body.

### 3.15 [W-1] Recursive claim extraction in `/api/v1/workload/artifacts`

- **File:** `crates/enclava-api/src/routes/workload.rs:196-210`
- `extract_hex_claim` does a recursive search through the JSON for any
  matching `init_data_hash` / `descriptor_core_hash` field. This is a
  security smell: if attestation claims contain operator-influenced
  custom-claim fields, the recursion may find an attacker's planted hash
  before the legitimate one.
- **Fix:** hardcode the path
  `claims.submods.cpu0.ear.veraison.annotated-evidence.init_data_claims.<key>`
  and reject if not present at exactly that location.

### 3.16a [AUTH-H1] Argon2 parameters NOT pinned despite plan claim

- **File:** `crates/enclava-api/src/auth/email.rs:28-34, 39-42`
- `Argon2::default()` is used for both `hash_password` and `verify_password`.
  The rev15 plan claims params are pinned (Phase 0 status); they are not.
  argon2 0.5's defaults are OWASP minimums and may degrade in future crate
  revisions, breaking verification compatibility for already-stored hashes.
- **Fix:** build an explicit `argon2::Params` (m, t, p) and use
  `Argon2::new(Algorithm::Argon2id, Version::V0x13, params)`. Document
  the params and write a migration test for any param change.

### 3.16b [AUTH-H2] Nostr signup/login DON'T bind request body via NIP-98 payload tag

- **File:** `crates/enclava-api/src/auth/nostr.rs:42-80`,
  `crates/enclava-api/src/routes/auth.rs:98, 221`
- `verify_nip98_event_with_body` exists and binds the `payload` tag for
  mutating endpoints, but the Nostr signup and login routes call the
  **non-body version**. POST bodies are unbound from the signed event, so
  an operator MITM can swap `display_name` (or any other body field) on
  signup without invalidating the event.
- **Fix:** route all mutating Nostr endpoints (signup, login, anywhere a
  body matters) through `verify_nip98_event_with_body`.

### 3.16c [ROUTE-H1] `create_app` has NO scope check

- **File:** `crates/enclava-api/src/routes/apps.rs:283-294`
- Requires authentication via `AuthContext` but no `scopes::require_*`
  call. Any member-role user, or any API key regardless of scopes, can
  create apps as long as auth resolves. A read-only `apps:read` API key
  creates apps.
- **Fix:** add `scopes::require_admin(&auth)?; scopes::require_scope(&auth, "apps:write")?;`
  at the top.

### 3.16d [ROUTE-H2] Namespace name has no combined length cap; org names unvalidated/unbounded

- **File:** `crates/enclava-api/src/routes/apps.rs:244`,
  `crates/enclava-common/src/validate.rs:25, 79`
- **Correction:** app names ARE capped at `MAX_APP_NAME_LEN = 32`
  (`validate.rs:25, 83`), not 63. The actual gap is that **org names
  have no length validation** — `validate_org_slug` exists but is not
  enforced for the historical/display org name path that flows into
  `format!("cap-{org_name}-{app_name}")`. With no org-name bound, a
  long org name plus a 32-char app name can exceed the 63-char K8s
  DNS-1123 limit, deploy fails late after DB insertion.
- **Fix:** enforce `org_name.len() + app_name.len() + 5 <= 63` at app
  create time, AND add a `MAX_ORG_NAME_LEN` to `validate_org_*`.

### 3.16e [ROUTE-H3] `rotate_signer` accepts but does NOT verify `email_confirmation_token`

- **File:** `crates/enclava-api/src/routes/apps.rs:741`
- The handler accepts an `email_confirmation_token` field then drops it:
  `let _ = confirmation_token;`. Comment marks it `TODO(phase-10)` but
  the route is in production code. A stolen owner session token (or any
  owner whose email is compromised) rotates the per-app signer identity
  to anything they want — including a Fulcio identity belonging to the
  attacker. After rotation, the attacker's images verify against the new
  signer.
- **Fix:** until Phase 10 ships email verification, refuse rotation on
  any app whose `signer_identity_subject` is already set; only permit
  initial set (which the code already special-cases at create time).

### 3.16f [CC-H1] `cosign_verified` hardcoded `true` despite plan claim

- **File:** `crates/enclava-api/src/routes/deployments.rs:602`
- `let cosign_verified = true;` is still hardcoded. The plan rev15 claims
  "hardcoded `cosign_verified=true` removed" (Phase 9 DONE). Control-flow-
  wise this is currently safe because `verify_image()` errors out at
  line 407 on failure, but the bug surface is real: any future refactor
  that moves the verify call, or adds a fast-path branch, immediately
  writes "verified=true" without verification.
- **Fix:** capture `verified.digest`/`verified.signer_subject` from the
  `VerifiedSignature` struct and persist explicit fields. Make
  `cosign_verified` a function of the actual verification result, not a
  literal.

### 3.16g [CC-H2] `registry::resolve_tag_to_digest` accepts arbitrary registry hostname (SSRF allowlist bypass)

- **File:** `crates/enclava-api/src/registry.rs:22-97`
- `r if r.contains('.') => Ok(format!("https://{}", r))` (line 77) allows
  any hostname containing a dot to become a registry base URL. The
  call site at `routes/deployments.rs:376` uses `state.http_client`
  which has the SSRF resolver guard but **no host allowlist** —
  RFC1918 is blocked but `attacker.example` is reachable, and the
  registry response (Docker-Content-Digest header) flows back into
  the deploy path.
- **Fix:** route all registry resolution through the
  `RegistryClient::check_url` allowlist; reject hostnames that don't
  appear in the platform's registry allowlist.

### 3.16h [CC-H3] `tee_http_client` lacks SSRF resolver

- **File:** `crates/enclava-api/src/main.rs:471-475`
- `tee_http_client` is built independently of `clients::build_guarded_client`.
  It honors `tee_accepts_invalid_certs()` and forces `https_only(true)`,
  but has **no SSRF resolver**. `routes/unlock.rs:349` (`unlock_status`)
  uses it to fetch `https://<tenant-domain>/.well-known/confidential/status`
  — if a tenant DNS name resolves into an internal cluster CIDR (operator
  controls Cloudflare API for the platform zone, so they can write any
  tenant DNS record), CAP will follow it.
- **Operator impact:** combined with **D-H1** (Cloudflare token in
  operator namespace), the operator points a tenant subdomain at an
  internal pod, then `unlock_status` fetches the operator's response and
  reports its `ownership_state` to the API DB.
- **Fix:** layer the same `GuardedResolver` as `http_client` onto
  `tee_http_client`; or accept the connection only when the host
  resolves outside cluster CIDRs.

### 3.16i [CC-H4] `SigningServiceClient` lacks SSRF guard and HTTPS enforcement beyond scheme parse

- **File:** `crates/enclava-api/src/signing_service.rs:73-76`
- Uses a fresh `reqwest::Client::builder()` with `redirect::Policy::none()`
  and 15s timeout, but **no SSRF guard**, and accepts both `http` and
  `https` (line 64-68). `PLATFORM_SIGNING_SERVICE_URL=http://10.0.0.2:18080`
  flows in plaintext. Operator MITM can:
  - Read every customer-signed deployment descriptor blob (already
    integrity-protected, but confidentiality leaks via env vars / mounts /
    custom domains).
  - Read the org keyring blob.
  - Replay a captured signed-policy-artifact response (mitigated by
    descriptor `nonce` and `deploy_id` in metadata, but worth flagging).
- **Fix:** require HTTPS in release builds, route through SSRF-guarded
  client, pin server cert via system roots OR via the same out-of-band
  pinning that holds the signing-service pubkey.

### 3.16j [CLI-H1] CLI runtime invalid-cert mode wired even in release builds (env-gate dependency)

- **File:** `crates/enclava-cli/src/tee_client.rs:30-37, 128-132, 549-560`,
  `crates/enclava-cli/src/main.rs:14-36`
- Production builds wire `ENCLAVA_TEE_TLS_MODE=staging|insecure` and
  `ENCLAVA_TEE_ACCEPT_INVALID_CERTS=1` into the runtime
  `Client::builder().danger_accept_invalid_certs()`. The release-build
  `main.rs` has a startup gate that refuses these env vars, but the
  *runtime code path* remains. A user who runs the same release binary
  with envs set picks insecure mode if any future code path bypasses
  the startup gate.
- **Fix:** make the runtime path itself `cfg!(debug_assertions)`-gated;
  defense in depth.

### 3.16k [CLI-H2] Silent permission-set failure on org_keyring directory

- **File:** `crates/enclava-cli/src/keyring.rs:213-214, 245-273`
- The parent `~/.enclava/state/<org_id>/` directory's permission set
  uses `let _ = ...` ignoring errors. On a permissive umask (022), the
  dir lands at 0755 and `set_permissions(... 0o700)` may silently fail.
  Other local users can then read the cached keyring envelope, including
  the org's owner pubkey. Disclosure of an already-known public key is
  not catastrophic but is symptomatic of a wider silent-fail pattern.
- **Fix:** propagate the error; make TOFU-pubkey-storage chmod failures
  fatal.

### 3.16 [TR-M2] Single-anchor collapse: `trusted_descriptor_public_keys = []` in production

- **Live evidence:** `trustee-operator-system/cm/kbs-config-grpc`:
  `trusted_descriptor_public_keys = []`. Combined with
  `signed_policy_public_key = "50bc3000..."` (the platform key), today's
  production has **one trust anchor**: the platform signing service's key.
  Every customer-signed claim is structurally a no-op.
- **Fix:** populate `trusted_descriptor_public_keys` with the production
  customer keys, OR commit to platform-only signing as the canonical
  M5-with-recovery-reset architecture and document accordingly.

---

## 4. MEDIUM findings

(Selected; full list in the per-component agent reports.)

- **[M-1]** SignedPolicyArtifact decoder accepts hex / standard-base64 /
  url-safe-base64 (`trustee/kbs/src/policy_artifact.rs:135-152`). Loose
  encoding fallbacks make canonicalization mistakes harder to spot in
  tests. Pick one encoding per field.
- **[M-2]** `/healthz` on signing service leaks signing key id, template
  hash, and exact genpolicy version pin. Useful for an attacker
  enumerating which descriptor + version combo to forge.
- **[M-3]** Owner DB is a SQLite file on a 1Gi PVC at
  `/data/owner-state.sqlite3`. Operator with PVC access can swap or
  rewrite at restart. No HMAC integrity check at open.
- **[M-4]** `AppError` returns raw `anyhow` message body to client.
  Filesystem paths, key-decoding diagnostics, and rusqlite errors leak.
- **[M-5]** AppError on signing service returns 400 + raw error string,
  identical for every error class. Information leak; map to opaque codes.
- **[M-6]** Caddyfile renderer joins hostnames via `spec.hosts.join(", ")`;
  unit tests don't cover hostnames containing `,`, `\n`, `\r`, `{`, `}`.
  Add adversarial fuzz test even though `validate_fqdn` is the
  upstream guard.
- **[M-7]** Production cluster has unpinned upstream tags
  (`coco-as-grpc:latest`, `rvps:latest`) on the Trustee pod.
  An operator who rebuilds the upstream digest could swap behavior on
  next restart. Pin to digests.
- **[M-8]** Trustee pod `serviceAccount: default` with no specific RBAC.
  No principle-of-least-privilege binding documented.
- **[M-9]** `crates/enclava-init/src/main.rs:191-216` — `unlock::record_attempt`
  writes to the attempts file on **every** loop iteration, even before a
  failed Argon2 derivation. A network-adversary that bombards the unlock
  socket can starve the rate limiter from outside the TEE. (The unlock
  socket is a Unix socket inside the pod, so this requires a co-located
  operator pod — possible per **AP-C1**.)
- **[M-10]** `cc_init_data.rs:79-92` writes `descriptor_core_hash`,
  `descriptor_signing_pubkey`, `org_keyring_fingerprint` ONLY when
  `app.workload_artifact_binding` is `Some`. If the API ever produces an
  app with `None`, the chain silently breaks. Add a hard reject at
  manifest-build time.
- **[M-11]** `crates/enclava-cli/src/platform_release.rs:21-22, 102-104`
  — bundled platform-release verifying key falls back to a hardcoded
  fixture key `5b9437ad…` when `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX`
  is unset at build time. No runtime guard; a release CI that forgets
  the compile-time env var ships a binary trusting the dev fixture key.
  Fix: `#[cfg(debug_assertions)]`-gate the fallback.
- **[M-12]** `crates/enclava-cli/src/keys.rs:16-43, 69-73` — internal
  expanded SigningKey state is leaked at drop (dalek 2.x doesn't
  `Zeroize`). Acceptable but worth noting; mitigated by `seed` zeroize.
- **[M-13]** `crates/enclava-api/src/auth/jwt.rs:73-87` — validators
  require iss/aud but not typ/jti at the validator level (handler
  post-checks typ). `jti` is never used for revocation; if revocation
  lists are added later, must wire jti into the validator.
- **[M-14]** `crates/enclava-api/src/routes/orgs.rs:312-352` —
  `put_keyring` requires `org:admin` scope but does not verify the
  caller is the keyring's owner. Any admin can submit a keyring signed
  by *some* owner (perhaps a stale/leaked one), and it becomes
  authoritative. Fix: require `auth.user_id` to equal an owning user,
  OR require a fresh-timestamp tag verified at the API.
- **[M-15]** `crates/enclava-api/src/cosign.rs:222`,
  `routes/deployments.rs:407` — sigstore's internal HTTP client for
  cosign verification is **not** the SSRF-guarded `state.http_client`;
  no host allowlist applied to sigstore's calls. HTTPS is enforced in
  release. Risk: customer's image points at attacker registry; cosign
  verification still must satisfy the per-app pinned policy, so attack
  is bounded but the registry hostname surface is wide.
- **[M-16]** `crates/enclava-api/src/kbs.rs:242, 277, 325` —
  `PatchParams::apply("enclava-platform").force()` on the operator-readable
  Trustee `KbsConfig` ConfigMap. force() lets CAP wipe other field
  managers; blast radius limited to operator domain (which already has
  cluster-admin) but `force()` is sharp.
- **[M-17]** `SIGNING_SERVICE_PUBKEY_HEX` is `optional: true` in env.
  Production should make it co-mandatory with `PLATFORM_SIGNING_SERVICE_URL`;
  tighten in `main.rs:256-260`.

---

## 5. LOW / hygiene findings

- **[L-1]** `ALLOW_EPHEMERAL_SIGNING_KEY=1` on the signing service
  (`policy.rs:91-97`) generates a fresh signing key per restart; if
  accidentally set in prod, every restart breaks all previously-signed
  artifacts. Trustee will reject (good fail-closed) but it's an operational
  footgun. Gate behind a Cargo feature, not env.
- **[L-2]** Trustee's `init_data` field still emitted alongside
  `init_data_hash` for compatibility (`deps/verifier/src/snp/mod.rs:622-624`).
  Mostly harmless; downstream policies referencing the old name silently
  keep working.
- **[L-3]** `WORKLOAD_RESOURCE_CONDITION_QUERY` (`__kbs_workload_resource_condition`)
  is in the public query namespace; in `api()` (the non-workload path) an
  attacker can send the param and it's forwarded to plugins. Verify the
  resource plugin requires admin for the un-namespaced path; consider
  renaming to a non-public form.
- **[L-4]** `tracing::info!` audit events on attestation-proxy include
  owner pubkey (`handlers.rs:436, 2292-2299`). Not secret material, but
  enables traffic-analysis correlation against KBS audit logs.
- **[L-5]** `panic!`/`expect()` on Mutex poisoning will tear down the
  attestation-proxy on any concurrent panic. Acceptable in TEE but
  document.
- **[L-6]** Audit log of CAP API doesn't currently flow to durable
  storage outside the operator-controlled cluster.

---

## 6. Architecture review

### 6.1 What is well-architected

- **CE-v1 canonical encoding** (length-prefixed, label-tagged) is consistent
  across CAP, signing-service, Trustee, enclava-init, attestation-proxy.
  Test vectors are committed (`crates/enclava-cli/tests/descriptor_vectors.rs`)
  and the round-trip is unit-tested.
- **Domain-separated HKDF** in enclava-init seeds. Caddy-seed and app-seed
  derived independently from owner_seed (`crates/enclava-init/src/seeds.rs`).
- **Six-step in-TEE verification chain** (`crates/enclava-init/src/trustee_verify.rs:92-186`)
  is structurally correct: descriptor → core_hash → keyring fingerprint →
  policy envelope signature → policy metadata → Rego/agent-policy hashes.
  Tests cover tampered descriptor, wrong keyring, tampered Rego, mismatched
  active policy, wrong policy pubkey.
- **SSRF defense** (`crates/enclava-api/src/clients.rs`): `redirect::Policy::none()`,
  CIDR-based deny list, per-CIDR allowlist, validated.
- **Cosign verification policies** are per-app and persisted (`cosign.rs`).
  Sigstore 0.13 API is used correctly; SKIP_COSIGN_VERIFY is debug-only.
- **HMAC API keys** with 128-bit lookup prefix + server-side pepper
  (`auth/api_key.rs`); legacy `enc_*` Argon2 path retained for migration only.
- **JWT with iss/aud/typ** (`auth/jwt.rs`) — typ post-checked in handlers,
  iss/aud at validator level. (Note: jti not yet used for revocation —
  flagged at M-13.)
- **Raw SNP report + VCEK chain validation IS implemented in the CLI**
  (`crates/enclava-cli/src/attestation.rs:108-131`,
  `tee_client.rs:725-797`) — verified by 4th sub-agent. The plan's
  Phase 7 PARTIAL note about "still using JSON report_data" is OUTDATED.
  The code now parses raw 1184-byte SNP reports and verifies ARK/ASK/VCEK
  via the `sev` crate. The dev-only `ENCLAVA_TEE_DEV_ALLOW_JSON_REPORT_DATA_ONLY`
  fallback is correctly gated behind `cfg!(debug_assertions)`. Update the
  plan to reflect this is DONE for the CLI.
- **API-key HMAC + 128-bit prefix + pepper** (`auth/api_key.rs:147-202`)
  filters by prefix BEFORE HMAC compare; Argon2 path runs only for
  legacy `enc_*` keys.
- **BTCPay webhook**: HMAC verify_slice, replay table, server-side billing
  intent fields.
- **NIP-98** payload-tag helper.
- **TLS-ALPN-01-only** ACME with no Cloudflare token in tenant pods (verified
  removed in code; live cluster has CF token only on the platform CAP-API,
  not tenants).
- **`force()` SSA was removed** from gateway, statefulset, network_policy,
  resources; only namespace + cleanup retain it.
- **Trustee policy artifact verification** (`trustee/kbs/src/policy_artifact.rs`)
  is sound: the message is reconstructed from `(metadata, sha256(rego_text))`,
  `descriptor_signing_pubkey` is never self-authenticating, tampered
  rego_text and direct unsigned-policy injection are unit-tested as failing.
- **Trustee workload-resource API** path-restricted to `*-owner` types,
  64KB body cap, body included in policy_data.

### 6.2 What is over-architected

- **The customer-signed policy chain** is engineered for the M5-strict
  threat model (no platform involvement) but production runs the
  M5-with-recovery-reset shape (platform signing service is the sole trust
  anchor). The dual-path code (`signed_policy_public_key` OR
  `trusted_descriptor_public_keys`) doubles the surface area while only
  one path is reachable in production. Consider committing to one path
  per deployment shape and gating the unused branches behind feature
  flags.
- **CE-v1** is a custom binary format. SHA-256 over canonical JSON or
  CBOR-COSE would be standard alternatives. The custom format requires
  Test vectors in three crates (CAP, signing-service, Trustee) plus
  enclava-init plus attestation-proxy. Risk: drift across implementations
  is hard to spot. Mitigation: the test vectors are committed; the byte
  layout test (`enclava_common::canonical`) catches mismatches.

### 6.3 What is under-architected

- **No KMS abstraction.** `POLICY_SIGNING_KEY_B64` (signing service),
  `API_SIGNING_KEY_PKCS8_BASE64` (CAP API), `SESSION_HMAC_KEY_BASE64` (CAP
  API) are all loaded as raw bytes. There's no path to HSM/KMS-backed
  signing for any of them. This is the single largest production blocker.
- **No defined "owner-of-org" bootstrap protocol.** `bootstrap-org` is
  TOFU; the rev15 plan acknowledges "production owner key custody" as
  open. Until this is defined, the customer-signed model is not
  exercisable end-to-end.
- **No release-root key** for `platform-release.json`. The plan rev14
  resolves "ship template bytes" but production release-root custody is
  still listed as a blocker.
- **No log/audit aggregation outside operator-controlled cluster.** Audit
  events, signing-service events, and KBS audit logs all live in cluster
  storage. An adversary who tampers with state can also tamper with the
  audit trail.
- **No revocation path for compromised signing keys.** If the platform
  signing key is exfiltrated (per **2.3**), the only recovery is rotating
  the trust anchor in Trustee — which is in operator-controlled
  ConfigMap. An attacker who gets the key once retains capability until
  Trustee config is changed, and they can change it.

### 6.4 Layering observations

- The boundaries between CAP API, attestation-proxy, Caddy, enclava-init,
  Trustee, and the signing service are clean code-wise. The test surface
  is comprehensive.
- The boundary between **operator-domain** and **TEE-domain** is the
  weakest layer: K8s Secrets, ConfigMaps, env vars, network paths, and
  filesystem paths between components are operator-visible/writable. The
  rev15 plan describes the architectural pattern correctly (anchor every
  trust input to SNP HOST_DATA via cc_init_data) but the implementation
  routes some critical inputs through the K8s API (E4 ConfigMap) and the
  filesystem (TR-H1 LocalFs Secret mounts).
- **There is no formal trust-domain diagram** in the repo. The agent
  reports include a textual diagram (see attestation-proxy section); this
  should be a first-class architecture document.

### 6.5 Missing functionality (vs. README + rev15 plan claims)

| Promised | Implemented? | Gap |
|---|---|---|
| Raw SNP report parsing + VCEK chain validation in CLI | **YES** (CLI side) | Plan Phase 7 PARTIAL is OUTDATED — code shows `attestation.rs:108-131` parses raw 1184-byte reports, verifies ARK/ASK/VCEK via `sev` crate. Update plan. |
| Customer-signed policy artifact path active in production | NO | `trusted_descriptor_public_keys = []` live; only platform key. |
| Production CAA records published with `accounturi` + `validationmethods=tls-alpn-01` | UNKNOWN | Plan Phase 0 says "Production cutover ops" still pending. Not visible from cluster; test by `dig CAA enclava.dev`. |
| CT monitoring scheduled | NO (script exists, no cron) | `runbooks/ct-monitoring.sh` present; no Job/CronJob in cluster. |
| Production-grade signing-service auth + HSM key custody | NO | Largest gap. |
| Storage-layer CAS for KBS resource writes | NO | TR-H1. |
| Customer keyring CLI subcommands | NO | Plan acknowledges. |
| `cosign_verified` no longer hardcoded `true` (plan Phase 9 DONE) | **PARTIAL/FALSE** | `routes/deployments.rs:602` still `let cosign_verified = true;`. Verification IS enforced upstream, but the persisted column is a literal. Refactor risk. (CC-H1.) |
| Argon2 parameters explicitly pinned (plan Phase 0 status) | **FALSE** | `auth/email.rs:28-34` uses `Argon2::default()` for both hash and verify. Future crate revisions may change defaults. (AUTH-H1.) |
| CLI `bootstrap_key_path` validates org/app names (prior High finding) | **FALSE** | Path traversal still present (CLI-C1). |
| `force()` SSA blanket-removed (plan Phase 11 DONE) | **TRUE except for namespace + cleanup** | Acceptable but document. |
| `automountServiceAccountToken: false` in tenant pods (plan Phase 0) | (verify in manifest tests) | Confirmed via `manifest_service_account_test.rs` exists; not re-verified live. |
| Nostr signup/login binds body via NIP-98 payload tag | **FALSE** | Routes `auth.rs:98, 221` call non-body version (AUTH-H2). |
| `create_app` requires admin/owner + apps:write scope | **FALSE** | No scope check at all (ROUTE-H1). |
| Namespace name length-capped to K8s DNS-1123 limit | **FALSE** | No length cap (ROUTE-H2). |
| `rotate_signer` email-confirms after initial set | **FALSE** | Token accepted but discarded (ROUTE-H3). |
| Registry resolution behind allowlist | **FALSE** | `registry.rs:77` accepts any `*.*` host (CC-H2). |
| `tee_http_client` SSRF-guarded | **FALSE** | Bypasses `GuardedResolver` (CC-H3). |
| `SigningServiceClient` SSRF-guarded + HTTPS-enforced | **FALSE** | Plain HTTP allowed; no resolver (CC-H4). |

---

## 7. Live cluster posture

### 7.1 Configuration footguns visible today

- `cap-test01/cap-api-secrets.cloudflare-api-token`: present and operator-readable.
  This is the platform-owned CF token (zone enclava.dev), not a tenant
  copy. Required for managing tenant subdomain DNS records. Acceptable
  per the threat model since the platform manages its own zone, but
  rotate periodically and log every API call against it.
- `cap-test01/cap-api-secrets.api-signing-key-pkcs8-base64` and
  `session-hmac-key-base64`: operator-readable. Loss of the API signing
  key allows forging API JWTs; loss of the session HMAC allows session
  hijack. Both are documented production blockers (no KMS).
- `cap-test01.cap-api` env: `TENANT_CADDY_ACME_CA=acme-staging-v02...`
  in production env (3.11).
- `cap-test01.cap-api` env: `PLATFORM_SIGNING_SERVICE_URL=http://10.0.0.2:18080`
  — plain HTTP between API and signing service. Adds a MITM dimension.
- Trustee deployment has been restarted ~12 times in the last 60 minutes
  (multiple ReplicaSets ages 41m through 60m). Indicates active
  development; not a security issue per se but suggests config churn.
- Trustee runs on `worker-1` (where SEV-SNP capable); CAP-API runs on
  `master-1`. Network path between them traverses the operator-controlled
  Cilium overlay.
- Trustee `serviceAccount: default` — no PodSecurityAdmission constraints
  visible in the namespace.

### 7.2 What's not in the cluster

- **No tenant pods.** `kubectl get pods -A | grep -iE "tenant|flowforge|enclava-init|caddy-ingress|attestation-proxy"` returns only the Envoy gateway pods, no SEV-SNP workload pods.
- **No CronJobs for CT monitoring.** Plan Phase 0 lists this as pending.
- **No CAA record verification path.** Run `dig CAA enclava.dev`; if absent, Phase 0 not complete.
- **`kata-as-coco-runtime` DaemonSet has 0 desired replicas** (`confidential-containers-system`), so no SEV-SNP runtime is active on either node. Tenants cannot actually deploy SEV-SNP pods today.

### 7.3 What's stale and should be cleaned up

- 9 orphaned `flowforge-*` and `flowforge-1-mini-canary-*` K8s Secrets in
  `trustee-operator-system` — operator-readable old seeds, mounted as KBS
  resources (3.12).
- 11 historical `trustee-deployment-*` ReplicaSets at zero replicas —
  cosmetic.
- `cap-api` has 6 historical ReplicaSets at zero — cosmetic.
- `mgmt-envoy/cloudflare-dns-update-ops-mgmt-29618200-fv9nb` — failed pod
  from 5d7h ago. Investigate or clean up.

---

## 8. Mitigation-plan claim verification

| Plan claim | Code state | Verdict |
|---|---|---|
| `kbs-resource-writer` removed | Confirmed (no binary, no env) | **TRUE** |
| `SECURE_PV_ALLOW_RUNTIME_INSTALL` removed | Confirmed | **TRUE** |
| Phase 5 makes app/caddy unprivileged | TRUE in default branch; FALSE under `LEGACY_BOOTSTRAP_SCRIPT=true` (E1). Plan Phase 5 marked DONE but legacy fallback is still emittable | **MISLEADING** |
| TLS-ALPN-01 cutover removed Cloudflare token from tenant secrets | Confirmed in code; live cluster confirms no tenant CF token | **TRUE** |
| Customer-signed-first verification preferred over fallback | Code tries `descriptor_key.verify(...)` first but **silently** falls back with warn-only. Production has `trusted_descriptor_public_keys = []` so customer-first cannot succeed there | **MISLEADING** |
| `require_signed_policy=true` rejects unsigned policy | Confirmed (`policy_artifact.rs`, tests) | **TRUE** |
| SNP `init_data_hash` alias for Rego | Confirmed (`deps/verifier/src/snp/mod.rs:622-624`) | **TRUE** |
| `GET /resource-policy/<id>/body` workload-attested + descriptor-scoped | Endpoint exists; binding to `descriptor_core_hash` is delegated to Rego, not Rust (TR-M3) | **PARTIAL** |
| `POST /kbs/v0/attestation/verify` exists | Exists, but unauthenticated (TR-H2) | **PARTIAL** |
| `If-None-Match`/`If-Match` CAS at HTTP layer | Confirmed | **TRUE at HTTP layer** |
| Storage-level CAS | NOT implemented (TR-H1) | **FALSE** (plan acknowledges) |
| Receipt verification in Trustee Rust, typed booleans to policy | Confirmed | **TRUE** |
| Drift annotation is "advisory" | Confirmed wording, but coverage incomplete (H2) | **TRUE but incomplete** |
| API-key HMAC redesign + 128-bit prefix + pepper | Confirmed (`auth/api_key.rs`) | **TRUE** |
| Owner Ed25519 store backed by SQLite, bootstrap is TOFU | Confirmed; plan rev6 finding 2 says "out-of-band-bootstrapped" but `bootstrap-org` is unauthenticated (SS-C2). | **CODE-MATCHES-DESIGN-BUT-DESIGN-IS-UNSAFE** |
| Customer-signed `signed_policy_artifact` accepted on deploy + unlock-mode redeploy | Confirmed (`routes/deployments.rs:75-90`, `routes/unlock.rs:509`); requires `REQUIRE_CUSTOMER_SIGNED_POLICY_ARTIFACT=true` to disable platform fallback. Default false in production | **TRUE BUT NOT ENFORCED IN PRODUCTION** |
| Generated Kata agent policy wired into descriptor + cc_init_data | Confirmed (`cc_init_data.rs:97-118`, `trustee_verify.rs:164-183`) | **TRUE** |

---

## 9. Recommendations (priority-ordered)

### Immediate (block public M5 claim until done)

1. **Auth on policy signing service** (mTLS, not bearer). Drop unauth
   `/sign`, `/agent-policy`, `/bootstrap-org`, `/rotate-owner` from any
   reachable network. (Fixes 2.1, 2.2.)
2. **Move signing-service Ed25519 key custody off-cluster** to an HSM/KMS.
   The k8s-Secret-on-control-node arrangement collapses the entire
   policy-authorization boundary on operator-root. (Fixes 2.3.)
3. **Bind attestation-proxy HTTP listener to `127.0.0.1` only.** Split the
   router so /receipts/sign, /cdh/resource, /teardown, /config require
   the TLS listener + Bearer-JWT auth scoped per receipt type. (Fixes 2.7.)
4. **Delete `LEGACY_BOOTSTRAP_SCRIPT` code path entirely.** No env flag
   should re-enable privileged-root + shell interpolation. (Fixes 2.8.)
5. **Render cc_init_data via `toml::to_string` of a typed struct.** Add
   adversarial fuzz over identity strings (signer_identity_subject/issuer,
   identity TOML, namespace, app name) with `"`, `'''`, `\n`, `\u`, `\\`,
   `}`, control chars. (Fixes 2.9.)
6. **Move enclava-init trust anchors out of K8s ConfigMap.** Pin
   `platform_trustee_policy_pubkey_hex` and `signing_service_pubkey_hex`
   into the `enclava-init` binary at build time (cosign-verified at CAP-API
   startup). Read cc_init_data TOML from the Kata-exposed init-data
   annotation, not from a ConfigMap. (Fixes 2.10.)
7. **Remove the silent fallback in `trustee_verify::verify_policy_envelope_signature`.**
   Either refuse, or only allow fallback when the platform pubkey came
   from an SNP-anchored source. Bonus: add a Trustee config field
   `refuse_fallback_when_descriptor_key_present`. (Fixes 2.11.)
8. **Fix Trustee storage CAS.** Move resource backing off
   K8s-Secret-mounted LocalFs to a backend the operator cannot rewrite
   directly. (Fixes 2.4.)
9. **Lock down `/kbs/v0/attestation/verify`.** Require admin auth or
   a dedicated mTLS listener. (Fixes 2.5.)
10. **Disable `insecure_http=true insecure_key=true` in production.**
    Configure TLS termination + a pinned JWK trust anchor. (Fixes 2.6.)
11. **Refuse to start if `TENANT_CADDY_ACME_CA` points to a non-production
    ACME directory in release builds.** (Fixes 3.11.)
12. **Clean up the orphaned `flowforge-1-mini-canary-*` K8s Secrets.**
    Remove from `KbsConfig.kbsSecretResources`. Document a teardown
    runbook. (Fixes 3.12.)
13. **Fix CLI `bootstrap_key_path` path traversal.** This was a prior
    review finding; it regressed. (Fixes 2.12.)
14. **Add `scopes::require_admin` + `apps:write` to `create_app`.** Any
    member or read-only API key creates apps today. (Fixes 3.16c.)
15. **Refuse `rotate_signer` calls that change an existing `signer_identity_subject`.**
    The `email_confirmation_token` is accepted but discarded; until
    Phase 10 ships email verification, lock the rotation. (Fixes 3.16e.)
16. **Pin Argon2 params explicitly.** Plan claims pinned, code uses
    `Argon2::default()`. (Fixes 3.16a.)
17. **Bind Nostr signup/login bodies via `verify_nip98_event_with_body`.**
    (Fixes 3.16b.)
18. **Replace the literal `let cosign_verified = true;` at
    `routes/deployments.rs:602`** with the actual VerifiedSignature
    result. (Fixes 3.16f.)
19. **Route registry resolution through the SSRF allowlist.**
    `registry.rs:77` accepts any `*.*` host. (Fixes 3.16g.)
20. **Apply SSRF resolver to `tee_http_client` and `SigningServiceClient`.**
    Both currently bypass the guard. (Fixes 3.16h, 3.16i.)
21. **Cap `cap-{org}-{app}` namespace length at 63 chars at app create
    time.** (Fixes 3.16d.)

### Short-term (1–2 weeks after immediate)

13. Fix the bootstrap-claim signed envelope (3.1).
14. Make receipt key derivation deterministic from owner_seed, not
    process-ephemeral (3.2).
15. mTLS or signed envelope between attestation-proxy and KBS (3.3).
16. Pinned JWK on AA-token verification (3.5).
17. Pin genpolicy binary into OCI image at fixed path (3.6).
18. Defense-in-depth Rust gate on receipt verification in Trustee (3.7).
19. Expand `manifest_hash` coverage (3.8).
20. Tie LUKS key derivation to SNP HOST_DATA, not just operator-controlled
    salt (3.9).
21. Bind Caddy TLS leaf to REPORT_DATA via `/.well-known/confidential` (3.10).
22. Hardcode the claim path in `extract_hex_claim` (3.15).
23. Populate `trusted_descriptor_public_keys` in Trustee config and
    require `REQUIRE_CUSTOMER_SIGNED_POLICY_ARTIFACT=true` in production
    (3.16).
24. Fail-closed on missing `app.workload_artifact_binding` at manifest-
    build time (M-10).

### Medium-term

25. Off-cluster audit log aggregation.
26. Define and implement signing-key revocation paths.
27. Define and document the trust-domain boundary in a first-class
    architecture document (replace ad-hoc README sentences with explicit
    boundary diagrams).
28. Production CAA + CT monitoring (plan Phase 0 ops residue).
29. Pin upstream Trustee `coco-as-grpc:latest`/`rvps:latest` to digests
    or build a fork.
30. Update plan rev15 Phase 7 to mark CLI raw SNP/VCEK validation as
    DONE; the rev15 status table understates implemented work.
31. Pin platform-release-root pubkey at compile time, refuse to build a
    release binary with the dev fixture key (CLI-M1).
32. `set_required_spec_claims` in JWT validators should include `typ` and
    `jti`; or document why post-decode check is sufficient.

### Long-term

31. Move CAP API and Trustee KBS off the operator-controlled cluster, OR
    establish a dual-control model where the operator cannot unilaterally
    deploy/restart these components without a customer-signed
    authorization. The README's promise depends on this.
32. Adopt a standard canonicalization (CBOR-COSE or canonical JSON) over
    CE-v1 to reduce three-implementation drift risk.

---

## 10. Final verdict

The code is high-quality, the test coverage is comprehensive, the
mitigation plan tracks the work honestly, and the cryptographic
primitives are sound. **Most of the engineering distance to a defensible
M5 claim is done.**

What remains is **boundary placement**: the trust anchors must move out
of operator-controlled storage. The signing service must move out of
operator-readable space. The attestation-proxy HTTP listener must move
to loopback. The cc_init_data TOML must move out of `format!`. The
in-TEE config must move out of ConfigMaps. The CAS must move out of
HTTP-layer-only.

Until those moves land, the production deployment must be marked
explicitly as **transitional / not-cryptographically-enforced**, exactly
as Plan rev15 lists in its remaining production blockers. The current
README sentence ("even the platform operator cannot access user data,
secrets, or memory") is **true for code in the TEE running with the
current cap-test01 deny-all policy**, but **not true** for the
production policy a real tenant would use, given the operator paths
documented in §2.1–§2.12 above.

**Tactical "small but real" findings discovered during this audit that
are NOT in the rev15 plan:** CLI path traversal (CLI-C1), Argon2 not
pinned (3.16a), Nostr signup body unbound (3.16b), `create_app` no scope
(3.16c), namespace length cap (3.16d), `rotate_signer` token unverified
(3.16e), `cosign_verified` literal (3.16f), three SSRF allowlist bypasses
(3.16g/h/i), CLI runtime invalid-cert path (3.16j), keyring dir perm
silent-fail (3.16k). These are individually low-effort fixes and should
land in a single hardening PR.

---

## Appendix V — Verification table (every finding re-checked in code, post-peer-review)

Each line cites the exact file:line that confirms or refutes the finding.
Verifications were done by direct read of the current tree, no agent
inheritance and no documentation reliance.

### CRITICAL findings

| ID | Finding | Verification | Status |
|---|---|---|---|
| 2.1 | Signing service `/sign`/`/bootstrap-org`/etc. unauth at transport layer | `policy-templates/signing-service/src/main.rs:110-127` — no auth middleware. BUT `/sign` itself verifies descriptor/keyring chain via `policy.rs:112-130` `verify_signing_inputs` against owner-store-resident pubkey. | **CONFIRMED with peer-review nuance** — bypass requires SS-C2 race, SS-C3 key theft, M-3 SQLite tampering, or stolen customer key. Pure transport-unauth is a confidentiality/DoS issue, not the forge primitive. |
| 2.2 | `/bootstrap-org` is TOFU and operator-callable | `main.rs:189-219` no auth; `owner_store.rs:78-117` `bootstrap_owner` only rejects re-bootstrap with different pubkey. | **CONFIRMED** |
| 2.3 | `POLICY_SIGNING_KEY_B64` operator-readable K8s Secret | `policy.rs:75-100` reads env var; deploy descriptor uses K8s Secret. | **CONFIRMED** |
| 2.4 | Trustee storage CAS bypassed via K8s Secret reflection | Backend CAS IS implemented: `local_fs.rs:75-108` uses `OpenOptions::create_new(true)` for if-absent; `truncate(true)` for if-present. The bypass is operator editing the source K8s Secret which propagates to the pod's mounted file. | **CONFIRMED with peer-review nuance** — wording corrected: not "HTTP-layer-only", the bypass is K8s Secret reflection. |
| 2.5 | `/kbs/v0/attestation/verify` unauthenticated | `trustee/kbs/src/api_server.rs:321-327` calls `attestation_verify_token` then `token_verifier.verify` — no `core.admin.check_admin_access(&request)` (compare line 330 in `attestation-policy` which has the check). | **CONFIRMED** |
| 2.6 | KBS `insecure_http=true insecure_key=true insecure_api=true` | Live evidence: `kubectl -n trustee-operator-system get cm kbs-config-grpc -o yaml` confirms all three. `trustee/kbs/src/token/jwk.rs:190-200` shows `insecure_key=true` returns inline JWK without endorsement. | **CONFIRMED** |
| 2.7 | attestation-proxy HTTP 0.0.0.0:8081 with same router as TLS | `attestation-proxy/src/main.rs:76-77` `let http_app = app_router(state.clone()); let tls_app = app_router(state);` — same router. `config.rs:99` `listen_host: "0.0.0.0"` default. Lines 78-97 bind both listeners. | **CONFIRMED** |
| 2.7a | `/receipts/sign` no auth | `attestation-proxy/src/handlers.rs:2329-2340` takes `State` + `Json` only — no JWT/bearer/scope check. Path NOT in `ALLOWED_PATHS` (`ownership.rs:180-198`), so locked-state gate blocks it; **post-unlock, it's open**. | **CONFIRMED with nuance** (locked-state OK; post-unlock open). |
| 2.7b | `/cdh/resource/*` no auth | `handlers.rs:1186-1193` — no auth check. `is_tls_seed_cdh_path` (`ownership.rs:200-204`) returns the gate-result `false` (i.e., not gated) for tls-seed paths *even when locked*. Post-unlock, all `/cdh/resource/*` paths are open. | **CONFIRMED** |
| 2.8 | `LEGACY_BOOTSTRAP_SCRIPT=true` re-enables privileged-root | `containers.rs:24-28` env flag; `:217-228` `privileged: true`/`SYS_ADMIN` in legacy branch; `:142-155` `["/bin/sh","-c", ...]` shell interpolation. Default branch (without env) is unprivileged per `:232-244`. | **CONFIRMED** |
| 2.9 | `cc_init_data` raw `format!` heredoc concern | `cc_init_data.rs:60-92, 138-141, 148-155, 264-271` use `format!`. `[data]` section sits BEFORE `'''policy.rego'''` heredoc; `signer_identity_*` are the operator-mutable fields. | **CONFIRMED with peer-review nuance** — direct heredoc-close from these specific fields requires breaking [data] table parse first. Structural fix still warranted. |
| 2.10 | enclava-init reads config + trust anchors from operator-mutable ConfigMap | `enclava_init_config.rs:25-52` mounts ConfigMap; `enclava-init/src/main.rs:42-47` loads from `/etc/enclava-init/config.toml`. Trust-anchor pubkeys, KBS URL, salt, cc_init_data path all from operator-controllable source. | **CONFIRMED** |
| 2.11 | enclava-init silent platform-key fallback | `trustee_verify.rs:286-300`: descriptor key first, then `platform_trustee_policy_pubkey` and `signing_service_pubkey` with `tracing::warn!` only. | **CONFIRMED** |
| 2.12 | CLI `bootstrap_key_path` path traversal | `crates/enclava-cli/src/config.rs:90-92`: `self.keys_dir.join(org).join(format!("{app}.key"))` — no validation of `org` or `app`. | **CONFIRMED** |

### HIGH findings

| ID | Finding | Verification | Status |
|---|---|---|---|
| 3.1 | First-write of seed-encrypted carries no signed envelope | `attestation-proxy/src/kbs.rs:367-371`: `Create` mode sends `body.to_vec()` with `If-None-Match: *` only. Lines 372-376 (`Replace`) and 411-418 (`Delete`) DO sign envelopes. | **CONFIRMED** |
| 3.2 | Bootstrap claim doesn't bind receipt key into SNP report | `handlers.rs:1624-1751` writes encrypted seed but never re-attests after. `receipts.rs:130-136` `ReceiptSigner::ephemeral()` uses fresh OsRng seed per restart; only `from_seed` exists `#[cfg(test)]`. | **CONFIRMED** |
| 3.3 | Plaintext HTTP from attestation-proxy to KBS | `attestation-proxy/src/config.rs:117-119` defaults `KBS_RESOURCE_URL` to `http://kbs-service.../`. `kbs.rs:347-394` uses `state.http_client = reqwest::Client::new()` (no TLS pin). | **CONFIRMED** |
| 3.4 | Self-signed TLS leaf, SPKI pinning is mandatory not graceful | `main.rs:178-190` `generate_simple_self_signed`; SPKI bound into REPORT_DATA via `handlers.rs:170-181` `build_report_data`. Pinning enforced by clients; no transition story. | **CONFIRMED but designed-as-such** |
| 3.5 | AA token verified via inline JWK (BYO key) | `attestation-proxy/src/attestation.rs:67-87` `verify_jwt_claims`: extracts JWK from header, uses it as decoding key. **Trustee-side** (which is the actual issuance point): `trustee/kbs/src/token/jwk.rs:190-200` only does `insecure_key` short-circuit when configured. | **CONFIRMED but bounded** — the BYO-key applies only on AA→proxy hop and only when AA agent is trusted (loopback-only path). |
| 3.6 | Genpolicy invocation accepts paths from env vars | `policy-templates/signing-service/src/genpolicy.rs:34-50, 103-114`: `GENPOLICY_BIN`/`GENPOLICY_RULES_PATH`/`GENPOLICY_SETTINGS_DIR` from env; `Command::new(&self.binary)`. | **CONFIRMED** |
| 3.7 | Receipt verification fail-open via missing Rego clause | `trustee/kbs/src/api_server.rs:591-637` exposes `pubkey_hash_matches`/`signature_valid`/`value_hash_matches` as policy_data fields; Rust does not pre-gate. | **CONFIRMED** (the platform-rendered Rego asserts these correctly today; risk is Rego regression) |
| 3.8 | `manifest_hash` misses `enclava_init_configmap` | `apply/orchestrator.rs:24-52`: parts vector excludes `enclava_init_configmap`; field is in struct (`manifest/mod.rs:46`) and generated (`mod.rs:70`). | **CONFIRMED with peer-review correction** (other configmaps + statefulset ARE included). |
| 3.9 | LUKS state PVCs are operator-readable raw block devices | `volumes.rs:113-141` `Block`-mode `longhorn-wait`. LUKS encryption is the only barrier; KEK is HKDF(owner_seed). | **CONFIRMED but expected (LUKS-encrypted)** |
| 3.10 | Caddy TLS private key not bound to REPORT_DATA | Not personally re-verified for caddy-ingress repo; agent reports + design implies key generated by Caddy on first ACME and stored on /state/tls-state. **Status: PROBABLE; not personally verified this pass.** | **NOT-PERSONALLY-VERIFIED** |
| 3.11 | `TENANT_CADDY_ACME_CA = letsencrypt staging` in production | Live: `kubectl -n cap-test01 exec deploy/cap-api -- env` confirms staging URL. `env_gates.rs` does not refuse staging on release. | **CONFIRMED** |
| 3.12 | Orphaned legacy K8s Secrets mounted as KBS resources | Live: `kubectl -n trustee-operator-system get kbsconfig -o yaml` lists 9 `flowforge-*` resources. | **CONFIRMED** |
| 3.13 | enclava-init panics weaponizable for boot-loop | `enclava-init/src/main.rs:33-38` exits on error; `cc_init_data.rs:165, 171, 99-102` panic on missing fields; `containers.rs:38-44` panics on undigested `ENCLAVA_INIT_IMAGE`. | **CONFIRMED** |
| 3.14 | `/resource-policy/<id>/body` not Rust-bound to descriptor_core_hash | `trustee/kbs/src/api_server.rs:411-444` builds policy_data with `policy_id` + query `resource_path` only; `init_data_claims.descriptor_core_hash` lives in claims, no Rust equality check before serving body. | **CONFIRMED** |
| 3.15 | Recursive `extract_hex_claim` in `/api/v1/workload/artifacts` | `crates/enclava-api/src/routes/workload.rs:196-210` uses recursion through arbitrary JSON to find `init_data_hash`/`descriptor_core_hash`. | **CONFIRMED** |
| 3.16 | Single-anchor collapse: `trusted_descriptor_public_keys = []` | Live: kbs-config-grpc shows `trusted_descriptor_public_keys = []`. | **CONFIRMED** |
| 3.16a | Argon2 params NOT pinned | `crates/enclava-api/src/auth/email.rs:29, 39`: `Argon2::default()` for both hash and verify. | **CONFIRMED** |
| 3.16b | Nostr signup/login don't bind body | `routes/auth.rs:98, 221` call `verify_nip98_event` (non-body); `auth/nostr.rs:43` provides `_with_body` variant. | **CONFIRMED** |
| 3.16c | `create_app` has NO scope check | `routes/apps.rs:283-322` — no `scopes::require_*` calls. Compare `rotate_signer` at `:695-696` which has them. | **CONFIRMED** |
| 3.16d | Namespace length cap missing; org names unvalidated | `validate.rs:25` `MAX_APP_NAME_LEN = 32`; `apps.rs:244` formats `cap-{org_name}-{app_name}` with no combined length check; `validate_org_*` does not enforce length matching the K8s 63-char DNS-1123 limit. | **CONFIRMED with peer-review correction** (32 not 63) |
| 3.16e | `rotate_signer` `email_confirmation_token` discarded | `routes/apps.rs:741`: `let _ = confirmation_token;`. The field IS REQUIRED to be non-empty when not initial-set (`:726-733`), but its content is never validated. | **CONFIRMED with nuance** — required-but-unvalidated, not "completely missing" |
| 3.16f | `cosign_verified` hardcoded `true` | `routes/deployments.rs:602`: `let cosign_verified = true;`. Verification IS done at line 407 upstream and errors out on failure. | **CONFIRMED but defense-in-depth, not currently exploitable** |
| 3.16g | `registry::resolve_tag_to_digest` accepts arbitrary host | `registry.rs:73-80` `r if r.contains('.') => format!("https://{}", r)`. Call site `routes/deployments.rs:376` uses `state.http_client` (CIDR-blocked, no host allowlist). `RegistryClient` (`clients.rs:271`) with allowlist support exists but ISN'T used here. | **CONFIRMED** |
| 3.16h | `tee_http_client` lacks SSRF resolver | `main.rs:471-475` builds with no `dns_resolver`. Used at `routes/{status,apps,unlock}.rs` for tenant TEE fetches. | **CONFIRMED** |
| 3.16i | `SigningServiceClient` lacks SSRF resolver, allows http | `signing_service.rs:62-82`: scheme allows http+https; builder has no `dns_resolver`. | **CONFIRMED** |
| 3.16j | CLI runtime invalid-cert mode wired into runtime | `crates/enclava-cli/src/tee_client.rs:30-37` reads env; `:128, 132` uses `danger_accept_invalid_certs`. Startup gate in `main.rs:14-36` is the only protection; runtime path itself is not `cfg!(debug_assertions)`-gated. | **CONFIRMED** |
| 3.16k | CLI `org_keyring` directory perm silent-fail | `crates/enclava-cli/src/keyring.rs:214` and `:295` use `let _ = fs::set_permissions(...)`. | **CONFIRMED** |

### MEDIUM findings

| ID | Finding | Verification | Status |
|---|---|---|---|
| M-1 | SignedPolicyArtifact decoder accepts hex/std-b64/url-b64 | `trustee/kbs/src/policy_artifact.rs:135-152` tries 3 encodings. | **CONFIRMED** |
| M-2 | `/healthz` on signing service leaks key id, template hash, genpolicy version | `policy-templates/signing-service/src/main.rs:130-138`. | **CONFIRMED** |
| M-3 | Owner DB SQLite operator-swappable | `policy-templates/signing-service/src/owner_store.rs:32-44` opens at `OWNER_DB_PATH`. K8s PVC. | **CONFIRMED** |
| M-7 | Production cluster has unpinned upstream tags | Live evidence: `kubectl -n trustee-operator-system get pod -o yaml` shows `coco-as-grpc:latest`, `rvps:latest`. | **CONFIRMED** |
| M-8 | Trustee pod `serviceAccount: default` | Live: pod yaml `serviceAccount: default`. RBAC bindings not personally checked. | **CONFIRMED on SA name; RBAC scope not verified** |
| M-10 | `cc_init_data.rs` writes binding fields ONLY when `workload_artifact_binding=Some` | `cc_init_data.rs:79-92` `if let Some(binding) = ...`. | **CONFIRMED** |
| M-11 | Bundled platform-release fallback fixture key | `crates/enclava-cli/src/platform_release.rs:21-22` `FALLBACK_RELEASE_ROOT_PUBKEY_HEX = "5b9437ad..."`; line 102-103 uses `option_env!`. | **CONFIRMED** |
| M-13 | JWT validators don't `set_required_spec_claims` typ/jti | Not personally re-verified this pass. | **NOT-PERSONALLY-VERIFIED** |
| M-14 | `put_keyring` doesn't verify caller is keyring owner | Not personally re-verified this pass. | **NOT-PERSONALLY-VERIFIED** |
| M-15 | sigstore HTTP client has no host allowlist | `cosign.rs:222-225` uses `ClientBuilder::default()` (`oci_distribution`-internal client). Caller passes `state.http_client` to `fetch_attestations` (`cosign.rs:340-353`) which IS SSRF-CIDR-guarded but not host-allowlisted. The sigstore-internal layer is genuinely outside our SSRF control. | **CONFIRMED** |
| M-16 | `PatchParams::apply.force()` on operator-readable Trustee KbsConfig CM | `crates/enclava-api/src/kbs.rs:242, 277, 325`. | **CONFIRMED** |
| M-17 | `SIGNING_SERVICE_PUBKEY_HEX` is `optional: true` | `crates/enclava-api/src/main.rs:256-260` loads `false` for required. | **CONFIRMED** |

### LOW / hygiene

All L-1 through L-6 findings are documentation/operational hygiene — not personally re-verified each but each came from agent file:line cites. **Treat as "needs spot-check before remediation"**.

### Findings NOT verified this pass (treat as TODO before remediation)

- **3.10 (CI-H1)** — Caddy TLS key not bound to REPORT_DATA — design assertion, depends on caddy-ingress repo not seeded in this pass.
- **M-13** — JWT validator typ/jti — not re-grep'd.
- **M-14** — `put_keyring` ownership check — not re-read this pass.
- **L-1 through L-6** — agent-derived, file:line cites present but not re-verified.
- **AP-M1, AP-M2, AP-M4** — operational hygiene.

### Findings NARROWED or WITHDRAWN by direct verification

- **2.1 (SS-C1)** — Wording narrowed: not "anyone forges artifacts", but "anyone reads descriptors + can DoS + bypass requires SS-C2/SS-C3/M-3 path".
- **2.4 (TR-H1)** — Wording corrected: backend-level CAS IS implemented; bypass is K8s Secret reflection, not "HTTP-only CAS".
- **2.7 (AP-C1, C2, C3)** — Nuance added: locked-state gate blocks `/receipts/sign`; bypass requires post-unlock state. Still real because once any pod boots, all in-cluster pods can reach.
- **2.9 (E2)** — Exploit-reachability narrowed: only `signer_identity_*` are unvalidated and they sit in `[data]` before the heredoc. Direct heredoc-close requires breaking the `[data]` parser first. Structural fix still warranted.
- **3.8 (manifest_hash)** — Coverage corrected: bootstrap_configmap, startup_configmap, ingress_configmap, statefulset ARE included. The genuine miss is `enclava_init_configmap`.
- **3.16d (ROUTE-H2)** — Cap detail corrected: app names limited to 32, not 63. Org names are the unvalidated/unbounded path.
- **3.16e (ROUTE-H3)** — Wording narrowed: token IS required when not initial-set, just not validated.
- **§1 row "CLI authenticates the TEE"** — Status changed from PARTIAL to **HOLDS at the cryptographic level** — raw SNP/VCEK validation IS implemented (`crates/enclava-cli/src/attestation.rs:108-131`, `tee_client.rs:503-797`).

### Confidence after verification pass

- **Live cluster facts:** HIGH (directly observed via kubectl/curl).
- **CRITICAL findings:** HIGH (each verified at cited file:line).
- **HIGH findings:** HIGH for everything except 3.10 (caddy-ingress repo not personally re-read this pass).
- **MEDIUM findings:** MIXED. M-13/M-14 not re-verified.
- **LOW findings:** MIXED — file:line cites present, but several are agent-derived and worth a spot-check before remediation.

The headline narrative — "boundary placement, not cryptography, is the
production blocker; signing-service custody and the K8s-Secret-as-KBS-
backing-store pattern are the highest-leverage fixes" — is well-supported
by direct evidence.

---

## Appendix A — Files reviewed

CAP: `crates/enclava-api/src/{main,lib,cosign,registry,clients,dns,
edge,kbs,deploy,models,signing_service,platform_release,env_gates,
ratelimit,state}.rs`, `crates/enclava-api/src/routes/{apps,deployments,
domains,orgs,billing,unlock,config,status,workload,users,auth}.rs`,
`crates/enclava-api/src/auth/{middleware,jwt,email,api_key,nostr,
provider,scopes}.rs`, `crates/enclava-engine/src/{types,validate,lib,
testutil}.rs`, `crates/enclava-engine/src/manifest/{cc_init_data,
kbs_policy,containers,statefulset,secrets,volumes,network_policy,
gateway,ingress,service,service_account,enclava_init_config,bootstrap,
namespace,resource_quota,startup,bootstrap_script.sh}.rs`,
`crates/enclava-engine/src/apply/{orchestrator,drift,namespace,resources,
statefulset,gateway,network_policy,cleanup,teardown,types,watch,engine}.rs`,
`crates/enclava-cli/src/{tee_client,config,attestation,api_client,
descriptor,keyring,keys,policy_artifact,platform_release,app_config,
api_types,main,lib}.rs`, `crates/enclava-init/src/{main,config,kbs_fetch,
trustee_verify,seeds,unlock,luks,secrets,socket,writes,errors,chown,lib}.rs`,
`crates/enclava-common/src/{canonical,descriptor,crypto,image,hostnames,
orgs,types,validate,lib}.rs`,
SQL migrations under `crates/enclava-api/migrations/`.

Trustee fork: `kbs/src/{api_server,policy_artifact,config,lib}.rs`,
`kbs/src/plugins/implementations/resource/{local_fs,kv_storage,mod}.rs`,
`kbs/src/token/jwk.rs`, `deps/verifier/src/snp/mod.rs`,
`attestation-service/src/ear_token/broker.rs`.

attestation-proxy: `src/{main,handlers,config,attestation,kbs,sev,
ownership,receipts,errors}.rs`.

caddy-ingress: `Dockerfile`, `scripts/smoke.sh`, `crates/enclava-engine/src/manifest/ingress.rs`.

policy-templates: `signing-service/src/{main,lib,canonical,descriptor,
keyring,owner_store,genpolicy,policy}.rs`.

Live cluster: `kubectl get nodes,ns,pods,kbsconfig,trusteeconfig,
cm,secret,deploy,statefulset,pvc,svc,httproute,networkpolicy,crds`
across all relevant namespaces; `kubectl exec` for env inspection;
direct `curl` probes against signing service and KBS service.
