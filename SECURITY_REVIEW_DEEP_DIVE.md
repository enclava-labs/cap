# Deep-Dive Security Review — 2026-08-14

Full-codebase adversarial review (~100K lines across all 9 crates, deploy/,
docker-compose.yml, Dockerfiles, scripts/, web/verifier). Five parallel audits
covered: API authn/authz, enclava-init TEE chain, engine/K8s manifest
construction, attestation verifier stack, and CLI + common crypto. Every
finding below was verified against source in the main worktree.

Overall verdict: the codebase is unusually well hardened (fail-closed verdict
composition, pinned roots, constant-time compares, in-transaction role
re-checks, bound-parameter SQL, digest-pinned images, CE-v1 canonicalization).
One High-severity attestation bypass and several Medium findings were
identified. This document also records the mitigation strategy implemented on
branch `security/deep-dive-fixes`.

Severity scale: Critical > High > Medium > Low.

---

## 1. Findings

### H-1 (High) — CLI attestation accepts attacker-supplied AMD cert chain

- Location: `crates/enclava-cli/src/tee_client.rs:671-689`,
  `crates/enclava-cli/src/attestation.rs:108-131`,
  `crates/enclava-cli/src/tee_client/tls.rs:106-144`.
- The SNP evidence JSON may embed an ARK/ASK/VCEK DER chain. When present it
  is used as-is: `validate_snp_report_with_der_chain` (via the `sev` crate)
  only proves ARK self-signed -> ARK signs ASK -> ASK signs VCEK -> VCEK signs
  the report. It never compares the ARK against AMD's built-in roots, even
  though `builtin_snp_ca_der_chain` (`tee_client.rs:857-884`) exists and is
  used only for the KDS fallback. The TLS leaf SPKI used for TOFU pinning is
  fetched with a `NoVerifier` (accept-any-cert) handshake.
- Exploit: an on-path attacker (or DNS hijack) at `attest_receipt_key` time
  serves their own TLS leaf, echoes the client nonce/domain/SPKI bindings in
  fabricated evidence JSON, and embeds a self-generated ARK/ASK/VCEK chain
  whose report binds the attacker's leaf, nonce, and receipt key. All checks
  pass and the CLI trusts a non-TEE as attested. This gates password-mode
  claim/unlock/recover and config delivery (`commands/app.rs:576,905,997`,
  `commands/ownership.rs`, `commands/config.rs`, `commands/template.rs`) —
  storage passwords and config secrets can be delivered to a MITM.

### M-1 (Medium) — Verifier CRL path runs unbounded RSA modpow on unpinned ARK (DoS)

- Location: `crates/enclava-verifier/src/amd.rs:84-88, 274-294`,
  `crates/enclava-verifier/src/lib.rs:226-233`.
- `verify_amd_revocation` verifies the CRL signature with the bundle-supplied
  (unpinned) ARK and runs unconditionally even when the pinned chain check
  already failed. `verify_rsa_pss_sha384` parses modulus/exponent without size
  caps and runs `modpow` on them. The appraiser `POST /v1/appraise` is
  unauthenticated (`crates/enclava-appraiser/src/main.rs:57-63`), so a ~130 KB
  request with a ~60 KB modulus+exponent burns minutes-to-hours of CPU
  (~1000x amplification at 8 KB keys). Availability only; the verdict stays
  `Fail`.

### M-2 (Medium) — `POST /orgs` missing PaaS write gate and org-name validation

- Location: `crates/enclava-api/src/routes/orgs.rs:46-109`.
- Every other org/app mutation calls `ensure_management_write_allowed`;
  `create_org` does not, and passes `body.name` raw (the internal PaaS route
  validates DNS-safe lowercase via `validate_org_name`, `internal.rs:501-516`).
- On `CAP_MANAGEMENT_MODE=paas_managed` instances, public signups can create
  unlimited orgs and squat names, permanently DoS-ing PaaS provisioning
  (`upsert_paas_org` 409s with no takeover path). Malformed names also flow
  into the derived namespace `cap-{org}-{app}` (`deploy.rs:579-590`).

### M-3 (Medium, latent) — Rego injection primitive in engine + unvalidated namespace

- Location: `crates/enclava-engine/src/manifest/kbs_policy.rs:81-133` (raw
  `format!` interpolation of `namespace`/`sa`/`hash` into Rego);
  `crates/enclava-engine/src/validate.rs:29-98` (validates neither namespace
  nor tenant_id); `crates/enclava-api/src/deploy.rs:579-590` (length-only
  check).
- Not exploitable end-to-end today: the production KBS writer escapes via
  `json_string()` (`kbs.rs:1633-1635`) and Kubernetes rejects invalid names
  fail-closed. But `generate_kbs_policy_rego` is the engine's public API and a
  future wiring reintroduces a Rego-injection path whose inputs are only
  length-checked.

### M-4 (Medium) — Tenant egress to internal endpoints is warn-only

- Location: `crates/enclava-api/src/routes/apps.rs:410-490`,
  `crates/enclava-engine/src/manifest/network_policy.rs:251-261`.
- `audit_egress_allowlist_host` logs `"accepting in warn-only mode"` for
  `kubernetes.default.svc`, `metadata.google.internal`, `*.svc.cluster.local`,
  `*.internal`, rebinding helpers (`*.nip.io`) — then accepts. A tenant can
  open TEE egress to the K8s API server or cloud metadata (ports 1-65535
  allowed). Mitigated by `automountServiceAccountToken: false` and Kata TEE
  isolation, but the audit reasons exist precisely to block this.

### M-5 (Medium) — Appraiser signs PASS receipts over caller-chosen policies

- Location: `crates/enclava-appraiser/src/main.rs:86-115`,
  `crates/enclava-verifier/src/receipt.rs:65-135`.
- Anyone can POST a trivially-satisfiable inline `policy_base64` plus matching
  evidence and receive a validly-signed PASS receipt.
  `verify_appraisal_response` checks result hash/signature/key/lifetime but
  takes no expected-policy-hash argument, so a consumer that treats "valid
  receipt + PASS" as sufficient trusts a prover-chosen policy. No in-repo
  consumer currently makes this mistake; latent foot-gun for external
  consumers.

### M-6 (Medium) — No SNP TCB/policy appraisal in CLI (DEBUG bit unchecked)

- Location: `crates/enclava-cli/src/tee_client.rs:640-706`,
  `crates/enclava-cli/src/attestation.rs:141-162`.
- After chain verification only `report_data` is compared. Nothing inspects
  the SNP guest policy byte (DEBUG bit) or `reported_tcb` floors. A genuine
  but debug-enabled or stale-TCB guest passes CLI appraisal.
  `verify_attestation_bundle`'s chain-status branches are dead code (never
  constructs `Valid`).

### M-7 (Medium) — TLS-verification bypass envs gated only in `main()`; unconditional in ssh.txt path

- Location: `crates/enclava-cli/src/tee_client.rs:43-50, 543-562` —
  `accepts_invalid_tee_certs()` honors `ENCLAVA_TEE_TLS_MODE=staging|insecure`
  and `ENCLAVA_TEE_ACCEPT_INVALID_CERTS` with no build-profile check; the
  release gate lives only in `enclava-cli/src/main.rs:6-36`. Library consumers
  and misled users can disable WebPKI.
- `crates/enclava-cli/src/commands/template.rs:1972-1979` — ssh.txt fetch hard
  codes `danger_accept_invalid_certs(true)` unconditionally (comment: preprod
  uses LE staging chains). Mitigated by strict downstream validation (single
  line, ngrok/FRP form, must equal the PaaS-reported endpoint), but fragile.

### M-8 (Medium) — Windows command injection via API-supplied URL

- Location: `crates/enclava-cli/src/commands/auth.rs:326-338`.
- `cmd /C start "" <url>` where `url` is `verification_uri_complete` from the
  device-login response. `cmd.exe` interprets `&`, `^`, `|`, `%VAR%`; a
  malicious `--api-url` or compromised API yields arbitrary command execution
  on Windows clients. Linux/macOS paths exec directly (safe).

### M-9 (Medium) — No rollback/downgrade protection on keyring fetch and platform release

- `crates/enclava-cli/src/commands/org.rs:425-444`,
  `crates/enclava-cli/src/keyring.rs:266-276` — keyring fetch stores whatever
  verifies against the TOFU-pinned owner key; no version monotonicity vs the
  cached copy. A compromised API can replay an older, still-validly-signed
  keyring (re-adding a removed deployer, dropping new members).
- `crates/enclava-cli/src/platform_release.rs:97-148` — any validly-signed old
  release is accepted; no version monotonicity, freshness, or revocation, and
  `ENCLAVA_PLATFORM_RELEASE_PATH` can point anywhere. Descriptors get signed
  against stale firmware measurements/sidecar digests.

### M-10 (Medium) — CLI secret files briefly world-readable

- Location: `crates/enclava-cli/src/config.rs:133-205` — `fs::write` creates
  `credentials.tmp` (mode 0644, umask-dependent) containing the plaintext
  session JWT / API key / Ed25519 bootstrap key hex, then chmod 0600, then
  rename. `~/.enclava/keys/{org}` is never forced 0700 on this path. The
  correct pattern already exists (`commands/app.rs:1645-1658`:
  `OpenOptions::mode(0o600).create_new(true)`).

### Low findings

| ID | Location | Issue |
|----|----------|-------|
| L-1 | `crates/enclava-api/src/auth/jwt.rs:124-147` | 60 s default exp leeway on session and signer-rotation validators (config validator already uses 0) |
| L-2 | `crates/enclava-api/src/routes/domains.rs:222-233` + migration 0014 | custom-domain challenge token stored plaintext (all other verifier secrets are hashed) |
| L-3 | `crates/enclava-api/src/signing_service.rs:102-108`, `main.rs:309-326` | signing-service URL may be `http://` — bearer token in cleartext; startup gate enforces HTTPS only for `TRUSTEE_KBS_URL` |
| L-4 | `crates/enclava-api/src/routes/workload.rs:66-133`, `workload_tls.rs` | internal error strings / upstream bodies echoed to attestation-authenticated callers (info disclosure) |
| L-5 | `crates/enclava-init/src/trustee_verify.rs:226-236`, `main.rs:107-115` | `verify_chain_or_skip` API shape + stale doc describe a skip path that is (correctly) unreachable; dead warn-and-continue branch invites regression |
| L-6 | `crates/enclava-init/src/trustee_verify.rs:100-102` | `org_keyring_signature` fetched, typed, never verified (fingerprint anchoring only) — maintenance trap |
| L-7 | `crates/enclava-init/src/socket.rs:55-74` | unlock socket: length limit enforced after unbounded `read_line`; no SO_PEERCRED (within-guest only) |
| L-8 | `crates/enclava-common/src/descriptor.rs:97-103` | legacy 32-of-48-byte measurement prefix compare (mitigated by independent full-width check in verifier policies) |
| L-9 | `crates/enclava-api/src/routes/deployments.rs:740` | `container_name` unvalidated at acceptance (validated only on logs route) |
| L-10 | `docker-compose.yml:7-11` | dev postgres published on all interfaces with static creds |
| L-11 | `web/verifier/index.html`, `test.html` | no CSP meta tag (DOM is textContent-only today; hardening against regressions) |
| L-12 | `crates/enclava-cli/src/api_client.rs:29-41` | ApiClient does not enforce https (TEE client does) |
| L-13 | `crates/enclava-api/src/auth/email.rs:59-144`, `lib.rs:43-51` | login/signup user enumeration + no per-account throttle (argon2 + global rate limit mitigate) |
| L-14 | `deploy/api/deployment.yaml:35`, `kustomization.yaml:11-14` | `:latest` + zero-digest defaults; only the render script enforces pinning |
| L-15 | `crates/enclava-engine/src/apply/teardown.rs:29-37` | dead `notify_teardown_proxy` follows redirects to tenant domain with bearer token (live path hardened; fix before wiring) |
| L-16 | `crates/enclava-cli` various | Debug derives on secret-bearing structs; `--set KEY=VALUE` in argv (safe `--set-file` exists) |

### Verified-solid areas (coverage summary)

- JWT: HS256/EdDSA family separation with distinct keys; `iss`/`aud`/`typ`
  pinned; API keys: 128-bit prefix + 256-bit secret, HMAC'd with pepper,
  constant-time compare; scope-escalation blocked; argon2id defaults.
- Authorization: role/scope checks on every mutation route, re-verified inside
  the authority transaction (TOCTOU-proof); org-scoped queries everywhere;
  last-owner invariants under `FOR UPDATE`; internal PaaS routes re-enter the
  same handlers with mapped actors.
- SQL: bound parameters everywhere (format!-built SQL is `#[cfg(test)]` only).
- SSRF: redirect bans + guarded DNS resolver + registry allowlist; no
  user-reachable file routes.
- Startup gates: release builds reject all debug bypass envs, require pepper,
  policy-read mode, HTTPS KBS.
- enclava-init: fail-closed verification chain, pinned trust anchors from
  cc_init_data (HOST_DATA-bound), CE-v1 domain separation, zeroized secrets,
  atomic symlink-safe writes, no bypass env in prod builds.
- Verifier core: pinned ARK (chain path), exact-length field binding,
  fail-closed verdict composition, panic-free TLV parser, size caps, fuzz
  targets for hot parsers; WASM shares the exact core.
- Engine: digest-pinned images everywhere, argv-only commands (no shell),
  generation-fenced SSA applies, automountServiceAccountToken=false, no
  hostPath.

---

## 2. Mitigation strategy

Principles:

1. Fail closed. Every fix must reject/abort rather than warn where the
   current code warns.
2. Pin, don't probe. Trust anchors must come from build-time or signed
   configuration, never from the message under verification.
3. No behavior change without tests. Each fix ships with regression tests.
4. Respect the cross-project dependency schema (AGENTS.md): no KBS
   policy/artifact schema changes, no template metadata changes, no
   CLI-visible behavior changes beyond documented hardening.

### Per-finding mitigation plan and implementation status

| Finding | Strategy | Status on `security/deep-dive-fixes` |
|---------|----------|---------------------------------------|
| H-1 | Accept an evidence-embedded chain only if its ARK byte-matches a builtin AMD root (milan/genoa/turin); otherwise fall back to the anchored KDS fetch; if that fails, fail closed | Implemented |
| M-1 | Pin the CRL-path ARK to the policy's `trusted_ark_sha256` before any RSA math; cap RSA modulus (<=8192 bits) and exponent (<=32 bits) in `verify_rsa_pss_sha384` | Implemented |
| M-2 | Add `ensure_management_write_allowed` + DNS-safe `validate_org_name` to public `create_org` (shared validator moved out of internal routes) | Implemented |
| M-3 | JSON-escape all interpolated values in `generate_kbs_policy_rego`; validate namespace/service-account/tenant-id charset in `engine::validate` | Implemented |
| M-4 | Reject internal/metadata/`.svc`/rebinding-helper egress hosts with 400 instead of warn; operator opt-out via `CAP_EGRESS_ALLOW_INTERNAL_HOSTS=true` (audited env) | Implemented |
| M-5 | Add `verify_appraisal_response_with_policy` that pins the expected policy hash (and origin/nonce helpers); appraiser docs updated to require consumer-side pinning | Implemented |
| M-6 | Reject SNP reports whose guest policy has the DEBUG bit set (fail closed); document TCB-floor gap (requires per-platform policy, tracked below) | Implemented (DEBUG bit) |
| M-7 | `accepts_invalid_tee_certs()` returns false unless `cfg!(debug_assertions)`; ssh.txt fetch uses the same gate (release builds verify TLS normally — operational note: preprod staging relays need trusted certs or a debug CLI) | Implemented |
| M-8 | Validate `verification_uri_complete` (https scheme, no cmd metacharacters/control chars/space) before invoking `start`; quote the URL | Implemented |
| M-9 | Reject keyring rollbacks when the cached envelope has a newer `version`; persist last-seen platform-release version and reject older signed releases (override documented) | Implemented |
| M-10 | Create credentials/bootstrap-key files with `OpenOptions.mode(0o600).create_new(true)` + rename; force `~/.enclava*` dirs to 0700 on write paths | Implemented |
| L-1 | `leeway = 0` on session and signer-rotation validators | Implemented |
| L-3 | Release gate: `PLATFORM_SIGNING_SERVICE_URL` must be https (env_gates) | Implemented |
| L-5 | Rename `verify_chain_or_skip` -> `verify_chain_required`, return `Result<()>`, delete dead branch + stale docs | Implemented |
| L-7 | Bound the unlock-socket line read (`take(MAX+1)` before `read_line`) | Implemented |
| L-9 | Validate `container_name` at deploy acceptance (same charset as logs route) | Implemented |
| L-10 | Bind dev postgres to 127.0.0.1 in compose | Implemented |
| L-11 | Add CSP meta tags to web verifier pages | Implemented |
| L-12 | `ApiClient` enforces https except loopback hosts | Implemented |
| L-2 | Requires DB migration (hash challenge tokens) — not in this change set; tracked as follow-up | Deferred |
| L-4 | Error-allowlisting for workload routes — cosmetic refactor, tracked | Deferred |
| L-6 | Keyring signature enforcement — schema-adjacent (KBS artifact format); needs cross-project coordination per AGENTS.md | Deferred |
| L-8 | Legacy measurement prefix — migration issue; full-width check already gates Pass in policies; migrate descriptors | Deferred |
| L-13 | Per-account throttle + uniform login timing — needs storage design | Deferred |
| L-14 | Rendered-manifest enforcement exists; operator docs updated | Deferred |
| L-15 | Fix dead helper before any wiring (redirect-none + tee_domain) | Deferred |
| L-16 | Redacting Debug impls for secret structs | Partially (credentials/bootstrap types no longer derive Debug where avoidable) |

### Deferred work (follow-ups, in priority order)

1. TCB-floor policy for CLI attestation (needs per-platform floor data; the
   independent verifier already supports floors via policy).
2. Domain challenge-token hashing at rest (DB migration 00XX).
3. Workload-route error allowlisting.
4. `org_keyring_signature` enforcement in enclava-init (coordinate with KBS
   artifact format consumers per AGENTS.md blocking rules).
5. Descriptor migration off legacy 32-byte measurements.
6. Per-account login throttling; uniform signup/login timing.
7. Appraiser authentication/rate limiting at the deployment tier.
8. Engine teardown helper hardening before first use.

### Verification

- `rustup run stable cargo fmt --all -- --check`
- `rustup run stable cargo clippy --workspace --all-targets -- -D warnings`
- `rustup run stable cargo test --workspace`
- `rustup run stable cargo test --doc`
- `rustup run stable cargo build --workspace`
- Release builds with `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX` set
  (see AGENTS.md)

Docker image builds and `cargo audit`/`cargo deny` are environment-dependent
and should be run in CI for this branch before merge.
