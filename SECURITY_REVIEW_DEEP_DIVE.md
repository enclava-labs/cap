# Deep-Dive Security Review — 2026-08-14 (rev 2, 2026-08-17)

Full-codebase adversarial review (~100K lines across all 9 crates, deploy/,
docker-compose.yml, Dockerfiles, scripts/, web/verifier). Five parallel audits
covered: API authn/authz, enclava-init TEE chain, engine/K8s manifest
construction, attestation verifier stack, and CLI + common crypto. Every
finding below was verified against source in the main worktree.

## Revision history

| Rev | Date | Scope | Basis |
|-----|------|-------|-------|
| 1 | 2026-08-14 | Initial deep-dive; fixes implemented on `security/deep-dive-fixes` (commit `07d6189`) | merge-base `a5e5fab2` |
| 2 | 2026-08-17 | Re-ran all v1 findings against merged main (`origin/main` `c7691b7`, incl. PR #86/#87 signing-authority rotation + GitOps migrations); audited all new code; recorded new findings | merge commit `a2f6309` + restore commit `197a045` |
| 3 | 2026-08-17 | Addressed N-1 (audited hatch + restored release↔runtime-class binding), N-2 (contract pinned at all touch points), N-3 (local `main` repaired) | `security/deep-dive-fixes` |

**Finding ID scheme:** v1 IDs keep their meaning forever. `H-1`, `M-n`, `L-n`
are v1 findings; each now carries a **Status (rev 2)** line. New rev-2
findings are `N-n`. A finding is only marked *Fixed* if the fix is present
and verified in the current worktree.

Overall verdict: the codebase is unusually well hardened (fail-closed verdict
composition, pinned roots, constant-time compares, in-transaction role
re-checks, bound-parameter SQL, digest-pinned images, CE-v1 canonicalization).
All v1 fixes shipped in `07d6189` survived the merge with main. Main's new
signing-authority rotation feature is defensively built (backup-first,
pin-only-accepted, lane-serialized, idempotent retries). One new Medium
finding (unaudited release-build escape hatch for the simulated CoCo runtime,
reintroduced by main) and two Low findings were identified.

Severity scale: Critical > High > Medium > Low.

---

## 1. Findings (v1)

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
- **Status (rev 2): Fixed — verified.** Evidence-embedded chains are accepted
  only when the ARK byte-matches a builtin AMD root (`ark_is_pinned_to_builtin_root`,
  `tee_client.rs:912-930`, pinning Milan/Genoa/Turin); otherwise the anchored
  KDS fetch runs and failure is closed (`tee_client.rs:684-698`).

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
- **Status (rev 2): Fixed — verified.** CRL path requires the policy-pinned
  ARK before any RSA math; `MAX_RSA_MODULUS_BITS = 8192` and exponent caps in
  `amd.rs:48-52`. Appraiser auth/rate limiting at the deployment tier remains
  deferred (follow-up 7).

### M-2 (Medium) — `POST /orgs` missing PaaS write gate and org-name validation

- Location: `crates/enclava-api/src/routes/orgs.rs:46-109`.
- Every other org/app mutation calls `ensure_management_write_allowed`;
  `create_org` did not, and passed `body.name` raw (the internal PaaS route
  validates DNS-safe lowercase via `validate_org_name`, `internal.rs:501-516`).
- On `CAP_MANAGEMENT_MODE=paas_managed` instances, public signups can create
  unlimited orgs and squat names, permanently DoS-ing PaaS provisioning
  (`upsert_paas_org` 409s with no takeover path). Malformed names also flow
  into the derived namespace `cap-{org}-{app}` (`deploy.rs:579-590`).
- **Status (rev 2): Fixed — verified.** `create_org` enforces the management
  write gate and DNS-safe names (`orgs.rs:56`); regression tests for both
  behaviors live beside main's new tests in the same module.

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
- **Status (rev 2): Fixed — verified.** All interpolated Rego strings go
  through `rego_quoted_string` (= `serde_json::to_string`,
  `kbs_policy.rs:156-158`); `engine::validate` requires DNS-label-safe
  namespace/service-account/tenant-id (`validate.rs:41-43,141`).

### M-4 (Medium) — Tenant egress to internal endpoints is warn-only

- Location: `crates/enclava-api/src/routes/apps.rs:410-490`,
  `crates/enclava-engine/src/manifest/network_policy.rs:251-261`.
- `audit_egress_allowlist_host` logged `"accepting in warn-only mode"` for
  `kubernetes.default.svc`, `metadata.google.internal`, `*.svc.cluster.local`,
  `*.internal`, rebinding helpers (`*.nip.io`) — then accepted. A tenant can
  open TEE egress to the K8s API server or cloud metadata (ports 1-65535
  allowed). Mitigated by `automountServiceAccountToken: false` and Kata TEE
  isolation, but the audit reasons exist precisely to block this.
- **Status (rev 2): Fixed — verified.** Internal/metadata/`.svc`/rebinding
  hosts are rejected with 400 (`apps.rs:456+`); operator opt-out via
  `CAP_EGRESS_ALLOW_INTERNAL_HOSTS=true` is logged per host. Note the asymmetry
  with rev-2 finding N-1: this opt-out is audited, the runtime-class one is not.

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
- **Status (rev 2): Fixed (latent foot-gun closed at the API edge) —
  verified.** `verify_appraisal_response_pinned` + `ExpectedReceipt`
  (policy hash / nonce / origin binding) exist in `receipt.rs:79-118`;
  appraiser docs updated. Deployment-tier appraiser auth remains deferred.

### M-6 (Medium) — No SNP TCB/policy appraisal in CLI (DEBUG bit unchecked)

- Location: `crates/enclava-cli/src/tee_client.rs:640-706`,
  `crates/enclava-cli/src/attestation.rs:141-162`.
- After chain verification only `report_data` was compared. Nothing inspected
  the SNP guest policy byte (DEBUG bit) or `reported_tcb` floors. A genuine
  but debug-enabled or stale-TCB guest passed CLI appraisal.
- **Status (rev 2): Partially fixed — verified.** DEBUG-bit guests are
  rejected fail-closed (`attestation.rs:142`). TCB floors still need
  per-platform policy data (deferred work 1).

### M-7 (Medium) — TLS-verification bypass envs gated only in `main()`; unconditional in ssh.txt path

- Location: `crates/enclava-cli/src/tee_client.rs:43-50, 543-562`;
  `crates/enclava-cli/src/commands/template.rs:1972-1979`.
- **Status (rev 2): Fixed — verified.** `accepts_invalid_tee_certs()` honors
  bypass envs only under `cfg!(debug_assertions)` (`tee_client.rs:49,58`);
  ssh.txt fetch uses the same gate. Operational note stands: preprod staging
  relays need trusted certs or a debug CLI.

### M-8 (Medium) — Windows command injection via API-supplied URL

- Location: `crates/enclava-cli/src/commands/auth.rs:326-338`.
- `cmd /C start "" <url>` where `url` is `verification_uri_complete` from the
  device-login response. `cmd.exe` interprets `&`, `^`, `|`, `%VAR%`; a
  malicious `--api-url` or compromised API yields arbitrary command execution
  on Windows clients.
- **Status (rev 2): Fixed — verified.** `try_open_browser` gates on
  `browser_safe_device_url` (scheme + charset) and quotes the URL
  (`auth.rs:335-353`); webbrowser bumped to 1.2.2 on main.

### M-9 (Medium) — No rollback/downgrade protection on keyring fetch and platform release

- `crates/enclava-cli/src/commands/org.rs:425-444`,
  `crates/enclava-cli/src/keyring.rs:266-276` — keyring fetch stores whatever
  verifies against the TOFU-pinned owner key; no version monotonicity vs the
  cached copy. A compromised API can replay an older, still-validly-signed
  keyring (re-adding a removed deployer, dropping new members).
- `crates/enclava-cli/src/platform_release.rs:97-148` — any validly-signed old
  release was accepted; no version monotonicity, freshness, or revocation, and
  `ENCLAVA_PLATFORM_RELEASE_PATH` can point anywhere.
- **Status (rev 2): Fixed — verified, partially superseded by main.**
  `store_keyring_envelope` refuses version rollbacks (equal = idempotent);
  `store_keyring_envelope_force` exists only for explicit restore/bootstrap
  (used by `key restore` and `finalize_local_owner_rotation` after a
  server-confirmed rotation). Main's backup-first flow (`2957872`,
  `0726db7`) additionally reorders bootstrap to upload-then-pin so a losing
  concurrent upload leaves no local trust state; the v1 force-store in the
  404 bootstrap paths was replaced by that ordering (merge resolution
  `a2f6309`). Platform-release version monotonicity is enforced.

### M-10 (Medium) — CLI secret files briefly world-readable

- Location: `crates/enclava-cli/src/config.rs:133-205`.
- **Status (rev 2): Fixed — verified.** Credentials/bootstrap keys are created
  with `create_new(true).mode(0o600)` + rename (`config.rs:203-207`); state
  dirs forced 0700. Main's new backup path writes ciphertext-only tmp files
  (plaintext seed never hits disk unencrypted), also 0600-before-rename.

### Low findings (v1)

| ID | Location | Issue | Status (rev 2) |
|----|----------|-------|----------------|
| L-1 | `crates/enclava-api/src/auth/jwt.rs:124-147` | 60 s default exp leeway | **Fixed** — `leeway = 0` (`jwt.rs:126-136`) |
| L-2 | `crates/enclava-api/src/routes/domains.rs:222-233` + migration 0014 | custom-domain challenge token stored plaintext | Deferred (unchanged, needs DB migration) |
| L-3 | `crates/enclava-api/src/signing_service.rs`, `main.rs` | signing-service URL may be `http://` | **Fixed** — release gate enforces https (`main.rs:747-749`) |
| L-4 | `crates/enclava-api/src/routes/workload.rs:66-133` | internal error strings echoed to callers | Deferred (unchanged) |
| L-5 | `crates/enclava-init/src/trustee_verify.rs` | skip-shaped API/dead branch | **Fixed** — `verify_chain_required`, no skip path |
| L-6 | `crates/enclava-init/src/trustee_verify.rs:100-102` | `org_keyring_signature` fetched, never verified | Deferred (cross-project per AGENTS.md) |
| L-7 | `crates/enclava-init/src/socket.rs:55-74` | unbounded `read_line` | **Fixed** — `take(MAX+1)` before read (`socket.rs:62-67`) |
| L-8 | `crates/enclava-common/src/descriptor.rs:97-103` | legacy 32-byte measurement prefix compare | Deferred (migration issue) |
| L-9 | `crates/enclava-api/src/routes/deployments.rs:740` | `container_name` unvalidated | **Fixed** — DNS-label validated at acceptance (`deployments.rs:743-748`) |
| L-10 | `docker-compose.yml:7-11` | dev postgres on all interfaces | **Fixed** — bound to 127.0.0.1 |
| L-11 | `web/verifier/*.html` | no CSP | **Fixed** — CSP meta tags present |
| L-12 | `crates/enclava-cli/src/api_client.rs:29-41` | ApiClient accepts http | **Fixed** — https except loopback (`api_client.rs:31-40`) |
| L-13 | `crates/enclava-api/src/auth/email.rs` | user enumeration, no per-account throttle | Deferred (unchanged) |
| L-14 | `deploy/api/deployment.yaml:35` | `:latest` default | Deferred (render script enforces pinning; unchanged) |
| L-15 | `crates/enclava-engine/src/apply/teardown.rs:29-37` | dead redirect-following helper | Deferred (fix before wiring) |
| L-16 | `crates/enclava-cli` various | Debug derives on secret structs; `--set KEY=VALUE` | Partially fixed; unchanged since v1 |

---

## 2. Findings (rev 2 — new)

Audited everything main added since `a5e5fab2` (PR #86 GitOps migration
ledger, PR #87 signing-authority rotation: `rotate_org_owner`,
`get_signing_readiness`, `bootstrap_signing_service_owner` hardening, CLI
`key setup/backup/restore/rotate-owner`, backup-first onboarding, webbrowser
1.2.2, `owner_rotation_directive_bytes` CE-v1 domain separation, migration
ledger verification).

### N-1 (Medium) — Release-build escape hatch for simulated CoCo runtime is unaudited

- Location: `crates/enclava-engine/src/manifest/cc_init_data.rs:260,291-296`,
  `crates/enclava-api/src/main.rs:356-368`.
- Main reintroduced `CAP_ALLOW_DEV_RUNTIME_CLASS=true` to permit
  `CAP_RUNTIME_CLASS=kata-qemu-coco-dev` (simulated CoCo, no real TEE) in
  **release builds**, reversing the v1-era invariant "release builds reject
  all debug bypass envs" (commit `d3c3ad2`). Compensating factors:
  - `load_platform_release` requires a loaded signed release to pin
    `DEFAULT_RUNTIME_CLASS`, but no longer compares it against the
    env-resolved class, so the hatch is not blocked by an enabled release;
  - signed descriptors still carry `expected_runtime_class` from the release
    and the verifier checks the observed class (`enclava-verifier/src/lib.rs:366`),
    so dev-runtime pods fail attestation verification fail-closed.
- Residual risk: an operator misconfiguration (or compromised GitOps repo)
  schedules all tenant workloads without real TEEs; unlocks/verified-status
  fail closed (availability, not confidentiality), but the startup gate that
  used to catch this is gone. Unlike `CAP_EGRESS_ALLOW_INTERNAL_HOSTS`
  (M-4's opt-out, logged per host), this env is not registered in any env
  gate and is never audit-logged.
- Recommendation: log loudly at resolution time, register in the audited-env
  set, and restore `release.expected_runtime_class == try_runtime_class()`
  when a platform release is enabled.
- **Status (rev 3): Fixed — verified.** (a) `resolve_runtime_class_with_env`
  emits a `tracing::warn!` every time the hatch resolves the simulated CoCo
  class; (b) `load_platform_release` binds the signed release to the
  **resolved** runtime class via `check_release_runtime_class` — hatch +
  enabled release now fails startup (behavior change: the hatch is only
  usable when no platform release is loaded, i.e. dev/preprod clusters
  without release metadata); (c) a source-assert regression test guards the
  call site against the dropped-hunk failure mode. The hatch stays
  release-legal by design (unlike `DEBUG_ONLY_FLAGS`) — observability plus
  the release binding are the compensating controls.
- Note: local `main` (merge `90ad634`) had silently dropped this whole change
  set (all three files reverted to pre-`origin/main` state); restored on this
  branch in `197a045`, and local `main` itself repaired in `49d8f48` (N-3).

### N-2 (Low) — `owner_pubkey_fingerprint` cross-repo contract is actually raw key hex

- Location: `crates/enclava-api/src/routes/orgs.rs` (rotate handler response
  consistency check), `crates/enclava-cli/src/commands/app/signing.rs:199`.
- The signing service's `owner_pubkey_fingerprint` field is compared against
  `hex::encode(<raw 32-byte pubkey>)`, while every in-repo "fingerprint" is a
  SHA-256 digest (`owner_key_fingerprint`, keyring fingerprints, CLI response
  checks). The field name lies. If the signing service ever starts returning a
  real digest, bootstrap/rotation consistency checks fail closed (DoS/confusion,
  not a bypass). Cross-repo contract should be documented and pinned
  (AGENTS.md blocking rules apply — policy-signing-service is a consumer).
- **Status (rev 3): Documented (fixed in-repo).** Contract pinned at every
  touch point: doc comments on `BootstrapOrgResponse::owner_pubkey_fingerprint`
  and `RotateOrgResponse::owner_pubkey_fingerprint` (`signing_service.rs`),
  comments at both comparison sites (API `orgs.rs` rotate handler, CLI
  `app/signing.rs`), and a "Policy-signing-service authority fields" section
  in `docs/verification/contracts-v1.md`. Cross-repo rename to
  `owner_pubkey_hex` stays recommended at the service's next contract revision
  (follow-up 10).

### N-3 (Low, process) — Merge on local `main` silently reverted origin/main hunks

- Local `main` merge commit `90ad634` dropped origin/main changes to
  `cc_init_data.rs`, its test, and `main.rs`'s `load_platform_release`
  (discovered because the runtime-class release binding failed to appear after
  the pull). Any branch merging local `main` instead of `origin/main` inherits
  the loss.
- **Status (rev 3): Fixed — verified.** Commit `49d8f48` on local `main`
  restores the three dropped files; `git diff origin/main main` is now empty
  (the worktree's unrelated dirty files were left untouched). Root cause:
  local `main`'s only unique commit (`d3c3ad2`) was fully superseded by
  origin/main's later evolution of the same hunks and the merge resolution
  silently favored the stale side. Guard: the new
  `release_runtime_class_binding_uses_the_resolved_class` source-assert test
  fails if this hunk is dropped again.

### Verified-solid: main's new signing-authority rotation (coverage summary)

- `rotate_org_owner` (API): owner scope + in-tx role re-check under the
  signing-authority lane lock; both signatures verified (replacement signs the
  new keyring, current owner signs the CE-v1 domain-separated rotation
  directive); version monotonicity (exact replay, +1 only, stale rejected);
  `validate_rotated_members` preserves every non-owner member exactly;
  replacement key must be a registered, unrevoked signing key of the caller;
  signing-service owner state must be consistent before/after (drift covered
  by idempotent retry and `recovery_required` readiness).
- `put_keyring`: a keyring version N+1 must be signed by the current pinned
  owner (double verify: new key + latest owner on the same canonical bytes) —
  a rotated-out (revoked) owner cannot re-upload or re-rotate back to
  authority. Owner changes are only possible through the directive-gated
  rotation route.
- CLI `key setup/backup/restore/rotate-owner`: backup written (argon2id +
  AEAD, secrets under ciphertext, 0600) before remote authority changes;
  upload-then-pin bootstrap leaves no losing local trust state;
  `finalize_local_owner_rotation` orders trusted-owner rotation, envelope
  store, and seed persistence for crash-safe retry; restore path uses the
  force store deliberately after server-side verification.
- Migration ledger (`db/pool.rs`): `verify` mode requires the exact
  successful, checksum-matching ledger (no gaps, no extra rows); release
  workflow publishes the migration version for the GitOps migration Job.

---

## 3. Mitigation strategy

Principles:

1. Fail closed. Every fix must reject/abort rather than warn where the
   current code warns.
2. Pin, don't probe. Trust anchors must come from build-time or signed
   configuration, never from the message under verification.
3. No behavior change without tests. Each fix ships with regression tests.
4. Respect the cross-project dependency schema (AGENTS.md): no KBS
   policy/artifact schema changes, no template metadata changes, no
   CLI-visible behavior changes beyond documented hardening.

### Per-finding mitigation plan and status

| Finding | Strategy | Status (rev 2) |
|---------|----------|----------------|
| H-1 | Pin evidence-embedded ARK to builtin AMD roots; anchored KDS fallback; fail closed | Implemented, verified post-merge |
| M-1 | Policy-pinned ARK before RSA math; modulus/exponent caps | Implemented, verified |
| M-2 | Management-write gate + DNS-safe names on public `create_org` | Implemented, verified |
| M-3 | JSON-escape Rego interpolation; DNS-label validation in engine | Implemented, verified |
| M-4 | Reject internal/rebinding egress hosts (audited opt-out env) | Implemented, verified |
| M-5 | `verify_appraisal_response_pinned` + `ExpectedReceipt` | Implemented, verified |
| M-6 | Reject DEBUG-bit SNP guests | Implemented; TCB floors deferred |
| M-7 | Bypass envs debug-only; ssh.txt uses same gate | Implemented, verified |
| M-8 | Validate + quote browser URL | Implemented, verified |
| M-9 | Keyring rollback refusal + platform-release monotonicity | Implemented; bootstrap paths superseded by main's upload-then-pin ordering (equivalent or stronger) |
| M-10 | 0600-from-birth file creation; 0700 dirs | Implemented, verified |
| L-1, L-3, L-5, L-7, L-9, L-10, L-11, L-12 | See Low table | Implemented, verified |
| N-1 | Audit-log + env-gate the dev-runtime hatch; restore release↔runtime-class binding when a release is loaded | Implemented (rev 3): warn at resolution + `check_release_runtime_class` binding + regression test |
| N-2 | Document/pin the signing-service fingerprint field contract | Implemented (rev 3): docs at all touch points + contracts-v1.md; cross-repo rename pending (follow-up 10) |
| N-3 | Fix local `main`; restored on this branch in `197a045` | Implemented (rev 3): local `main` repaired in `49d8f48`; `git diff origin/main main` empty |

### Deferred work (follow-ups, in priority order)

1. TCB-floor policy for CLI attestation (needs per-platform floor data; the
   independent verifier already supports floors via policy).
2. Domain challenge-token hashing at rest (DB migration 00XX).
3. Workload-route error allowlisting.
4. `org_keyring_signature` enforcement in enclava-init (coordinate with KBS
   artifact format consumers per AGENTS.md blocking rules).
5. Descriptor migration off legacy 32-byte measurements.
6. Per-account login throttling; uniform signup/login timing.
7. Appraiser authentication/rate limiting at the deployment tier (residual
   M-1/M-5 exposure).
8. Engine teardown helper hardening before first use.
9. ~~N-1: audited env-gate + release binding for `CAP_ALLOW_DEV_RUNTIME_CLASS`.~~
    Done (rev 3); residual: none in-repo.
10. N-2 cross-repo rename: rename the signing-service's
    `owner_pubkey_fingerprint` to `owner_pubkey_hex` at the service's next
    contract revision (coordinated change per AGENTS.md; contract now
    documented in-repo).

### Verification

Run on this branch after the merge (`a2f6309` + `197a045`):

- `rustup run stable cargo fmt --all -- --check` — clean
- `rustup run stable cargo clippy --workspace --all-targets -- -D warnings` — clean
- `rustup run stable cargo test --workspace` — all green
  (note: `enclava-api` DB-backed `deployment_jobs` tests share one database
  and assume a pristine queue; if they fail with `VersionMismatch` or
  cross-test claims, reset the test DB and rerun `--test-threads=1` —
  environment flakiness, not a regression)
- `rustup run stable cargo test --doc` — clean
- Release builds with `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX` set
  (see AGENTS.md) — not rerun for rev 2; required before merge.

Docker image builds and `cargo audit`/`cargo deny` are environment-dependent
and should be run in CI for this branch before merge.
