# Canonical policy validation without the signing service

Status: proposed design. This document does not change acceptance.
`resolve_signed_policy_artifact` still returns 503 when
`state.signing_service` is absent, including when the caller supplies
`signed_policy_artifact`. A customer keyring or descriptor signature is
not a canonical-policy witness. Do not implement the absent-service path
until the gate at the end of this document has passed review.

Tracked by cap#263. Does not close #232. The accepted-artifact enqueue
fixed there stays as it is.

## What is missing

`resolve_signed_policy_artifact`
(`crates/enclava-api/src/routes/deployments.rs`) already checks customer
authority, then requires both `SIGNING_SERVICE_PUBKEY_HEX` and a live
signing-service client. The client is not used only to produce an
artifact. It is called at `POST /agent-policy` so
`validate_canonical_agent_policy` can compare the artifact to what the
trusted generator emits **now** for this descriptor and log-encryption
config:

- generated hash equals `sha256(generated text)`
- descriptor `expected_agent_policy_hash` equals that hash
- artifact `agent_policy_sha256` and `agent_policy_text` equal the
  generated values
- artifact `metadata.genpolicy_version_pin` equals the generated pin

Deploy and unlock redeploy both enter through this function. Both must
keep that single gate. Do not add a second acceptance function for the
absent-service case.

The platform signature check is a different question. Policy artifacts
are signed by the off-cluster signing-service key
(`policy_artifact_signing_input`: purpose `enclava-policy-artifact-v1`,
metadata hash, rego hash). That signature binds issuance. It does not
bind "this text is what the current generator would emit." A historical
or compromised signer can put the current pin string in metadata and a
weaker policy in `agent_policy_text`. The live `/agent-policy` response
is the check that catches that. Removing it because a customer artifact
was supplied is a downgrade, not a convenience path.

The live supplied-artifact branch is also not a template for the
witness path. If `validate_signed_artifact` fails, that branch swallows
the error and falls through to `signing_service.sign()`
(`deployments.rs`, the `is_ok()` check before the canonical compare).
On the witness path that fall-through is forbidden. A signature, field
cap, or metadata failure is terminal. Do not call `/sign`, and do not
fill the hole by synthesizing an artifact from witness output.

`SIGNING_SERVICE_PUBKEY_HEX` and `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX`
stay separate trust domains. Startup already rejects setting them equal.
The in-TEE trustee key must not become the acceptance authority for
`/sign` artifacts, and the signing-service private key must not be
loaded into CAP or into the guest.

## Trust anchor

The witness is the signed platform release, not the customer and not a
cache of the signing service.

The release signature is not over the JSON document. Both
`canonical_release_bytes` implementations — API
(`crates/enclava-api/src/platform_release.rs`) and CLI
(`crates/enclava-cli/src/platform_release.rs`) — hash an explicit field
list and must stay byte-identical. `PlatformRelease` has no
`deny_unknown_fields`. A serde field that those functions do not emit
is attacker-controlled on `ENCLAVA_PLATFORM_RELEASE_PATH`: the host can
rewrite it and `verify_envelope` still succeeds. enclava-init does not
verify release signatures, so it is not a third verifier of this field.

The generator measurement therefore follows the `luks2_header_seal`
pattern, not a JSON-only additive field:

- Add `canonical_policy_generator_id`,
  `canonical_policy_generator_digest` (lowercase hex sha256), and
  `canonical_policy_input_schema` to `PlatformRelease` in both crates.
- Emit them in both `canonical_release_bytes` functions only when the
  digest is non-empty, as one record each, in the same order, before
  `created_at`. Empty digest omits all three records, so envelopes
  signed before the field existed keep verifying byte-for-byte. A
  tampered, stripped, or half-present value changes the signed bytes
  and fails verification. Digest present with empty id or schema is
  invalid and fails closed at release load, not at accept time.
- `policy_template_text` is already in those signed bytes. That is the
  template the witness may use. Do not add a second unsigned template
  path.

Empty digest means the witness is not configured. That is the only
switch. Do not add a second enablement flag that can disagree with the
release.

### What is executed

A release field does not measure "whatever this CAP binary linked."
In-process code is not a witness unless a digest compiled into the
measured binary equals the signed digest, the compare happens before
the function runs, and mismatch refuses. This design does not take
that option: CAP does not contain genpolicy, and a function pointer has
no separate bytes to hash.

The witness is a helper file. Before exec:

1. CAP opens one path derived from the signed digest
   (`<release-generator-dir>/<digest>`), not from `PATH`, the request,
   or the release JSON. `release-generator-dir` is a startup config
   directory, not a per-request input.
2. CAP hashes those exact file bytes and compares them to
   `canonical_policy_generator_digest`. Mismatch, missing file, extra
   files, or a non-regular file is a broken witness: 503, do not exec.
3. CAP execs that file with a cleared environment, no extra arguments
   that name a template path, and the already validated inputs on
   stdin: the signature-checked descriptor, the validated
   `log_encryption` config, the release-pinned `policy_template_text`,
   and `genpolicy_version`. The helper must not open the release file,
   a template path, or any other policy file. If it needs bytes, they
   were on stdin. A helper that reads anything else is not an
   implementation of this design.

Output is an `AgentPolicyResponse`. Acceptance then calls the existing
`validate_canonical_agent_policy` only after the witness self-checks
below. No parallel compare. CAP never holds the signing-service private
key and never calls `/sign` on this path.

Rejected alternatives:

- Customer keyring or descriptor signature alone. Already required.
  Does not bind current generator output. Forbidden by #263.
- Platform signature alone. Proves issuance under
  `SIGNING_SERVICE_PUBKEY_HEX`, not current canonicity.
- A cache of a previous `/agent-policy` response. Stale by
  construction, empty on first deploy, and still depends on the service
  having been reachable.
- Reusing the trustee policy key. Collapses the two trust domains.
- A serde field that `canonical_release_bytes` does not emit. Unsigned.
- An in-process function whose digest is not compared to bytes this
  process will execute.

## Acceptance rules

When the signing-service client is present, it remains the only
acceptance source. The witness is not consulted. A disagreement between
a live service response and a local witness is an operator alarm in
parity tests, never a reason to accept the witness output instead.

The release envelope is loaded once at startup and is not re-read under
the signing-authority lane. Repeating the witness compare inside the
acceptance transaction would observe the same release as the pre-lock
call. The lane serializes keyring rotation, which does not change
generator output; customer authority is already repeated inside the
lock for that reason. The pre-lock compare in
`resolve_signed_policy_artifact` is the authority for both deploy and
unlock redeploy, because both call that function. Do not add a second
compare on only one of those paths.

`platform_release_envelope` immutability is also why
`descriptor_platform_binding_for` does not need a new in-lock repeat
for this design. Unlock already repeats that binding inside its lock;
deploy does not. That existing difference is out of scope. The witness
path must not skip the binding on either caller.

When the client is absent:

| Condition | HTTP |
| --- | --- |
| No release loaded, digest empty, measurement mismatch, helper fails, helper pin ≠ `release.genpolicy_version`, or witness hash ≠ `sha256(witness text)` | 503 `canonical policy validation requires the platform signing service`. Check witness self-consistency before `validate_canonical_agent_policy`. A self-inconsistent witness must not become 400. |
| Witness configured, no `signed_policy_artifact` | 503 `signed_policy_artifact required when the platform signing service is absent`. Do not synthesize an artifact. |
| Pubkey absent | 503 `platform signing-service pubkey required for signed_policy_artifact verification`. Unchanged. |
| `validate_signed_artifact` fails (signature, field caps, metadata binds) | Terminal. Existing `signing_error_response` for that error. Do not fall through to `/sign`. |
| Witness is self-consistent and the artifact disagrees | 400 `signed_artifact_mismatch`. The HTTP body does not include the internal name. Internal names, for logs only, are the existing `validate_canonical_agent_policy` mismatches: `generated_agent_policy.agent_policy_sha256`, `generated_agent_policy.expected_agent_policy_hash`, `canonical_agent_policy_sha256`, `canonical_agent_policy_text`, `canonical_genpolicy_version_pin`. |
| `signed_at` unparseable, in the future, or before `release.created_at` | 400 `signed_artifact_mismatch`. Internal log name `canonical_signed_at`. |

`signing_error_response` maps every `Mismatch` to 400
`signed_artifact_mismatch` and drops the name. Tests of this path
assert that HTTP body, not the internal field name.

The witness path adds checks the live path gets by trusting the
service:

1. `witness.genpolicy_version_pin == release.genpolicy_version`,
   exact string, compared to the loaded release, not to the artifact's
   own pin. Failure is the 503 above, not an artifact mismatch.
2. Refuse to run when the signed digest is empty or does not match the
   hashed helper bytes.
3. `descriptor.policy_template_sha256` must equal the release template
   hash via the existing `descriptor_platform_binding_for` check. Do
   not skip it.

`AgentPolicyResponse.log_encryption` is not an acceptance input.
`validate_canonical_agent_policy` ignores it, and the agent-policy
broker overwrites it with the request config. The witness must not
persist `generated.log_encryption` over the validated request config.
The text compare does not bind log encryption when the text does not
change. Both callers already run
`validate_and_pin_cc_init_data_render` after resolve; the witness path
must keep that caller-side check.

## Stale and replay

Existing metadata binds stay and are not optional: `app_id`,
`deploy_id`, `descriptor_core_hash`, `descriptor_signing_pubkey`,
`platform_release_version`, `policy_template_id`,
`policy_template_sha256`, and the expected policy hashes. A cross-deploy
or cross-release artifact already fails those compares.

`PolicyMetadata.signed_at` is a `String`. The signature covers those
raw bytes. It is not parsed today. The witness path parses both
`signed_at` and `release.created_at` as `DateTime<Utc>` and fails
closed on any unparseable value. A string compare is not acceptable:
unpadded dates and offsets would still verify under the signature.

The freshness window is new. It is not the owner-rotation directive
rule.

- Do not copy `PRECHECK_CLOCK_SKEW_SECONDS` (300s, `routes/orgs.rs`).
  That constant runs before the lane, against `Utc::now()`. After the
  lock, the owner-rotation future check is `signed_at > lane_now` with
  zero skew. `lock_org_signing_authority_lane_now` returns post-lock
  `clock_timestamp()` and does not add 300s.
- Deploy and unlock call `lock_org_signing_authority_lane`, not
  `_now`. The implementation reads `clock_timestamp()` after that lock
  is held, on the same transaction, and uses that instant. Do not
  sample `Utc::now()` before the lock and call it the bound.
- Authoritative window, parsed instants:
  `release.created_at <= signed_at <= post-lock clock_timestamp()`.
  No added skew. `signed_at` in the future of that clock fails closed.
- This floor is not `enforce_release_not_older_than_bundled`. That
  check rejects envelopes older than the compiled baseline. The
  artifact claims `platform_release_version`, not `created_at`. The
  `created_at` floor is an additional anti-replay bound for this path
  only.
- Content staleness of agent policy is the witness text compare. An
  old artifact whose agent-policy text is not what the measured helper
  emits now fails `canonical_agent_policy_text`, even if the signature
  and the pin string still verify.
- Key rotation is the pubkey check. After
  `signing_service_pubkey_hex` changes, artifacts signed by the retired
  key fail `InvalidSignature`. Do not accept them under the witness.

Do not copy the 900-second owner-directive max age. That bound is for
an online directive. An absent-service artifact was produced earlier.
A 15-minute TTL would reject the artifacts this path exists to accept,
without covering agent-policy downgrade the text compare already
covers.

## What the witness does not re-derive

`validate_canonical_agent_policy` compares agent-policy text, hash, and
pin. It does not re-derive `rego_text`. The platform signature covers
`rego_sha256`, and `validate_signed_artifact_common` checks that hash
against `descriptor.expected_kbs_policy_hash`, which the customer
signed. The live supplied-artifact path does not call `/sign` again
once the signature verifies, so it does not re-derive rego either.

The witness replaces the `/agent-policy` call only. It is not a
replacement for `/sign`. Rego stays signature-bound and bound to the
customer-committed hash. A historical or compromised platform signer
can still attach weaker rego that matches that hash. That hole exists
on the live supplied-artifact path and is an explicit non-goal here.
Do not describe the witness as "the same compares as `/sign`." The
compares that must match the live path are the ones
`validate_canonical_agent_policy` already performs, plus the
measurement and release-pin checks above.

## Transactional enqueue

`accept_signed_workload_artifacts` inserts the workload-artifact row
and calls `enqueue_signed_policy_reconciliation` on the same
transaction. That bumps
`kbs_signed_policy_reconciliation.desired_generation`. Deploy and
unlock redeploy already call it only after
`resolve_signed_policy_artifact` returns `Ok`, inside the transaction
that also holds the org signing-authority lane and repeats
`validate_customer_authority_in_tx`. Rollback of that transaction rolls
back the row and the generation together.

The witness path must return into that same caller. It must not enqueue
from `resolve_signed_policy_artifact`, and it must not open its own
transaction. Unlock-mode transition and rollback revalidate a stored
artifact (`validate_stored_authority`) and must not grow a witness
dependency. That is a different path from unlock redeploy, which does
call `resolve_signed_policy_artifact` and therefore gets this gate.

## Threats

| Threat | Result |
| --- | --- |
| Customer substitutes a weaker `agent_policy_text` or hash | Witness compare rejects. Customer signature does not authorize the policy text. |
| Artifact claims the current genpolicy pin but was produced by an older agent-policy generator | Pin must equal the release pin, and text must equal a run of the measured helper. Either mismatch rejects. |
| Weaker `rego_text` whose hash matches the customer-committed `expected_kbs_policy_hash` | Not covered. Same as the live supplied-artifact path. Signature-bound. Not a witness failure. |
| Artifact signed by the customer key, or by the trustee policy key | `validate_signed_artifact` rejects, and that rejection is terminal. |
| Replay onto another app, deploy, descriptor, or release | Existing metadata binds reject. |
| Replay of an artifact whose parsed `signed_at` is before the loaded release `created_at` | 400 `signed_artifact_mismatch`. |
| Host rewrites a generator digest that is not in `canonical_release_bytes` | Not possible under this design: the digest is in both canonicalizers, or the witness is not configured. |
| Host swaps the helper file after release verify | Exec-time hash of the bytes CAP will run fails closed. |
| Signing service suppressed to force a weaker path | Empty digest means the same 503 as today. Configured witness means the agent-policy compares above, not a customer-only accept. |
| Split brain between service and witness | Service present: service wins. Witness is not an accept path. |
| Witness or release missing | 503. Never fall through to customer checks. |
| CAP asked to sign because the service is down | Refused. No private signing key in CAP. No synthesized artifact. |

## Sibling sites

- `generate_agent_policy` (`routes/deployments/generic.rs`, and the
  PaaS forwarder) returns a different 503, `platform signing service
  is not configured`. That route is a preflight broker. It does not
  accept artifacts and must not grow a witness. Ruled out.
- Unlock-mode transition revalidates a stored artifact with
  `validate_signed_artifact` and the signing-service pubkey. It does
  not call `/agent-policy`. Requiring a fresh witness there would fail
  unlock when the generator moves. Ruled out. Unlock redeploy is not
  this path; it calls `resolve_signed_policy_artifact`.
- Rollback revalidates a stored artifact and enqueues. Ruled out.
- Org owner bootstrap and rotation talk to the signing service for
  owner state, not for canonical agent policy. Ruled out.

## Implementation gate

A later change may enable the absent-service path only when all of the
following are true. Until then the 503 in
`resolve_signed_policy_artifact` stays, including for a supplied
artifact. The only switch is a non-empty generator digest in the signed
release. Clearing it restores the 503. No second flag. No migration.
No KBS schema change.

1. Both `canonical_release_bytes` functions emit the three generator
   records under the empty-omission rule above, and a test shows a
   tampered digest fails envelope verification while a pre-field
   envelope still verifies.
2. Exec-time hash: the bytes CAP will exec are hashed and compared to
   the signed digest before exec. Mismatch is the 503, and a test
   tampers the helper bytes and shows no exec and no accept.
3. Parity fixture: the same descriptor and log-encryption inputs
   through the live `/agent-policy` client and the measured helper
   produce byte-identical `agent_policy_text`, `agent_policy_sha256`,
   and `genpolicy_version_pin`, and both pins equal
   `release.genpolicy_version`. Parity against a service that has
   drifted from the release is a failure, not a pass.
4. Fail-closed tests, asserting the HTTP bodies in the table: mismatched
   text, mismatched hash, stale pin, tampered signature, tampered text,
   cross-deploy id, cross-release, unparseable `signed_at`, `signed_at`
   before `release.created_at`, `signed_at` after the post-lock clock,
   customer-key signature, trustee-key signature. Signature failure
   does not fall through.
5. Isolated DB test: valid artifact, service absent, witness present,
   release loaded. The acceptance transaction persists the artifact and
   increments `desired_generation` together; aborting the transaction
   leaves both unchanged. Same shape as the existing
   `accept_signed_workload_artifacts` commit/rollback tests.
6. Sabotage: deleting the witness compare, accepting when the digest is
   empty, or accepting when the exec hash mismatches, fails (2) or (4)
   or the 503 pin. A regression test that passes in both states is not
   evidence.

## Rollback

This design adds no runtime flag and no schema. Reverting the document
does not change acceptance. A future implementation reverts by clearing
the signed generator digest, which must return the 503 above without a
database migration.
