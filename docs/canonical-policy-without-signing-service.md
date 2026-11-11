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

Deploy and `update_unlock_mode` both enter through this function. Both must
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
  `canonical_policy_generator_digest`, and
  `canonical_policy_input_schema` to `PlatformRelease` in both crates,
  each with `#[serde(default)]`. Without that attribute a pre-field
  envelope fails to deserialize before verify. `luks2_header_seal`
  already has it.
- Emit the three records in both `canonical_release_bytes` functions
  only when the digest is non-empty, in this order, immediately after
  the optional `luks2_header_seal` record and immediately before
  `created_at`: id, digest, schema. Empty digest omits all three, so
  envelopes signed before the field existed keep verifying. A tampered
  or stripped value changes the signed bytes and fails verification.
  The two canonicalizers must emit the same records; a cross-crate
  byte fixture is part of the gate, not a comment.
- `canonical_policy_generator_id` is a log label. It is not a path and
  not a selector. Do not exec by id.
- `canonical_policy_generator_digest` must match `^[0-9a-f]{64}$` at
  release load. Do not reuse `hex32`: that helper trims, and a trimmed
  value must not become a path component or a compare against file
  bytes.
- `canonical_policy_input_schema` is a contract, not a label. When the
  digest is non-empty, release load fails closed unless the schema
  equals the one string this binary implements,
  `agent-policy-stdin-v1`. Any other string, including empty, is
  invalid. CAP must not feed a framing the signed schema does not name.
  The equality check lives in both crates' `validate_release_payload`:
  a bad release already refuses startup, so the per-request 503 row
  below is a backstop, not the check that runs. The CLI load is the
  other verifier of these bytes.
- `policy_template_text` is already in those signed bytes. That is the
  template the witness may use. Do not add a second unsigned template
  path.

Empty digest means the witness is not configured. That is the only
switch. Do not add a second enablement flag that can disagree with the
release.

### What is executed

A release field does not measure "whatever this CAP binary linked."
This design does not use an in-process function. CAP does not contain
genpolicy, and a function pointer has no separate bytes to hash.

The witness is one static ELF. Before any accept:

1. Do not exec unless `signed_policy_artifact` is present and
   `validate_signed_artifact` has already succeeded. The helper inputs
   do not include the artifact. Signature-first does not weaken the
   compare, and it avoids running the helper on a body the platform
   key did not sign. Signature failure stays terminal; do not fall
   through to `/sign`.
2. Open `<release-generator-dir>/<digest>` with `O_NOFOLLOW | O_CLOEXEC`.
   `release-generator-dir` is captured as an absolute path at startup,
   not a per-request input, and the leaf is the 64-hex digest, not the
   id. `O_NOFOLLOW` protects only the leaf; intermediate components are
   not covered, so a relative path plus a later `chdir` is not part of
   the measurement and must not become one. `fstat` that fd. Reject
   anything that is not a regular file. Do not follow a symlink. Other
   files in the directory are irrelevant; do not reject the witness
   because a previous digest's file is still there.
3. Read that fd into exactly one buffer, hashing incrementally, and 503
   above a fixed read cap so a swapped multi-gigabyte file cannot OOM
   CAP before the compare. Compare the final hash to the signed digest.
   Mismatch or a short read is 503. That buffer is the only copy of the
   bytes: step 4 writes exactly it. The fd is not `lseek`ed or read
   again. Do not hash a path and then exec the path: the host can
   replace the inode between those steps. Do not hash the fd and then
   re-read the fd either: a `pwrite` to the same inode after the hash
   read changes what a re-read returns, and a test that only replaces
   the inode does not see that swap.
4. Execute those same bytes, not a path and not bytes re-read from the
   fd. Write the hashed buffer from step 3 to a memfd — that one buffer,
   no `lseek` and no second read of the helper fd — then seal the memfd
   with `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW` before the fork.
   Until the seal, `/proc/<pid>/fd/<memfd>` is a writable path to the
   bytes that will run. Exec with `execveat(memfd, "", ..., AT_EMPTY_PATH)`,
   not a libc `fexecve` that opens `/proc/self/fd/N`: landlock in the
   child can deny that `open`, and its `/proc` fallback would turn every
   run into a 503. Fail-closed is not an implementation of this witness.
   Empty argv. Cleared environment. No interpreter: reject a non-ELF, a
   script, and any ELF with a `PT_INTERP` (dynamically linked helper or
   shebang). The dynamic loader and libc are not in the digest. A wrapper
   whose text matches the digest and then runs a host genpolicy is not
   this witness.
5. In the child, after fork and before `execveat`, close every fd
   except stdin, stdout, and stderr, then apply a landlock (or
   equivalent) that denies every filesystem open. Landlock does not
   revoke fds inherited across fork: the helper file fd is `O_CLOEXEC`,
   but other CAP sockets are not, and the helper must not inherit them.
   Do not apply landlock to the CAP process. The helper may use only the
   already-open stdin, stdout, and stderr. If the restriction cannot be
   installed, 503 and do not exec. "The helper must not open files" is not a
   check. The host can change a default template path the helper
   reads, the digest still matches, and the witness emits the weaker
   policy the artifact was signed to.
6. Stdin framing is `agent-policy-stdin-v1`, not `AgentPolicyRequest`.
   The live `/agent-policy` body does not carry the template. The
   framing is four fields, each a `u64` little-endian length prefix
   followed by exactly that many bytes, in order:
   `descriptor_canonical_bytes`; the serde encoding of the
   already-validated `LogEncryptionConfig`, or a zero length when
   absent (a zero length, not a JSON `null`); `policy_template_text`
   bytes; and `genpolicy_version` bytes. No paths. Any trailing byte
   after the fourth field is a framing error: 503. Two binaries that
   both claim this schema string must feed identical bytes; the string
   binds this layout, and gate item 3's parity fixture proves it.
7. Bound the helper the way the signing-service client is bounded:
   wall time 120 seconds (`DEFAULT_SIGNING_SERVICE_TIMEOUT_SECONDS`),
   a CPU rlimit no larger than that wall time, and stdout capped at a
   size that can carry one field-legal response.
   `MAX_POLICY_TEXT_BYTES` (`signing_service.rs`) caps the JSON-escaped
   `agent_policy_text` field of `AgentPolicyResponse`, not the response
   envelope; a 160 KiB stdout cap would reject a field-legal response
   the signing service itself returns. Cap stdout at
   `MAX_POLICY_TEXT_BYTES` plus a fixed envelope allowance, and 503
   before parsing anything above the cap. Exceeding any bound is a
   broken witness: 503, kill the child, do not accept.

Output is one `signing_service::AgentPolicyResponse` parsed from that
capped stdout. Stdout carries only that JSON; every diagnostic goes to
stderr. A helper that logs to stdout is a broken witness, not a noisy
one.
Acceptance then calls `validate_canonical_agent_policy` only after the
witness self-checks below. CAP never holds the signing-service private
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
- Hash the path, then `execve` that path. The host replaces the inode
  between the hash read and exec. Execute the hashed bytes (the sealed
  memfd via `execveat(AT_EMPTY_PATH)`), not the path, and not bytes
  re-read from the fd after the hash.

## Acceptance rules

When the signing-service client is present, it remains the only
acceptance source. The witness is not consulted. A disagreement between
a live service response and a local witness is an operator alarm in
parity tests, never a reason to accept the witness output instead.
None of the `signed_at` checks in Stale and replay run when the client
is present: they are witness-branch checks. `signed_at` is not parsed
today, and a zero-skew future bound against `clock_timestamp()` would
reject an artifact the service just signed whenever the service clock
runs ahead of Postgres. #263 requires preserving that behavior.

The release envelope is loaded once at startup and is not re-read under
the signing-authority lane. Repeating the agent-policy text compare
inside the acceptance transaction would observe the same release as the
call in `resolve_signed_policy_artifact`. That text compare stays in
that function, which both callers use: `deploy_app_candidate` and
`update_unlock_mode`. Do not add a second text compare on only one of
them. The `signed_at` future bound is not that compare. It cannot live
in `resolve_signed_policy_artifact`, because that function runs before
either acceptance transaction. See Stale and replay.

`platform_release_envelope` immutability is also why
`descriptor_platform_binding_for` does not need a new in-lock repeat
for this design. Unlock already repeats that binding inside its lock;
deploy does not. That existing difference is out of scope. The witness
path must not skip the binding on either caller.

When the client is absent:

| Condition | HTTP |
| --- | --- |
| No release loaded, digest empty, digest not 64 lowercase hex, schema not `agent-policy-stdin-v1`, measurement mismatch, helper fails, landlock unavailable, helper pin ≠ `release.genpolicy_version`, or witness hash ≠ `sha256(witness text)` | 503 `canonical policy validation requires the platform signing service`. Log a distinct reason for each cause. The HTTP string stays shared, so a test that asserts only the body cannot tell the causes apart; sabotage tests assert the log reason. Check witness self-consistency before `validate_canonical_agent_policy`. A self-inconsistent witness must not become 400. |
| Witness configured, no `signed_policy_artifact` | 503 `signed_policy_artifact required when the platform signing service is absent`. Do not synthesize an artifact. |
| Pubkey absent | 503 `platform signing-service pubkey required for signed_policy_artifact verification`. Unchanged. |
| `validate_signed_artifact` fails (signature, field caps, metadata binds) | Terminal. Existing `signing_error_response` for that error. Do not fall through to `/sign`. |
| Witness is self-consistent and the artifact disagrees | 400 `signed_artifact_mismatch`. The HTTP body does not include the internal name. Internal names, for logs only: `generated_agent_policy.expected_agent_policy_hash`, `canonical_agent_policy_sha256`, `canonical_agent_policy_text`, `canonical_genpolicy_version_pin`. `generated_agent_policy.agent_policy_sha256` is the self-inconsistent witness and is the 503 above, not this row. |
| `signed_at` unparseable, after the post-lock clock, or before `release.created_at` | 400 `signed_artifact_mismatch`. Internal log name `canonical_signed_at`. Parse with `DateTime::parse_from_rfc3339`, the parser release load already uses. Do not use a lenient parser. |

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
raw bytes. It is not parsed today. On the witness branch only, parse
both `signed_at` and `release.created_at` with
`DateTime::parse_from_rfc3339` and fail closed on any unparseable
value. Do not add the parse to the live path: an unparseable
`signed_at` there is covered by the signature over the raw bytes and
must not become a new rejection. A string compare is not acceptable:
unpadded dates and offsets would still verify under the signature.

The freshness window is new. It is not the owner-rotation directive
rule. The floor and the future bound are different checks and live in
different functions. Putting both in `resolve_signed_policy_artifact`
is wrong: that function runs before either acceptance transaction, and
a `Utc::now()` sample there is not the post-lock clock.

Both checks are witness-branch checks. They run only on the
absent-service path — after `state.signing_service` has been found
absent, never before. `resolve_signed_policy_artifact`,
`deploy_app_candidate`, and `commit_unlock_mode_transition` all run for
the live `/agent-policy` path today. Coding the checks where that path
also executes would parse `signed_at` (it is not parsed today) and
reject artifacts the signing service just signed.

- `created_at` floor: only in the absent-service branch of
  `resolve_signed_policy_artifact`, after the pubkey check and instead
  of the current 503 — not before `state.signing_service` is tested.
  The release envelope is immutable for the process. Parsed
  `release.created_at <= signed_at`. This is not
  `enforce_release_not_older_than_bundled`. That check rejects
  envelopes older than the compiled baseline. The artifact claims
  `platform_release_version`, not `created_at`.
- Future bound: only when that absent-service branch produced the
  artifact — skip it for a service-present resolve. After
  `lock_org_signing_authority_lane` and before
  `accept_signed_workload_artifacts`, on that transaction's
  `clock_timestamp()`, in both acceptance transactions:
  `deploy_app_candidate` (the `begin` in `routes/deployments.rs`) and
  `commit_unlock_mode_transition` (`routes/unlock.rs`). Window:
  `signed_at <=` that instant, zero skew. A missing check on either
  transaction is a failed gate, not a follow-up. Do not sample
  `Utc::now()` before the lock and call it the bound.
- Do not copy `PRECHECK_CLOCK_SKEW_SECONDS` (300s, `routes/orgs.rs`).
  That constant runs before the lane, against `Utc::now()`. After the
  lock, the owner-rotation future check is `signed_at > lane_now` with
  zero skew. `lock_org_signing_authority_lane_now` returns post-lock
  `clock_timestamp()` and does not add 300s. Deploy and
  `commit_unlock_mode_transition` call
  `lock_org_signing_authority_lane`, not `_now`. Read
  `clock_timestamp()` after that lock, on the same transaction.
- Content staleness of agent policy is the witness text compare, which
  stays in `resolve_signed_policy_artifact`. That is not a second copy
  of the future bound.
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
`kbs_signed_policy_reconciliation.desired_generation`. Both callers
already invoke it only after `resolve_signed_policy_artifact` returns
`Ok`, inside the transaction that also holds the org signing-authority
lane and repeats `validate_customer_authority_in_tx`. Rollback of that
transaction rolls back the row and the generation together.

The witness path must return into that same caller. It must not enqueue
from `resolve_signed_policy_artifact`, and it must not open its own
transaction. The `signed_at` future bound is the one check added inside
those two transactions, after the lane lock and before
`accept_signed_workload_artifacts`, and only when
`resolve_signed_policy_artifact` took the absent-service witness
branch. A service-present resolve carries the live artifact and skips
it. Rollback and dispatch revalidate a stored artifact via
`validate_stored_authority` and must not grow a witness dependency.

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
| Host swaps the helper inode after the hash read and before exec, rewrites the same inode in that window, or writes the memfd after the seal | Not possible under this design: one buffer is hashed, that same buffer is written to a memfd sealed with `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW` before fork, and `execveat` runs it. The fd is never re-read and the memfd is not writable after the seal. The gate tests all three swaps. |
| Signing service suppressed to force a weaker path | Empty digest means the same 503 as today. Configured witness means the agent-policy compares above, not a customer-only accept. |
| Split brain between service and witness | Service present: service wins. Witness is not an accept path. |
| Witness or release missing | 503. Never fall through to customer checks. |
| CAP asked to sign because the service is down | Refused. No private signing key in CAP. No synthesized artifact. |

## Sibling sites

- `generate_agent_policy` (`routes/deployments/generic.rs`, and the
  PaaS forwarder) returns a different 503, `platform signing service
  is not configured`. That route is a preflight broker. It does not
  accept artifacts and must not grow a witness. Ruled out.
- Both callers of `resolve_signed_policy_artifact` keep this gate:
  `deploy_app_candidate` and `update_unlock_mode`.
  `update_unlock_mode` is the unlock-mode transition. When artifacts
  are present it calls resolve, which calls `/agent-policy` today.
  There is no separate "unlock redeploy" path. Do not rule
  `update_unlock_mode` out.
- `commit_unlock_mode_transition` rechecks the signature of the
  artifact resolve just returned. It does not call
  `validate_stored_authority`, and that artifact is not a previously
  stored row. The `signed_at` future bound is added here and in the
  deploy transaction. It is not a witness text compare.
- `validate_stored_authority` is rollback and dispatch. Those do not
  call `/agent-policy`. Ruled out.
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
   records immediately after the optional `luks2_header_seal` record
   and immediately before `created_at`, under the empty-omission rule.
   A cross-crate fixture shows the signed bytes match. A tampered
   digest fails envelope verification. A pre-field envelope still
   deserializes (`serde(default)`) and still verifies.
2. Executed bytes, not a path. Open with `O_NOFOLLOW`, hash one buffer,
   write that buffer to a memfd sealed with
   `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW` before fork, and
   `execveat` it with `AT_EMPTY_PATH`. Three swaps are tested and must
   either run the hashed bytes or fail closed: replacing the inode after
   the hash read and before exec (that test alone is not sufficient), a
   `pwrite` to the same inode between the hash read and exec, and a
   write to the memfd after the seal. A test that tampers the file only
   before the hash sees none of them. A `PT_INTERP` ELF and a script are
   rejected. A landlock (or equivalent) that cannot be installed is 503
   and does not exec. For the restriction test, the unrestricted helper
   must actually attempt to open a named path (the release file, or cwd)
   and that open must fail under the restriction; identical output alone
   does not prove the restriction was installed.
3. Parity fixture: the same descriptor and log-encryption inputs
   through the live `/agent-policy` client and the measured helper
   produce byte-identical `agent_policy_text`, `agent_policy_sha256`,
   and `genpolicy_version_pin`, and both pins equal
   `release.genpolicy_version`. Parity against a service that has
   drifted from the release is a failure, not a pass.
4. Fail-closed tests, asserting the HTTP bodies in the table: mismatched
   text, mismatched hash, stale pin, tampered signature, tampered text,
   cross-deploy id, cross-release, unparseable `signed_at`, `signed_at`
   before `release.created_at`, `signed_at` after the post-lock clock
   on both `deploy_app_candidate` and `commit_unlock_mode_transition`,
   customer-key signature, trustee-key signature. A deploy-only future
   bound test is not enough. Signature failure does not fall through.
   Each 503 cause is distinguishable in logs even though the HTTP
   string is shared. The same table is pinned in the other direction:
   a service-present deploy whose `signed_at` is slightly ahead of the
   post-lock `clock_timestamp()` stays 200. That test is what keeps the
   new checks off the live path; a witness-only suite passes with the
   signing-service path broken.
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
