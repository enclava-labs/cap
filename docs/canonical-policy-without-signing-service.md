# Canonical policy validation without the signing service

Status: design only. This document does not change acceptance.
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

Deploy (`deployments.rs`) and unlock redeploy (`unlock.rs`) both enter
through this function. Both must keep that single gate. Do not add a
second acceptance function for the absent-service case.

The platform signature check is a different question. Policy artifacts
are signed by the off-cluster signing-service key
(`policy_artifact_signing_input`: purpose `enclava-policy-artifact-v1`,
metadata hash, rego hash). That signature binds issuance. It does not
bind "this text is what the current generator would emit." A historical
or compromised signer can put the current pin string in metadata and a
weaker policy in `agent_policy_text`. The live `/agent-policy` response
is the check that catches that. Removing it because a customer artifact
was supplied is a downgrade, not a convenience path.

`SIGNING_SERVICE_PUBKEY_HEX` and `PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX`
stay separate trust domains. Startup already rejects setting them equal.
The in-TEE trustee key must not become the acceptance authority for
`/sign` artifacts, and the signing-service private key must not be
loaded into CAP or into the guest.

## Trust anchor

The witness is the signed platform release, not the customer and not a
cache of the signing service.

The release is already verified against the profile root at startup. It
already pins `genpolicy_version`, `policy_template_id`,
`policy_template_sha256`, and `policy_template_text`, and it carries
`signing_service_pubkey_hex` and `created_at`. Those pins are necessary
and not sufficient: a pin string inside a customer-supplied artifact is
claimed by the signer, and CAP does not contain genpolicy.

Future implementation, coordinated per `AGENTS.md` (release schema is
consumed by the API, the CLI, and enclava-init):

- Add an additive signed release field for the canonical-policy
  generator measurement: generator id, digest, and the
  `AgentPolicyRequest` schema version it consumes. Empty or absent
  means the witness is not configured.
- The generator runs locally, in-process or as a digest-pinned helper
  whose measurement is that release field. It is not a network call and
  not the signing service under another name.
- Inputs are only the already signature-checked descriptor, the already
  validated `log_encryption` config, and the release-pinned template
  bytes. Customer-supplied policy text, template text, or pin strings
  are not inputs.
- Output is an `AgentPolicyResponse` with the same three fields
  `/agent-policy` returns today. Acceptance then calls the existing
  `validate_canonical_agent_policy`. No parallel compare.

Rejected alternatives:

- Customer keyring or descriptor signature alone. Already required.
  Does not bind current generator output. Forbidden by #263.
- Platform signature alone. Proves issuance under
  `SIGNING_SERVICE_PUBKEY_HEX`, not current canonicity.
- A cache of a previous `/agent-policy` response. Stale by
  construction, empty on first deploy, and still depends on the service
  having been reachable.
- Reusing the trustee policy key. Collapses the two trust domains.

## Acceptance rules

When the signing-service client is present, it remains the only
acceptance source. The witness is not consulted. A disagreement between
a live service response and a local witness is an operator alarm in
parity tests, never a reason to accept the witness output instead.

When the client is absent:

| Condition | Result |
| --- | --- |
| No release loaded, or the generator measurement field is absent/empty, or the generator fails, or its pin does not equal `release.genpolicy_version` exactly | 503 `canonical policy validation requires the platform signing service`. A broken or unconfigured witness is not a bypass. Keep this string so existing clients do not fork. |
| Witness configured, no `signed_policy_artifact` | 503 `signed_policy_artifact required when the platform signing service is absent`. CAP does not call `/sign` and does not synthesize an artifact. |
| Pubkey absent | Existing 503 `platform signing-service pubkey required for signed_policy_artifact verification`. Unchanged, and still checked. |
| Witness and artifact disagree | Existing `SigningServiceError::Mismatch` names from `validate_canonical_agent_policy` (`canonical_agent_policy_text`, `canonical_agent_policy_sha256`, `canonical_genpolicy_version_pin`, `generated_agent_policy.expected_agent_policy_hash`). Not 503: the witness ran and rejected. |
| Signature, field caps, or metadata binds fail | Existing `validate_signed_artifact` errors. The witness does not skip them. |
| Witness, signature, customer authority, and metadata binds all pass | Same `SignedPolicyArtifact` the service path returns. The caller persists and enqueues. This function does not enqueue. |

The witness path adds checks the live path gets by trusting the
service:

1. `witness.genpolicy_version_pin == release.genpolicy_version`.
   Compare to the loaded release, not to the artifact's own pin.
2. Refuse to run the witness when `platform_release_envelope` is
   absent. There is no trust anchor.
3. `descriptor.policy_template_sha256` must equal the release template
   hash. `descriptor_platform_binding_for` already enforces this when a
   release is loaded; the witness path must not skip that binding.

`log_encryption` is a generator input, not a field on
`SignedPolicyArtifact`. The witness must be invoked with the same
validated config the deploy request carried. If that config changes the
generated text, the text compare covers it. Do not invent a second
log-encryption signature in this design.

## Stale and replay

Existing metadata binds stay and are not optional on the witness path:
`app_id`, `deploy_id`, `descriptor_core_hash`,
`descriptor_signing_pubkey`, `platform_release_version`,
`policy_template_id`, `policy_template_sha256`, and the expected policy
hashes (`validate_signed_artifact_common`). A cross-deploy or
cross-release artifact already fails those compares.

`signed_at` is inside the platform signature and is not windowed today.
Do not copy the owner-rotation 900-second directive age
(`MAX_DIRECTIVE_AGE_SECONDS` in `routes/orgs.rs`). That bound exists for
an online owner directive. An absent-service deploy is useful only when
the artifact was produced earlier, by a signer that held the platform
key, and is being presented now. A 15-minute TTL would reject the
artifacts this path exists to accept, without adding downgrade
protection the witness text compare does not already provide.

Stale handling for the witness path:

- Future skew: `signed_at` must not be more than the existing
  precheck skew (300 seconds) ahead of `clock_timestamp()` read after
  `lock_org_signing_authority_lane` is held. Same clock rule as
  `lock_org_signing_authority_lane_now`: do not sample time before the
  lock.
- Floor: `signed_at` must not predate the loaded release envelope's
  `created_at`. A release rollback floor already rejects older
  envelopes; an artifact older than the release it claims is a
  downgrade. This is the anti-replay bound, not a short TTL.
- Content staleness is the witness compare. An old artifact whose text
  is not what the pinned generator emits now fails
  `canonical_agent_policy_text`, even if the signature and the pin
  string still verify.
- Key rotation is the pubkey check. After
  `signing_service_pubkey_hex` changes, artifacts signed by the retired
  key fail `InvalidSignature`. Do not accept them under the witness.

## Transactional enqueue

`accept_signed_workload_artifacts` inserts the workload-artifact row
and calls `enqueue_signed_policy_reconciliation` on the same
transaction. That bumps `kbs_signed_policy_reconciliation.desired_generation`.
Deploy and unlock redeploy already call it only after
`resolve_signed_policy_artifact` returns `Ok`, inside the transaction
that also holds the org signing-authority lane and repeats
`validate_customer_authority_in_tx`. Rollback of that transaction rolls
back the row and the generation together (covered by the existing
acceptance tests).

The witness path must return into that same caller. It must not enqueue
from `resolve_signed_policy_artifact`, and it must not open its own
transaction. Unlock-mode transition and rollback already enqueue
previously accepted artifacts; they must not grow a witness dependency.

One ordering gap the future implementation must close for the witness
path only: today `resolve_signed_policy_artifact` runs **before** the
acceptance transaction and the lane lock (`deployments.rs` resolve,
then `lock_org_signing_authority_lane`, then
`validate_customer_authority_in_tx`, then
`accept_signed_workload_artifacts`). Repeating customer authority inside
the lock does not repeat the canonical compare. The witness compare
must be repeated inside that locked transaction, immediately before
`accept_signed_workload_artifacts`, against the same release the
transaction will commit under. A witness result from before the lock is
not authority. The live service path is unchanged by this design; do
not move it as a drive-by.

## Threats

| Threat | Result |
| --- | --- |
| Customer substitutes a weaker `agent_policy_text` or hash | Witness compare rejects. Customer signature does not authorize the policy text. |
| Artifact claims the current genpolicy pin but was produced by an older generator | Pin must equal the release pin, and text must equal a local run of the release-pinned generator. Either mismatch rejects. |
| Artifact signed by the customer key, or by the trustee policy key | `validate_signed_artifact` rejects. Those keys are not the policy acceptance authority. |
| Replay onto another app, deploy, descriptor, or release | Existing metadata binds reject. |
| Replay of a pre-release artifact after a release advance | `signed_at` floor against `release.created_at`, plus `platform_release_version` bind. |
| Signing service suppressed to force a weaker path | No witness configured means the same 503 as today. Witness configured means the same compares, not a subset. |
| Split brain between service and witness | Service present: service wins, witness is not an accept path. |
| Witness or release missing | 503. Never fall through to customer checks. |
| CAP asked to sign because the service is down | Refused. No private signing key in CAP. No synthesized artifact. |

## Sibling sites

- `generate_agent_policy` (`routes/deployments/generic.rs`, and the
  PaaS forwarder) returns a different 503, `platform signing service is
  not configured`. That route is a preflight broker. It does not accept
  artifacts and must not grow a witness. Ruled out.
- Unlock-mode transition revalidates a stored artifact with
  `validate_signed_artifact` and the signing-service pubkey. It does
  not call `/agent-policy`. Requiring a fresh witness there would fail
  unlock when the generator moves, which is a separate product
  decision. Ruled out of this design.
- Rollback enqueues an already-accepted artifact. Ruled out.
- Org owner bootstrap and rotation talk to the signing service for
  owner state, not for canonical agent policy. Ruled out.

## Implementation gate

A later change may enable the absent-service path only when all of the
following are true. Until then the 503 in
`resolve_signed_policy_artifact` stays, including for a supplied
artifact.

1. Parity fixture: the same descriptor and log-encryption inputs through
   the live `/agent-policy` client and the local witness produce
   byte-identical `agent_policy_text`, `agent_policy_sha256`, and
   `genpolicy_version_pin`.
2. Fail-closed tests: mismatched text, mismatched hash, stale pin,
   tampered signature, tampered text, cross-deploy id, cross-release,
   `signed_at` before `release.created_at`, `signed_at` beyond skew,
   customer-key signature, trustee-key signature. All rejected with the
   errors in the table above.
3. Isolated DB test: valid artifact, service absent, witness present,
   release loaded. The acceptance transaction persists the artifact and
   increments `desired_generation` together; aborting the transaction
   leaves both unchanged. Same shape as the existing
   `accept_signed_workload_artifacts` commit/rollback tests.
4. Sabotage: deleting the witness compare, or accepting when the
   witness is absent, fails (2) or the 503 pin. A regression test that
   passes in both states is not evidence.
5. The enablement flag or release field defaults off. Clearing it
   restores the 503. No migration. No KBS schema change.

## Rollback

This design adds no runtime flag and no schema. Reverting the document
does not change acceptance. A future implementation reverts by clearing
the generator measurement field or the enablement flag, which must
return the 503 above without a database migration.
