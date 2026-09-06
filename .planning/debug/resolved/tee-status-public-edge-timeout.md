---
status: resolved
trigger: CAP tenant TEE status observation remains partial during preprod admission even after the TEE hostname resolves correctly
created: 2026-07-29
updated: 2026-07-29
---

# Symptoms

- Expected: CAP observes the confidential status endpoint and returns a fresh,
  deployment-bound observation within the rollout admission window.
- Actual: PaaS remains at `observation_state=partial` with
  `observation_reason=tee_unavailable` until the 300-second gate expires.
- Error: the CAP pod resolves the exact TEE hostname to `95.217.56.248`, but
  TCP/HTTPS to that public edge address times out. The control host reaches the
  same endpoint and receives HTTP 200.
- Timeline: reproduced during the 2026-07-29 clean-cut preprod admission.
- Reproduction: deploy the reviewed canary and poll hosted status until the
  admission timeout.

# Current Focus

- hypothesis: The status probe hairpins through the public edge even though CAP
  already has an internal, TLS-preserving tenant Service path allowed by
  NetworkPolicy.
- test: Reuse the encrypted-log route's internal Service `ClusterIP:8081`
  resolution for status while retaining the TEE hostname for SNI and TLS.
- expecting: The status request avoids public DNS/edge hairpinning, remains
  bounded by five seconds, and every transport or payload failure still
  classifies the observation as unavailable or malformed.
- next_action: Build and deploy the CAP image, then rerun the contained
  staging-only admission canary.

# Evidence

- timestamp: 2026-07-29T00:00:00Z
  observation: The admission gate ended with `PaaS status did not converge
    within 300s (app=partial, deployment=partial)` and then removed all owned
    canary resources and authority.
- timestamp: 2026-07-29T00:00:01Z
  observation: CAP pod DNS and external resolvers returned `95.217.56.248` for
    `debian-ssh-canary.c42495ce.tee.enclava.dev`, but CAP TCP/HTTPS to
    `95.217.56.248:443` timed out while the control host received HTTP 200.
- timestamp: 2026-07-29T00:00:02Z
  observation: `routes/status.rs` sends the probe to the public TEE hostname.
    `routes/logs.rs` already resolves the tenant Service ClusterIP, pins the TEE
    hostname to that socket for SNI/TLS, and uses Service port 8081.
- timestamp: 2026-07-29T00:00:03Z
  observation: Live NetworkPolicy `allow-cap-api-to-tenant-attestation` permits
    CAP API egress to `10.43.0.0/16:8081`.

# Eliminated

- hypothesis: The TEE endpoint or certificate is unavailable.
  evidence: The exact hostname returned HTTP 200 with the expected staging TEE
    certificate path from the control host.
- hypothesis: The TEE hostname remains unresolvable.
  evidence: CAP pod DNS and independent resolvers returned the exact public IP.
- hypothesis: Readiness classification is incorrectly accepting partial data.
  evidence: The gate remained fail closed and timed out with
    `tee_unavailable`; only the transport path needs correction.

# Resolution

- root_cause: CAP status observation resolved the signed TEE hostname to the
  public edge and attempted a public-edge hairpin from the CAP pod. DNS was
  correct, but TCP/HTTPS to `95.217.56.248:443` timed out from CAP for the full
  admission window. The internal tenant Service path was already present and
  allowed but used only by the encrypted-log proxy.
- fix: Resolve the tenant Service `ClusterIP:8081`, pin the signed TEE hostname
  to that socket for SNI/TLS, disable redirects, and bound Service resolution,
  client construction, HTTPS, and body parsing under the existing five-second
  status deadline. Resolution/client/request failure remains
  `TeeEvidence::Unavailable`; there is no public fallback in the status path.
- verification: `cargo fmt --all -- --check`; focused status tests 32/32;
  focused log transport tests 3/3; `cargo clippy -p enclava-api --all-targets
  -- -D warnings`; full isolated serial API library suite 387/387.
- files_changed:
  - crates/enclava-api/src/routes/logs.rs
  - crates/enclava-api/src/routes/status.rs
