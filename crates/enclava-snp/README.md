# enclava-snp

The SNP-attested TLS channel to an Enclava TEE, shared by CAP (teardown token
delivery) and PaaS (managed config delivery). Report and certificate
cryptography comes from `enclava-verifier`; this crate adds the I/O (TLS leaf
learning, SPKI pinning, AMD KDS) and the collateral policy below.

## Handshake

`attest_tee` takes the admissible launch identities (`LaunchIdentity`, from
`enclava-common`) and refuses to start without at least one. Any genuine SNP
guest produces valid evidence; only HOST_DATA (the cc_init_data hash) and the
firmware measurement tell the expected deployment apart. Callers pass the
app's KBS policy authority: CAP loads it for teardown, and PaaS receives it in
CAP's internal config-token response.

1. A TLS handshake learns the TEE's per-boot leaf. Nothing is trusted yet.
2. Every later request goes over a client pinned to that leaf's SPKI SHA-256.
3. `GET /.well-known/confidential/attestation?nonce=…&domain=…&leaf_spki_sha256=…`.
   The body is capped at 256 KiB; the nonce, domain and leaf echoes must match.
4. The report's `report_data` must equal the `enclava-tee-report-data-v1`
   binding of domain, nonce, leaf SPKI and receipt-key hash.
5. The report and chain pass the policy below.
6. The report's HOST_DATA and measurement must match one admissible identity.
   A legacy descriptor pins only the first 32 measurement bytes. `attest_tee`
   then returns the pinned TLS config.

## Collateral policy

Decided once for both repos: the stricter rule of the two former
implementations wins, and features no Enclava host uses (VLEK, masked chip
IDs, Turin) are rejected instead of widening trust on one side.

| Check | Rule | Before |
| --- | --- | --- |
| Anchor | ARK SHA-256 equals a builtin AMD root (`BUILTIN_AMD_ARK_SHA256_PINS`: Milan, Genoa, Turin). | Both |
| Embedded chain | Used only when its ARK is pinned. Otherwise the VCEK is fetched from AMD KDS and chained to the builtin ARK/ASK. | PaaS rejected unpinned chains outright |
| Signatures | ARK self-signed, ASK under ARK, VCEK under ASK (RSA-PSS SHA-384), report under VCEK. | Both |
| Validity | ARK, ASK and VCEK are inside their validity windows at verification time. | PaaS only |
| Signing key | VCEK only. VLEK-signed and chip-key-masked reports are rejected. | PaaS accepted both |
| Guest policy | The DEBUG bit is rejected. | CAP only |
| Binding | VCEK HWID and reported TCB match the report (Milan/Genoa layout). Turin is rejected until `enclava-verifier` handles its TCB layout. | PaaS accepted Turin |
| Revocation | Not checked here. CAP unlock transitions still require a fresh ARK-signed CRL. | Unchanged |
| Bounds | Embedded certificates ≤ 16 KiB, VCEK ≤ 64 KiB, attestation body ≤ 256 KiB, no redirects. | Partial on each side |

## AMD KDS

`Kds { base_url, ca_bundle_path, max_attempts }` configures the fallback.
Without a CA bundle, KDS TLS trusts Mozilla's roots compiled in from
`webpki-root-certs`, not the image's CA store. Redirects are never followed.
429 and 5xx responses are retried on a jittered 2/5/10/20/30 s schedule, and
`Retry-After` is honored up to 120 s. CAP makes one attempt because the
teardown lane has its own deadline; PaaS makes eight.

VCEKs are cached per process, keyed by product, HWID and the complete reported
TCB, until the earlier of one hour and the certificate's `notAfter`. Cached
bytes are re-verified on every use.

`certs/` holds sev 7.1.0's builtin AMD ARK/ASK roots. The ARK pins above match
them, and an `enclava-api` test keeps the pins in sync with the roots the CLI
gets from `sev`.

## Logs

Target `enclava_snp`:

- `attestation_timing` info events: stage, outcome, attempt, HTTP status and
  elapsed time. Never URLs, chip IDs or guest content.
- `tee_attestation_unanchored_chain` warning when evidence carries an
  unpinned chain.
