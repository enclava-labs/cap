# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## Security Invariants (Highest Priority)
1. **[2026-07-28] Receipt mutation authority comes only from affirming embedded evidence**
   Do instead: verify embedded evidence, require exact `/submods/cpu0/ear.status == "affirming"`, and never derive receipt-key binding from bearer claims or `report_data`.
2. **[2026-07-28] Attestation retries require typed availability failures**
   Do instead: preserve typed dependency failures through AS, retry only source I/O/transport/body failures plus 429/5xx, and let invalid evidence failures win.
3. **[2026-07-28] Release evidence must identify immutable signed bytes**
   Do instead: promote only a full repository-at-digest reference independently verified against the publishing workflow's exact keyless identity and issuer.
4. **[2026-07-28] Read receipt bindings only from verified EAR CPU evidence**
   Do instead: extract workload fields only from `/submods/cpu0/ear.veraison.annotated-evidence/init_data_claims` and the init hash only from the sibling verifier-produced `init_data`.
5. **[2026-07-10] Resolve and verify deployment authorization before Rego**
   Do instead: derive the receipt from the unique attested descriptor hash, verify its strict schema/signature/bindings, and deny on every resolver error.
6. **[2026-07-10] Keep receipt resource identifiers canonical**
   Do instead: accept exactly `repository/type/tag` with canonical `default/policy-receipts/<64-lowercase-hex>` receipt paths.
7. **[2026-07-10] Preserve terminal revocation across republish attempts**
   Do instead: check the durable tombstone before create/reactivate and never let PUT clear it.
