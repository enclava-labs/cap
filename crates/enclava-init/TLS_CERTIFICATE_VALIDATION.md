# Static TLS certificate validation (enclava-init)

`src/tls_certificate.rs` provisions the tenant-ingress TLS certificate through
the workload-attested broker and validates retained state on the encrypted
`tls-state` volume before reuse.

## Trust model

- Every chain — retained on disk or freshly delivered by the broker — is
  validated with `rustls-webpki` `EndEntityCert::verify_for_usage` for
  `serverAuth` against the independently trusted public root store
  (`webpki-roots`, the Mozilla CA certificate programme). Path building
  enforces per-certificate signatures, issuer validity windows, CA basic
  constraints/path lengths, name constraints, and the serverAuth EKU.
- Certificates carried inside a chain never extend the trust store. A
  trailing self-signed root, a root sent in the same broker response, a
  leaf-only chain, or a chain rooted at an untrusted CA all fail closed.
- The leaf must cover every configured hostname, and a signature probe
  verifies the leaf was issued for exactly the retained/generated private key.
- The public root store deliberately does not contain the Let's Encrypt
  **staging** roots, so staging-issued chains are rejected by default.
  Production evidence (enclava-work, reviewed 2026-09-09) shows the live
  `ACME_DIRECTORY_URL`/`TENANT_CADDY_ACME_CA`/signed-release
  `tenant_caddy_acme_ca` all point at the production Let's Encrypt directory,
  whose chains validate against the public store. A future staging deployment
  needs explicit, separately reviewed trust support (e.g. pinned reviewed
  staging roots plus a signed issuer selection); it must never be inferred
  from URLs, chain contents, or broker responses, and it is not implemented
  here.

## Retained-state policy

- Reuse is only permitted when `certificates/tls.crt` and
  `certificates/tls.key` are regular files (no symlinks, including dangling
  ones; no directories or other non-regular inodes; stat errors fail) and the
  full anchored validation passes. Repeated valid reuse performs zero broker
  calls.
- Invalid retained state aborts init without ordering a replacement
  certificate and without replacing the retained private key. This covers
  malformed, untrusted, hostname-mismatched, and key-mismatched state, and
  certificates that are expired but were *not* otherwise valid within their
  own window (see renewal below). Recovery is explicit operator removal of
  the stale `tls.crt`.
- Only an actually missing certificate (`ENOENT`) starts issuance. A
  certificate-less retained key is kept and reused for the new CSR, so an
  interrupted first issuance retries with the same key.
- Fresh broker responses are validated with the same anchored checks before
  `tls.crt` is written.

`notBefore` tolerates at most 300 s of clock skew (validation is retried at
the certificate's own `notBefore`); expiry is strict at the current time.

## Renewal

A retained certificate is **due** when it is expired but otherwise valid —
the full anchored validation passes when evaluated at the start of the
leaf's own validity window — or when it is valid but its remaining lifetime
is under one third of its total validity (`notAfter − notBefore`, ~30 days
for a 90-day Let's Encrypt certificate).

- Due certificates are renewed through the same broker path as first
  issuance. The CSR is built from the *retained* private key and the
  configured hostnames, so the ACME order carries the exact same identifier
  set and the CA counts it as a renewal rather than a new certificate. The
  retained key is never rotated or regenerated while a certificate exists.
- The renewed chain is validated with the identical anchored checks before
  `tls.crt` is replaced atomically (`writes::atomic_write`).
- If renewal fails while the retained certificate is still unexpired, it
  keeps serving: the failure is logged as a warning and the next check
  retries. If the retained certificate is expired, a failed renewal is the
  terminal provisioning error.
- Checks run at every boot and, in broker mode, every 15 minutes inside
  the enclava-init stay-alive loop (the same persisted ACME cooldown
  marker and per-attempt attestation token apply). Each check is a cheap
  local validation: the broker is contacted only when the certificate is
  due and no persisted cooldown deadline is still pending, so a deferred
  rate-limited renewal retries within 15 minutes of the cooldown ending.
  Only the boot check waits out a rate limit (bounded at four hours per
  wait): the runtime renewal never sleeps on an ACME cooldown — a
  still-pending persisted deadline returns before any broker request, and
  a fresh `acme_rate_limited` response persists the broker's deadline
  (honored out to eight days, covering the provider's weekly windows) and
  defers to a later check, so a long provider cooldown neither parks the
  loop nor triggers a re-order inside the limit. A successful renewal is
  mirrored into the caddy runtime handoff atomically — `tls.crt` only,
  since renewals reuse the retained key and the runtime `tls.key` never
  changes; tenant-ingress watches `tls.crt` and restarts caddy on change
  because the generated Caddyfile runs with `admin off`.
- In broker mode the stay-alive loop also re-evaluates readiness from the
  certificate caddy currently serves once a minute, independent of the
  renewal check: an expired or not-yet-valid runtime certificate clears
  readiness (`tls-certificate-unusable`) within a minute even while a
  rate-limited renewal is deferred. Restoring readiness waits until the
  runtime `tls.crt` has been in place for two minutes, past the
  tenant-ingress certificate-watch reload window, so readiness never
  claims a renewed certificate is served before caddy actually loads it.
