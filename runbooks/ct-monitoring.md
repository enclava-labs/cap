# Certificate Transparency Monitoring

`runbooks/ct-monitoring.sh` polls crt.sh for certificates issued under the
configured domain and fails when an issuer does not match the allowed issuer
regex.

## DNS Policy

Publish CAA records for the production platform zone and TEE zone. For the
current Let's Encrypt TLS-ALPN-01 path, the expected shape is:

```text
enclava.dev.       CAA 0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<id>; validationmethods=tls-alpn-01"
enclava.dev.       CAA 0 issuewild ";"
tee.enclava.dev.   CAA 0 issue ";"
tee.enclava.dev.   CAA 0 issuewild ";"
```

Replace `<id>` with the production ACME account id.

## Polling Check

```bash
CT_DOMAIN=enclava.dev \
CT_ALLOWED_ISSUER_REGEX="Let's Encrypt" \
runbooks/ct-monitoring.sh
```

The script writes:

- `runbooks/audits/ct-monitoring/seen-<domain>.txt`
- `runbooks/audits/ct-monitoring/report-<domain>.json`

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Poll succeeded and issuers matched. |
| `1` | crt.sh or local JSON processing failed. |
| `2` | At least one matching certificate used an unexpected issuer. |

Schedule the script and alert on exit code `2`.
