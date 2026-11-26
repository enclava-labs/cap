# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately by email to <security@enclava-labs.com>.

Include what you can of the following:

- the component (`enclava-api`, `enclava-cli`, `enclava-init`,
  `enclava-engine`, the verifier, or a workflow or script);
- the commit or release you tested;
- the steps to reproduce, and what an attacker gains;
- whether the issue depends on a particular configuration.

## Scope

In scope: the code, workflows, and release artifacts of this repository.

Issues in the components CAP depends on (Kata Containers, Trustee, AMD SEV-SNP
firmware, Sigstore) belong with those projects, unless the problem is in how
CAP uses them.

## Supported versions

Fixes land on `main` and ship in the next release. Older releases are not
patched.
