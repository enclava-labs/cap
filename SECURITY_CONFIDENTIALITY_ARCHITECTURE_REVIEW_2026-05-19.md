# CAP Security and Confidentiality Architecture Review - 2026-05-19

## Scope and Method

This review treats source code, tests, deployment manifests, and CI workflows as the only source of truth. Documentation, README files, prior review notes, and comments that are not backed by executable behavior are not used as evidence.

Reviewed areas:

- API authentication, authorization, routing, outbound clients, environment gates, deployment flow, signing service, billing, and config handling under `crates/enclava-api`.
- CLI customer-side deployment signing flow under `crates/enclava-cli`.
- TEE bootstrap, Trustee verification, seed derivation, unlock, and certificate request paths under `crates/enclava-init`.
- Kubernetes manifest generation under `crates/enclava-engine`.
- Static deployment manifests under `deploy/api`.
- Build and release workflows under `.github/workflows`.

This is a source-level architecture review. It does not assert what is currently deployed unless that deployment state is represented in this repository.

## Executive Verdict

The confidentiality architecture has several strong pieces: signed customer deployment descriptors, KBS policy binding, in-TEE Trustee verification, sidecar image verification, strict default workload container hardening, per-workload network policies, separate session/config JWT audiences, and release-time environment gates that block several debug bypasses.

The practical security posture is weakened by authorization gaps in the API. The most serious issue is that API key creation accepts arbitrary scopes from any authenticated org context and does not require owner/admin privileges or `org:admin`. Combined with missing authorization on create/deploy/rollback routes, a low-privilege member or limited API key can escalate into privileged workload mutation. There is also an explicit TODO in signer rotation where the confirmation token is required but never validated.

Several confidentiality controls are also configuration-dependent in ways the release gates do not enforce. In particular, Trustee policy verification can be skipped while `enclava-init` still releases seeds, the legacy privileged bootstrap path can be enabled in production, and the KBS URL defaults to HTTP.

Overall: the core design is promising and several cryptographic and runtime controls are well-considered, but the API authorization boundary is underengineered relative to the platform's confidentiality goals.

## Code-Derived Architecture Summary

### Control Plane

The API process initializes release gates, optional signed platform release verification, sidecar image verification, database state, signing keys, attestation settings, DNS, ACME, KBS, and signing-service settings before serving routes (`crates/enclava-api/src/main.rs:495`, `crates/enclava-api/src/main.rs:500`, `crates/enclava-api/src/main.rs:515`, `crates/enclava-api/src/main.rs:543`, `crates/enclava-api/src/main.rs:598`, `crates/enclava-api/src/main.rs:680`, `crates/enclava-api/src/main.rs:704`). The router mounts auth, org, app, deploy, config, domain, status, unlock, billing, and workload routes, then applies a global API rate governor and CORS layer (`crates/enclava-api/src/lib.rs:45`, `crates/enclava-api/src/lib.rs:63`, `crates/enclava-api/src/lib.rs:88`, `crates/enclava-api/src/lib.rs:102`, `crates/enclava-api/src/lib.rs:138`, `crates/enclava-api/src/lib.rs:160`, `crates/enclava-api/src/lib.rs:178`, `crates/enclava-api/src/lib.rs:190`, `crates/enclava-api/src/lib.rs:205`, `crates/enclava-api/src/lib.rs:231`, `crates/enclava-api/src/lib.rs:250`, `crates/enclava-api/src/lib.rs:273`).

API authentication accepts either session JWTs or API keys from `Authorization: Bearer` or `X-API-Key` (`crates/enclava-api/src/auth/middleware.rs:113`). API-key auth resolves the key, then accepts it only if the key creator is still an active member of the key org (`crates/enclava-api/src/auth/middleware.rs:149`). Session auth resolves the session user and active membership (`crates/enclava-api/src/auth/middleware.rs:167`).

### Customer-Signed Deployment Chain

The CLI requires deployment images to be digest-pinned before descriptor signing (`crates/enclava-cli/src/commands/app.rs:381`). It loads a verified platform release, requires digest-pinned sidecar anchors, requires a trusted local org keyring, checks the local deployer key is an owner/admin/deployer in that keyring, requires a pinned image signer identity, builds a descriptor, fetches generated agent policy, computes expected agent-policy, `cc_init_data`, and KBS policy hashes, then signs the policy artifact and descriptor (`crates/enclava-cli/src/commands/app.rs:393`, `crates/enclava-cli/src/commands/app.rs:396`, `crates/enclava-cli/src/commands/app.rs:425`, `crates/enclava-cli/src/commands/app.rs:432`, `crates/enclava-cli/src/commands/app.rs:433`, `crates/enclava-cli/src/commands/app.rs:466`, `crates/enclava-cli/src/commands/app.rs:480`, `crates/enclava-cli/src/commands/app.rs:533`, `crates/enclava-cli/src/commands/app.rs:554`, `crates/enclava-cli/src/commands/app.rs:558`, `crates/enclava-cli/src/commands/app.rs:561`, `crates/enclava-cli/src/commands/app.rs:571`).

The API deploy path verifies image signatures against the app's pinned signer identity, resolves the image digest, and sends customer descriptor, org keyring, and signed policy artifact into signing-service validation when required (`crates/enclava-api/src/routes/deployments.rs:521`, `crates/enclava-api/src/routes/deployments.rs:540`, `crates/enclava-api/src/signing_service.rs:280`, `crates/enclava-api/src/signing_service.rs:399`, `crates/enclava-api/src/signing_service.rs:481`, `crates/enclava-api/src/signing_service.rs:554`).

### Runtime Confidentiality Path

Generated workload manifests use a Kata SNP runtime class, disable service account token automount, disable service links, and apply runtime node constraints (`crates/enclava-engine/src/manifest/statefulset.rs:123`). The default app and attestation proxy containers are non-root, disallow privilege escalation, drop capabilities, and use read-only root filesystems; default Caddy is non-root, disallows privilege escalation, and drops capabilities, but keeps a writable root filesystem (`crates/enclava-engine/src/manifest/containers.rs:240`, `crates/enclava-engine/src/manifest/containers.rs:524`, `crates/enclava-engine/src/manifest/containers.rs:777`). `enclava-init` is the explicit privileged component used for storage setup (`crates/enclava-engine/src/manifest/containers.rs:338`).

Before writing seed material, `enclava-init` runs in-TEE verification and then provisions TLS, storage, and unlock/config services (`crates/enclava-init/src/main.rs:103`). Trustee verification checks active policy, descriptor core hash, descriptor signature, `cc_init_data` forward chain, keyring fingerprint, deployer membership, policy signature, and policy metadata anchors (`crates/enclava-init/src/trustee_verify.rs:95`, `crates/enclava-init/src/trustee_verify.rs:116`, `crates/enclava-init/src/trustee_verify.rs:128`, `crates/enclava-init/src/trustee_verify.rs:136`, `crates/enclava-init/src/trustee_verify.rs:153`, `crates/enclava-init/src/trustee_verify.rs:161`, `crates/enclava-init/src/trustee_verify.rs:173`).

## Findings

### 1. Critical: API Key Creation Allows Privilege Escalation to Any Scope

The API key creation route accepts a caller-provided list of scopes and does not require an owner/admin role, `org:admin`, or any existing scope before creating the key (`crates/enclava-api/src/routes/auth.rs:261`, `crates/enclava-api/src/routes/auth.rs:277`, `crates/enclava-api/src/routes/auth.rs:278`, `crates/enclava-api/src/routes/auth.rs:290`). The API key creation helper validates only that each requested scope is one of the known valid names (`crates/enclava-api/src/auth/api_key.rs:19`, `crates/enclava-api/src/auth/api_key.rs:81`). Valid scopes include `apps:read`, `apps:write`, `config:write`, and `org:admin` (`crates/enclava-api/src/auth/api_key.rs:19`).

API keys can be supplied as bearer tokens or through `X-API-Key` (`crates/enclava-api/src/auth/middleware.rs:113`). An API key is accepted if the key validates and its creator remains an active member of the org (`crates/enclava-api/src/auth/middleware.rs:149`). Scope enforcement exists as a helper, but it is not called by API key creation (`crates/enclava-api/src/auth/scopes.rs:37`, `crates/enclava-api/src/routes/auth.rs:277`).

Practical impact:

- A regular org member can mint an API key with `org:admin`, `apps:write`, and `config:write`.
- A limited API key can mint a more privileged API key.
- The escalated key can reach routes that do correctly check `org:admin`, `apps:write`, or `config:write`.

Recommended fix:

- Require owner/admin role and `org:admin` for API key creation and revocation.
- For API-key callers, require the new key's scopes to be a subset of the caller key's scopes.
- Add regression tests proving a low-privilege member and a limited API key cannot mint `org:admin` or broader scopes.

### 2. High: App Create, Deploy, and Rollback Lack Route-Level Authorization

`create_app` accepts only `AuthContext` and proceeds into validation, app creation, DNS setup, and database inserts without `require_admin` or `require_scope` (`crates/enclava-api/src/routes/apps.rs:282`, `crates/enclava-api/src/routes/apps.rs:373`). This contrasts with `delete_app`, which requires admin and `apps:write` (`crates/enclava-api/src/routes/apps.rs:509`).

`deploy` accepts only `AuthContext`, fetches the app, resolves the image digest, verifies the image signature, prepares artifacts, updates deployment state, and spawns apply without an initial role or scope check (`crates/enclava-api/src/routes/deployments.rs:452`, `crates/enclava-api/src/routes/deployments.rs:459`, `crates/enclava-api/src/routes/deployments.rs:506`, `crates/enclava-api/src/routes/deployments.rs:540`, `crates/enclava-api/src/routes/deployments.rs:738`, `crates/enclava-api/src/routes/deployments.rs:947`). `rollback` has the same issue before mutating app containers and spawning apply (`crates/enclava-api/src/routes/deployments.rs:997`, `crates/enclava-api/src/routes/deployments.rs:1020`, `crates/enclava-api/src/routes/deployments.rs:1268`).

Other routes in this area do apply authorization. Generated agent policy requires `apps:write` (`crates/enclava-api/src/routes/deployments.rs:387`), and secret-agent deployment creation requires `apps:write` (`crates/enclava-api/src/routes/secret_agent.rs:61`).

Practical impact:

- Any authenticated org member can create workloads.
- Any authenticated org member or any API key accepted for the org can attempt deployment or rollback.
- In combination with finding 1, a limited key can escalate and mutate workloads.

Recommended fix:

- Require `apps:write` for create, deploy, and rollback.
- Consider requiring admin/owner for create and rollback, with deployer-level access only for deploy if the org keyring model intends that split.
- Add route tests for member, limited API key, deployer key, admin, and owner cases.

### 3. High: Signer Identity Rotation Requires a Token but Never Validates It

The signer rotation route requires owner and `apps:write` (`crates/enclava-api/src/routes/apps.rs:689`). It accepts `email_confirmation_token` in the request (`crates/enclava-api/src/routes/apps.rs:674`). For non-initial rotations, it rejects missing tokens (`crates/enclava-api/src/routes/apps.rs:719`), but then explicitly does not validate the token before updating signer identity (`crates/enclava-api/src/routes/apps.rs:735`, `crates/enclava-api/src/routes/apps.rs:743`).

Deploy uses the app's pinned signer subject and issuer to build a cosign policy (`crates/enclava-api/src/routes/deployments.rs:521`) and verifies the candidate image against that policy (`crates/enclava-api/src/routes/deployments.rs:540`).

Practical impact:

- If an owner account or owner API key is compromised, signer identity can be rotated without an independent confirmation path.
- If combined with the API key escalation bug, a low-privilege caller may be able to create a path toward signer rotation if it can acquire or abuse owner-equivalent permissions elsewhere.
- Once rotated, an attacker can deploy images signed by the attacker-controlled identity.

Recommended fix:

- Implement confirmation token issuance, storage, expiry, one-time use, and validation before signer identity changes.
- Require a recent session or second factor for signer rotation.
- Add tests that missing, invalid, expired, reused, and wrong-app tokens fail.

### 4. High: Trustee Policy Verification Can Be Skipped While Seeds Are Still Released

Signed platform release loading is enabled only when one of `TRUSTEE_POLICY_READ_AVAILABLE`, `ENCLAVA_USE_PLATFORM_RELEASE`, or `ENCLAVA_PLATFORM_RELEASE_PATH` is set (`crates/enclava-api/src/main.rs:270`). Attestation config reads `TRUSTEE_POLICY_READ_AVAILABLE`; if true, it requires workload artifact and policy endpoints and release public keys (`crates/enclava-api/src/main.rs:318`, `crates/enclava-api/src/main.rs:364`, `crates/enclava-api/src/main.rs:371`). If false, the platform can still construct attestation config without Trustee policy read verification.

The deploy path requires customer-signed deployment artifacts only if the signing service is configured, `REQUIRE_CUSTOMER_SIGNED_POLICY_ARTIFACT` is set, or attestation settings indicate Trustee policy read or release public keys (`crates/enclava-api/src/routes/deployments.rs:55`, `crates/enclava-api/src/main.rs:660`, `crates/enclava-api/src/routes/deployments.rs:485`).

Inside the TEE, `enclava-init` calls verification before seed writes (`crates/enclava-init/src/main.rs:103`). However, if Trustee policy read is unavailable, it calls `verify_chain_or_skip(None)` and continues after a warning (`crates/enclava-init/src/main.rs:1141`). `verify_chain_or_skip` returns `Ok(false)` rather than failing when the bundle is absent (`crates/enclava-init/src/trustee_verify.rs:193`). The caller only treats an error as fatal; `Ok(false)` does not block seed release (`crates/enclava-init/src/main.rs:104`).

Release environment gates do not require `TRUSTEE_POLICY_READ_AVAILABLE`, `ENCLAVA_USE_PLATFORM_RELEASE`, or a customer-signed-policy requirement (`crates/enclava-api/src/env_gates.rs:14`, `crates/enclava-api/src/env_gates.rs:42`).

Configuration-dependent impact:

- A production-like deployment can run without in-TEE policy verification if the relevant environment is absent.
- In that mode, seed release depends on weaker external configuration assumptions.

Recommended fix:

- In release builds, fail closed unless Trustee policy read and signed platform release validation are explicitly enabled.
- Make seed release fatal when `verify_chain_or_skip` returns false, except in a clearly named development mode that release gates reject.
- Add release-mode tests for missing Trustee policy read and missing platform release.

### 5. High: API Scope Enforcement Is Inconsistent Across Read and Metadata Routes

`require_scope` enforces scopes only when the caller used an API key; session users bypass scope checks by design (`crates/enclava-api/src/auth/scopes.rs:37`). Some sensitive routes use it correctly, such as config token issuance (`crates/enclava-api/src/routes/config.rs:31`) and secret-agent deployment (`crates/enclava-api/src/routes/secret_agent.rs:61`).

Several routes that expose or mutate app metadata lack scope checks:

- App list and get do not require `apps:read` (`crates/enclava-api/src/routes/apps.rs:465`, `crates/enclava-api/src/routes/apps.rs:490`).
- Deployment history does not require `apps:read` (`crates/enclava-api/src/routes/deployments.rs:954`).
- Domain lookup does not require `apps:read` (`crates/enclava-api/src/routes/domains.rs:511`).
- Status and logs do not require `apps:read` (`crates/enclava-api/src/routes/status.rs:26`, `crates/enclava-api/src/routes/status.rs:105`).
- Unlock status and endpoint lookup do not require `apps:read` (`crates/enclava-api/src/routes/unlock.rs:323`, `crates/enclava-api/src/routes/unlock.rs:375`).
- Config key listing, metadata sync, and metadata delete do not require `apps:read` or `config:write` (`crates/enclava-api/src/routes/config.rs:87`, `crates/enclava-api/src/routes/config.rs:136`, `crates/enclava-api/src/routes/config.rs:194`).

Practical impact:

- A key with an unrelated scope can read app names, status, deployment history, domains, unlock endpoint URLs, log surfaces, and config key names.
- Config metadata can be forged or deleted without `config:write`.
- This does not expose config values directly, but it leaks operational metadata and weakens the scoped API contract.

Recommended fix:

- Apply `apps:read` to all app status, domain, deployment-history, unlock-read, and config-key listing routes.
- Apply `config:write` to config metadata sync and delete, or replace those routes with an internal attested callback that cannot be called by general org auth.
- Add a route authorization matrix test covering every router entry in `crates/enclava-api/src/lib.rs`.

### 6. Medium: Legacy Bootstrap Path Enables Privileged Root Workload Containers in Release

Release environment gates block several debug flags, including `SKIP_COSIGN_VERIFY`, `COSIGN_ALLOW_HTTP_REGISTRY`, `ALLOW_EPHEMERAL_KEYS`, and invalid TLS certificate flags (`crates/enclava-api/src/env_gates.rs:14`). They do not block `LEGACY_BOOTSTRAP_SCRIPT`.

The manifest generator reads `LEGACY_BOOTSTRAP_SCRIPT` (`crates/enclava-engine/src/manifest/containers.rs:22`). When enabled, the app container is generated with a shell wrapper, root user, privilege escalation, and `SYS_ADMIN` capability (`crates/enclava-engine/src/manifest/containers.rs:159`, `crates/enclava-engine/src/manifest/containers.rs:227`). Legacy Caddy similarly runs root with privilege escalation and `SYS_ADMIN` plus `NET_BIND_SERVICE` (`crates/enclava-engine/src/manifest/containers.rs:701`, `crates/enclava-engine/src/manifest/containers.rs:761`).

The default non-legacy app and Caddy containers are much harder: the app is non-root, no privilege escalation, read-only root filesystem, and dropped capabilities; Caddy is non-root, no privilege escalation, and dropped capabilities, though its root filesystem remains writable (`crates/enclava-engine/src/manifest/containers.rs:240`, `crates/enclava-engine/src/manifest/containers.rs:777`).

Configuration-dependent impact:

- One environment variable can revert tenant app and Caddy containers to a privileged/root posture.
- If accidentally set in production, this substantially expands the blast radius of a workload compromise.

Recommended fix:

- Add `LEGACY_BOOTSTRAP_SCRIPT` to release-blocked flags.
- If still needed, require a compile-time development feature or an explicit non-release build.
- Add manifest tests proving release-mode generation never emits privileged app or Caddy containers.

### 7. Medium: KBS Defaults to HTTP and Signed Release Validation Allows HTTP

`cc_init_data` defaults the KBS URL to `http://kbs-service.trustee-operator-system.svc.cluster.local:8080` (`crates/enclava-engine/src/manifest/cc_init_data.rs:11`). A KBS CA certificate is optional (`crates/enclava-engine/src/manifest/cc_init_data.rs:22`). Signed platform release validation permits both `http` and `https` schemes for `trustee_kbs_url` (`crates/enclava-api/src/platform_release.rs:249`). Startup release validation only checks that environment matches the signed release, and checks the CA only when the release includes a nonempty CA value (`crates/enclava-api/src/main.rs:515`, `crates/enclava-api/src/main.rs:531`).

The KBS fetcher performs a simple GET to the configured KBS URL and expects a raw 32-byte wrap key on success (`crates/enclava-init/src/kbs_fetch.rs:33`, `crates/enclava-init/src/kbs_fetch.rs:68`).

Configuration-dependent impact:

- Wrap-key confidentiality and integrity depend on cluster network isolation and KBS policy behavior if HTTP is used.
- A pod-network attacker or misrouted service path has a larger opportunity than it would under HTTPS with a pinned CA.

Recommended fix:

- Require HTTPS plus pinned CA for release configurations unless the KBS address is proven to be inside a hardware-protected local channel.
- If HTTP remains supported for development, gate it behind release-blocked environment or signed-release policy.

### 8. Medium: TLS Certificate Broker Accepts Caller-Supplied `cc_init_data_hash` When Trustee Omits It

The workload TLS route requires an attestation token, verifies it through Trustee, and extracts the descriptor core hash from Trustee claims (`crates/enclava-api/src/routes/workload_tls.rs:27`, `crates/enclava-api/src/routes/workload_tls.rs:49`, `crates/enclava-api/src/routes/workload_tls.rs:65`). It then selects the init-data hash using `extract_init_data_hash(claims).or_else(body.cc_init_data_hash...)` (`crates/enclava-api/src/routes/workload_tls.rs:157`).

The route still checks the selected hash against the deployment descriptor and limits hostnames to descriptor-bound domains (`crates/enclava-api/src/routes/workload_tls.rs:109`, `crates/enclava-api/src/routes/workload_tls.rs:116`, `crates/enclava-api/src/routes/workload_tls.rs:224`). The init component sends a local `cc_init_data_hash` when requesting a certificate (`crates/enclava-init/src/tls_certificate.rs:62`, `crates/enclava-init/src/tls_certificate.rs:127`).

Potential impact:

- The fallback does not allow arbitrary hostnames because descriptor checks still apply.
- It does weaken the attested runtime binding when Trustee does not provide the claim, because the API accepts part of the binding from the request body.

Recommended fix:

- In release mode, require `init_data_hash` to come from Trustee claims.
- Keep body-supplied fallback only for development or during a clearly versioned migration.
- Add tests that release configuration rejects missing Trustee init-data hash.

### 9. Medium: Registry Allowlist Client Exists but Deploy Path Does Not Use It

The API has a `RegistryClient` that validates registry base URLs against an allowlist and enforces HTTPS, no redirects, DNS resolution, private-IP blocking, and response size limits (`crates/enclava-api/src/clients.rs:17`, `crates/enclava-api/src/clients.rs:269`). The generic guarded client enforces HTTPS, no redirects, DNS resolution, and private-IP blocking (`crates/enclava-api/src/clients.rs:250`).

Startup stores only the generic guarded client in app state (`crates/enclava-api/src/main.rs:674`). The deploy path passes that generic client into registry digest resolution (`crates/enclava-api/src/routes/deployments.rs:506`). `registry_base_url` permits any host containing a dot and maps it to HTTPS (`crates/enclava-api/src/registry.rs:72`).

Potential impact:

- Authenticated deployers can cause the API to connect to arbitrary public registry-looking hosts.
- Private and cluster IPs are blocked, so this is not raw internal SSRF.
- The implemented registry allowlist appears to be intended but is not part of the deploy path.

Recommended fix:

- Store and use `RegistryClient` for registry operations.
- Add an allowlist test that a non-allowlisted public registry host is rejected during deploy.

### 10. Medium: Static API Deployment Manifest Is Weaker Than Workload Hardening

The static API deployment manifest uses a mutable image reference path: the deployment names `ghcr.io/enclava-ai/enclava-api:latest`, and kustomize rewrites it to tag `v1.0.0` (`deploy/api/deployment.yaml:18`, `deploy/api/kustomization.yaml:12`). The deployment manifest does not set pod or container security context, `automountServiceAccountToken: false`, read-only root filesystem, seccomp, or dropped capabilities in the deployment spec (`deploy/api/deployment.yaml:15`).

The API Dockerfile creates a non-root user and runs as that user (`crates/enclava-api/Dockerfile:34`, `crates/enclava-api/Dockerfile:45`), but the Kubernetes manifest does not enforce equivalent runtime hardening.

Potential impact:

- Source deploy config for the control-plane API is weaker than generated tenant workload config.
- Mutable tags weaken rollback and provenance analysis compared with digest pinning.

Recommended fix:

- Pin the API image by digest in deployment inputs.
- Add pod and container security contexts: non-root UID/GID, no privilege escalation, read-only root filesystem where feasible, dropped capabilities, seccomp runtime default, and `automountServiceAccountToken: false` unless the API truly needs it.

### 11. Medium: KBS Egress Policy Allows Namespace-Wide Port 8080

Generated network policy allows DNS, same-namespace traffic, and egress to the Trustee namespace on TCP 8080 (`crates/enclava-engine/src/manifest/network_policy.rs:24`, `crates/enclava-engine/src/manifest/network_policy.rs:44`, `crates/enclava-engine/src/manifest/network_policy.rs:54`). It also adds a `toServices` rule for `kbs-service` on port 8080 (`crates/enclava-engine/src/manifest/network_policy.rs:71`). The policy applies to all pods selected by an empty selector in the workload namespace (`crates/enclava-engine/src/manifest/network_policy.rs:106`).

Potential impact:

- If any non-KBS workload listens on port 8080 in `trustee-operator-system`, tenant workloads can reach it.
- The service-specific rule is more precise than the namespace-wide direct-pod rule.

Recommended fix:

- Remove the broad namespace egress rule if the service-specific rule is sufficient.
- If direct pod egress is needed, restrict by pod labels owned by the KBS deployment.

### 12. Medium-Low: Recursive Trustee Claim Extraction Accepts First Matching Key Anywhere

Claim extraction for `descriptor_core_hash` and `init_data_hash` recursively walks arbitrary JSON objects and arrays and returns the first matching key it finds (`crates/enclava-api/src/routes/workload.rs:205`, `crates/enclava-api/src/routes/workload.rs:213`). Tests intentionally support nested EAR-style output (`crates/enclava-api/src/routes/workload.rs:241`).

Potential impact:

- Trustee output is trusted, but if the verifier response format changes or embeds attacker-controlled sub-documents, first-match recursive extraction could bind to the wrong claim.
- This affects workload artifact delivery and the TLS broker because both use the extracted claims (`crates/enclava-api/src/routes/workload.rs:36`, `crates/enclava-api/src/routes/workload_tls.rs:65`).

Recommended fix:

- Accept a small set of explicit, versioned claim paths.
- Reject responses containing multiple conflicting values.
- Add tests for duplicate/conflicting nested claims.

### 13. Medium-Low: Public Auth Controls Rely Mostly on a Global Rate Limit

The router applies a global rate governor with one request per second and burst size 100 (`crates/enclava-api/src/lib.rs:38`, `crates/enclava-api/src/lib.rs:250`). Email signup checks only nonempty email/password and inserts a verified user immediately (`crates/enclava-api/src/auth/email.rs:52`, `crates/enclava-api/src/auth/email.rs:95`). Login checks nonempty inputs and verifies Argon2 password hashes (`crates/enclava-api/src/auth/email.rs:124`, `crates/enclava-api/src/auth/email.rs:141`). Password hashing uses Argon2id with random salts (`crates/enclava-api/src/auth/email.rs:26`).

Potential impact:

- The global limiter is useful but not a substitute for per-account, per-email, and per-source login abuse controls.
- Immediate verified signup may be acceptable in a private beta, but source code does not enforce email ownership.

Recommended fix:

- Add per-account and per-source login failure tracking.
- Require email verification before granting org access if public signup is enabled.
- Enforce a minimum password length and reject known-bad passwords if this is internet-facing.

### 14. Medium-Low: Billing Authorization and BTCPay Configuration Are Weakly Bounded

Billing upgrade, subscription status, and renewal routes accept `AuthContext` but do not apply role or scope checks (`crates/enclava-api/src/routes/billing.rs:81`, `crates/enclava-api/src/routes/billing.rs:173`, `crates/enclava-api/src/routes/billing.rs:227`). The webhook path does verify `BTCPay-Sig`, prevents duplicate event handling, fetches invoice status, validates amount, and then updates tier/subscription (`crates/enclava-api/src/routes/billing.rs:311`, `crates/enclava-api/src/routes/billing.rs:352`, `crates/enclava-api/src/routes/billing.rs:375`, `crates/enclava-api/src/routes/billing.rs:424`).

Release gates require `BTCPAY_WEBHOOK_SECRET` but do not require `BTCPAY_API_KEY` (`crates/enclava-api/src/env_gates.rs:22`, `crates/enclava-api/src/env_gates.rs:65`). Startup defaults `BTCPAY_API_KEY` to empty (`crates/enclava-api/src/main.rs:600`). The BTCPay client uses a plain `reqwest::Client` and sends the configured token to the configured base URL (`crates/enclava-api/src/billing/btcpay.rs:50`, `crates/enclava-api/src/billing/btcpay.rs:92`).

Potential impact:

- Any org member can create or renew billing flows.
- Missing API key becomes a runtime failure mode for billing.
- The BTCPay base URL is operator-controlled, so this is not a direct user-driven SSRF, but the client does not share the hardened outbound client.

Recommended fix:

- Require owner/admin for billing tier changes and renewals.
- Require `BTCPAY_API_KEY` in release if billing routes are enabled.
- Use the guarded HTTP client for BTCPay or validate the configured base URL at startup.

### 15. Medium-Low: CI/CD Source Shows Provenance but Not Signing or Digest Pinning

The API image workflow builds and pushes GHCR images with branch and SHA tags and enables provenance (`.github/workflows/api-image.yml:29`, `.github/workflows/api-image.yml:46`, `.github/workflows/api-image.yml:55`, `.github/workflows/api-image.yml:65`). The `enclava-init` image workflow follows the same pattern (`.github/workflows/enclava-init-image.yml:24`, `.github/workflows/enclava-init-image.yml:41`, `.github/workflows/enclava-init-image.yml:50`, `.github/workflows/enclava-init-image.yml:60`). The release workflow generates `SHA256SUMS` for binaries but does not sign them in the observed source (`.github/workflows/release.yml:95`).

The runtime source expects signed sidecar and workload images in several places (`crates/enclava-api/src/main.rs:543`, `crates/enclava-api/src/routes/deployments.rs:540`, `crates/enclava-api/src/cosign.rs:207`).

Source-observed impact:

- This repository shows provenance generation but not image or release artifact signing in the workflows reviewed.
- Signing may happen elsewhere, but it is not represented in this source tree.

Recommended fix:

- Add explicit keyless cosign signing to image workflows and verify the resulting identities match the runtime policies.
- Sign release checksums or release envelopes with a pinned key.
- Add CI assertions that published deployment inputs use digest-pinned images.

## Positive Controls Observed

- Release environment gates block multiple debug bypass flags and require critical secrets such as API key pepper and BTCPay webhook secret in release builds (`crates/enclava-api/src/env_gates.rs:14`, `crates/enclava-api/src/env_gates.rs:42`, `crates/enclava-api/src/env_gates.rs:65`).
- Session JWTs and config JWTs use separate purposes, issuers/audiences, algorithms, and expirations; tests reject cross-audience use (`crates/enclava-api/src/auth/jwt.rs:73`, `crates/enclava-api/src/auth/jwt.rs:128`, `crates/enclava-api/src/auth/jwt.rs:245`).
- API keys use a lookup prefix plus HMAC-secret format, expiry filtering, and last-use tracking (`crates/enclava-api/src/auth/api_key.rs:67`, `crates/enclava-api/src/auth/api_key.rs:142`, `crates/enclava-api/src/auth/api_key.rs:174`, `crates/enclava-api/src/auth/api_key.rs:185`).
- Password hashing uses Argon2id with generated salts (`crates/enclava-api/src/auth/email.rs:26`).
- Cosign verification enforces trusted signature layers and Fulcio/public-key constraints (`crates/enclava-api/src/cosign.rs:207`, `crates/enclava-api/src/cosign.rs:267`).
- Signed platform releases use a canonical envelope, pinned root, sidecar digest validation, runtime class validation, and genpolicy version validation (`crates/enclava-api/src/platform_release.rs:101`, `crates/enclava-api/src/platform_release.rs:143`, `crates/enclava-api/src/platform_release.rs:204`).
- Workload artifact delivery requires an attestation token, Trustee verification, descriptor hash extraction, init-data hash extraction, and descriptor-bound artifact lookup (`crates/enclava-api/src/routes/workload.rs:36`, `crates/enclava-api/src/routes/workload.rs:49`, `crates/enclava-api/src/routes/workload.rs:64`, `crates/enclava-api/src/routes/workload.rs:111`).
- `enclava-init` uses zeroizing secret wrappers, HKDF per-purpose seed derivation, Argon2id unlock derivation, rate limiting, Unix socket permissioning, and atomic file writes (`crates/enclava-init/src/secrets.rs:5`, `crates/enclava-init/src/seeds.rs:14`, `crates/enclava-init/src/unlock.rs:18`, `crates/enclava-init/src/socket.rs:30`, `crates/enclava-init/src/writes.rs:13`).
- Generated default workload manifests use strong runtime confinement for app, attestation proxy, and Caddy containers, with the caveat that Caddy keeps a writable root filesystem (`crates/enclava-engine/src/manifest/containers.rs:240`, `crates/enclava-engine/src/manifest/containers.rs:524`, `crates/enclava-engine/src/manifest/containers.rs:777`).

## Remediation Order

1. Fix API key creation and revocation authorization. This closes the broadest practical escalation path.
2. Add route-level authorization to app create, deploy, rollback, read/status, unlock, and config metadata routes. Back it with an authorization matrix test.
3. Implement signer rotation confirmation token validation and tests.
4. Fail closed on Trustee policy verification and signed platform release in release deployments.
5. Block `LEGACY_BOOTSTRAP_SCRIPT` and HTTP KBS in release unless explicitly modeled as an accepted production risk.
6. Remove the TLS broker body-supplied init-hash fallback in production.
7. Wire the registry allowlist client into deploy resolution.
8. Harden the static API deployment manifest and pin image digests.
9. Tighten KBS network policy egress, auth abuse controls, billing authorization, and CI signing.

## Test Plan for Fixes

Recommended test additions:

- API-key escalation tests: member cannot create `org:admin`; API key cannot create broader scopes; admin can create subset scopes.
- Route authorization matrix tests generated from router entries: unauthenticated, member, limited API key, `apps:read`, `apps:write`, `config:write`, `org:admin`, owner.
- Signer rotation tests for missing, invalid, expired, reused, and wrong-app confirmation tokens.
- Release env-gate tests for missing Trustee policy read, missing signed platform release, HTTP KBS, and `LEGACY_BOOTSTRAP_SCRIPT`.
- TLS broker tests rejecting missing Trustee `init_data_hash` in release mode.
- Registry tests proving non-allowlisted public registries are rejected.
- Manifest snapshot tests proving app and Caddy containers are never privileged in release mode.
