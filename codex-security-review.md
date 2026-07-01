Current repo-state update (2026-06-30)
======================================

This section updates the generated findings below against the current working
tree. Keep the original finding evidence for provenance, but do not apply the
generated patches below as a patch stack without reworking them against the
current code.

Patch applicability check:
- `FQDN egress can be rebound to private metadata IPs`: the generated patch is
  stale and does not apply cleanly to `crates/enclava-api/src/routes/apps.rs`,
  `crates/enclava-engine/src/manifest/network_policy.rs`, or the engine tests.
  It also conflicts with the updated mitigation plan in this file, which says
  to keep wildcard DNS by default.
- `Egress allowlist permits private DNS targets`: the generated patch is stale
  for `crates/enclava-api/src/routes/apps.rs`. Its tests partially apply, but
  the implementation hunk does not.
- `Best-effort teardown can leave reusable KBS seed material`: the route change
  hunk is close to current source, but the test hunk is stale. Applying the
  behavior literally is an API/operations breaking change.
- `Global signed KBS policy retention enables tenant DoS`: this patch still
  applies cleanly to `crates/enclava-api/src/kbs.rs`, but it changes retention
  semantics and can increase shared Trustee policy size.
- `Global GHCR pull secret attached to every tenant app`: the generated patch is
  stale for `crates/enclava-api/src/deploy.rs`. It also removes private image
  pull support outright, which is a breaking change for deployments relying on
  `GHCR_USERNAME` / `GHCR_TOKEN` or `TENANT_IMAGE_PULL_SECRET_NAME`.

Current code observations:
- DNS egress still uses Cilium DNS proxy `matchPattern: "*"` in
  `crates/enclava-engine/src/manifest/network_policy.rs`. Tenant
  `egress_allowlist` entries are still rendered as direct `toFQDNs.matchName`
  rules with tenant-selected TCP ports.
- `EgressMode::PublicInternet` now exists. It emits a `toCIDRSet` for
  `0.0.0.0/0` with private/reserved IPv4 exclusions, but those exclusions do
  not protect the tenant FQDN allowlist path unless an explicit deny layer is
  added.
- `validate_egress_allowlist` still rejects surrounding whitespace, IP literal
  hosts, malformed FQDN syntax, empty port lists, and port 0. It now also emits
  warn-only audit logs for obvious metadata/internal/rebinding host patterns.
  It does not yet reject those names, so this remains migration-safe.
- Running-app delete still treats unreachable or non-success workload teardown
  as success and continues app deletion. Later deletion soft-deletes CAP KBS
  policy bindings; the visible code does not delete underlying KBS resource
  contents.
- Signed KBS policy reconciliation now selects up to the configured retention
  per active app with a window function. The selector no longer enforces a
  single global artifact cap, and it errors instead of silently dropping
  required latest/current artifacts when the byte budget is too small.
- GHCR environment credentials still preserve the legacy global fallback when
  no repository scope is configured. Operators can now set
  `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES` to attach/create the tenant pull
  secret only when every workload image matches the configured exact repository
  or subrepository scope.

Breaking-change assessment and current remediation guidance:
1. FQDN egress / private DNS targets

   The safest current remediation is the updated plan already documented below,
   not the generated exact-DNS patch. Keep wildcard DNS by default so
   `EgressMode::PublicInternet` and workloads with incidental DNS lookups keep
   working. Add a Cilium deny layer for loopback, link-local/metadata, RFC1918,
   CGNAT, multicast/reserved ranges, IPv6 local/link-local/ULA ranges, and
   operator-configured pod/service/node CIDRs. Then add allowlist hostname
   validation for obvious internal and rebinding names after auditing existing
   stored `egress_allowlist` values.

   Breaking risk: rejecting `.internal`, `.local`, `.svc`, `.cluster.local`,
   metadata names, or rebinding helper domains will reject requests that are
   currently accepted. Replacing wildcard DNS with exact `matchName` entries
   would likely break public-internet egress and arbitrary DNS resolution.

2. KBS teardown / app delete

   The generated fail-closed delete patch fixes the immediate stale-resource
   path but changes API behavior: a running app delete can start returning
   `502` or `409` and leave the app present when the workload endpoint is down.
   That can be the right security posture, but it needs an operator recovery
   path.

   Prefer a current fix that also prevents stale path reuse: include an
   incarnation-unique value such as `app_id` or `instance_id` in KBS owner
   resource paths, block same-name recreation while teardown/KBS cleanup is
   incomplete, or add explicit KBS resource deletion/tombstoning. If delete is
   made fail-closed, add a documented admin-only force-delete flow that marks
   KBS material unsafe or unreusable before freeing the app name.

3. Signed KBS policy retention

   Implemented: reconciliation retains artifacts per active app rather than by
   global recency. Required current/latest artifacts are guaranteed unless the
   byte budget is too small, in which case reconciliation fails explicitly.
   If the platform can have many active signed apps, consider sharding policy
   by tenant/app or adding operational limits.

   Breaking risk: low for API clients, moderate for operations because the
   shared ConfigMap can grow and Trustee restarts can become more expensive.

4. GHCR tenant pull secret

   Implemented migration-safe scope support: unset
   `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES` preserves existing global fallback
   behavior; setting it makes the pull secret attach only when all workload
   images match the configured repository scope.

   Remaining hardening: use per-template or per-repository least-privilege
   tokens and eventually require repository scope in production environments.

Validation performed for this update:
- Read current source for the five affected paths:
  `network_policy.rs`, `routes/apps.rs`, `deploy.rs`, `kbs.rs`, and
  `service_account.rs`.
- Ran non-mutating `git apply --check` against each generated patch block. Only
  the signed KBS retention patch applies cleanly to the current tree.
- After implementing the safe bets, ran focused tests for KBS selection, egress
  allowlist auditing, and GHCR pull-secret scoping.
- Ran `cargo test -p enclava-api` and `cargo test --workspace`; both passed.

----

FQDN egress can be rebound to private metadata IPs
Link: https://chatgpt.com/codex/cloud/security/findings/90ea8c0c83a08191bc456af6e053db72?sev&repo=https%3A%2F%2Fgithub.com%2Fenclava-ai%2Fcap%2Chttps%3A%2F%2Fgithub.com%2Fenclava-ai%2Fenclava-paas
Criticality: high (attack path: high)
Status: new

# Metadata
Repo: enclava-ai/cap
Commit: cca8ea7
Author: codex@enclava.local
Created: 6/29/2026, 6:22:46 PM
Assignee: Unassigned
Signals: Security, Validated, Patch generated, Attack-path

# Summary
A security bug was introduced by enabling wildcard DNS proxying for FQDN egress without adding resolved-address safeguards or hostname restrictions for tenant-controlled egress allowlist entries.
The new DNS L7 rule uses matchPattern "*", which makes Cilium observe and learn all tenant DNS responses for FQDN egress enforcement. Per-app egress rules are then rendered directly as toFQDNs entries with tenant-selected TCP ports. However, validation only rejects IP literals in the submitted host; it does not reject special hostnames such as metadata.google.internal, Kubernetes/internal service names, or attacker-controlled domains that resolve/rebind to RFC1918, link-local, or cloud metadata IPs. Once the DNS proxy learns that response, the generated toFQDNs rule can permit the tenant workload to connect to the resolved private address on the selected port, bypassing the intended public FQDN/world-egress allowlist boundary and potentially exposing cloud metadata or internal services.

# Validation
## Rubric
- [x] Confirm the commit introduced wildcard DNS proxying (`matchPattern: "*"`) for tenant DNS egress.
- [x] Confirm tenant-supplied allowlist validation rejects IP literals but accepts metadata/internal/rebinding-candidate FQDNs.
- [x] Confirm tenant-selected TCP ports are preserved, including sensitive ports such as 80 and 8080.
- [x] Confirm accepted rules are rendered directly as Cilium `toFQDNs` entries and lack CIDR/entity/private/link-local safeguards.
- [ ] Exercise a live Cilium cluster to prove post-DNS-resolution connection to private/metadata IPs; not available in this container, so validation stops at generated CRD/code-path evidence.
## Report
Validated the finding as a policy/validation logic vulnerability, not a crash-class bug. Commit cca8ea7e adds Cilium DNS L7 proxying with `{"matchPattern":"*"}` in `crates/enclava-engine/src/manifest/network_policy.rs:25-48`, so tenant DNS queries are broadly proxied/learned. The same generator renders per-app rules directly as `toFQDNs` with tenant-selected TCP ports at `network_policy.rs:146-155`. API validation in `crates/enclava-api/src/routes/apps.rs:271-301` rejects IP literals but otherwise only calls syntactic `validate_fqdn`; `crates/enclava-common/src/validate.rs:98-128` checks ASCII/DNS-label syntax only, with no metadata/internal hostname or resolved-address filtering. I added targeted PoC tests. `cargo test -p enclava-api poc_egress_allowlist_accepts_internal_metadata_and_rebinding_candidates -- --nocapture` passed and proved `metadata.google.internal` on port 80, `kubernetes.default.svc.cluster.local`, and an attacker-controlled FQDN on port 8080 are accepted, while `169.254.169.254` is rejected only because it is an IP literal. `cargo test -p enclava-engine poc_fqdn_policy_has_wildcard_dns_and_no_private_ip_safeguard -- --nocapture` passed and proved the generated policy contains wildcard DNS and a direct `toFQDNs` rule for `metadata.google.internal` port 80/TCP without `toCIDR`, `toCIDRSet`, or `toEntities` safeguards. LLDB was used non-interactively on the API test binary; it stopped at `apps.rs:296` returning `Ok(EgressRule { ... })` with `host = "metadata.google.internal"`, confirming the accepted path in the debugger. Valgrind was attempted but unavailable (`bash: command not found: valgrind`); direct crash reproduction is not applicable because this is a Cilium policy bypass/configuration bug. A live Cilium cluster was not available, so the final packet-level DNS-learning/private-IP connection step was not exercised, but the code-generated CRD and validation path match the suspected bypass conditions.

# Evidence
crates/enclava-api/src/routes/apps.rs (L271 to 301)
  Note: Validation rejects only IP literal hosts and basic malformed FQDNs; it does not reject internal/metadata hostnames or domains that resolve to private/link-local addresses.
```
pub(crate) fn validate_egress_allowlist(
    rules: &[CreateEgressAllowRule],
) -> Result<Vec<EgressRule>, String> {
    rules
        .iter()
        .map(|rule| {
            let host = rule.host.as_str();
            if host.trim() != host {
                return Err(
                    "egress_allowlist host must not have surrounding whitespace".to_string()
                );
            }
            if host.parse::<std::net::IpAddr>().is_ok() {
                return Err(
                    "egress_allowlist host must be a DNS hostname, not an IP address".to_string(),
                );
            }
            enclava_common::validate::validate_fqdn(host)
                .map_err(|e| format!("invalid egress_allowlist host: {e}"))?;

            let ports = rule.ports.clone().unwrap_or_else(|| vec![443]);
            if ports.is_empty() || ports.contains(&0) {
                return Err("egress_allowlist ports must be between 1 and 65535".to_string());
            }

            Ok(EgressRule {
                host: host.to_string(),
                ports,
            })
        })
        .collect()
```

crates/enclava-engine/src/manifest/network_policy.rs (L146 to 155)
  Note: Tenant-controlled egress entries are rendered directly as Cilium toFQDNs rules with tenant-selected TCP ports, so learned DNS answers drive what IPs become reachable.
```
fn egress_rule_value(rule: &EgressRule) -> Value {
    let ports: Vec<Value> = rule
        .ports
        .iter()
        .map(|p| json!({ "port": p.to_string(), "protocol": "TCP" }))
        .collect();
    json!({
        "toFQDNs": [{ "matchName": rule.host }],
        "toPorts": [{ "ports": ports }],
    })
```

crates/enclava-engine/src/manifest/network_policy.rs (L25 to 48)
  Note: The commit adds a wildcard Cilium DNS L7 rule, causing tenant DNS responses for any name to be proxied and learned for FQDN policy decisions.
```
        // Rule: DNS to kube-dns
        json!({
            "toEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": "kube-system",
                        "k8s-app": "kube-dns"
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        { "port": "53", "protocol": "UDP" },
                        { "port": "53", "protocol": "TCP" }
                    ],
                    "rules": {
                        "dns": [
                            { "matchPattern": "*" }
                        ]
                    }
                }
            ]
        }),
```

# Updated mitigation plan
This plan supersedes the generated patch below. We should not remove broad DNS
resolution by default: tenant apps may legitimately need to resolve arbitrary
domains, and CAP cannot know every lookup a workload will perform.

Default behavior should be:
- Keep DNS `matchPattern: "*"` so workloads can resolve arbitrary names.
- Treat tenant `egress_allowlist` as public-destination egress only.
- Add mandatory Cilium `egressDeny` rules for destinations that must never be
  reached through tenant-controlled FQDN rules: loopback, link-local/metadata,
  RFC1918, CGNAT, multicast/reserved IPv4 ranges, IPv6 localhost/link-local/ULA,
  plus operator-configured pod/service/node CIDRs.
- Keep platform internal access, such as KBS and CAP-managed broker/service
  routes, modeled as explicit platform-owned routes rather than tenant FQDN
  allowlist entries.
- Add hostname blacklist validation for obvious internal/metadata allowlist
  targets: `localhost`, `metadata`, `metadata.google.internal`,
  Kubernetes service domains such as `.svc` and `.svc.cluster.local`, internal
  suffixes such as `.cluster.local`, `.internal`, `.local`, and rebinding helper
  domains such as `nip.io`, `sslip.io`, `localtest.me`, and `lvh.me`.
- Add an opt-in strict DNS mode later for tenants who explicitly want
  whitelist-based DNS resolution. In that mode, generate exact DNS `matchName`
  entries for platform and tenant allowlist hosts instead of wildcard DNS.

Rollout:
- First add tests that prove private/link-local/reserved `egressDeny` CIDRs are
  emitted and obvious internal hostnames are rejected.
- Then validate in a live Cilium cluster that an allowlisted FQDN resolving to
  `169.254.169.254` or RFC1918 space is denied while normal public FQDN egress
  still works.
- Audit existing stored `egress_allowlist` values before enforcing hostname
  blacklist validation on updates/deployments, so legitimate but incompatible
  tenants can be migrated to an explicit platform-managed route where needed.

Proposed patch:
diff --git a/crates/enclava-api/src/routes/apps.rs b/crates/enclava-api/src/routes/apps.rs
index 61f80b155e669e8fec3972bb3747fcf9d01050dc..7337a24e2c67b40e2739604b615af226ca9b2a62 100644
--- a/crates/enclava-api/src/routes/apps.rs
+++ b/crates/enclava-api/src/routes/apps.rs
@@ -265,64 +265,99 @@ fn default_unlock_mode() -> String {
 pub struct CreateEgressAllowRule {
     pub host: String,
     #[serde(default)]
     pub ports: Option<Vec<u16>>,
 }

 pub(crate) fn validate_egress_allowlist(
     rules: &[CreateEgressAllowRule],
 ) -> Result<Vec<EgressRule>, String> {
     rules
         .iter()
         .map(|rule| {
             let host = rule.host.as_str();
             if host.trim() != host {
                 return Err(
                     "egress_allowlist host must not have surrounding whitespace".to_string()
                 );
             }
             if host.parse::<std::net::IpAddr>().is_ok() {
                 return Err(
                     "egress_allowlist host must be a DNS hostname, not an IP address".to_string(),
                 );
             }
             enclava_common::validate::validate_fqdn(host)
                 .map_err(|e| format!("invalid egress_allowlist host: {e}"))?;
+            validate_public_egress_hostname(host)?;

             let ports = rule.ports.clone().unwrap_or_else(|| vec![443]);
             if ports.is_empty() || ports.contains(&0) {
                 return Err("egress_allowlist ports must be between 1 and 65535".to_string());
             }

             Ok(EgressRule {
                 host: host.to_string(),
                 ports,
             })
         })
         .collect()
 }

+fn validate_public_egress_hostname(host: &str) -> Result<(), String> {
+    let host = host.to_ascii_lowercase();
+    let blocked_exact = [
+        "localhost",
+        "metadata.google.internal",
+        "metadata",
+        "169.254.169.254.nip.io",
+        "kubernetes.default.svc.cluster.local",
+    ];
+    if blocked_exact.contains(&host.as_str()) {
+        return Err(
+            "egress_allowlist host must not target local or cloud metadata services".to_string(),
+        );
+    }
+
+    let blocked_suffixes = [
+        ".localhost",
+        ".local",
+        ".internal",
+        ".svc",
+        ".svc.cluster.local",
+        ".cluster.local",
+        ".nip.io",
+        ".sslip.io",
+        ".localtest.me",
+        ".lvh.me",
+    ];
+    if blocked_suffixes.iter().any(|suffix| host.ends_with(suffix)) {
+        return Err("egress_allowlist host must be a public DNS hostname".to_string());
+    }
+
+    Ok(())
+}
+
 #[derive(Debug, Serialize)]
 pub struct AppResponse {
     pub id: Uuid,
     pub name: String,
     pub namespace: String,
     pub instance_id: String,
     pub service_account: String,
     pub bootstrap_owner_pubkey_hash: String,
     pub tenant_instance_identity_hash: String,
     pub domain: String,
     pub tee_domain: Option<String>,
     pub custom_domain: Option<String>,
     pub unlock_mode: String,
     pub status: String,
     pub signer_identity_subject: Option<String>,
     pub signer_identity_issuer: Option<String>,
     pub source_provider: Option<String>,
     pub source_repository: Option<String>,
     pub created_at: chrono::DateTime<chrono::Utc>,
 }

 impl From<App> for AppResponse {
     fn from(a: App) -> Self {
         Self {
             id: a.id,


diff --git a/crates/enclava-api/src/routes/apps/tests/mod.rs b/crates/enclava-api/src/routes/apps/tests/mod.rs
index c88e0c8b95b2529980b6ada2100ea5ac1b4296cc..51f715ca6b11360a834ab085420f9997820417f2 100644
--- a/crates/enclava-api/src/routes/apps/tests/mod.rs
+++ b/crates/enclava-api/src/routes/apps/tests/mod.rs
@@ -33,50 +33,71 @@ fn egress_allowlist_defaults_omitted_ports_to_https() {

     let rules = validate_egress_allowlist(&body.egress_allowlist).unwrap();
     assert_eq!(rules[0].host, "relay.enclava.me");
     assert_eq!(rules[0].ports, vec![20000]);
     assert_eq!(rules[1].host, "rekor.sigstore.dev");
     assert_eq!(rules[1].ports, vec![443]);
 }

 #[test]
 fn egress_allowlist_rejects_ip_hosts_and_empty_ports() {
     let ip_host: CreateAppRequest = serde_json::from_value(serde_json::json!({
         "name": "demo",
         "egress_allowlist": [{ "host": "1.2.3.4", "ports": [443] }]
     }))
     .unwrap();
     assert!(validate_egress_allowlist(&ip_host.egress_allowlist).is_err());

     let empty_ports: CreateAppRequest = serde_json::from_value(serde_json::json!({
         "name": "demo",
         "egress_allowlist": [{ "host": "relay.enclava.me", "ports": [] }]
     }))
     .unwrap();
     assert!(validate_egress_allowlist(&empty_ports.egress_allowlist).is_err());
 }

+#[test]
+fn egress_allowlist_rejects_internal_metadata_and_rebinding_hosts() {
+    for host in [
+        "metadata.google.internal",
+        "kubernetes.default.svc.cluster.local",
+        "169.254.169.254.nip.io",
+        "metadata.localtest.me",
+    ] {
+        let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
+            "name": "demo",
+            "egress_allowlist": [{ "host": host, "ports": [443] }]
+        }))
+        .unwrap();
+
+        assert!(
+            validate_egress_allowlist(&body.egress_allowlist).is_err(),
+            "{host} should be rejected"
+        );
+    }
+}
+
 #[test]
 fn initial_set_call_omits_token() {
     let body: RotateSignerRequest = serde_json::from_value(serde_json::json!({
         "subject": "repo:me/app:ref:refs/heads/main",
         "issuer":  "https://token.actions.githubusercontent.com",
     }))
     .expect("token must be optional");
     assert!(body.email_confirmation_token.is_none());
 }

 #[test]
 fn rotation_call_carries_token() {
     let body: RotateSignerRequest = serde_json::from_value(serde_json::json!({
         "subject": "repo:me/app:ref:refs/heads/main",
         "issuer":  "https://token.actions.githubusercontent.com",
         "email_confirmation_token": "tok-123",
     }))
     .unwrap();
     assert_eq!(body.email_confirmation_token.as_deref(), Some("tok-123"));
 }

 #[test]
 fn whitespace_only_token_is_treated_as_absent_by_handler_logic() {
     // The handler trims and filters; reproduce that exact predicate so
     // future refactors that drop the trim/filter trip a unit test.


diff --git a/crates/enclava-engine/src/manifest/network_policy.rs b/crates/enclava-engine/src/manifest/network_policy.rs
index 58518d54f3d0d9412c5b982c53cfc27dbe6c3da4..bcd563cf5f633d70b8602e9a762c71dbeae01a82 100644
--- a/crates/enclava-engine/src/manifest/network_policy.rs
+++ b/crates/enclava-engine/src/manifest/network_policy.rs
@@ -1,69 +1,68 @@
 use serde_json::{Value, json};

 use crate::types::{ConfidentialApp, EgressRule};

 /// Platform-default FQDN egress allowlist.
 ///
 /// Hardcoded so the operator cannot quietly drop these. Caddy needs ACME
 /// reachability to issue and renew TLS certs for tenant ingress.
 const PLATFORM_DEFAULT_FQDNS: &[&str] = &[
     "acme-v02.api.letsencrypt.org",
     "acme-staging-v02.api.letsencrypt.org",
 ];

 /// Generate a CiliumNetworkPolicy (cilium.io/v2 CRD).
 ///
 /// Default: no egress to `world`. The previous policy allowed unrestricted
 /// HTTP/HTTPS egress to the internet, which let a compromised workload
 /// exfiltrate plaintext to any host. Phase 11: per-app FQDN allowlist instead.
 ///
 /// Each `EgressRule` becomes a Cilium `toFQDNs` rule scoped to the listed ports.
 /// The platform-default allowlist (DNS, KBS, ACME) is always present; per-app
 /// `egress_allowlist` adds on top.
 pub fn generate_network_policy(app: &ConfidentialApp) -> Value {
+    let dns_rules = dns_match_rules(app);
     let mut egress = vec![
         // Rule: DNS to kube-dns
         json!({
             "toEndpoints": [
                 {
                     "matchLabels": {
                         "io.kubernetes.pod.namespace": "kube-system",
                         "k8s-app": "kube-dns"
                     }
                 }
             ],
             "toPorts": [
                 {
                     "ports": [
                         { "port": "53", "protocol": "UDP" },
                         { "port": "53", "protocol": "TCP" }
                     ],
                     "rules": {
-                        "dns": [
-                            { "matchPattern": "*" }
-                        ]
+                        "dns": dns_rules
                     }
                 }
             ]
         }),
         // Rule: same namespace
         json!({
             "toEndpoints": [
                 {
                     "matchLabels": {
                         "io.kubernetes.pod.namespace": &app.namespace
                     }
                 }
             ]
         }),
         // Rule: KBS endpoint (direct pod access)
         json!({
             "toEndpoints": [
                 {
                     "matchLabels": {
                         "io.kubernetes.pod.namespace": "trustee-operator-system"
                     }
                 }
             ],
             "toPorts": [
                 {
@@ -121,50 +120,67 @@ pub fn generate_network_policy(app: &ConfidentialApp) -> Value {
         "spec": {
             "description": "Strict network isolation for confidential workload",
             "endpointSelector": {},
             "ingress": [
                 {
                     "fromEndpoints": [
                         {
                             "matchLabels": {
                                 "io.kubernetes.pod.namespace": &app.namespace
                             }
                         },
                         {
                             "matchLabels": {
                                 "io.kubernetes.pod.namespace": "tenant-envoy",
                                 "app.kubernetes.io/name": "envoy"
                             }
                         }
                     ]
                 }
             ],
             "egress": egress,
         }
     })
 }

+fn dns_match_rules(app: &ConfidentialApp) -> Vec<Value> {
+    let mut hosts: Vec<String> = PLATFORM_DEFAULT_FQDNS
+        .iter()
+        .map(|host| (*host).to_string())
+        .collect();
+    hosts.extend(app.egress_allowlist.iter().map(|rule| rule.host.clone()));
+    if let Some(host) = tls_certificate_broker_fqdn_host(app) {
+        hosts.push(host);
+    }
+    hosts.sort();
+    hosts.dedup();
+    hosts
+        .into_iter()
+        .map(|host| json!({ "matchName": host }))
+        .collect()
+}
+
 fn egress_rule_value(rule: &EgressRule) -> Value {
     let ports: Vec<Value> = rule
         .ports
         .iter()
         .map(|p| json!({ "port": p.to_string(), "protocol": "TCP" }))
         .collect();
     json!({
         "toFQDNs": [{ "matchName": rule.host }],
         "toPorts": [{ "ports": ports }],
     })
 }

 fn tls_certificate_broker_egress_rules(app: &ConfidentialApp) -> Vec<Value> {
     let Some(url) = app.attestation.tls_certificate_broker_url.as_deref() else {
         return Vec::new();
     };
     let Some((scheme, rest)) = url.trim().split_once("://") else {
         return Vec::new();
     };
     let Some(authority) = rest.split('/').next().map(str::trim) else {
         return Vec::new();
     };
     if authority.is_empty() {
         return Vec::new();
     }
@@ -194,49 +210,75 @@ fn tls_certificate_broker_egress_rules(app: &ConfidentialApp) -> Vec<Value> {
             ],
             "toPorts": [{ "ports": [{ "port": port.to_string(), "protocol": "TCP" }] }],
         })];
         if service_name == "cap-api" {
             rules.push(json!({
                 "toEndpoints": [
                     {
                         "matchLabels": {
                             "io.kubernetes.pod.namespace": namespace,
                             "app.kubernetes.io/name": service_name
                         }
                     }
                 ],
                 "toPorts": [{ "ports": [{ "port": "3000", "protocol": "TCP" }] }],
             }));
         }
         return rules;
     }

     vec![json!({
         "toFQDNs": [{ "matchName": host }],
         "toPorts": [{ "ports": [{ "port": port.to_string(), "protocol": "TCP" }] }],
     })]
 }

+fn tls_certificate_broker_fqdn_host(app: &ConfidentialApp) -> Option<String> {
+    let (_, _, host) = tls_certificate_broker_authority(app)?;
+    if kubernetes_service_name(host).is_some() {
+        return None;
+    }
+    Some(host.to_string())
+}
+
+fn tls_certificate_broker_authority(app: &ConfidentialApp) -> Option<(&str, &str, &str)> {
+    let url = app.attestation.tls_certificate_broker_url.as_deref()?;
+    let (scheme, rest) = url.trim().split_once("://")?;
+    let authority = rest.split('/').next().map(str::trim)?;
+    if authority.is_empty() {
+        return None;
+    }
+    let host = authority
+        .strip_prefix('[')
+        .and_then(|value| value.split_once(']').map(|(host, _)| host))
+        .unwrap_or_else(|| authority.split(':').next().unwrap_or(authority))
+        .trim();
+    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
+        return None;
+    }
+    Some((scheme, authority, host))
+}
+
 fn explicit_url_port(authority: &str) -> Option<u16> {
     if authority.starts_with('[') {
         return authority
             .split_once("]:")
             .and_then(|(_, port)| port.parse().ok());
     }
     let mut parts = authority.split(':');
     let _host = parts.next()?;
     let port = parts.next()?;
     if parts.next().is_some() {
         return None;
     }
     port.parse().ok()
 }

 fn kubernetes_service_name(host: &str) -> Option<(&str, &str)> {
     let parts: Vec<&str> = host.split('.').collect();
     match parts.as_slice() {
         [service, namespace, "svc"] | [service, namespace, "svc", "cluster", "local"] => {
             Some((*service, *namespace))
         }
         _ => None,
     }
 }


diff --git a/crates/enclava-engine/tests/manifest_network_policy_test.rs b/crates/enclava-engine/tests/manifest_network_policy_test.rs
index 0e9760af769a947785cd151f72c3fcd287e92c46..98cdadb93da3389974b9a0baa5cce25e85343c2f 100644
--- a/crates/enclava-engine/tests/manifest_network_policy_test.rs
+++ b/crates/enclava-engine/tests/manifest_network_policy_test.rs
@@ -31,53 +31,86 @@ fn network_policy_ingress_allows_same_namespace() {
 #[test]
 fn network_policy_ingress_allows_envoy_gateway() {
     let app = sample_app();
     let val = generate_network_policy(&app);
     let from = &val["spec"]["ingress"][0]["fromEndpoints"];
     assert_eq!(
         from[1]["matchLabels"]["io.kubernetes.pod.namespace"],
         "tenant-envoy"
     );
     assert_eq!(from[1]["matchLabels"]["app.kubernetes.io/name"], "envoy");
 }

 #[test]
 fn network_policy_egress_has_dns() {
     let app = sample_app();
     let val = generate_network_policy(&app);
     let egress = &val["spec"]["egress"];
     let dns_endpoints = &egress[0]["toEndpoints"][0]["matchLabels"];
     assert_eq!(dns_endpoints["io.kubernetes.pod.namespace"], "kube-system");
     assert_eq!(dns_endpoints["k8s-app"], "kube-dns");
     let dns_ports = &egress[0]["toPorts"][0]["ports"];
     assert_eq!(dns_ports[0]["port"], "53");
     assert_eq!(dns_ports[0]["protocol"], "UDP");
     assert_eq!(dns_ports[1]["port"], "53");
     assert_eq!(dns_ports[1]["protocol"], "TCP");
-    assert_eq!(
-        egress[0]["toPorts"][0]["rules"]["dns"][0]["matchPattern"],
-        "*"
+    let dns_rules = egress[0]["toPorts"][0]["rules"]["dns"].as_array().unwrap();
+    assert!(
+        dns_rules
+            .iter()
+            .all(|rule| rule.get("matchPattern").is_none())
+    );
+    assert!(
+        dns_rules
+            .iter()
+            .any(|rule| { rule["matchName"].as_str() == Some("acme-v02.api.letsencrypt.org") })
+    );
+}
+
+#[test]
+fn per_app_egress_adds_exact_dns_proxy_match() {
+    use enclava_engine::types::EgressRule;
+    let mut app = sample_app();
+    app.egress_allowlist = vec![EgressRule {
+        host: "api.stripe.com".to_string(),
+        ports: vec![443],
+    }];
+
+    let val = generate_network_policy(&app);
+    let dns_rules = val["spec"]["egress"][0]["toPorts"][0]["rules"]["dns"]
+        .as_array()
+        .unwrap();
+
+    assert!(
+        dns_rules
+            .iter()
+            .any(|rule| { rule["matchName"].as_str() == Some("api.stripe.com") })
+    );
+    assert!(
+        dns_rules
+            .iter()
+            .all(|rule| rule.get("matchPattern").is_none())
     );
 }

 #[test]
 fn network_policy_egress_has_same_namespace() {
     let app = sample_app();
     let val = generate_network_policy(&app);
     let egress = &val["spec"]["egress"];
     assert_eq!(
         egress[1]["toEndpoints"][0]["matchLabels"]["io.kubernetes.pod.namespace"],
         "cap-test-org-test-app"
     );
 }

 #[test]
 fn network_policy_egress_has_kbs() {
     let app = sample_app();
     let val = generate_network_policy(&app);
     let egress = &val["spec"]["egress"];
     assert_eq!(
         egress[2]["toEndpoints"][0]["matchLabels"]["io.kubernetes.pod.namespace"],
         "trustee-operator-system"
     );
     assert_eq!(egress[2]["toPorts"][0]["ports"][0]["port"], "8080");
 }

# Attack-path analysis
Final: high | Decider: model_decided | Matrix severity: high | Policy adjusted: high
## Rationale
Kept at high. Static evidence confirms the core claim: tenant-controlled egress_allowlist hosts are accepted with only IP-literal and syntax checks, persisted, copied into deployment state, and rendered as Cilium toFQDNs rules; the generated policy also proxies/learns wildcard DNS responses with matchPattern "*" and lacks private/link-local/metadata CIDR safeguards. The issue is in main product API and manifest code and is reachable via authenticated public app creation/deployment. The likely security consequence is a serious tenant network-isolation bypass to cloud metadata or internal services. It is not raised to critical because exploitation requires authenticated org admin/apps:write access and live-cluster/cloud conditions, and the provided validation did not exercise a real Cilium cluster or prove direct credential exfiltration.
## Likelihood
high - The path is normal product use through a public API and the attacker controls both the allowlist hostname and workload DNS/connect behavior. However, exploitation requires authenticated admin/apps:write privileges within a tenant org, a deployed workload, Cilium FQDN enforcement semantics, and a sensitive private/metadata endpoint reachable in the target cluster. | Remote network vector
## Impact
high - Successful exploitation can bypass the platform's intended tenant world-egress boundary and allow an untrusted tenant workload to reach cloud metadata or internal cluster/private services on attacker-selected TCP ports. That can expose credentials or internal control/data-plane services depending on the deployment. The impact is major for tenant isolation, but not proven to be universal because actual metadata/service reachability depends on live cluster/cloud controls outside the repository.
## Assumptions
- CAP is deployed with Cilium enforcing generated CiliumNetworkPolicy resources.
- Tenant workloads are untrusted and an authenticated org admin or API key with apps:write can create/deploy an app with an egress_allowlist entry.
- The cluster/cloud environment has sensitive private, link-local, metadata, or internal services reachable from tenant pod network paths if Cilium policy permits the destination IP and port.
- Authenticated CAP user or API key with admin role and apps:write scope
- Ability to create or update an app/deployment egress_allowlist
- Tenant workload can issue DNS queries and TCP connections
- Cilium FQDN policy observes DNS answers and enforces generated toFQDNs rules
## Path
tenant admin/apps:write -> POST /apps egress_allowlist -> syntactic FQDN validation -> persisted app rule -> Cilium DNS matchPattern '*' + toFQDNs(matchName, ports) -> workload DNS resolution to private/metadata IP -> connection to internal/metadata service
## Path evidence
- `crates/enclava-api/src/lib.rs:270-273` - The public API router exposes POST /apps to the create_app handler.
- `crates/enclava-api/src/routes/apps.rs:234-257` - CreateAppRequest includes a tenant-controlled egress_allowlist field.
- `crates/enclava-api/src/routes/apps.rs:271-301` - validate_egress_allowlist rejects IP literals and malformed FQDN syntax, but does not reject metadata/internal hostnames or resolved private/link-local addresses; ports are tenant-selected except for default 443.
- `crates/enclava-common/src/validate.rs:98-128` - validate_fqdn is syntax-only ASCII/DNS-label validation and contains no internal hostname or DNS resolution safeguards.
- `crates/enclava-api/src/routes/apps.rs:419-445` - create_app is reachable by authenticated requests and invokes the vulnerable egress allowlist validation after require_app_write.
- `crates/enclava-api/src/routes/apps.rs:548-571` - The normalized egress_allowlist is persisted with the app record.
- `crates/enclava-api/src/deploy.rs:419-444` - Deployment construction copies the persisted app egress_allowlist into the ConfidentialApp used for manifest generation.
- `crates/enclava-engine/src/manifest/mod.rs:57-62` - generate_all_manifests includes the generated network policy as a standard product manifest.
- `crates/enclava-engine/src/manifest/network_policy.rs:23-48` - The CiliumNetworkPolicy generator adds a DNS rule to kube-dns with rules.dns matchPattern "*" for both UDP and TCP port 53.
- `crates/enclava-engine/src/manifest/network_policy.rs:107-155` - Each tenant egress_allowlist rule is rendered directly as toFQDNs matchName plus the tenant-supplied TCP ports, without CIDR/entity/private-address exclusions.
- `crates/enclava-api/src/deploy.rs:184-188` - The generated CiliumNetworkPolicy is applied during deployment.
- `deploy/api/ingress.yaml:9-24` - Repository deployment manifests expose the API through an nginx Ingress for api.enclava.dev.
- `deploy/api/service.yaml:7-13` - The API service maps public ingress traffic on service port 80 to container port 3000.
- `crates/enclava-api/src/auth/scopes.rs:64-67` - The main mitigating control is strong authorization: app writes require admin role and apps:write scope.
## Narrative
The finding is a real, in-scope vulnerability in product code. Public API app creation accepts tenant-controlled egress_allowlist entries after requiring apps:write, but validation only rejects IP literals and syntactically invalid FQDNs. The accepted rules are stored, copied into the deployment model, and rendered into a CiliumNetworkPolicy. The generated policy has a wildcard DNS L7 rule, so tenant DNS answers can be learned, and each allowlist entry becomes a direct toFQDNs matchName with attacker-selected TCP ports. There is no repo evidence of private/link-local/metadata resolved-address filtering in this path. Because tenant workloads are untrusted and network policy is a tenant-isolation boundary, this can let an authenticated tenant app admin bypass intended public FQDN egress restrictions to reach cloud metadata or internal services. Authn/authz and lack of live Cilium packet proof keep this at high rather than critical.
## Controls
- AuthContext extractor requires bearer session JWT or API key for create_app.
- require_app_write requires org admin/owner role and apps:write scope.
- Global API rate limiting is configured in build_router_inner.
- Tenant ServiceAccount and Pod specs set automount service account token to false.
- Generated CiliumNetworkPolicy is intended to restrict tenant egress, but wildcard DNS learning and direct toFQDNs rendering are the vulnerable controls.
- No repository evidence of resolved-address denylisting for private, link-local, metadata, or cluster CIDRs in this egress_allowlist path.
## Blindspots
- Static analysis cannot verify actual Cilium runtime behavior for toFQDNs entries resolving to link-local, RFC1918, or Kubernetes service IPs in the deployed version.
- No live cluster was available to prove packet-level access to metadata.google.internal, 169.254.169.254, Kubernetes service IPs, or other internal services.
- Repository manifests do not fully define cloud provider metadata protections, Kubernetes service/pod CIDRs, node firewall rules, or Cilium cluster-wide deny policies that might mitigate the final connection step.
- The API supports internal PaaS app creation paths as well, but this analysis focused on the public authenticated /apps and deploy paths evidenced in product code.

#################

Egress allowlist permits private DNS targets
Link: https://chatgpt.com/codex/cloud/security/findings/089b81c8587c8191bbaf6b1fc3532f92?sev&repo=https%3A%2F%2Fgithub.com%2Fenclava-ai%2Fcap%2Chttps%3A%2F%2Fgithub.com%2Fenclava-ai%2Fenclava-paas
Criticality: high (attack path: high)
Status: new

# Metadata
Repo: enclava-ai/cap
Commit: ceec746
Author: codex@enclava.local
Created: 6/29/2026, 11:32:32 AM
Assignee: Unassigned
Signals: Security, Validated, Patch generated, Attack-path

# Summary
Introduced. Previously build_confidential_app always set egress_allowlist to an empty vector, so API-supplied app allowlists were not rendered into runtime Cilium policies. This commit wires stored app egress_allowlist values into ConfidentialApp and adds API/internal/generic request fields, but the new validation is insufficient for security-sensitive network policy generation.
This commit begins preserving and rendering app-provided egress allowlists into tenant network policies. The validator rejects literal IP address strings, but accepts any syntactically valid DNS name and does not block cluster-local/internal suffixes or resolve the name through the platform's private/link-local CIDR blocklist. Because the network policy generator turns each accepted hostname directly into a Cilium toFQDNs allow rule, an authenticated org admin/API key with apps:write can create or update an app with entries such as metadata.google.internal, kubernetes.default.svc.cluster.local, or an attacker-controlled DNS name that resolves/rebinds to 169.254.169.254 or RFC1918/cluster IPs. The resulting workload egress policy can allow direct access from tenant pods to cloud metadata or internal cluster services, undermining the intended tenant isolation and SSRF defenses.

# Validation
## Rubric
- [x] Identify the API field and validator and confirm whether validation blocks only literal IPs/syntax rather than internal DNS suffixes or private/link-local resolutions.
- [x] Reproduce acceptance of security-sensitive hostnames through the actual API crate validator.
- [x] Confirm the accepted allowlist is stored and copied into ConfidentialApp for deployment.
- [x] Reproduce that the engine renders accepted hostnames directly into Cilium toFQDNs.matchName egress rules with requested ports.
- [ ] Validate end-to-end traffic in a live Kubernetes/Cilium cluster; not attempted because the container lacks a cluster, but generated policy evidence confirms the vulnerable runtime configuration.
## Report
Validated commit ceec74609f11bd64f2e8ebf16345a03084b3157c. The API request type exposes egress_allowlist (crates/enclava-api/src/routes/apps.rs:255-257). The validator only checks surrounding whitespace, rejects literal IpAddr strings, then calls validate_fqdn and accepts ports/default 443 (apps.rs:271-301). validate_fqdn is only syntactic ASCII/DNS-label validation and has no internal suffix/CIDR/DNS-resolution checks (crates/enclava-common/src/validate.rs:98-125). The create path validates and stores the resulting JSON egress_allowlist (apps.rs:445-571). Deployment construction copies stored app.egress_allowlist directly into ConfidentialApp (crates/enclava-api/src/deploy.rs:405-432). The engine then appends each rule to policy egress and renders it directly as Cilium toFQDNs.matchName with requested TCP ports (crates/enclava-engine/src/manifest/network_policy.rs:102-149). I added targeted PoC tests against the actual crates. API test output: accepted_rules=[{"host":"metadata.google.internal","ports":[80]},{"host":"kubernetes.default.svc.cluster.local","ports":[443]},{"host":"attacker-controlled.example.com","ports":[8080]}], test ok. Engine test output: metadata_rule={"toFQDNs":[{"matchName":"metadata.google.internal"}],"toPorts":[{"ports":[{"port":"80","protocol":"TCP"}]}]} and kube_rule={"toFQDNs":[{"matchName":"kubernetes.default.svc.cluster.local"}],"toPorts":[{"ports":[{"port":"443","protocol":"TCP"}]}]}, test ok. Direct crash-style execution exited 0 as expected for this logic flaw; valgrind and gdb were attempted but not installed in the container.

# Evidence
crates/enclava-api/src/deploy.rs (L405 to 433)
  Note: The commit changed deployment construction to pass the stored app egress_allowlist into the ConfidentialApp, making the insufficiently validated hostnames effective at runtime.
```
    Ok(ConfidentialApp {
        app_id: app.id,
        name: app.name.clone(),
        namespace: app.namespace.clone(),
        instance_id: app.instance_id.clone(),
        tenant_id: app.tenant_id.clone(),
        bootstrap_owner_pubkey_hash: app.bootstrap_owner_pubkey_hash.clone(),
        tenant_instance_identity_hash: app.tenant_instance_identity_hash.clone(),
        service_account: app.service_account.clone(),
        image_pull_secret_name: configured_tenant_image_pull_secret_name(),
        signer_identity_subject: app.signer_identity_subject.clone(),
        signer_identity_issuer: app.signer_identity_issuer.clone(),
        containers,
        storage,
        unlock_mode,
        domain: DomainSpec {
            platform_domain: app.domain.clone(),
            tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
            custom_domain: app.custom_domain.clone(),
        },
        api_signing_pubkey: api_signing_pubkey.to_string(),
        api_url: api_url.to_string(),
        resources: ResourceLimits {
            cpu: resources.cpu_limit,
            memory: resources.memory_limit,
        },
        attestation: attestation_config.clone(),
        egress_allowlist: app.egress_allowlist.0.clone(),
        workload_artifact_binding: None,
```

crates/enclava-api/src/routes/apps.rs (L271 to 299)
  Note: The new egress allowlist validator only rejects literal IP strings and checks DNS syntax; it does not reject internal DNS names, metadata hostnames, cluster-local service names, or names resolving to private/link-local/cluster CIDRs.
```
pub(crate) fn validate_egress_allowlist(
    rules: &[CreateEgressAllowRule],
) -> Result<Vec<EgressRule>, String> {
    rules
        .iter()
        .map(|rule| {
            let host = rule.host.as_str();
            if host.trim() != host {
                return Err(
                    "egress_allowlist host must not have surrounding whitespace".to_string()
                );
            }
            if host.parse::<std::net::IpAddr>().is_ok() {
                return Err(
                    "egress_allowlist host must be a DNS hostname, not an IP address".to_string(),
                );
            }
            enclava_common::validate::validate_fqdn(host)
                .map_err(|e| format!("invalid egress_allowlist host: {e}"))?;

            let ports = rule.ports.clone().unwrap_or_else(|| vec![443]);
            if ports.is_empty() || ports.contains(&0) {
                return Err("egress_allowlist ports must be between 1 and 65535".to_string());
            }

            Ok(EgressRule {
                host: host.to_string(),
                ports,
            })
```

crates/enclava-engine/src/manifest/network_policy.rs (L102 to 150)
  Note: Each accepted egress rule is rendered directly as a Cilium toFQDNs allow rule for the requested ports, so an accepted private/internal-resolving hostname becomes allowed workload egress.
```
    for rule in &app.egress_allowlist {
        egress.push(egress_rule_value(rule));
    }

    json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "tenant-isolation",
            "namespace": app.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "enclava-platform"
            }
        },
        "spec": {
            "description": "Strict network isolation for confidential workload",
            "endpointSelector": {},
            "ingress": [
                {
                    "fromEndpoints": [
                        {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": &app.namespace
                            }
                        },
                        {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": "tenant-envoy",
                                "app.kubernetes.io/name": "envoy"
                            }
                        }
                    ]
                }
            ],
            "egress": egress,
        }
    })
}

fn egress_rule_value(rule: &EgressRule) -> Value {
    let ports: Vec<Value> = rule
        .ports
        .iter()
        .map(|p| json!({ "port": p.to_string(), "protocol": "TCP" }))
        .collect();
    json!({
        "toFQDNs": [{ "matchName": rule.host }],
        "toPorts": [{ "ports": ports }],
    })
```

Proposed patch:
diff --git a/crates/enclava-api/src/routes/apps.rs b/crates/enclava-api/src/routes/apps.rs
index 61f80b155e669e8fec3972bb3747fcf9d01050dc..35cfd0663682093b582f26559bbbb789b84de548 100644
--- a/crates/enclava-api/src/routes/apps.rs
+++ b/crates/enclava-api/src/routes/apps.rs
@@ -1,49 +1,50 @@
 use axum::{
     Json,
     extract::{Path, State},
     http::StatusCode,
 };
 use chrono::Duration;
 use ed25519_dalek::SigningKey;
 use rand::rngs::OsRng;
 use serde::{Deserialize, Serialize};
 use sha2::{Digest, Sha256};
 use uuid::Uuid;

 use crate::auth::jwt::{
     SignerRotationTokenInput, issue_signer_rotation_token, verify_signer_rotation_token,
 };
 use crate::auth::middleware::{AuthContext, ManagementOrigin};
 use crate::auth::scopes;
 use crate::models::{App, AppStatus};
 use crate::source_provider::{
     SourceProvider, validate_signing_identity, validate_source_repository,
 };
 use crate::state::{AppState, CapManagementMode};
 use enclava_engine::types::EgressRule;
 use sqlx::types::Json as SqlJson;
+use std::net::ToSocketAddrs;

 /// Helper function for consistent internal server error responses
 fn internal_server_error() -> (StatusCode, Json<serde_json::Value>) {
     (
         StatusCode::INTERNAL_SERVER_ERROR,
         Json(serde_json::json!({"error": "internal server error"})),
     )
 }

 fn deploy_blocked_response(reason: &str, message: String) -> (StatusCode, Json<serde_json::Value>) {
     (
         StatusCode::FORBIDDEN,
         Json(serde_json::json!({
             "error": "deploy_blocked",
             "reason": reason,
             "message": message,
         })),
     )
 }

 fn dns_error_response(error: crate::dns::DnsError) -> (StatusCode, Json<serde_json::Value>) {
     let status = match &error {
         crate::dns::DnsError::OutsideManagedZone(_) => StatusCode::BAD_REQUEST,
         crate::dns::DnsError::HostnameInUse { .. } => StatusCode::CONFLICT,
         crate::dns::DnsError::NotConfigured => StatusCode::INTERNAL_SERVER_ERROR,
@@ -265,64 +266,110 @@ fn default_unlock_mode() -> String {
 pub struct CreateEgressAllowRule {
     pub host: String,
     #[serde(default)]
     pub ports: Option<Vec<u16>>,
 }

 pub(crate) fn validate_egress_allowlist(
     rules: &[CreateEgressAllowRule],
 ) -> Result<Vec<EgressRule>, String> {
     rules
         .iter()
         .map(|rule| {
             let host = rule.host.as_str();
             if host.trim() != host {
                 return Err(
                     "egress_allowlist host must not have surrounding whitespace".to_string()
                 );
             }
             if host.parse::<std::net::IpAddr>().is_ok() {
                 return Err(
                     "egress_allowlist host must be a DNS hostname, not an IP address".to_string(),
                 );
             }
             enclava_common::validate::validate_fqdn(host)
                 .map_err(|e| format!("invalid egress_allowlist host: {e}"))?;
+            validate_egress_allowlist_host_safety(host)?;

             let ports = rule.ports.clone().unwrap_or_else(|| vec![443]);
             if ports.is_empty() || ports.contains(&0) {
                 return Err("egress_allowlist ports must be between 1 and 65535".to_string());
             }

             Ok(EgressRule {
                 host: host.to_string(),
                 ports,
             })
         })
         .collect()
 }

+fn validate_egress_allowlist_host_safety(host: &str) -> Result<(), String> {
+    let lower_host = host.to_ascii_lowercase();
+    if is_internal_egress_hostname(&lower_host) {
+        return Err(
+            "egress_allowlist host must not target internal or metadata DNS names".to_string(),
+        );
+    }
+
+    let blocked = crate::clients::BlockedNetworks::defaults();
+    let lookup = format!("{host}:0");
+    if let Ok(addrs) = lookup.to_socket_addrs() {
+        for addr in addrs {
+            if blocked.contains(addr.ip()) {
+                return Err(format!(
+                    "egress_allowlist host resolves to blocked address {}",
+                    addr.ip()
+                ));
+            }
+        }
+    }
+
+    Ok(())
+}
+
+fn is_internal_egress_hostname(host: &str) -> bool {
+    const EXACT: &[&str] = &[
+        "metadata.google.internal",
+        "metadata",
+        "169.254.169.254.nip.io",
+        "kubernetes.default.svc",
+        "kubernetes.default.svc.cluster.local",
+    ];
+    const SUFFIXES: &[&str] = &[
+        ".cluster.local",
+        ".svc",
+        ".svc.cluster.local",
+        ".internal",
+        ".local",
+        ".localhost",
+        ".localdomain",
+    ];
+
+    EXACT.iter().any(|exact| host == *exact) || SUFFIXES.iter().any(|suffix| host.ends_with(suffix))
+}
+
 #[derive(Debug, Serialize)]
 pub struct AppResponse {
     pub id: Uuid,
     pub name: String,
     pub namespace: String,
     pub instance_id: String,
     pub service_account: String,
     pub bootstrap_owner_pubkey_hash: String,
     pub tenant_instance_identity_hash: String,
     pub domain: String,
     pub tee_domain: Option<String>,
     pub custom_domain: Option<String>,
     pub unlock_mode: String,
     pub status: String,
     pub signer_identity_subject: Option<String>,
     pub signer_identity_issuer: Option<String>,
     pub source_provider: Option<String>,
     pub source_repository: Option<String>,
     pub created_at: chrono::DateTime<chrono::Utc>,
 }

 impl From<App> for AppResponse {
     fn from(a: App) -> Self {
         Self {
             id: a.id,


diff --git a/crates/enclava-api/src/routes/apps/tests/mod.rs b/crates/enclava-api/src/routes/apps/tests/mod.rs
index c88e0c8b95b2529980b6ada2100ea5ac1b4296cc..fe7310c177bb044cc7e02a57350adb31c052ac68 100644
--- a/crates/enclava-api/src/routes/apps/tests/mod.rs
+++ b/crates/enclava-api/src/routes/apps/tests/mod.rs
@@ -33,50 +33,81 @@ fn egress_allowlist_defaults_omitted_ports_to_https() {

     let rules = validate_egress_allowlist(&body.egress_allowlist).unwrap();
     assert_eq!(rules[0].host, "relay.enclava.me");
     assert_eq!(rules[0].ports, vec![20000]);
     assert_eq!(rules[1].host, "rekor.sigstore.dev");
     assert_eq!(rules[1].ports, vec![443]);
 }

 #[test]
 fn egress_allowlist_rejects_ip_hosts_and_empty_ports() {
     let ip_host: CreateAppRequest = serde_json::from_value(serde_json::json!({
         "name": "demo",
         "egress_allowlist": [{ "host": "1.2.3.4", "ports": [443] }]
     }))
     .unwrap();
     assert!(validate_egress_allowlist(&ip_host.egress_allowlist).is_err());

     let empty_ports: CreateAppRequest = serde_json::from_value(serde_json::json!({
         "name": "demo",
         "egress_allowlist": [{ "host": "relay.enclava.me", "ports": [] }]
     }))
     .unwrap();
     assert!(validate_egress_allowlist(&empty_ports.egress_allowlist).is_err());
 }

+#[test]
+fn egress_allowlist_rejects_internal_and_metadata_hosts() {
+    for host in [
+        "metadata.google.internal",
+        "kubernetes.default.svc.cluster.local",
+        "api.default.svc",
+        "localhost.localdomain",
+    ] {
+        let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
+            "name": "demo",
+            "egress_allowlist": [{ "host": host, "ports": [443] }]
+        }))
+        .unwrap();
+        assert!(
+            validate_egress_allowlist(&body.egress_allowlist).is_err(),
+            "{host} must be rejected"
+        );
+    }
+}
+
+#[test]
+fn egress_allowlist_rejects_hosts_resolving_to_blocked_networks() {
+    let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
+        "name": "demo",
+        "egress_allowlist": [{ "host": "localhost", "ports": [443] }]
+    }))
+    .unwrap();
+
+    assert!(validate_egress_allowlist(&body.egress_allowlist).is_err());
+}
+
 #[test]
 fn initial_set_call_omits_token() {
     let body: RotateSignerRequest = serde_json::from_value(serde_json::json!({
         "subject": "repo:me/app:ref:refs/heads/main",
         "issuer":  "https://token.actions.githubusercontent.com",
     }))
     .expect("token must be optional");
     assert!(body.email_confirmation_token.is_none());
 }

 #[test]
 fn rotation_call_carries_token() {
     let body: RotateSignerRequest = serde_json::from_value(serde_json::json!({
         "subject": "repo:me/app:ref:refs/heads/main",
         "issuer":  "https://token.actions.githubusercontent.com",
         "email_confirmation_token": "tok-123",
     }))
     .unwrap();
     assert_eq!(body.email_confirmation_token.as_deref(), Some("tok-123"));
 }

 #[test]
 fn whitespace_only_token_is_treated_as_absent_by_handler_logic() {
     // The handler trims and filters; reproduce that exact predicate so
     // future refactors that drop the trim/filter trip a unit test.

# Attack-path analysis
Final: high | Decider: model_decided | Matrix severity: high | Policy adjusted: high
## Rationale
Keep as high, not critical. Static evidence confirms the complete product path: user-controlled egress_allowlist is exposed in app/deployment APIs, insufficiently validated, persisted, copied into deployment state, and rendered into Cilium toFQDNs rules. This is in scope for the platform's tenant-isolation and SSRF/egress goals. The impact is potentially major because tenant pods may reach cloud metadata or internal cluster/private services. However, exploitation requires authenticated org admin/apps:write privileges and live impact depends on cluster/cloud network posture and Cilium behavior; Kubernetes service-account tokens are also not automounted. Those preconditions prevent a critical rating, but the egress-isolation bypass and credible metadata/internal-service access justify high.
## Likelihood
high - The vulnerable input is reachable through normal API usage and confirmed by validation tests, but exploitation requires an authenticated org Owner/Admin or apps:write API key and a deployed workload. Those are meaningful privileges, so likelihood is lower than unauthenticated SSRF but still plausible for malicious tenants or compromised tenant admin keys. | Remote network vector
## Impact
high - The bug can turn a tenant-controlled DNS allowlist entry into actual pod egress to metadata, Kubernetes service DNS, or private/internal IPs. That undermines tenant egress isolation and can expose cloud metadata credentials or internal service data depending on the cluster/cloud environment. It is not proven to yield universal cross-tenant compromise because Kubernetes tokens are not automounted and live cloud metadata reachability was not tested.
## Assumptions
- Runtime uses Cilium FQDN policy behavior where a toFQDNs matchName can authorize traffic to the IPs returned by DNS for that name unless a separate deny policy blocks those IPs.
- An org owner/admin or API key with apps:write can deploy or run a workload that attempts outbound connections.
- The target cluster/cloud environment does not separately block pod access to metadata/private/cluster-service IPs outside the rendered policy.
- authenticated org owner/admin session or API key with apps:write
- public standalone management route or authenticated PaaS internal management route
- app creation or generic deployment path that stores egress_allowlist
- deployment apply of generated CiliumNetworkPolicy
- tenant workload makes traffic to the allowed hostname and port
## Path
org admin/apps:write -> POST /apps or /deployments with egress_allowlist -> syntactic FQDN validation -> stored app.egress_allowlist -> ConfidentialApp -> Cilium toFQDNs.matchName -> tenant pod egress to metadata/internal DNS target
## Path evidence
- `crates/enclava-api/src/lib.rs:184-199` - Main API router merges app and deployment routes into the product router.
- `crates/enclava-api/src/lib.rs:272-273` - POST /apps is routed to create_app.
- `crates/enclava-api/src/routes/apps.rs:419-425` - create_app is remotely reachable through the API and protected by AuthContext, require_app_write, and management-mode checks.
- `crates/enclava-api/src/auth/scopes.rs:64-67` - App writes require Owner/Admin role and apps:write for API keys, confirming authenticated-admin precondition.
- `crates/enclava-api/src/routes/apps.rs:255-268` - CreateAppRequest exposes attacker-supplied egress_allowlist host and ports.
- `crates/enclava-api/src/routes/apps.rs:271-301` - Validator rejects whitespace and literal IP addresses, then accepts any syntactically valid FQDN and requested ports; no internal suffix or DNS-resolution private-CIDR check exists here.
- `crates/enclava-common/src/validate.rs:98-128` - validate_fqdn is syntactic ASCII/DNS-label validation and does not know about internal/private DNS targets.
- `crates/enclava-api/src/routes/apps.rs:445-571` - create_app validates and stores the normalized allowlist into the apps table.
- `crates/enclava-api/src/routes/deployments/generic.rs:227-240` - Generic deployment path also validates app.egress_allowlist and passes it into app metadata handling.
- `crates/enclava-api/src/routes/deployments/generic.rs:546-563` - Generic deployment updates persisted app egress_allowlist for existing apps.
- `crates/enclava-api/src/deploy.rs:405-432` - Deployment construction copies app.egress_allowlist into ConfidentialApp, making the stored allowlist effective at runtime.
- `crates/enclava-engine/src/manifest/network_policy.rs:14-23` - Network policy comments describe per-app FQDN allowlist as the intended egress control.
- `crates/enclava-engine/src/manifest/network_policy.rs:102-149` - Each accepted rule is appended to egress and rendered directly as Cilium toFQDNs.matchName with the chosen TCP ports.
- `crates/enclava-api/src/clients.rs:7-9` - The repository has SSRF-aware DNS/private CIDR blocking for outbound HTTP clients, highlighting that private/link-local resolution is a recognized control but is not applied to this egress allowlist path.
- `deploy/api/ingress.yaml:9-24` - Checked-in deployment exposes the API through nginx ingress at api.enclava.dev.
- `deploy/api/service.yaml:7-13` - API service is ClusterIP on port 80 targeting container port 3000.
- `crates/enclava-api/src/main.rs:773-779` - API process defaults to listening on 0.0.0.0:3000.
- `crates/enclava-engine/src/manifest/service_account.rs:16-29` - Generated tenant service account disables automounting Kubernetes API tokens, a mitigating control but not an egress destination block.
## Narrative
The finding is real and reachable in the main product. The public app create and generic deployment APIs accept app-provided egress_allowlist entries. The validator only trims, rejects literal IP strings, then calls a syntactic FQDN validator; it does not block cluster-local/metadata names or resolve DNS through the repository's private/link-local CIDR blocklist. Stored allowlist entries are copied into ConfidentialApp and rendered directly as Cilium toFQDNs.matchName rules. The route is not unauthenticated: it requires org Owner/Admin and apps:write for API keys, plus management-mode checks. That lowers likelihood versus an unauthenticated SSRF, but the impact remains high because a tenant app writer can deliberately weaken workload egress isolation and potentially reach cloud metadata or internal cluster/private services.
## Controls
- AuthContext authentication
- require_app_write Owner/Admin plus apps:write scope for API keys
- management-mode write gating
- global API rate limit in build_router
- CORS default-deny in release when no origins are configured
- CiliumNetworkPolicy default egress allowlist model
- tenant workload service-account token automount disabled
- API outbound guarded resolver/private CIDR blocklist exists but is not used by egress_allowlist validation
## Blindspots
- No live Kubernetes/Cilium cluster was used to confirm actual packet flow from a tenant pod to metadata or cluster services.
- Cloud metadata impact depends on provider configuration, node metadata protections, workload identity settings, and external network/firewall controls not visible in the repository.
- Checked-in deploy manifests do not show the API's Kubernetes apply RBAC/credential source, so identity privileges for applying Cilium policies could not be fully mapped.
- Cilium policy precedence with any operator-installed clusterwide deny policies cannot be verified from repository artifacts alone.


########

Best-effort teardown can leave reusable KBS seed material
Link: https://chatgpt.com/codex/cloud/security/findings/325863ef7e508191ac62af846b5a60a6?sev&repo=https%3A%2F%2Fgithub.com%2Fenclava-ai%2Fcap%2Chttps%3A%2F%2Fgithub.com%2Fenclava-ai%2Fenclava-paas
Criticality: high (attack path: high)
Status: new

# Metadata
Repo: enclava-ai/cap
Commit: 0dce817
Author: codex@enclava.local
Created: 6/29/2026, 10:30:29 AM
Assignee: Unassigned
Signals: Security, Validated, Patch generated, Attack-path

# Summary
Introduced: workload teardown is now best-effort in the API deletion path even though successful teardown is the only visible mechanism that removes workload-owned KBS resource contents. This interacts unsafely with stable, name-derived KBS resource paths and app-row deletion/recreation.
Before this change, deleting a running app failed if the workload teardown endpoint was unreachable or returned a non-success status. The new code logs those failures and returns Ok, allowing deletion to continue. Later deletion only soft-deletes CAP's KBS policy binding and deletes the app row; it does not delete the underlying workload-owned KBS resource. The KBS owner resource path is stable for a given org/app name because the namespace is cap-{org}-{app} and owner_resource_type is {namespace}-{name}-owner. After the app row is deleted, the same app name can be recreated, producing the same namespace and KBS resource path. When KBS bindings are recreated for the new app, Trustee can authorize the new workload identity to read the same resource path, potentially exposing stale owner seed/wrap-key material left behind by the previous app incarnation.

# Validation
## Rubric
- [x] Confirm the commit introduced best-effort workload teardown instead of returning an API error on unreachable or non-success teardown.
- [x] Confirm app deletion proceeds after the best-effort teardown result into status update, policy-binding removal, and app-row deletion.
- [x] Confirm the remaining deletion path removes/reconciles CAP policy bindings only and does not delete underlying KBS resource contents.
- [x] Confirm same org/app recreation reuses namespace, service account, owner_resource_type, and owner_resource_path despite a new app_id/instance_id.
- [x] Confirm a new active KBS owner binding can be generated for the same stable binding_key/resource path, authorizing the new identity to the old path if contents remain.
## Report
Validated the finding as a logic/security bug, not a memory crash. Direct crash attempt: `cargo test -p enclava-api unreachable_running_workload_teardown_is_best_effort -- --nocapture` completed successfully, proving the introduced behavior is non-crashing but allows deletion to proceed when teardown is unreachable. Valgrind attempt was made but valgrind is not installed in the container. Debugger validation: LLDB breakpoint at `crates/enclava-api/src/routes/apps.rs:157` stopped on `return Ok(())` after a teardown connection error; backtrace shows the path from `unreachable_running_workload_teardown_is_best_effort` into `request_workload_teardown`, confirming the API treats unreachable workload teardown as success. Code evidence: `apps.rs:140-157` returns `Ok(())` on HTTP send error; `apps.rs:165-176` also returns `Ok(())` on non-success teardown status. `delete_app` calls teardown then proceeds to mark deleting at `apps.rs:664-667`, despite the comment saying this is after workload-owned KBS material removal. The later deletion path only calls `soft_delete_owner_binding`, `soft_delete_tls_binding`, reconciles policy, and deletes the app row (`apps.rs:745-772`), with no KBS resource-content deletion. `soft_delete_owner_binding` only updates `deleted_at` in CAP DB (`kbs.rs:174-185`), and `reconcile_policy` only reads active DB bindings (`kbs.rs:212-217`) to render policy. Stable reuse was reproduced with a targeted engine PoC test: two app incarnations with different app_id/instance_id but same org/app name produced the same owner resource path `default/cap-test-org-test-app-test-app-owner/seed-encrypted`, while the KBS policy binding key also remained the same and the identity hash changed to the new app. This follows from identity derivation (`apps.rs:332-336`: namespace `cap-{org}-{app}` and service account `cap-{app}-sa`) and owner path derivation (`types.rs:310-325`: `default/{namespace}-{name}-owner/seed-encrypted`). Because the app row is physically deleted and the apps unique constraint is only on live rows (`0002_apps_and_deployments.sql:7-23`), the same org/app name can be recreated. The recreated app then gets a fresh active owner binding for the same binding_key via `ensure_owner_binding` (`kbs.rs:94-109`), authorizing access to the stable resource path if stale KBS contents remain.

# Evidence
crates/enclava-api/src/kbs.rs (L174 to 185)
  Note: Soft deletion removes only the database policy binding for the old app_id; it does not delete the KBS resource value at the stable path.
```
pub async fn soft_delete_owner_binding(db: &PgPool, app_id: Uuid) -> Result<(), KbsPolicyError> {
    sqlx::query(
        "UPDATE kbs_owner_bindings
         SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
         WHERE app_id = $1",
    )
    .bind(app_id)
    .execute(db)
    .await?;

    Ok(())
}
```

crates/enclava-api/src/kbs.rs (L94 to 109)
  Note: KBS owner policy bindings are recreated for the app's stable binding_key/resource type, allowing a new app incarnation to be authorized for the old path.
```
    let binding_key = app.owner_resource_type();
    sqlx::query(
        "INSERT INTO kbs_owner_bindings (
            app_id, binding_key, repository, allowed_tags, namespace, service_account,
            tenant_instance_identity_hash, deleted_at
         )
         VALUES ($1, $2, 'default', ARRAY['seed-encrypted', 'seed-sealed'], $3, $4, $5, NULL)
         ON CONFLICT (app_id) DO UPDATE
         SET binding_key = EXCLUDED.binding_key,
             repository = EXCLUDED.repository,
             allowed_tags = EXCLUDED.allowed_tags,
             namespace = EXCLUDED.namespace,
             service_account = EXCLUDED.service_account,
             tenant_instance_identity_hash = EXCLUDED.tenant_instance_identity_hash,
             deleted_at = NULL,
             updated_at = now()",
```

crates/enclava-api/src/routes/apps.rs (L140 to 158)
  Note: The introduced behavior treats an unreachable teardown endpoint as success and continues deletion, leaving workload-owned KBS material potentially undeleted.
```
    let response = match state
        .tee_http_client
        .post(&url)
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                app_name = %app.name,
                namespace = %app.namespace,
                url = %url,
                error = %error,
                "workload teardown endpoint unreachable; continuing app deletion"
            );
            return Ok(());
        }
```

crates/enclava-api/src/routes/apps.rs (L165 to 176)
  Note: The introduced behavior also treats explicit non-success teardown responses as success, including cases that previously returned conflict/bad-gateway.
```
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    tracing::warn!(
        app_id = %app.id,
        app_name = %app.name,
        namespace = %app.namespace,
        url = %url,
        status = status.as_u16(),
        body = %body,
        "workload teardown endpoint returned non-success; continuing app deletion"
    );
    Ok(())
```

crates/enclava-api/src/routes/apps.rs (L332 to 336)
  Note: A recreated app with the same org and name receives the same namespace and service account; only instance_id changes with app_id.
```
    let tenant_id = org_name.to_string();
    let app_id_short = &app_id.to_string()[..8];
    let instance_id = format!("{tenant_id}-{app_id_short}");
    let namespace = format!("cap-{org_name}-{app_name}");
    let service_account = format!("cap-{app_name}-sa");
```

crates/enclava-api/src/routes/apps.rs (L664 to 676)
  Note: Deletion proceeds after the best-effort teardown call even though the comment states the app should be marked deleting only after workload-owned KBS material has been removed.
```
    request_workload_teardown(&state, &auth, &app).await?;

    // Mark as deleting after workload-owned KBS material has been removed.
    sqlx::query("UPDATE apps SET status = 'deleting', updated_at = now() WHERE id = $1")
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
```

crates/enclava-api/src/routes/apps.rs (L738 to 772)
  Note: The remaining deletion path soft-deletes CAP policy bindings and deletes the app row, but does not remove the underlying KBS resource contents.
```
    delete_tenant_namespace(&app.namespace).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("failed to delete tenant namespace: {}", e)})),
        )
    })?;

    crate::kbs::soft_delete_owner_binding(&state.db, app.id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("failed to remove KBS owner binding: {}", e)})),
            )
        })?;
    crate::kbs::soft_delete_tls_binding(&state.db, state.kbs_policy.as_ref(), app.id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("failed to remove KBS TLS binding: {}", e)})),
            )
        })?;
    crate::kbs::reconcile_policy(&state.db, state.kbs_policy.as_ref())
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(
                    serde_json::json!({"error": format!("failed to reconcile KBS policy: {}", e)}),
                ),
            )
        })?;

    sqlx::query("DELETE FROM apps WHERE id = $1")
```

crates/enclava-engine/src/types.rs (L308 to 326)
  Note: KBS owner resource paths are derived from namespace and app name, so deleting and recreating the same app name reuses the same KBS resource path.
```
    /// KBS owner ciphertext path for this app.
    /// E.g., "default/{namespace}-{name}-owner/seed-encrypted"
    pub fn owner_resource_path(&self) -> String {
        format!("default/{}/seed-encrypted", self.owner_resource_type())
    }

    /// Stable owner-resource instance name used by the attestation proxy.
    ///
    /// The live Trustee policy derives owner resource access from the attested
    /// Kubernetes namespace and the tenant instance annotation, so CAP uses the
    /// namespace and app name for the KBS owner path.
    pub fn owner_instance_id(&self) -> String {
        format!("{}-{}", self.namespace, self.name)
    }

    /// KBS owner resource type for `owner_resource_bindings`.
    pub fn owner_resource_type(&self) -> String {
        format!("{}-owner", self.owner_instance_id())
    }
```

Proposed patch:
diff --git a/crates/enclava-api/src/routes/apps.rs b/crates/enclava-api/src/routes/apps.rs
index f3c05661fc2cd1fcea96aaf8d5d315984edc06a3..9b97ea88406f45d0cb0642e16afe6f3dce9dbf19 100644
--- a/crates/enclava-api/src/routes/apps.rs
+++ b/crates/enclava-api/src/routes/apps.rs
@@ -130,72 +130,85 @@ async fn request_workload_teardown(
             StatusCode::INTERNAL_SERVER_ERROR,
             Json(serde_json::json!({"error": format!("failed to issue teardown token: {e}")})),
         )
     })?;

     let domain = app.tee_domain.as_deref().unwrap_or(&app.domain);
     let url = format!(
         "https://{}/.well-known/confidential/teardown",
         domain.trim_end_matches('/')
     );
     let response = match state
         .tee_http_client
         .post(&url)
         .bearer_auth(token)
         .send()
         .await
     {
         Ok(response) => response,
         Err(error) => {
             tracing::warn!(
                 app_id = %app.id,
                 app_name = %app.name,
                 namespace = %app.namespace,
                 url = %url,
                 error = %error,
-                "workload teardown endpoint unreachable; continuing app deletion"
+                "workload teardown endpoint unreachable; blocking app deletion"
             );
-            return Ok(());
+            return Err((
+                StatusCode::BAD_GATEWAY,
+                Json(serde_json::json!({
+                    "error": format!("failed to contact workload teardown endpoint: {error}")
+                })),
+            ));
         }
     };

     if response.status().is_success() {
         return Ok(());
     }

     let status = response.status();
     let body = response.text().await.unwrap_or_default();
     tracing::warn!(
         app_id = %app.id,
         app_name = %app.name,
         namespace = %app.namespace,
         url = %url,
         status = status.as_u16(),
         body = %body,
-        "workload teardown endpoint returned non-success; continuing app deletion"
+        "workload teardown endpoint returned non-success; blocking app deletion"
     );
-    Ok(())
+    Err((
+        StatusCode::CONFLICT,
+        Json(serde_json::json!({
+            "error": format!(
+                "workload teardown endpoint returned non-success status {}",
+                status.as_u16()
+            )
+        })),
+    ))
 }

 /// Comprehensive app name validation
 pub(crate) fn validate_app_name(name: &str) -> Result<(), String> {
     if name.is_empty() || name.len() > 63 {
         return Err("app name must be between 1 and 63 characters".to_string());
     }

     // Reserved names (Kubernetes system names)
     let reserved = [
         "kubernetes",
         "kube",
         "kube-system",
         "kube-public",
         "kube-node-lease",
         "default",
         "kube-service-account",
         "kube-root-ca",
         "config",
         "health",
         "status",
         "metrics",
         "prometheus",
         "grafana",
     ];


diff --git a/crates/enclava-api/src/routes/apps/tests/mod.rs b/crates/enclava-api/src/routes/apps/tests/mod.rs
index 95335dd326afb850e506bb70d0a1fb1e804ee600..3dbf8b89c03b51c32c045e2ae2f9ff9e95fd322f 100644
--- a/crates/enclava-api/src/routes/apps/tests/mod.rs
+++ b/crates/enclava-api/src/routes/apps/tests/mod.rs
@@ -69,84 +69,92 @@ fn teardown_token_instance_id_matches_attestation_proxy_owner_instance_id() {
         signer_identity_subject: None,
         signer_identity_issuer: None,
         signer_identity_set_at: None,
         source_provider: None,
         source_repository: None,
         created_at: chrono::Utc::now(),
         updated_at: chrono::Utc::now(),
     };

     assert_eq!(
         workload_teardown_instance_id(&app),
         "cap-a826eb13-demo-demo"
     );
 }

 #[test]
 fn only_running_apps_require_workload_teardown_endpoint() {
     assert!(requires_workload_teardown(AppStatus::Running));
     assert!(!requires_workload_teardown(AppStatus::Creating));
     assert!(!requires_workload_teardown(AppStatus::Failed));
     assert!(!requires_workload_teardown(AppStatus::Stopped));
     assert!(!requires_workload_teardown(AppStatus::Deleting));
 }

 #[tokio::test]
-async fn unreachable_running_workload_teardown_is_best_effort() {
+async fn unreachable_running_workload_teardown_blocks_deletion() {
     let mut state = crate::test_support::lazy_state();
     state.tee_http_client = reqwest::Client::builder()
         .timeout(Duration::from_millis(200))
         .build()
         .unwrap();
     let auth = crate::test_support::auth_context(Role::Admin, &["apps:write"]);
     let app = App {
         id: uuid::Uuid::new_v4(),
         org_id: auth.org_id,
         name: "demo".to_string(),
         namespace: "cap-a826eb13-demo".to_string(),
         instance_id: "a826eb13-12345678".to_string(),
         tenant_id: "a826eb13".to_string(),
         service_account: "cap-demo-sa".to_string(),
         bootstrap_owner_pubkey_hash: "00".repeat(32),
         tenant_instance_identity_hash: "11".repeat(32),
         unlock_mode: UnlockMode::Password,
         domain: "127.0.0.1:9".to_string(),
         tee_domain: Some("127.0.0.1:9".to_string()),
         custom_domain: None,
         status: AppStatus::Running,
         signer_identity_subject: None,
         signer_identity_issuer: None,
         signer_identity_set_at: None,
         source_provider: None,
         source_repository: None,
         created_at: chrono::Utc::now(),
         updated_at: chrono::Utc::now(),
     };

-    request_workload_teardown(&state, &auth, &app)
+    let err = request_workload_teardown(&state, &auth, &app)
         .await
-        .expect("unreachable workload teardown endpoint must not block deletion");
+        .expect_err("unreachable workload teardown endpoint must block deletion");
+
+    assert_eq!(err.0, StatusCode::BAD_GATEWAY);
+    assert!(
+        err.1["error"]
+            .as_str()
+            .unwrap_or_default()
+            .contains("failed to contact workload teardown endpoint")
+    );
 }

 #[tokio::test]
 async fn create_app_rejects_member_before_database_access() {
     let result = create_app(
         crate::test_support::auth_context(Role::Member, &[]),
         State(crate::test_support::lazy_state()),
         Json(CreateAppRequest {
             name: "demo".to_string(),
             unlock_mode: "password".to_string(),
             bootstrap_pubkey_hash: None,
             signer_identity_subject: None,
             signer_identity_issuer: None,
             source_provider: None,
             source_repository: None,
         }),
     )
     .await;
     let err = match result {
         Ok(_) => panic!("member app creation unexpectedly passed authorization"),
         Err(err) => err,
     };

     assert_eq!(err.0, StatusCode::FORBIDDEN);
 }

# Attack-path analysis
Final: high | Decider: model_decided | Matrix severity: high | Policy adjusted: high
## Rationale
The original high severity is upheld. Static evidence shows the product API route is reachable by authenticated org admins/API keys, teardown failure is intentionally non-fatal, the subsequent delete path only soft-deletes CAP policy bindings and deletes the app row, and app recreation reuses the same name-derived KBS owner resource path. The impact is serious because stale owner seed/wrap-key material may be disclosed to a new app incarnation. It is not raised to critical because there is strong authorization on the route, the impact appears same-tenant/same-org rather than cross-tenant, and exploitation depends on stale KBS material remaining after a failed workload teardown.
## Likelihood
high - Reachability is realistic through normal remote API app deletion/recreation flows, and validation showed the best-effort behavior. However, exploitation requires org admin/apps:write privileges, KBS policy/resource configuration, successful app name reuse, and a failed or non-success teardown leaving resource contents behind. | Remote network vector
## Impact
high - The exposed data is KBS owner seed/wrap-key material for a previous confidential app incarnation. That can undermine confidentiality and lifecycle isolation for workload secrets within the org. The impact is not assessed as critical because the path is same-org and requires privileged app-management access plus stale KBS contents.
## Assumptions
- Trustee/KBS policy reconciliation is enabled in production for confidential workloads.
- The workload teardown endpoint is the mechanism intended to delete workload-owned KBS owner seed material.
- A failed or unreachable teardown endpoint can leave the KBS resource value present at its existing resource path.
- An org owner/admin or API key with apps:write can delete and recreate an app name in the same org.
- authenticated org owner/admin role or equivalent API key with apps:write
- target app is running or otherwise has existing KBS owner seed material
- workload teardown endpoint is unreachable or returns non-success during deletion
- same org/app name is recreated and deployed so a new workload identity can request the stable KBS path
## Path
Remote admin/API key
  -> DELETE /apps/{name}
  -> teardown endpoint unreachable or 5xx
  -> request_workload_teardown returns Ok
  -> app deletion soft-deletes CAP binding and deletes app row
  -> recreate same app name
  -> same namespace/service account/owner_resource_path
  -> new KBS binding authorizes stale resource path
  -> stale owner seed/wrap-key exposure
## Path evidence
- `crates/enclava-api/src/lib.rs:270-278` - The main API exposes POST /apps and DELETE /apps/{name} routes.
- `crates/enclava-api/src/main.rs:773-780` - The API binds to BIND_ADDR, defaulting to 0.0.0.0:3000.
- `crates/enclava-api/src/routes/apps.rs:639-646` - delete_app is an authenticated app-management route requiring admin role and apps:write scope.
- `crates/enclava-api/src/routes/apps.rs:140-157` - An unreachable workload teardown endpoint logs a warning and returns Ok, allowing deletion to continue.
- `crates/enclava-api/src/routes/apps.rs:165-176` - A non-success teardown response also logs a warning and returns Ok.
- `crates/enclava-api/src/routes/apps.rs:664-667` - Deletion proceeds after the best-effort teardown despite the comment that KBS material should already be removed.
- `crates/enclava-api/src/routes/apps.rs:745-772` - The remaining deletion path only soft-deletes KBS bindings, reconciles policy, and deletes the app row; no KBS resource content deletion is visible.
- `crates/enclava-api/src/kbs.rs:174-185` - soft_delete_owner_binding only sets deleted_at in CAP's database.
- `crates/enclava-api/src/kbs.rs:212-219` - Policy reconciliation renders active, non-deleted bindings; it does not purge Trustee/KBS resource values.
- `crates/enclava-api/src/routes/apps.rs:332-336` - Namespace and service account are derived from org/app name, so recreating the same name reuses them; only instance_id includes app_id.
- `crates/enclava-engine/src/types.rs:309-325` - The KBS owner resource path/type are derived from namespace and app name, producing a stable path for name reuse.
- `crates/enclava-api/src/kbs.rs:85-116` - ensure_owner_binding creates an active binding using app.owner_resource_type for the stable binding key.
- `crates/enclava-api/src/kbs.rs:623-630` - Rendered owner policy authorizes allowed tags/namespaces/service accounts/identity hashes for each binding key.
- `crates/enclava-api/migrations/0002_apps_and_deployments.sql:7-24` - Apps have a unique org/name constraint only while the row exists; physical deletion permits recreating the same name.
## Narrative
The finding is a real, in-scope lifecycle vulnerability. The public CAP API exposes app create/delete routes and listens on 0.0.0.0:3000. Deleting an app requires admin/apps:write, but the deletion path now treats unreachable or non-success workload teardown as success. The code comment says deletion marks the app as deleting after workload-owned KBS material has been removed, but after the best-effort teardown the remaining path only deletes DNS/edge/Kubernetes namespace state, soft-deletes CAP's KBS binding rows, reconciles active policy, and physically deletes the app row. Recreating the same org/app name is possible after the row is deleted and derives the same namespace, service account, owner_resource_type, and owner_resource_path. ensure_owner_binding then creates a fresh active policy binding for the same binding key/path with the new app identity hash. If stale KBS owner seed/wrap-key material remains because teardown failed, the new workload can be authorized to read it. Severity remains high because the impacted data is sensitive KBS owner material, but not critical because exploitation is constrained to authenticated same-org app-management privileges and a failed/stale teardown condition rather than unauthenticated or cross-tenant access.
## Controls
- AuthContext authentication
- owner/admin role check
- apps:write API-key scope check
- org_id scoping in app lookup
- global API rate limit
- KBS policy reconciliation
- tenant namespace deletion
- soft-delete of CAP KBS binding rows
## Blindspots
- Static analysis cannot directly inspect live Trustee/KBS storage to prove the resource value remains after every teardown failure.
- No cloud or cluster APIs were called, so runtime RBAC and actual ingress/LB configuration were not verified.
- The exact workload-side teardown implementation was not found in the inspected repository paths, so the conclusion relies on API comments and visible deletion/KBS policy code.
- Whether a newly deployed workload can immediately request the stale KBS path may depend on runtime Trustee policy deployment timing and attestation behavior.

#####
Global signed KBS policy retention enables tenant DoS
Link: https://chatgpt.com/codex/cloud/security/findings/30b88ef01c008191bbd315bf31b9225e?sev&repo=https%3A%2F%2Fgithub.com%2Fenclava-ai%2Fcap%2Chttps%3A%2F%2Fgithub.com%2Fenclava-ai%2Fenclava-paas
Criticality: high (attack path: high)
Status: new

# Metadata
Repo: enclava-ai/cap
Commit: 3e83d83
Author: codex@enclava.local
Created: 6/29/2026, 9:57:18 AM
Assignee: Unassigned
Signals: Security, Validated, Patch generated, Attack-path

# Summary
Introduced: signed KBS artifact retention is now enforced globally instead of per active app, allowing one tenant's recent signed deployments to evict other tenants' active policy artifacts from the global Trustee/KBS policy set.
The new reconciliation query selects active signed policy artifacts with a single global `LIMIT $1`, and the new selector enforces the same `signed_policy_retention` globally. Since the default retention is only 6, the KBS ConfigMap policy set can contain artifacts for only the six most recent active deployments platform-wide, not the latest artifacts for each active app. Any signed deployment now calls this global reconciliation path. As a result, an authenticated tenant with app deployment privileges can create enough recent signed deployments to consume the global slots and push older active deployments from other tenants out of the Trustee policy set. The init-side verifier explicitly fails when the active Trustee policy set does not include the workload's descriptor hash, so evicted tenants can fail startup/restart or KBS artifact/secret access. The prior query retained artifacts per `app_id`; the new global limit turns a local tenant action into a cross-tenant KBS availability issue.

# Validation
## Rubric
- [x] Confirm signed deployment requests enter global signed-policy reconciliation regardless of local/per-app context.
- [x] Confirm reconciliation SQL uses one platform-wide active-artifact ordering and `LIMIT`, not per-app/per-tenant partitioning.
- [x] Confirm artifact selector applies `max_artifacts` and byte budget globally and does not guarantee one artifact per active app/tenant.
- [x] Confirm default retention is small enough to make eviction practical and demonstrate with six attacker artifacts excluding one victim artifact.
- [x] Confirm init-side verifier/KBS consumer fails when the active Trustee policy set lacks the workload descriptor hash.
## Report
Validated the finding as a logic/availability flaw. The commit changed signed deployment behavior so any signed artifact triggers global reconciliation: `should_reconcile_global_signed_policy_artifacts` returns only `signed_policy_artifact_present` at `crates/enclava-api/src/deploy.rs:113-118`, and signed deployments call `crate::kbs::reconcile_signed_policy_artifacts(...)` at `crates/enclava-api/src/deploy.rs:1050-1057`. The reconciliation query at `crates/enclava-api/src/kbs.rs:280-287` selects all active signed workload artifacts platform-wide with `ORDER BY d.created_at DESC, wa.created_at DESC LIMIT $1`; there is no partition/filter by `app_id`, `org_id`, or `tenant_id`. This matters because apps are tenant/org scoped (`apps.org_id`, `apps.tenant_id` in `crates/enclava-api/migrations/0002_apps_and_deployments.sql:7-14`), deployments are per app (`0002_apps_and_deployments.sql:55-64`), and workload artifacts are per app/deploy (`0025_workload_artifacts.sql:5-15`). The selector then enforces only a global cap (`selected.len() >= max_artifacts`) at `crates/enclava-api/src/kbs.rs:361-386`; default retention is 6 at `crates/enclava-api/src/kbs.rs:15` and used unless overridden at `kbs.rs:678-682`. I added a targeted PoC unit test invoking the real selector with six newer attacker artifacts followed by one older active victim artifact. Command: `cargo test -p enclava-api kbs::tests::signed_policy_global_retention_allows_recent_tenant_to_evict_victim -- --nocapture`. Output showed: `selected_count=6 selected=["99999999-9999-9999-9999-999999999999:b0b0", ..., "99999999-9999-9999-9999-999999999999:b5b5"] victim_present=false`, proving the victim artifact is absent from the generated policy set. I also ran LLDB non-interactively on the same test; it stopped after the actual selector returned and showed `selected.len = 6`, then the test passed. Init-side impact is confirmed by `crates/enclava-init/src/trustee_verify.rs:260-270`, where a policy set lacking the workload descriptor hash returns `InitError::TrusteePolicy("active Trustee policy set did not include matching workload artifact")`. I attempted an init-side dynamic test, but `enclava-init` could not build in this container due missing system `libcryptsetup` (`Package 'libcryptsetup' ... not found`). I attempted Valgrind as required, but Valgrind is not installed. No crash is expected because this is a deterministic authorization/availability logic bug rather than memory corruption.

# Evidence
crates/enclava-api/src/deploy.rs (L1050 to 1057)
  Note: Signed deployments invoke `reconcile_signed_policy_artifacts`, applying the global artifact selection to the shared KBS policy ConfigMap.
```
    if let Some(signed_policy_artifact) = signed_policy_artifact.as_ref() {
        if should_reconcile_global_signed_policy_artifacts(true, &app_spec.attestation) {
            crate::kbs::reconcile_signed_policy_artifacts(
                &pool,
                kbs_policy_config.as_ref(),
                Some(signed_policy_artifact),
            )
            .await?;
```

crates/enclava-api/src/deploy.rs (L113 to 118)
  Note: The commit makes every signed deployment request global signed-policy reconciliation, so any tenant signed deploy can rewrite the shared KBS policy aggregate.
```
fn should_reconcile_global_signed_policy_artifacts(
    signed_policy_artifact_present: bool,
    _attestation: &AttestationConfig,
) -> bool {
    signed_policy_artifact_present
}
```

crates/enclava-api/src/kbs.rs (L280 to 313)
  Note: The new query orders all active workload artifacts platform-wide and applies a single `LIMIT $1`, then passes the candidates through the global retention selector. This is no longer partitioned by app/tenant, so recent deployments from one tenant can evict other tenants' active artifacts.
```
    let rows: Vec<SignedPolicyArtifactRow> = sqlx::query_as(
        r#"
        SELECT wa.signed_policy_artifact
        FROM workload_artifacts wa
        JOIN deployments d ON d.id = wa.deploy_id AND d.app_id = wa.app_id
        WHERE d.status::text IN ('pending', 'applying', 'watching', 'healthy')
        ORDER BY d.created_at DESC, wa.created_at DESC
        LIMIT $1
        "#,
    )
    .bind(config.signed_policy_retention)
    .fetch_all(db)
    .await?;

    if rows.is_empty() && extra_artifact.is_none() {
        return Ok(());
    }

    let mut candidates = Vec::with_capacity(rows.len() + usize::from(extra_artifact.is_some()));
    if let Some(extra_artifact) = extra_artifact {
        candidates.push(extra_artifact.clone());
    }
    candidates.extend(
        rows.into_iter()
            .map(|row| serde_json::from_value(row.signed_policy_artifact))
            .collect::<Result<Vec<_>, _>>()?,
    );

    let candidate_count = candidates.len();
    let artifacts = select_signed_policy_artifacts_for_policy_body(
        candidates,
        config.signed_policy_retention,
        config.signed_policy_max_bytes,
    )?;
```

crates/enclava-api/src/kbs.rs (L361 to 383)
  Note: The selector enforces `max_artifacts` and the byte budget across the entire candidate list, rather than ensuring coverage for each active app, causing older active apps to be dropped from the policy body.
```
fn select_signed_policy_artifacts_for_policy_body(
    candidates: Vec<crate::signing_service::SignedPolicyArtifact>,
    max_artifacts: i64,
    max_policy_bytes: usize,
) -> Result<Vec<crate::signing_service::SignedPolicyArtifact>, KbsPolicyError> {
    let max_artifacts = usize::try_from(max_artifacts.max(1)).unwrap_or(1);
    let mut selected = Vec::new();
    let mut seen = HashSet::new();

    for artifact in candidates {
        if !seen.insert(artifact.metadata.descriptor_core_hash.clone()) {
            continue;
        }
        if selected.len() >= max_artifacts {
            continue;
        }

        let mut candidate_selection = selected.clone();
        candidate_selection.push(artifact.clone());
        let candidate_body = signed_policy_artifact_policy_body(&candidate_selection)?;
        if candidate_body.len() <= max_policy_bytes || selected.is_empty() {
            selected.push(artifact);
        }
```

crates/enclava-api/src/kbs.rs (L678 to 687)
  Note: The default global signed policy retention is only 6 artifacts, making cross-tenant eviction practical unless operators override the environment.
```
        signed_policy_retention: std::env::var("KBS_SIGNED_POLICY_RETENTION")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_SIGNED_POLICY_RETENTION),
        signed_policy_max_bytes: std::env::var("KBS_SIGNED_POLICY_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_SIGNED_POLICY_MAX_BYTES),
```

crates/enclava-init/src/trustee_verify.rs (L260 to 270)
  Note: Workload verification fails when the active Trustee policy set does not include the workload's descriptor hash, so eviction from the global set causes KBS/policy verification failure for victim workloads.
```
    policy_set
        .artifacts
        .into_iter()
        .find(|artifact| {
            artifact.metadata.descriptor_core_hash
                == bundle.signed_policy_artifact.metadata.descriptor_core_hash
        })
        .ok_or_else(|| {
            InitError::TrusteePolicy(
                "active Trustee policy set did not include matching workload artifact".into(),
            )
```

Proposed patch:
diff --git a/crates/enclava-api/src/kbs.rs b/crates/enclava-api/src/kbs.rs
index 58690716dd75a9d057e6424713624c447b3b9e9d..6db347b780c2b8c1edc68872db7d3742a19ce742 100644
--- a/crates/enclava-api/src/kbs.rs
+++ b/crates/enclava-api/src/kbs.rs
@@ -257,146 +257,148 @@ pub async fn reconcile_policy(
                 "namespace": config.namespace,
             },
             "data": data,
         });
         let pp = PatchParams::apply("enclava-platform").force();
         cm_api
             .patch(&config.configmap_name, &pp, &Patch::Apply(&patch))
             .await?;
         restart_trustee_deployment(client, config).await?;
     }

     Ok(())
 }

 pub async fn reconcile_signed_policy_artifacts(
     db: &PgPool,
     config: Option<&KbsPolicyConfig>,
     extra_artifact: Option<&crate::signing_service::SignedPolicyArtifact>,
 ) -> Result<(), KbsPolicyError> {
     let Some(config) = config else {
         return Err(KbsPolicyError::NotConfigured);
     };

     let rows: Vec<SignedPolicyArtifactRow> = sqlx::query_as(
         r#"
-        SELECT wa.signed_policy_artifact
-        FROM workload_artifacts wa
-        JOIN deployments d ON d.id = wa.deploy_id AND d.app_id = wa.app_id
-        WHERE d.status::text IN ('pending', 'applying', 'watching', 'healthy')
-        ORDER BY d.created_at DESC, wa.created_at DESC
-        LIMIT $1
+        SELECT signed_policy_artifact
+        FROM (
+            SELECT
+                wa.signed_policy_artifact,
+                d.app_id,
+                d.created_at AS deployment_created_at,
+                wa.created_at AS artifact_created_at,
+                ROW_NUMBER() OVER (
+                    PARTITION BY d.app_id
+                    ORDER BY d.created_at DESC, wa.created_at DESC
+                ) AS app_artifact_rank
+            FROM workload_artifacts wa
+            JOIN deployments d ON d.id = wa.deploy_id AND d.app_id = wa.app_id
+            WHERE d.status::text IN ('pending', 'applying', 'watching', 'healthy')
+        ) ranked_active_artifacts
+        WHERE app_artifact_rank <= $1
+        ORDER BY deployment_created_at DESC, artifact_created_at DESC
         "#,
     )
     .bind(config.signed_policy_retention)
     .fetch_all(db)
     .await?;

     if rows.is_empty() && extra_artifact.is_none() {
         return Ok(());
     }

     let mut candidates = Vec::with_capacity(rows.len() + usize::from(extra_artifact.is_some()));
     if let Some(extra_artifact) = extra_artifact {
         candidates.push(extra_artifact.clone());
     }
     candidates.extend(
         rows.into_iter()
             .map(|row| serde_json::from_value(row.signed_policy_artifact))
             .collect::<Result<Vec<_>, _>>()?,
     );

     let candidate_count = candidates.len();
-    let artifacts = select_signed_policy_artifacts_for_policy_body(
-        candidates,
-        config.signed_policy_retention,
-        config.signed_policy_max_bytes,
-    )?;
+    let artifacts =
+        select_signed_policy_artifacts_for_policy_body(candidates, config.signed_policy_max_bytes)?;

     let client = kube::Client::try_default().await?;
     let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
     let cm = cm_api.get(&config.configmap_name).await?;
     let mut data = cm.data.unwrap_or_default();
     let next_policy = signed_policy_artifact_policy_body(&artifacts)?;
     tracing::info!(
         candidate_artifacts = candidate_count,
         selected_artifacts = artifacts.len(),
         policy_bytes = next_policy.len(),
         max_policy_bytes = config.signed_policy_max_bytes,
         "reconciled bounded signed KBS policy artifacts"
     );

     if data.get(&config.policy_key) != Some(&next_policy) {
         data.insert(config.policy_key.clone(), next_policy);
         let patch = serde_json::json!({
             "apiVersion": "v1",
             "kind": "ConfigMap",
             "metadata": {
                 "name": config.configmap_name,
                 "namespace": config.namespace,
             },
             "data": data,
         });
         let pp = PatchParams::apply("enclava-platform").force();
         cm_api
             .patch(&config.configmap_name, &pp, &Patch::Apply(&patch))
             .await?;
         restart_trustee_deployment(client, config).await?;
     }

     Ok(())
 }

 fn signed_policy_artifact_policy_body(
     artifacts: &[crate::signing_service::SignedPolicyArtifact],
 ) -> Result<String, KbsPolicyError> {
     if let [artifact] = artifacts {
         return Ok(serde_json::to_string(artifact)?);
     }
     Ok(serde_json::to_string(&SignedPolicyArtifactSet {
         schema_version: SIGNED_POLICY_SET_SCHEMA_VERSION,
         artifacts,
     })?)
 }

 fn select_signed_policy_artifacts_for_policy_body(
     candidates: Vec<crate::signing_service::SignedPolicyArtifact>,
-    max_artifacts: i64,
     max_policy_bytes: usize,
 ) -> Result<Vec<crate::signing_service::SignedPolicyArtifact>, KbsPolicyError> {
-    let max_artifacts = usize::try_from(max_artifacts.max(1)).unwrap_or(1);
     let mut selected = Vec::new();
     let mut seen = HashSet::new();

     for artifact in candidates {
         if !seen.insert(artifact.metadata.descriptor_core_hash.clone()) {
             continue;
         }
-        if selected.len() >= max_artifacts {
-            continue;
-        }
-
         let mut candidate_selection = selected.clone();
         candidate_selection.push(artifact.clone());
         let candidate_body = signed_policy_artifact_policy_body(&candidate_selection)?;
         if candidate_body.len() <= max_policy_bytes || selected.is_empty() {
             selected.push(artifact);
         }
     }

     Ok(selected)
 }

 fn is_signed_policy_artifact_body(policy: &str) -> bool {
     let Ok(value) = serde_json::from_str::<serde_json::Value>(policy) else {
         return false;
     };
     let is_single = value.get("metadata").is_some()
         && value.get("rego_text").is_some()
         && value.get("signature").is_some();
     let is_set = value
         .get("artifacts")
         .and_then(serde_json::Value::as_array)
         .map(|artifacts| !artifacts.is_empty())
         .unwrap_or(false);
     is_single || is_set
 }
@@ -894,79 +896,76 @@ owner_resource_bindings := {}
             agent_policy_text: "package agent_policy\n\ndefault CreateContainerRequest := true\n"
                 .to_string(),
             agent_policy_sha256: "11".repeat(32),
             signature: "ee".repeat(64),
             verify_pubkey_b64: "ZmFrZS1wdWJrZXk=".to_string(),
             org_keyring: None,
         };

         let body =
             signed_policy_artifact_policy_body(&[artifact.clone(), artifact.clone()]).unwrap();
         let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();

         assert_eq!(parsed["schema_version"], "enclava-signed-policy-set-v1");
         assert_eq!(parsed["artifacts"].as_array().unwrap().len(), 2);
         assert!(is_signed_policy_artifact_body(&body));
     }

     #[test]
     fn signed_policy_selection_prefers_first_artifact_and_dedupes_by_descriptor_hash() {
         let current = test_signed_policy_artifact("aa", 16);
         let duplicate_old = test_signed_policy_artifact("aa", 4096);
         let recent_other = test_signed_policy_artifact("bb", 16);

         let selected = select_signed_policy_artifacts_for_policy_body(
             vec![current.clone(), duplicate_old, recent_other.clone()],
-            6,
             usize::MAX,
         )
         .unwrap();

         assert_eq!(selected, vec![current, recent_other]);
     }

     #[test]
-    fn signed_policy_selection_enforces_global_retention() {
+    fn signed_policy_selection_keeps_artifacts_across_apps_without_global_retention() {
         let current = test_signed_policy_artifact("aa", 16);
         let recent_one = test_signed_policy_artifact("bb", 16);
         let recent_two = test_signed_policy_artifact("cc", 16);

         let selected = select_signed_policy_artifacts_for_policy_body(
-            vec![current.clone(), recent_one.clone(), recent_two],
-            2,
+            vec![current.clone(), recent_one.clone(), recent_two.clone()],
             usize::MAX,
         )
         .unwrap();

-        assert_eq!(selected, vec![current, recent_one]);
+        assert_eq!(selected, vec![current, recent_one, recent_two]);
     }

     #[test]
     fn signed_policy_selection_prunes_old_artifacts_to_byte_budget() {
         let current = test_signed_policy_artifact("aa", 128);
         let old = test_signed_policy_artifact("bb", 4096);
         let current_body_len = signed_policy_artifact_policy_body(std::slice::from_ref(&current))
             .unwrap()
             .len();

         let selected = select_signed_policy_artifacts_for_policy_body(
             vec![current.clone(), old],
-            6,
             current_body_len + 32,
         )
         .unwrap();

         assert_eq!(selected, vec![current]);
         let selected_body = signed_policy_artifact_policy_body(&selected).unwrap();
         assert!(selected_body.len() <= current_body_len + 32);
     }

     #[test]
     fn signed_policy_selection_keeps_first_artifact_even_when_it_exceeds_budget() {
         let current = test_signed_policy_artifact("aa", 128);

         let selected =
-            select_signed_policy_artifacts_for_policy_body(vec![current.clone()], 6, 1).unwrap();
+            select_signed_policy_artifacts_for_policy_body(vec![current.clone()], 1).unwrap();

         assert_eq!(selected, vec![current]);
     }
 }

# Attack-path analysis
Final: high | Decider: model_decided | Matrix severity: high | Policy adjusted: high
## Rationale
Severity remains high. The finding is in the main product API and KBS reconciliation path, reachable from the public deploy endpoint by an authenticated tenant org admin or apps:write API key. Static evidence confirms that signed deployments trigger shared KBS reconciliation, the query and selector enforce a single global retention cap with no tenant/app partition, the default cap is 6, and the resulting policy is patched into the shared Trustee policy ConfigMap. Init-side code explicitly fails when the workload descriptor hash is missing. This supports a credible cross-tenant availability attack against KBS-protected workloads. It is not raised to critical because the attacker must already have valid tenant deployment privileges, the exploit is specific to KBS-enabled signed-policy mode, and the demonstrated impact is denial of service rather than direct compromise of credentials, arbitrary code execution, or secret exfiltration.
## Likelihood
high - Exploitation is straightforward for a tenant with normal deployment privileges in a KBS-enabled signed-policy deployment: submit at least the global retention count of newer signed deployments. It is not unauthenticated and depends on KBS policy management being enabled, so likelihood is below critical/wormable exposure. | Remote network vector
## Impact
high - The flaw crosses tenant boundaries and affects a shared KBS/Trustee policy set. Evicting a victim's active signed policy artifact makes their workload fail Trustee policy matching on startup/restart or KBS resource access. This is a significant availability impact on security-critical confidential workload infrastructure, but it does not directly disclose secrets or grant code execution.
## Assumptions
- KBS policy management is enabled with KBS_POLICY_MANAGEMENT_ENABLED or KBS_POLICY_MANAGEMENT_REQUIRED in the production deployment.
- The platform is operating in the signed-policy / Trustee policy-read mode described by the project threat model.
- The attacker has a normal tenant account with org admin or API-key privileges sufficient for apps:write deployments.
- Victim workloads depend on their signed policy artifact remaining present in the active Trustee/KBS policy set for startup, restart, or KBS resource access.
- authenticated CAP API access
- tenant org admin role or API key with apps:write scope
- ability to submit valid signed deployment artifacts
- KBS policy management enabled
- more recent attacker signed deployments than the global signed_policy_retention cap
## Path
Tenant attacker -> public API /apps/{name}/deploy -> signed artifact stored -> global KBS reconciliation LIMIT 6 -> shared Trustee policy omits victim artifact -> victim init/KBS verification fails
## Path evidence
- `deploy/api/ingress.yaml:8-24` - The API is exposed through an nginx Ingress for api.enclava.dev to the enclava-api service.
- `deploy/api/service.yaml:7-13` - The service is ClusterIP on port 80 targeting the API container port 3000.
- `crates/enclava-api/src/main.rs:773-781` - The API process binds to 0.0.0.0:3000 by default.
- `crates/enclava-api/src/lib.rs:289-306` - The product router exposes POST /apps/{name}/deploy.
- `crates/enclava-api/src/routes/deployments.rs:325-337` - The deploy route is reachable to authenticated users and scopes the app lookup by auth.org_id.
- `crates/enclava-api/src/auth/scopes.rs:64-67` - Deployment requires org admin role and apps:write scope, making the attacker an authenticated tenant deployer rather than a platform admin.
- `crates/enclava-api/src/routes/deployments.rs:745-752` - Signed workload artifacts are persisted for the app/deployment before the async apply path reconciles KBS state.
- `crates/enclava-api/src/deploy.rs:113-118` - Any present signed policy artifact causes global signed-policy reconciliation; attestation details are ignored.
- `crates/enclava-api/src/deploy.rs:1050-1057` - The signed deployment apply path invokes reconcile_signed_policy_artifacts for the shared KBS policy.
- `crates/enclava-api/src/kbs.rs:280-313` - The reconciliation query selects active signed workload artifacts platform-wide with a single ORDER BY/LIMIT and no org_id, tenant_id, or app_id partition.
- `crates/enclava-api/src/kbs.rs:328-343` - The selected global artifact set is written into the shared KBS policy ConfigMap and Trustee is restarted.
- `crates/enclava-api/src/kbs.rs:361-386` - The selector enforces max_artifacts globally over the candidate list, so older active victim artifacts can be dropped.
- `crates/enclava-api/src/kbs.rs:15-16` - The default signed policy retention is only 6 artifacts.
- `crates/enclava-api/src/kbs.rs:657-683` - KBS policy management is optional but, when enabled, uses the default Trustee namespace/configmap/deployment and default retention unless overridden.
- `crates/enclava-api/migrations/0002_apps_and_deployments.sql:7-17` - Apps are org/tenant scoped, establishing the tenant boundary that the global KBS query ignores.
- `crates/enclava-api/migrations/0025_workload_artifacts.sql:5-15` - Workload artifacts are stored per app/deployment, but the reconciliation query does not retain per-app coverage.
- `crates/enclava-init/src/trustee_verify.rs:260-270` - Workload verification fails when the active Trustee policy set lacks the workload's descriptor_core_hash.
## Narrative
This is a real in-scope security vulnerability in the main public deployment path. The deploy route is authenticated and org-scoped, but any tenant with app deployment privileges can submit signed deployments. Once a signed artifact is present, the API reconciles the shared KBS policy aggregate. That reconciliation selects active workload artifacts across the whole platform with a single ORDER BY/LIMIT and then applies a global max_artifacts cap, defaulting to 6. There is no partition by org, tenant, or app. The resulting policy body is written to the shared Trustee/KBS ConfigMap. The init-side verifier fails if the active policy set does not include the workload descriptor hash. Therefore, a tenant can create enough recent signed deployments to evict older active artifacts belonging to other tenants and cause cross-tenant KBS startup/resource-access denial of service. The issue is not critical because it requires authenticated deployment privileges and causes availability loss rather than direct secret disclosure or code execution, but it is high severity due to cross-tenant impact on KBS-protected workloads.
## Controls
- Deploy route requires AuthContext
- Deploy route requires org admin role and apps:write scope
- App lookup is scoped by auth.org_id
- Signed deployment artifact validation is performed before persistence
- API routes have tower-governor rate limiting with default 1 request/second and burst 100
- Production CORS defaults to no allowed cross-origin origins
- KBS policy management is disabled unless KBS_POLICY_MANAGEMENT_ENABLED or KBS_POLICY_MANAGEMENT_REQUIRED is set
- Container manifest uses non-root user, read-only root filesystem, dropped capabilities, and automountServiceAccountToken: false
## Blindspots
- Static review cannot confirm the exact production KBS_POLICY_MANAGEMENT_* environment values.
- deploy/api manifests do not include explicit KBS policy-management env vars or RBAC, so the packaged manifest may be incomplete relative to the KBS-enabled threat model.
- Static review cannot measure operational quotas, billing controls, or external Paas-managed entitlement limits that may restrict how many apps/deployments a tenant can create.
- The provided validation PoC exercised the selector logic directly rather than performing a full end-to-end multi-tenant deployment against Kubernetes/Trustee.



#####
Global GHCR pull secret attached to every tenant app
Link: https://chatgpt.com/codex/cloud/security/findings/7132cdbaad208191a54347eb10dee401?sev&repo=https%3A%2F%2Fgithub.com%2Fenclava-ai%2Fcap%2Chttps%3A%2F%2Fgithub.com%2Fenclava-ai%2Fenclava-paas
Criticality: high (attack path: high)
Status: new

# Metadata
Repo: enclava-ai/cap
Commit: 1a3ac46
Author: codex@enclava.local
Created: 6/27/2026, 7:37:28 PM
Assignee: Unassigned
Signals: Security, Validated, Patch generated, Attack-path

# Summary
Introduced a credential over-scoping vulnerability: platform GHCR credentials intended for private template pulls are materialized in every tenant namespace and referenced by every tenant ServiceAccount when the environment variables are present.
The new tenant image-pull secret plumbing is applied globally. If GHCR_USERNAME and GHCR_TOKEN are set, build_confidential_app() always sets image_pull_secret_name for every ConfidentialApp, generate_service_account() attaches that secret to the app ServiceAccount, and apply_all_with_tenant_image_pull_secret() creates the dockerconfigjson Secret in the tenant namespace. Because tenants can deploy workloads with attacker-chosen image references subject to CAP's normal signing policy, this makes the kubelet a confused deputy for the platform GHCR token: a tenant can attempt to pull any ghcr.io image that the platform token can read, including private template or platform images, rather than only the intended template image. The Secret is not mounted into the pod, but its registry authority is still usable for all image pulls made under that ServiceAccount. The fix should scope pull credentials to the specific hosted-template deployment/image, use per-template/per-repository least-privilege credentials, or otherwise avoid attaching a broad platform registry credential to arbitrary tenant workloads.

# Validation
## Rubric
- [x] GHCR env vars globally enable a tenant image-pull secret name without template/app/image scoping.
- [x] The platform GHCR username/token are materialized into a `kubernetes.io/dockerconfigjson` Secret for `ghcr.io` in a tenant namespace.
- [x] Deployment code applies that Secret during tenant deployment when the env config exists.
- [x] Every `ConfidentialApp` built from DB state receives the configured pull-secret name, not only private hosted-template apps.
- [x] The generated workload ServiceAccount references that Secret and the pod uses that ServiceAccount, making the credential available to kubelet pulls for the app workload images.
## Report
Validated the credential over-scoping finding. Direct crash/ASan are not meaningful for this authorization/credential-scoping bug; `valgrind` and `gdb` were not installed, but I used a debug Rust test binary under `lldb` and targeted Cargo tests. Code evidence: `crates/enclava-api/src/deploy.rs:89-98` makes `configured_tenant_image_pull_secret_name()` return the global default `enclava-registry-auth` whenever `GHCR_USERNAME` and `GHCR_TOKEN` are set, without checking app/template/image scope. `deploy.rs:100-110` builds `TenantImagePullSecretConfig` directly from those platform GHCR env vars. `deploy.rs:113-144` materializes them into a Kubernetes `kubernetes.io/dockerconfigjson` Secret for registry authority `ghcr.io`, including username/password/auth. `deploy.rs:167-169` applies that Secret into the tenant namespace during deployment. `deploy.rs:397-407` assigns `image_pull_secret_name: configured_tenant_image_pull_secret_name()` to every `ConfidentialApp` built from DB state. `deploy.rs:988-1013` obtains the env config and applies the manifests/tenant Secret on deployment. `crates/enclava-engine/src/manifest/service_account.rs:23-26` attaches that Secret as `image_pull_secrets` on the workload ServiceAccount. `crates/enclava-engine/src/manifest/statefulset.rs:130` makes the pod use that ServiceAccount, and `containers.rs:265-267` uses the app-specified primary container image. Dynamic evidence: I added a minimal validation unit test that sets `GHCR_USERNAME=platform-bot` and `GHCR_TOKEN=platform-token-can-read-private-templates`, then asserts that the real deploy code returns the global default secret name and creates a tenant namespace dockerconfigjson Secret containing those credentials for `ghcr.io`. Command output: `cargo test -p enclava-api validation_global_ghcr_env_creates_tenant_secret_and_name -- --nocapture` => `test deploy::tests::validation_global_ghcr_env_creates_tenant_secret_and_name ... ok`. Existing engine test output: `cargo test -p enclava-engine service_account_references_image_pull_secret_when_configured -- --nocapture` => `test service_account_references_image_pull_secret_when_configured ... ok`. Debugger evidence: `lldb` breakpoints hit `enclava_api::deploy::configured_tenant_image_pull_secret_name` at `deploy.rs:90` from the validation test, then `enclava_api::deploy::generate_tenant_image_pull_secret` at `deploy.rs:119` with namespace length 8 / `tenant-a`; after continuing, the test passed. This confirms the suspected chain: platform GHCR credentials become a tenant Secret and are referenced by the ServiceAccount used for the tenant workload, so kubelet image pulls under that ServiceAccount can use the broad GHCR credential rather than a template-scoped credential.

# Evidence
crates/enclava-api/src/deploy.rs (L113 to 144)
  Note: The platform GHCR username/token are written into a Kubernetes dockerconfigjson Secret for ghcr.io.
```
fn generate_tenant_image_pull_secret(
    namespace: &str,
    config: &TenantImagePullSecretConfig,
) -> Secret {
    use base64::Engine as _;

    let auth = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", config.username, config.token));
    let docker_config_json = serde_json::json!({
        "auths": {
            "ghcr.io": {
                "username": config.username,
                "password": config.token,
                "auth": auth,
            }
        }
    })
    .to_string();

    let mut string_data = std::collections::BTreeMap::new();
    string_data.insert(".dockerconfigjson".to_string(), docker_config_json);

    Secret {
        metadata: ObjectMeta {
            name: Some(config.name.clone()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        string_data: Some(string_data),
        type_: Some("kubernetes.io/dockerconfigjson".to_string()),
        ..Default::default()
    }
```

crates/enclava-api/src/deploy.rs (L167 to 169)
  Note: The registry credential Secret is applied inside the tenant namespace during every deployment when configured.
```
    if let Some(config) = image_pull_secret_config {
        let secret = generate_tenant_image_pull_secret(ns_name, config);
        apply_namespaced_resource(engine, ns_name, &secret).await?;
```

crates/enclava-api/src/deploy.rs (L397 to 407)
  Note: Every ConfidentialApp built from the database receives the configured pull secret name, with no check that the app is a private hosted template.
```
    Ok(ConfidentialApp {
        app_id: app.id,
        name: app.name.clone(),
        namespace: app.namespace.clone(),
        instance_id: app.instance_id.clone(),
        tenant_id: app.tenant_id.clone(),
        bootstrap_owner_pubkey_hash: app.bootstrap_owner_pubkey_hash.clone(),
        tenant_instance_identity_hash: app.tenant_instance_identity_hash.clone(),
        service_account: app.service_account.clone(),
        image_pull_secret_name: configured_tenant_image_pull_secret_name(),
        signer_identity_subject: app.signer_identity_subject.clone(),
```

crates/enclava-api/src/deploy.rs (L89 to 110)
  Note: If GHCR_USERNAME and GHCR_TOKEN are configured, a tenant image-pull secret name is enabled globally; there is no template/app/image scope decision here.
```
fn configured_tenant_image_pull_secret_name() -> Option<String> {
    if let Some(name) = env_nonempty(TENANT_IMAGE_PULL_SECRET_NAME_ENV) {
        return Some(name);
    }

    match (env_nonempty("GHCR_USERNAME"), env_nonempty("GHCR_TOKEN")) {
        (Some(_), Some(_)) => Some(DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string()),
        _ => None,
    }
}

fn tenant_image_pull_secret_config_from_env() -> Option<TenantImagePullSecretConfig> {
    let username = env_nonempty("GHCR_USERNAME")?;
    let token = env_nonempty("GHCR_TOKEN")?;
    let name = configured_tenant_image_pull_secret_name()
        .unwrap_or_else(|| DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string());

    Some(TenantImagePullSecretConfig {
        name,
        username,
        token,
    })
```

crates/enclava-engine/src/manifest/service_account.rs (L23 to 26)
  Note: The secret is attached to the workload ServiceAccount, so all image pulls for that tenant app can use the broad GHCR credential.
```
        image_pull_secrets: app
            .image_pull_secret_name
            .as_ref()
            .map(|name| vec![LocalObjectReference { name: name.clone() }]),
```

Proposed patch:
diff --git a/crates/enclava-api/src/deploy.rs b/crates/enclava-api/src/deploy.rs
index 8157c3c2afec0ce254e21772e21200fac3b99527..d88b2f9a8d7162d9c21e2a0188f67fa5741c4c62 100644
--- a/crates/enclava-api/src/deploy.rs
+++ b/crates/enclava-api/src/deploy.rs
@@ -1,201 +1,113 @@
 //! Deploy orchestrator: builds ConfidentialApp from DB state, calls engine, records result.

 use enclava_common::image::ImageRef;
 use enclava_common::types::{ResourceLimits, UnlockMode as CommonUnlockMode};
 use enclava_engine::apply::{
     engine::ApplyEngine,
     gateway::apply_gateway_resources,
     namespace::apply_namespace,
     network_policy::apply_network_policy,
     orchestrator::{MANIFEST_HASH_ANNOTATION, manifest_hash},
-    resources::{apply_namespaced_resource, apply_standard_resources},
+    resources::apply_standard_resources,
     statefulset::apply_statefulset,
     types::{DeployPhase, DeployStatus as EngineDeployStatus},
     watch::watch_rollout,
 };
 use enclava_engine::manifest::generate_all_manifests;
 use enclava_engine::types::{
     AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, StorageSpec,
     WorkloadArtifactBinding,
 };
-use k8s_openapi::api::core::v1::Secret;
-use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
 use sqlx::PgPool;
 use uuid::Uuid;

 use crate::models::{App, AppContainer, AppResources, AppStatus};

-const DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME: &str = "enclava-registry-auth";
-const TENANT_IMAGE_PULL_SECRET_NAME_ENV: &str = "TENANT_IMAGE_PULL_SECRET_NAME";
-
-#[derive(Debug, Clone)]
-struct TenantImagePullSecretConfig {
-    name: String,
-    username: String,
-    token: String,
-}
-
 #[derive(Debug, PartialEq, Eq)]
 struct DeploymentOutcome {
     deploy_status: &'static str,
     app_status: &'static str,
     error_message: Option<String>,
 }

 fn classify_rollout_result(
     result: Result<EngineDeployStatus, String>,
     previous_app_status: AppStatus,
     unlock_mode: crate::models::UnlockMode,
 ) -> DeploymentOutcome {
     match result {
         Ok(status) if status.phase == DeployPhase::Running => DeploymentOutcome {
             deploy_status: "healthy",
             app_status: "running",
             error_message: None,
         },
         Ok(status)
             if status.phase == DeployPhase::TimedOut
                 && previous_app_status == AppStatus::Running
                 && unlock_mode == crate::models::UnlockMode::Password =>
         {
             DeploymentOutcome {
                 deploy_status: "healthy",
                 app_status: "running",
                 error_message: None,
             }
         }
         Ok(status) => DeploymentOutcome {
             deploy_status: "failed",
             app_status: "failed",
             error_message: status
                 .message
                 .or_else(|| Some(format!("{:?}", status.phase))),
         },
         Err(err) => DeploymentOutcome {
             deploy_status: "failed",
             app_status: "failed",
             error_message: Some(err),
         },
     }
 }

-fn env_nonempty(name: &str) -> Option<String> {
-    std::env::var(name).ok().and_then(|value| {
-        let trimmed = value.trim();
-        (!trimmed.is_empty()).then(|| trimmed.to_string())
-    })
-}
-
-fn configured_tenant_image_pull_secret_name() -> Option<String> {
-    if let Some(name) = env_nonempty(TENANT_IMAGE_PULL_SECRET_NAME_ENV) {
-        return Some(name);
-    }
-
-    match (env_nonempty("GHCR_USERNAME"), env_nonempty("GHCR_TOKEN")) {
-        (Some(_), Some(_)) => Some(DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string()),
-        _ => None,
-    }
-}
-
-fn tenant_image_pull_secret_config_from_env() -> Option<TenantImagePullSecretConfig> {
-    let username = env_nonempty("GHCR_USERNAME")?;
-    let token = env_nonempty("GHCR_TOKEN")?;
-    let name = configured_tenant_image_pull_secret_name()
-        .unwrap_or_else(|| DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string());
-
-    Some(TenantImagePullSecretConfig {
-        name,
-        username,
-        token,
-    })
-}
-
-fn generate_tenant_image_pull_secret(
-    namespace: &str,
-    config: &TenantImagePullSecretConfig,
-) -> Secret {
-    use base64::Engine as _;
-
-    let auth = base64::engine::general_purpose::STANDARD
-        .encode(format!("{}:{}", config.username, config.token));
-    let docker_config_json = serde_json::json!({
-        "auths": {
-            "ghcr.io": {
-                "username": config.username,
-                "password": config.token,
-                "auth": auth,
-            }
-        }
-    })
-    .to_string();
-
-    let mut string_data = std::collections::BTreeMap::new();
-    string_data.insert(".dockerconfigjson".to_string(), docker_config_json);
-
-    Secret {
-        metadata: ObjectMeta {
-            name: Some(config.name.clone()),
-            namespace: Some(namespace.to_string()),
-            ..Default::default()
-        },
-        string_data: Some(string_data),
-        type_: Some("kubernetes.io/dockerconfigjson".to_string()),
-        ..Default::default()
-    }
-}
-
-async fn apply_all_with_tenant_image_pull_secret(
+async fn apply_all(
     engine: &ApplyEngine,
     manifests: &enclava_engine::manifest::GeneratedManifests,
     manifest_hash: &str,
-    image_pull_secret_config: Option<&TenantImagePullSecretConfig>,
 ) -> Result<(), DeployError> {
     let ns_name = manifests
         .namespace
         .metadata
         .name
         .as_deref()
         .ok_or_else(|| {
             enclava_engine::apply::engine::ApplyError::NamespaceNotReady(
                 "namespace has no name".to_string(),
             )
         })?;

     apply_namespace(engine, &manifests.namespace).await?;
     tracing::info!(namespace = %ns_name, "step 1/5: namespace ready");

-    if let Some(config) = image_pull_secret_config {
-        let secret = generate_tenant_image_pull_secret(ns_name, config);
-        apply_namespaced_resource(engine, ns_name, &secret).await?;
-        tracing::info!(
-            namespace = %ns_name,
-            secret = %config.name,
-            "tenant image pull secret applied"
-        );
-    }
-
     apply_standard_resources(engine, manifests).await?;
     tracing::info!(namespace = %ns_name, "step 2/5: standard resources applied");

     apply_network_policy(engine, ns_name, &manifests.network_policy).await?;
     tracing::info!(namespace = %ns_name, "step 3/5: CiliumNetworkPolicy applied");

     apply_gateway_resources(
         engine,
         ns_name,
         &manifests.envoy_proxy,
         &manifests.gateway,
         &manifests.tls_route,
     )
     .await?;
     tracing::info!(namespace = %ns_name, "step 4/5: Gateway API resources applied");

     let mut sts = manifests.statefulset.clone();
     sts.metadata
         .annotations
         .get_or_insert_with(Default::default)
         .insert(
             MANIFEST_HASH_ANNOTATION.to_string(),
             manifest_hash.to_string(),
         );

@@ -381,51 +293,51 @@ pub async fn build_confidential_app(
     let mut storage = StorageSpec::new(&resources.app_data_size, &resources.tls_data_size);
     // Set bind mounts from the primary container
     if let Some(primary) = containers_rows.iter().find(|c| c.is_primary) {
         let paths = primary.storage_paths.clone().unwrap_or_default();
         storage.app_data.bind_mounts = paths
             .iter()
             .map(|path| {
                 let subdir = path.strip_prefix('/').unwrap_or(path).replace('/', "-");
                 BindMount {
                     source: format!("/data/{}", subdir),
                     destination: path.clone(),
                 }
             })
             .collect();
     }

     Ok(ConfidentialApp {
         app_id: app.id,
         name: app.name.clone(),
         namespace: app.namespace.clone(),
         instance_id: app.instance_id.clone(),
         tenant_id: app.tenant_id.clone(),
         bootstrap_owner_pubkey_hash: app.bootstrap_owner_pubkey_hash.clone(),
         tenant_instance_identity_hash: app.tenant_instance_identity_hash.clone(),
         service_account: app.service_account.clone(),
-        image_pull_secret_name: configured_tenant_image_pull_secret_name(),
+        image_pull_secret_name: None,
         signer_identity_subject: app.signer_identity_subject.clone(),
         signer_identity_issuer: app.signer_identity_issuer.clone(),
         containers,
         storage,
         unlock_mode,
         domain: DomainSpec {
             platform_domain: app.domain.clone(),
             tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
             custom_domain: app.custom_domain.clone(),
         },
         api_signing_pubkey: api_signing_pubkey.to_string(),
         api_url: api_url.to_string(),
         resources: ResourceLimits {
             cpu: resources.cpu_limit,
             memory: resources.memory_limit,
         },
         attestation: attestation_config.clone(),
         egress_allowlist: Vec::new(),
         workload_artifact_binding: None,
         generated_agent_policy: None,
     })
 }

 /// Record a deployment result in the database.
 pub async fn record_deployment_result(
@@ -497,86 +409,50 @@ mod tests {
         assert_eq!(outcome.app_status, "failed");
         assert_eq!(
             outcome.error_message.as_deref(),
             Some("rollout did not complete within 600s")
         );
     }

     #[test]
     fn password_create_timeout_still_fails() {
         let outcome = classify_rollout_result(
             Ok(EngineDeployStatus::timed_out(
                 "rollout did not complete within 600s",
             )),
             AppStatus::Creating,
             crate::models::UnlockMode::Password,
         );

         assert_eq!(outcome.deploy_status, "failed");
         assert_eq!(outcome.app_status, "failed");
         assert_eq!(
             outcome.error_message.as_deref(),
             Some("rollout did not complete within 600s")
         );
     }

-    #[test]
-    fn tenant_image_pull_secret_uses_dockerconfigjson_shape() {
-        let config = TenantImagePullSecretConfig {
-            name: "enclava-registry-auth".to_string(),
-            username: "cap-bot".to_string(),
-            token: "ghp_fake".to_string(),
-        };
-
-        let secret = generate_tenant_image_pull_secret("tenant-ns", &config);
-        let string_data = secret.string_data.as_ref().unwrap();
-        let docker_config: serde_json::Value =
-            serde_json::from_str(string_data.get(".dockerconfigjson").unwrap()).unwrap();
-
-        assert_eq!(
-            secret.metadata.name.as_deref(),
-            Some("enclava-registry-auth")
-        );
-        assert_eq!(secret.metadata.namespace.as_deref(), Some("tenant-ns"));
-        assert_eq!(
-            secret.type_.as_deref(),
-            Some("kubernetes.io/dockerconfigjson")
-        );
-        assert_eq!(
-            docker_config["auths"]["ghcr.io"]["username"].as_str(),
-            Some("cap-bot")
-        );
-        assert_eq!(
-            docker_config["auths"]["ghcr.io"]["password"].as_str(),
-            Some("ghp_fake")
-        );
-        assert_eq!(
-            docker_config["auths"]["ghcr.io"]["auth"].as_str(),
-            Some("Y2FwLWJvdDpnaHBfZmFrZQ==")
-        );
-    }
-
     fn customer_app_descriptor() -> DeploymentDescriptor {
         DeploymentDescriptor {
             schema_version: "v1".to_string(),
             org_id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
             org_slug: "8f346820".to_string(),
             app_id: uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
             app_name: "customer-app".to_string(),
             deploy_id: uuid::Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
             created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 12, 0, 0).unwrap(),
             nonce: [1; 32],
             app_domain: "customer-app.8f346820.enclava.dev".to_string(),
             tee_domain: "customer-app.8f346820.tee.enclava.dev".to_string(),
             custom_domains: Vec::new(),
             namespace: "cap-demo-org-customer-app".to_string(),
             service_account: "cap-customer-app-sa".to_string(),
             identity_hash: [2; 32],
             image_ref:
                 "ghcr.io/acme/customer-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                     .to_string(),
             image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 .to_string(),
             signer_identity: SignerIdentity {
                 subject:
                     "https://github.com/acme/customer-app/.github/workflows/docker.yaml@refs/heads/main"
                         .to_string(),
@@ -963,77 +839,70 @@ pub async fn apply_deployment_manifests(
         app_spec.attestation.local_trustee_policy_json = Some(trustee_policy);
     }
     if let Some(signed_policy_artifact) = signed_policy_artifact.as_ref() {
         let policy_sha256: [u8; 32] = hex::decode(&signed_policy_artifact.agent_policy_sha256)
             .map_err(|err| DeployError::Validation(format!("agent_policy_sha256: {err}")))?
             .try_into()
             .map_err(|bytes: Vec<u8>| {
                 DeployError::Validation(format!(
                     "agent_policy_sha256 must be 32 bytes, got {}",
                     bytes.len()
                 ))
             })?;
         app_spec.generated_agent_policy = Some(enclava_engine::types::GeneratedAgentPolicy {
             policy_text: signed_policy_artifact.agent_policy_text.clone(),
             policy_sha256,
             genpolicy_version_pin: signed_policy_artifact
                 .metadata
                 .genpolicy_version_pin
                 .clone(),
         });
     }

     enclava_engine::validate::validate_app(&app_spec)
         .map_err(|e| DeployError::Validation(e.to_string()))?;

-    let tenant_image_pull_secret_config = tenant_image_pull_secret_config_from_env();
     let manifests = generate_all_manifests(&app_spec);
     let hash = manifest_hash(&manifests);
     set_deployment_status(&pool, deployment_id, "applying", Some(&hash), None, false).await?;
     set_app_status(&pool, app.id, "creating").await?;

     if signed_policy_artifact.is_some() {
         crate::kbs::reconcile_signed_policy_artifacts(
             &pool,
             kbs_policy_config.as_ref(),
             signed_policy_artifact.as_ref(),
         )
         .await?;
     } else {
         crate::kbs::ensure_owner_binding(&pool, kbs_policy_config.as_ref(), &app_spec).await?;
         crate::kbs::ensure_tls_binding(&pool, kbs_policy_config.as_ref(), &app_spec).await?;
         crate::kbs::reconcile_policy(&pool, kbs_policy_config.as_ref()).await?;
     }

     let engine = ApplyEngine::try_default().await?;
-    apply_all_with_tenant_image_pull_secret(
-        &engine,
-        &manifests,
-        &hash,
-        tenant_image_pull_secret_config.as_ref(),
-    )
-    .await?;
+    apply_all(&engine, &manifests, &hash).await?;
     let edge_config = crate::edge::EdgeRouteConfig::from_env();
     let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
         .bind(app.org_id)
         .fetch_one(&pool)
         .await?;
     let app_target =
         crate::edge::resolve_backend_target(&app_spec.name, &app_spec.namespace, 443).await?;
     let tee_target =
         crate::edge::resolve_backend_target(&app_spec.name, &app_spec.namespace, 8081).await?;
     let app_backend =
         crate::edge::backend_name_for(&org_slug, &app_spec.name, crate::edge::BackendTag::App)?;
     let tee_backend =
         crate::edge::backend_name_for(&org_slug, &app_spec.name, crate::edge::BackendTag::Tee)?;
     let mut routes = vec![
         crate::edge::SniRoute::new(&app_spec.domain.platform_domain, &app_backend, &app_target)?,
         crate::edge::SniRoute::new(&app_spec.domain.tee_domain, &tee_backend, &tee_target)?,
     ];
     if let Some(custom) = app_spec.domain.custom_domain.as_deref()
         && !custom.is_empty()
     {
         routes.push(crate::edge::SniRoute::new(
             custom,
             &app_backend,
             &app_target,
         )?);

# Attack-path analysis
Final: high | Decider: model_decided | Matrix severity: high | Policy adjusted: high
## Rationale
Original high severity is justified. The issue is in-scope product code and reachable through the public tenant deployment API by an authenticated tenant with normal deployment rights. Static evidence shows GHCR env credentials are globally transformed into a tenant namespace dockerconfigjson Secret and attached to every workload ServiceAccount, while tenant-controlled deploy inputs select the image rendered into the pod. The main impact is unauthorized use of a platform registry credential to pull private ghcr.io images, a meaningful cross-boundary data/supply-chain exposure. It is not raised to critical because it does not directly disclose the GHCR token, requires tenant authentication and app deployment privileges, and still depends on target image references and CAP signing-policy acceptance.
## Likelihood
high - The vulnerable code is on the normal public deployment path and tenant app deployment is an intended product function, but exploitation requires authenticated app-write privileges, GHCR env configuration, a broadly scoped platform token, and a target image that passes CAP's signing checks or has a signer identity the tenant can configure. These are plausible in this product context but not unauthenticated or guaranteed. | Remote network vector
## Impact
high - The bug crosses a tenant/platform authorization boundary by allowing tenant-triggered kubelet pulls to use a platform GHCR credential for ghcr.io. If that token can read private template or platform repositories, tenants can pull and run images they are not authorized to read, potentially exposing private container contents or proprietary platform/template code. The impact is reduced from critical because the token itself is not mounted into the pod and exploitation still depends on registry token scope, image knowledge, and signing-policy acceptance.
## Assumptions
- The deployed environment sets GHCR_USERNAME and GHCR_TOKEN for private GHCR access, as required for the vulnerable branch to activate.
- The GHCR token has read access to at least one private ghcr.io repository or image that ordinary tenants should not be able to pull.
- A tenant has normal app deployment privileges and can submit image references and, where required, customer-signed deployment descriptors through the public CAP API.
- The tenant knows or can discover a target private image reference/digest and can satisfy CAP's normal image signing policy for the target image, for example by pinning an app signer identity that matches an image signer during app creation.
- Authenticated tenant with apps:write / app deployment capability
- GHCR_USERNAME and GHCR_TOKEN configured in the API environment
- Platform GHCR token has broader read scope than the tenant
- Target image reference is accepted by CAP's digest resolution and cosign verification path
## Path
Tenant(apps:write)
  -> POST /apps/{name}/deploy(image=ghcr.io/target/private@sha256:...)
  -> CAP global GHCR env config
  -> tenant namespace Secret enclava-registry-auth
  -> workload ServiceAccount imagePullSecrets
  -> kubelet pulls with platform GHCR token
  -> unauthorized private image access
## Path evidence
- `crates/enclava-api/src/routes/deployments.rs:325-440` - Public app deploy route requires tenant auth/apps:write, loads the org-scoped app, parses the attacker-supplied image, resolves digest, and verifies the image with the app signer policy.
- `crates/enclava-api/src/routes/deployments.rs:838-853` - The deploy route asynchronously invokes apply_deployment_manifests, reaching the Kubernetes manifest apply path.
- `crates/enclava-api/src/deploy.rs:89-110` - If GHCR_USERNAME and GHCR_TOKEN are set, configured_tenant_image_pull_secret_name returns the global default pull-secret name and tenant_image_pull_secret_config_from_env builds config directly from those platform env vars.
- `crates/enclava-api/src/deploy.rs:113-144` - The platform GHCR username/token are serialized into a Kubernetes kubernetes.io/dockerconfigjson Secret for registry authority ghcr.io.
- `crates/enclava-api/src/deploy.rs:167-169` - The generated pull Secret is applied in the tenant namespace during deployment whenever image_pull_secret_config exists.
- `crates/enclava-api/src/deploy.rs:397-407` - Every ConfidentialApp built from DB state receives image_pull_secret_name from the global configuration, with no template/app/image scoping.
- `crates/enclava-api/src/deploy.rs:988-1013` - The manifest apply function obtains the tenant image pull secret config from env and passes it into apply_all_with_tenant_image_pull_secret for every deployment.
- `crates/enclava-engine/src/manifest/service_account.rs:17-30` - The generated workload ServiceAccount includes image_pull_secrets from app.image_pull_secret_name while disabling token automount.
- `crates/enclava-engine/src/manifest/statefulset.rs:126-131` - The generated pod uses app.service_account as its serviceAccountName, making the ServiceAccount imagePullSecrets applicable to pod image pulls.
- `crates/enclava-engine/src/manifest/containers.rs:265-267` - The primary workload container image is rendered from the app's container image reference/digest.
- `deploy/api/ingress.yaml:1-24` - Repository deployment artifact exposes the API through an nginx Ingress at api.enclava.dev.
- `deploy/api/service.yaml:1-14` - Repository deployment artifact maps service port 80 to API container port 3000.
## Narrative
This is a real in-scope vulnerability in the main deployment path. The public deploy route accepts tenant-controlled image references after AuthContext/apps:write checks and cosign policy verification. In deploy.rs, the presence of GHCR_USERNAME and GHCR_TOKEN globally enables the default tenant pull secret name and creates a dockerconfigjson Secret for ghcr.io using those platform credentials. The same deployment flow assigns that pull secret name to every ConfidentialApp and applies the Secret in the tenant namespace. The engine then renders the workload ServiceAccount with image_pull_secrets and the StatefulSet uses that ServiceAccount for the pod whose primary image is the app-specified image. This does not directly mount the GHCR token into the tenant pod, but it authorizes kubelet pulls for all images under that ServiceAccount, so an authenticated tenant can cause platform registry credentials to be used outside the intended private-template scope.
## Controls
- AuthContext required on deploy route
- scopes::require_app_write on deploy route
- ensure_management_write_allowed on deploy route
- Org-scoped app lookup by auth.org_id and app name
- Image digest resolution and cosign/Rekor verification before deployment
- Optional customer-signed deployment descriptor/policy artifact validation
- Generated tenant pod has automount_service_account_token:false
- Generated app container runs non-root with allowPrivilegeEscalation:false and readOnlyRootFilesystem:true in the non-legacy path
## Blindspots
- Static review cannot confirm the real production scope of GHCR_TOKEN or which private GHCR repositories it can read.
- Static review cannot confirm which private template/platform image references or digests are exposed to tenants.
- No live Kubernetes cluster was used here to observe an end-to-end private image pull.
- The practical amount of image content a tenant can exfiltrate depends on image contents, available shell/tools, configured command/descriptor behavior, and application exposure.
