# AWS or Bare-Metal Deployment Plan for CAP and Enclava PaaS

**Status:** Draft for architecture and security review

**Date:** 2026-08-26

**Scope:** Make one complete Enclava PaaS + CAP installation deployable on either the existing bare-metal platform or AWS. Each installation selects exactly one infrastructure profile. Mixed capacity, cross-site scheduling, shared application state, automatic failover, and migration between profiles are deferred to a separate project. ARM is out of scope.

**AWS recommendation:** AMD64 Amazon EKS for PaaS, CAP, and ordinary platform services; Confidential Containers Cloud API Adaptor (CAA) for tenant pods, with one AMD SEV-SNP EC2 peer-pod VM per tenant pod.

## 1. Executive decision

The practical first implementation is two deployment profiles, not a hybrid platform:

1. **`baremetal` profile:** preserve the current Kubernetes, local Kata/QEMU SNP runtime, VCEK attestation, Longhorn raw-block storage, databases, networking, and operational model.
2. **`aws` profile:** deploy a separate, self-contained PaaS + CAP installation on EKS. PaaS and CAP run as ordinary control-plane pods because they must not receive tenant plaintext. Tenant applications and their sidecars run only inside AMD SEV-SNP peer-pod EC2 VMs.
3. A PaaS installation has one `CAP_API_URL`, one CAP identity namespace, one CAP database, and one signed deployment context. No placement service, `execution_site` column, site-scoped CAP mappings, multi-CAP client registry, cross-site list merge, or app-specific site selection is required.
4. Infrastructure chooses the profile at deployment time. CAP uses profile-wide runtime, storage, quota, attestation, and network settings. The hosted API remains infrastructure-neutral unless AWS VM-tier billing or tenant-private registry support proves that a product DTO must change.
5. An AWS installation does not share or fail over applications to the bare-metal installation. Moving users or applications between installations is an explicit future migration project with identity, encrypted data, KBS policy, DNS, and rollback design.

The official AWS Confidential Containers example proves the basic mechanism, not this production system. On AWS, a Kubernetes pod is logically scheduled through an ordinary EKS worker, but CAA calls EC2 to create a separate `m6a` SNP VM as the pod sandbox. The application, `enclava-init`, Caddy, and the attestation proxy run inside that peer VM. The EKS worker runs the Kata shim, CAA, and Kubernetes machinery; it must not run tenant plaintext.

No non-confidential fallback is permitted. If CAA cannot create an approved SNP peer VM, attestation fails, storage cannot be attached safely, or Trustee refuses the release, the deployment fails closed.

## 2. Explicitly deferred work

The following does not belong in this project:

- One PaaS routing applications between a bare-metal CAP and an AWS CAP.
- Bare-metal and EC2 nodes in one Kubernetes worker pool.
- EKS Hybrid Nodes or conversion of the current k0s cluster into EKS.
- Running AWS peer VMs from the current bare-metal workers across a WAN/VPN tunnel.
- Cross-installation identity synchronization, CAP UUID mapping, entitlement allocation, status aggregation, or billing reconciliation.
- Automatic overflow, rebalancing, failover, live migration, encrypted volume replication, or DNS cutover.
- A generic multi-cloud scheduler or dynamic CAP endpoint discovery.

**Reasoning:** None of this is required to prove and operate a secure AWS installation. Deferring it removes an entire distributed-systems layer while preserving a clean future boundary: a later project can coordinate two already working installations.

## 3. Security contract

### 3.1 Information that must remain confidential

- Tenant workload memory, application data, credentials, TLS private keys, and derived storage keys.
- Tenant persistent-volume plaintext and encrypted-log plaintext.
- Tenant secrets before they enter an attested guest.
- Tenant-private registry credentials. If application image content is part of the product claim, image layers and decryption keys are also confidential.
- Trustee/KBS repository material, policy-signing private keys, platform-release signing roots, and recovery keys.
- The authenticated key-release channel and the policy material binding release to an approved measurement.

AWS, the EKS control plane, ordinary EKS workers, Kubernetes administrators, and AWS administrators must not be able to recover these values from worker memory, Kubernetes Secrets, EC2 user data, EBS snapshots, RDS, logs, crash dumps, or container-runtime state.

### 3.2 Visible metadata

AWS and platform operators will see operational metadata: tenant/resource identifiers, image references, EC2 types, addresses, volume sizes, timestamps, traffic volume, and lifecycle events. An unencrypted image and any ordinary Kubernetes image-pull secret consumed by CAA are also outside the peer VM's confidentiality boundary. SEV-SNP does not hide traffic patterns or prevent denial of service. Product claims must say this directly.

### 3.3 Trusted computing base

The confidentiality claim depends on:

- AMD SEV-SNP firmware and the correct endorsement chain.
- The measured PodVM kernel, initrd/rootfs, Kata agent, guest components, and fixed configuration.
- Trustee/KBS, attestation verification, reference values, policy repository, and TLS identities.
- The policy-signing service, offline platform-release root, CAP/CLI verification code, and recovery process.
- `enclava-init`, attestation proxy, Caddy, image policy, and every artifact named by the signed release.
- Build, provenance, signing, and release pipelines for those components.

PaaS, CAP, EKS, IAM, RDS, and Kubernetes may orchestrate or store metadata, but none may independently authorize Trustee to release a tenant key to an unapproved guest.

### 3.4 Release blockers

- `DISABLECVM=true`, a `t3` or other non-TEE PodVM, or a normal-container fallback RuntimeClass.
- Running a tenant application directly on an ordinary EKS worker.
- A proof-of-concept/debug PodVM AMI, SSH access that can expose tenant state, or an unmeasured boot component.
- Treating CAP's `kernel_params` annotation as effective on Kata remote without proof.
- Staging/insecure verifier flags, HTTP KBS, disabled TLS verification, or raw production signing keys in pod environment variables.
- Accepting VLEK by relabeling it as VCEK or skipping the ARK-ASVK-VLEK certificate/report binding.
- Tenant plaintext on the outer EBS filesystem, Kubernetes Secrets, standard pod logs, RDS, or unencrypted temporary storage.
- An unreviewed/mutable CAA or CSI image, or a tenant-private credential sent through CAA's worker-visible image-pull-secret path.
- Promising container cgroup enforcement after the CAA webhook has removed those limits.
- A signed release that does not bind the actual runtime, PodVM measurement/configuration, policy, init, proxy, Caddy, and image policy.
- Trustee or the policy signer holding production keys on an ordinary EKS worker.

## 4. Deployment profiles

| Concern | `baremetal` | `aws` | Contract |
|---|---|---|---|
| Kubernetes | Existing cluster | Standard EKS with managed system nodes | One cluster per installation. |
| PaaS-to-CAP | One internal CAP URL | One internal CAP URL | Preserve the current single-client PaaS model. |
| Tenant runtime | Local Kata/QEMU SNP | Kata remote through CAA | Tenant plaintext stays inside an SNP VM. |
| Logical RuntimeClass | `kata-qemu-snp` | Prefer the same name mapped to `kata-remote` | Gate A must prove the alias; otherwise use a coordinated AWS release value. |
| Endorsement chain | ARK-ASK-VCEK | ARK-ASVK-VLEK for AWS shared tenancy | Verify as separate typed paths. |
| Persistent storage | Existing raw-block/Longhorn path | gp3 filesystem PVC containing a guest-opened LUKS2 file, subject to Gate B | The encryption key is released only after attestation. |
| Resource enforcement | Current pod/container plus local Kata accounting | Approved PodVM tier/count | Do not claim removed container limits survive CAA mutation. |
| Database | Existing platform databases | RDS PostgreSQL Multi-AZ with TLS | Database contains metadata, never tenant plaintext. |
| Tenant ingress | Existing edge | TCP NLB path | Tenant TLS terminates inside the confidential guest. |
| Platform ingress | Existing | NLB/ALB as approved | Platform TLS may terminate outside a guest only for endpoints whose data contract permits it. |
| Delivery | Existing Flux overlay | Separate AWS Flux overlay | Do not mutate the working profile in place. |

The profile is configuration, not a per-request field. A rendered installation must contain one coherent set of runtime, storage, quota, database, network, and release values. Mixed-profile manifests are rejected during rendering or startup.

Use `us-east-2` for the first AWS installation. AWS shared-tenancy SEV-SNP is currently available in `us-east-2` and `eu-west-1`; Ireland is therefore the only direct second-region profile using the same shared-tenancy model. Treat another region as a Dedicated Host redesign with separate cost, capacity, operations, and attestation review rather than a routine overlay value.

## 5. Blocking evidence gates

### Gate A — RuntimeClass alias and fixed PodVM boot contract

First test a Kubernetes `RuntimeClass` named `kata-qemu-snp` whose handler is `kata-remote`, and set CAA's `TARGET_RUNTIMECLASS` to that alias. This preserves CAP's current logical runtime value in the platform release, `cc_init_data`, policy generation, CLI, and `enclava-init`.

Kata 4.0.0's remote runtime does not pass the per-pod `io.katacontainers.config.hypervisor.kernel_params` value to the remote hypervisor. CAP currently uses that annotation for:

- `agent.aa_kbc_params=cc_kbc::<kbs>`
- `agent.guest_components_rest_api=all`

The AWS production design must instead prove the PodVM's fixed boot configuration. CAA 0.22.0 starts the Kata agent with `/etc/agent-config.toml`, launches AA and CDH as separate systemd services using `/run/peerpod/aa.toml` and `/run/peerpod/cdh.toml`, and runs `api-server-rest --features all`.

At the pinned guest-components version:

- `api-server-rest` binds `127.0.0.1:8006`.
- It serves both `/aa/token?token_type=kbs` and `/cdh/resource/...`.
- It forwards to the AA Unix socket at `/run/confidential-containers/attestation-agent/attestation-agent.sock` and CDH Unix socket at `/run/confidential-containers/cdh.sock`.
- Port 8081 is not the CDH REST service; CAP's `attestation-proxy` may use it as its own gateway.

The spike must record which CDH endpoint `enclava-init` actually calls and whether `attestation-proxy` fronts `api-server-rest`, duplicates its resource route, or talks to AA/CDH directly. Phase 2 must encode only that observed dependency.

Also record whether the pinned AMI uses the Go runtime or `runtime-rs`, its active configuration, and its effective annotation allowlist. If the RuntimeClass alias fails, make `kata-remote` an AWS-profile runtime through a coordinated signed-release, policy, init, CLI, and PaaS compatibility change. Do not keep ambiguous dual names.

### Gate B — Persistent storage and CSI maturity

CAP currently emits two `ReadWriteOnce`, `volumeMode: Block`, `longhorn-wait` claims and gives them to privileged `enclava-init` as `volumeDevices`. The current `caa-csi-block-driver` rejects raw Kubernetes block volumes, so the bare-metal manifest cannot be reused unchanged.

The preferred AWS experiment is:

1. Create one filesystem-mode gp3 PVC for each CAP claim.
2. Mount the outer filesystem only into `enclava-init` inside the peer VM.
3. Create/open a fixed-size LUKS2 container file using the existing Trustee-derived secret.
4. Open and format the inner filesystem inside the guest, then reuse the current guest-local bind-mount handoff to the application and Caddy.
5. Keep EBS encryption enabled only as defense in depth; guest LUKS remains the tenant boundary.

This depends on a small, prerelease third-party CSI project. Production acceptance requires an exact reviewed source commit and image digest, reproducible build, SBOM, provenance/signature, dependency and vulnerability review, privileged/RBAC/IAM review, tenant-volume binding tests, attach/detach race tests, upgrade/rollback tests, and a named internal owner willing to patch or fork it.

Before adopting it, estimate and time-box raw-device passthrough. If the driver review fails, maintenance stalls, the file-backed design loses data, or performance is unacceptable, raw-device passthrough becomes the primary implementation. Plaintext storage on EBS is never a fallback.

The current `enclava-init` LUKS path formats only demonstrably blank media and should be reused. Its present LUKS2 configuration has no authenticated integrity mode; `dm-integrity` support and performance must be measured rather than assumed.

### Gate C — VLEK verification

AWS shared-tenancy SNP uses VLEK. The repository currently accepts `vlek` and `asvk` labels but collapses them into VCEK/ASK fields, after which the verifier applies VCEK-specific chain, TCB, chip-ID, and hardware-ID rules.

Implement separate typed paths:

- Existing: ARK → ASK → VCEK.
- AWS: ARK → ASVK → VLEK.

The AWS path must verify the certificate chain, report signature, VLEK/report TCB binding required by AMD/AWS, report policy, measurement, nonce/report data, minimum TCB, and all required extensions. Cross-labeling (`ASVK + VCEK`, `ASK + VLEK`), altered certificates/reports, missing extensions, stale TCB, and wrong measurements must fail.

Gate acceptance requires a sanitized genuine AWS VLEK fixture and negative tests approved against AMD and AWS documentation. The existing VCEK path must retain regression coverage.

### Gate D — PodVM sizing, quota, and billing

CAA 0.22.0 supports `PODVM_INSTANCE_TYPES`, not only one global type. Its webhook aggregates pod/init-container resource values into default vCPU/memory annotations; the AWS provider selects the smallest allowlisted instance satisfying them. An explicit machine type has higher priority but must still be allowlisted.

The remaining constraints are important:

- The webhook removes resources from every application, sidecar, and init container and adds `kata.peerpods.io/vm: 1` to one container.
- CAP's current CPU/memory ResourceQuota can reject or mis-account the mutated pod.
- CAA aggregates the application plus proxy, Caddy, `enclava-init`, and init-container overhead.
- The selected VM is the cross-tenant isolation, capacity, availability, metering, and billing boundary. The application may consume enough of its VM to starve its own sidecars.

Start with one CAA deployment and a small reviewed allowlist such as `m6a.large`, `m6a.xlarge`, and `m6a.2xlarge`. Add explicit sidecar headroom and an AWS ResourceQuota based on `requests.kata.peerpods.io/vm`, storage, and object counts. Use selected VM tier/count for AWS capacity and billing. Add a named CAP size tier only if automatic mapping is nondeterministic or the product must expose it.

### Gate E — Guest image pull and registry credentials

With peer pods, guest components pull the workload image inside the PodVM. CAP's digest pin and cosign check do not by themselves prove guest registry reachability, signature enforcement, decryption, or credential safety.

Choose one credential contract:

1. **Public signed image:** preferred; no pull credential. Use encrypted images plus a Trustee-released decryption key if image content is confidential.
2. **Platform-managed pull-only credential:** allowed only if classified as non-tenant infrastructure data, read-only, narrowly scoped, rotated, and safe to expose to the ordinary CAA worker. This can use CAA's built-in `auth.json` path.
3. **Tenant-private credential:** retrieve only inside the attested guest, for example through CDH's KBS-backed authenticated-registry configuration. Do not put it in the Kubernetes/CAA image-pull-secret path.

Private ECR requires a real refresh strategy because authorization tokens expire, and private peer-pod subnets require DNS plus `ecr.api`, `ecr.dkr`, and S3 layer access through endpoints or a reviewed egress route. GHCR requires reviewed internet egress. Missing credentials, endpoint loss, digest mismatch, unsigned images, or decryption-policy failure must fail closed without host-side execution.

### Gate F — Trust-plane location

For the first AWS production installation, reuse the independently operated Trustee/KBS and signing trust anchors over authenticated TLS. This avoids moving the authority that can release tenant keys while the workload platform is changing.

If all services must later reside in AWS, Trustee and signing require a separate confidential trust-plane design: attested confidential VMs, measured boot, secret injection after attestation, encrypted persistence, backup, recovery/quorum, and non-circular bootstrap. Ordinary EKS pods with AWS KMS-protected production keys do not satisfy a threat model that excludes AWS or cluster administrators.

## 6. Repository evidence

- `crates/enclava-engine/src/manifest/cc_init_data.rs` accepts `kata-qemu-snp` by default and a local development escape hatch, not arbitrary `kata-remote`.
- `crates/enclava-cli/platform-release.json`, CAP, CLI, and `enclava-init` share the signed expected RuntimeClass contract.
- `crates/enclava-engine/src/manifest/statefulset.rs` emits the kernel-parameter annotation and generic Kata/worker selectors.
- `crates/enclava-engine/src/manifest/resource_quota.rs` accounts normal CPU/memory resources and local Kata overhead.
- `crates/enclava-engine/src/manifest/volumes.rs` hardcodes two raw-block `longhorn-wait` claims.
- `crates/enclava-engine/src/manifest/containers.rs` exposes raw devices only to privileged `enclava-init`, then gives other containers guest-local decrypted mountpoints. The AWS design preserves this isolation.
- `crates/enclava-init/src/luks.rs` contains conservative blank-media formatting logic but currently disables LUKS authenticated integrity.
- `crates/enclava-cli/src/tee_client.rs` maps both `ask/asvk` and `vcek/vlek` into common fields; `crates/enclava-verifier/src/amd.rs` then verifies the VCEK model.
- CAP creates a GHCR Docker-config secret and attaches it to the service account. CAA can use it, but the credential is worker-visible.
- Enclava PaaS already has one `CAP_API_URL`, one CAP internal client, one CAP org/user mapping, and one durable CAP operation path. This plan intentionally preserves that model.
- The operations manifests contain Longhorn, on-prem CIDRs, staging flags, and a host-network tenant edge; AWS therefore needs a separate overlay.

## 7. Execution plan

### Phase 0 — Freeze threat model and profile contract

1. Trace every secret, image credential, descriptor, policy, configuration value, and storage key from PaaS through CAP, Kubernetes, CAA, EC2 user data, initdata, Trustee, and the tenant process.
   - **Reasoning:** A TEE does not help if PaaS or CAP has already stored tenant plaintext outside it.
   - **Acceptance:** PaaS/RDS/Kubernetes/CAA/worker/log paths contain only encrypted payloads, references, approved metadata, or explicitly classified platform credentials.
2. Inventory signing and release authority, including recovery keys and who can approve a new measurement.
   - **Reasoning:** The ability to sign an accepted release can be equivalent to access to tenant keys.
3. Define `baremetal` and `aws` as complete, mutually exclusive rendered profiles and list every setting that differs.
   - **Reasoning:** Partial profile selection could combine an AWS runtime with local storage or VLEK policy with a VCEK release.
4. Capture a secret-redacted live bare-metal baseline using `ssh control1.encl kubectl ...` for runtime labels, images, storage, PaaS/CAP/Trustee, network policy, and edge resources.
   - **Reasoning:** The existing profile must remain regression-tested and rollback-ready.

**Exit gate:** Security, CAP, PaaS, and operations owners approve the threat model, plaintext flow, trust authority, and complete profile matrix.

### Phase 1 — Disposable AWS compatibility spike

1. Create a disposable `us-east-2` account/VPC and small AMD64 EKS cluster using temporary `eksctl`/AWS CLI configuration and least privilege derived from CloudTrail.
2. Install pinned CAA 0.22.0 with `TEE_PLATFORM=amd`, confidential VMs enabled, and an approved `m6a` type. Prove the upstream sample creates a separate EC2 peer VM and does not execute the tenant process on the worker.
3. Test the `kata-qemu-snp` → `kata-remote` RuntimeClass alias, matching webhook target, CAP node selectors, actual Go/Rust runtime variant, active config, and effective annotation allowlist.
4. Prove Gate A's fixed guest topology: ignored kernel parameters absent from `/proc/cmdline`; initdata-written `aa.toml`/`cdh.toml`; AA/CDH sockets; `api-server-rest` on `127.0.0.1:8006`; both AA and CDH routes; and the exact `enclava-init`/proxy call chain.
5. Test at least three allowlisted SNP sizes and record original/mutated pods, aggregate resources, selected type, guest-visible resources, cgroups, ResourceQuota behavior, sidecar pressure, and over-limit rejection.
6. Capture genuine VLEK evidence and prove the current verifier rejects it for the understood typed-chain reason while all tampered variants also fail.
7. Review the exact CSI commit and test the gp3 filesystem/LUKS-file design: first format, read/write, pod restart, peer-VM replacement, detach/reattach, unclean shutdown, full disk, concurrent attach denial, snapshot plaintext scan, wrong key, absent attestation, ambiguous media refusal, and cleanup.
8. Test public, platform-private, tenant-private, and encrypted image paths as applicable. Remove endpoints, expire credentials, alter signatures/digests, inspect worker/user-data/logs for secrets, and test scratch-space limits.
9. Test Trustee TLS/key release and inbound tenant TCP through an NLB with tenant TLS terminating inside the guest.
10. Delete the sandbox and verify no orphan peer VMs, ENIs, EBS volumes, load balancers, security groups, or IAM roles remain.

**Exit gate:** Runtime, boot topology, sizing, VLEK fixture, storage safety, registry path, Trustee, ingress, and cleanup pass. A failed confidentiality or durability gate stops the production build.

### Phase 2 — Implement minimum profile-aware CAP changes

1. Add one validated installation-wide storage profile: existing `raw-block` default or AWS `filesystem-luks-file`, plus an explicit storage class.
   - **Reasoning:** Two real platforms require different transport; per-app storage selection is unnecessary.
2. Extend `enclava-init` with safe LUKS backing-file creation/opening only if the spike passes. Reuse existing format/open/mount logic; add durable allocation, permissions, fsync, no-reformat, mapping cleanup, and useful secret-free errors.
3. Implement typed ARK-ASVK-VLEK verification while preserving ARK-ASK-VCEK.
4. Use the RuntimeClass alias if proven. Otherwise make the AWS runtime a profile-wide signed value and coordinate release/policy/init/CLI/PaaS tests.
5. Make the kernel annotation local-profile-only or remove it from AWS manifests, and bind the production PodVM fixed service configuration into its measurement/release.
6. Add an AWS quota/resource profile using peer-VM tier/count. Preserve existing bare-metal ResourceQuota output.
7. Implement only the Gate E registry additions that the selected product contract requires.
8. Update signed release metadata for every changed image, policy, runtime, PodVM artifact, measurement, and fixed configuration.
9. Keep CAP internal API DTOs unchanged unless selected VM tier or tenant-private registry behavior must be exposed to PaaS. If a DTO changes, update/test PaaS before deploying the CAP producer.
10. Add profile validation that rejects incomplete or mixed configurations at startup and snapshot-tests both complete manifest outputs.

**Required CAP checks:**

```bash
rustup run stable cargo fmt --all -- --check
rustup run stable cargo clippy --workspace --all-targets -- -D warnings
rustup run stable cargo test --workspace
rustup run stable cargo test --doc
rustup run stable cargo audit --ignore RUSTSEC-2023-0071
rustup run stable cargo deny check advisories sources
rustup run stable cargo build --workspace
ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release --bin enclava-api
ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release --bin enclava
ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release -p enclava-init --features prod-strict
sudo docker build -f crates/enclava-init/Dockerfile -t enclava-init:local .
sudo docker build -f crates/enclava-api/Dockerfile -t enclava-api:local .
```

If PaaS contracts change, also run:

```bash
cargo fmt --all -- --check
cargo clippy -p enclava-paas-server --all-targets -- -D warnings
cargo check -p enclava-paas-server
cargo test -p enclava-paas-server
```

**Exit gate:** Both profiles render and test independently; local VCEK/raw-block behavior is unchanged; AWS VLEK/storage/runtime/image paths pass; and release artifacts are pinned.

### Phase 3 — Production AWS foundation

1. Create separate production/non-production AWS accounts with Organizations/SCP guardrails, CloudTrail, Config, GuardDuty, central audit logs, and break-glass roles.
2. Build a three-AZ VPC with public load-balancer subnets, private EKS/platform subnets, and private peer-pod subnets. Add only the NAT or VPC endpoints required for Trustee, registries, and AWS APIs.
3. Create standard EKS with a small multi-AZ AMD64 managed node group for platform availability. Tenant capacity does not require large workers because tenant compute lives in peer VMs.
4. Install pinned CAA, peerpod controller, fail-closed webhook, RuntimeClass, approved instance list, reviewed CSI image, EBS CSI, and AWS Load Balancer Controller using IRSA and tag-conditioned least privilege.
5. Build a production PodVM AMI from pinned sources with no default SSH/debug path, required crypto/filesystem drivers, fixed AA/CDH/REST services, provenance, SBOM, scan, reproducible measurement, and restricted AMI/snapshot permissions.
6. Create RDS PostgreSQL Multi-AZ databases/schemas and least-privilege roles for CAP, PaaS, Zitadel, and Lago according to supported isolation. Require CA verification, encryption, backups, and restore tests.
7. Configure gp3 platform storage and the reviewed peer-pod storage transport with explicit retention/deletion policies.
8. Deploy public PaaS/API ingress and tenant TCP NLB services. Terminate tenant TLS only inside the peer VM; use ACM only for explicitly approved platform endpoints.
9. Configure Route 53, tenant edge reconciliation, and FRP only if the hosted product still needs it on AWS. Delete rather than reproduce obsolete routing components.
10. Add metrics/alerts for CAA/webhook, selected VM tier, peer launch, attestation/KBS, registry auth, orphan resources, EBS attach, NLB, RDS, certificates, and EC2/ENI/EBS/address quotas.

**Exit gate:** IaC recreates the foundation; least privilege, private networking, restore, measurement, and observability tests pass; no example AMI or broad policy remains.

### Phase 4 — GitOps deployment profiles

1. Preserve the current bare-metal overlay and add a separate AWS overlay rather than conditionally patching individual live resources.
2. Put CAA, webhook `failurePolicy: Fail`, RuntimeClass, VM allowlist, CSI commit/digest, AWS controllers, IAM annotations, and peer-VM quota in the AWS overlay.
3. Configure AWS CAP with gp3/LUKS-file storage, RDS TLS, VLEK policy, production flags, Trustee CA/mTLS, pinned images, and the AWS signed release.
4. Deploy PaaS in AWS with its normal single `CAP_API_URL` pointing to AWS CAP and AWS-local RDS/Zitadel/Lago/FRP/public endpoints. Do not add multi-CAP configuration.
5. Configure the selected registry route and credential class in one rendered path.
6. Remove staging verifier flags, raw signing-key environment values, mutable tags, debug AMIs, broad management ingress, Longhorn references, on-prem CIDRs, and ordinary CPU/memory quota assumptions from AWS output.
7. Add automated rendering checks proving `baremetal` contains no AWS/CAA assumptions and `aws` contains no Longhorn/on-prem/staging assumptions.

**Exit gate:** Both overlays render cleanly, server-side dry-run/policy checks pass, and reviewers can identify one coherent profile from every manifest.

### Phase 5 — Deployment order

1. Deploy EBS/CAA/CSI/LB controllers, RuntimeClass, namespaces, quotas, registry networking, RDS, DNS, and observability first.
2. Verify Trustee TLS, attestation, policy repository, signing, and backup paths from a production-shaped peer VM.
3. If init/artifact parsing changed, publish and deploy `enclava-init` before the CAP API that emits the new form.
4. Deploy policy/release material and CAP only when runtime, PodVM measurement/configuration, sidecar digests, and schema agree.
5. Verify CAP internal mTLS/API, then deploy PaaS. If CAP DTOs changed, the compatible PaaS consumer must already be tested and deployable.
6. Deploy Zitadel, Lago, public ingress, and retained FRP dependencies, then enable hosted routes.

**Exit gate:** All live images are digest-pinned; signed release and measured guest agree; every VM tier maps correctly; a genuine VLEK canary obtains only its resource; altered evidence is denied; and PaaS completes the CAP lifecycle.

### Phase 6 — End-to-end AWS canary

1. Use the normal hosted PaaS/CLI path, not direct Kubernetes, to create a synthetic app.
2. Exercise create, deployment-context fetch, descriptor signing, start, readiness, ingress, encrypted logs, persistent write, restart, peer replacement, upgrade, rollback, proof/config/domain/status, delete, and failed-create cleanup for every offered tier/registry mode.
3. Run negative tests for wrong AMI/measurement, modified initdata, wrong runtime, malformed/stale VLEK, wrong report data, downgraded TCB, wrong sidecar digest, and unavailable Trustee.
4. Search EKS workers, CAA memory/logs, EC2 user data, outer EBS/snapshot, RDS, CloudWatch, load-balancer logs, Kubernetes objects, and PaaS/CAP logs for seeded tenant plaintext and tenant-private registry markers.
5. Inject EKS node replacement, peer termination, EBS detach, CAA/CSI restart, webhook outage, AZ loss, RDS failover, NLB/DNS failure, Trustee timeout, unsupported size, EC2 exhaustion, registry loss/expiry, policy rejection, and VM quota exhaustion.
6. Confirm a webhook outage blocks only new tenant admission, leaves existing workloads running, alerts immediately, and returns an actionable hosted status rather than retrying forever or using a normal runtime.
7. Run one internal workload and a small opt-in AWS tenant cohort. Rollback means disabling new AWS signups/deployments while preserving already-created AWS data; it does not redirect them to bare metal.

**Exit gate:** Complete lifecycle, confidentiality scans, failure injection, durability, cleanup, performance, and observation window pass with no severity-1 or confidentiality finding.

### Phase 7 — Production operations

1. Rehearse recovery for RDS, encrypted tenant volumes, Trustee metadata, signing keys, Flux state, and PodVM AMI loss without bypassing attestation.
2. Establish coordinated patch policy for EKS, CAA, Kata, PodVM kernel, AMD minimum TCB, CAP, PaaS, sidecars, and Trustee. Stage new measurements before release.
3. Forecast and alarm on approved PodVM type/count, on-demand `m6a` vCPU, EC2 API limits, ENIs, EBS, NLB targets, addresses, and `kata.peerpods.io/vm`; do not forecast from webhook-removed container resources.
4. Evaluate Capacity Reservations only after measured demand; keep tenant peer VMs on-demand initially and do not use Spot for confidential stateful workloads.
5. Reconcile cloud resources by mandatory ownership tags and run periodic orphan cleanup.
6. Repeat VLEK/VCEK regression, wrong-measurement, image-policy, storage snapshot, registry-marker, and plaintext-leakage canaries on every release.
7. Maintain separate recovery and release evidence for `baremetal` and `aws`. A release passing on one profile is not evidence for the other.

## 8. Cross-project change matrix

| Project | Expected changes | Avoid | Coordination |
|---|---|---|---|
| `cap` | Installation-wide AWS storage/runtime/quota profile; typed VLEK; fixed PodVM boot contract; registry path; fixtures/releases | Multi-site placement or PaaS product semantics | Init before API for artifact changes; preserve local defaults; PaaS first for DTO changes. |
| `enclava-paas` | AWS deployment configuration and possibly VM-tier/registry DTO support | Multi-CAP clients, site mappings, placement scheduler | Preserve one `CAP_API_URL`; test before incompatible CAP DTO rollout. |
| `enclava-ops-manifests` | Separate AWS overlay with CAA, RDS, gp3, NLB, AWS URLs, production flags | Mutating bare-metal overlay; mixed profile output | Controllers before CAP; verify live digests and canary manifests. |
| Policy/signing | Typed VLEK rules, AWS measurement/release, fixed guest services | Permissive VCEK/VLEK alias or raw production keys | Must agree with CAP, PodVM, Trustee, and CLI. |
| AWS IaC owner | VPC/EKS/RDS/IAM/NLB/Route53/endpoints/observability | General multi-cloud abstraction before spike | Choose repository at Gate review; keep bare-metal IaC intact. |
| CAA/CSI owner | Reviewed pins, provenance, security updates, fallback estimate | Unowned prerelease dependency | Named internal owner blocks production. |
| Trustee | AWS VLEK appraisal, TLS reachability, policies, backup/recovery | Production keys on ordinary EKS | Independent security and recovery review. |

## 9. Validation matrix

| Property | Positive proof | Negative proof |
|---|---|---|
| Profile isolation | Each overlay renders one coherent runtime/storage/evidence model | Mixed settings fail render/startup |
| Confidential placement | Tenant process exists only in approved SNP peer VM | Worker process inspection and non-SNP launch fail |
| Guest boot | AA/CDH sockets and both REST routes work on `127.0.0.1:8006` | Fixed service loss blocks unlock despite annotation |
| VLEK | Genuine ARK-ASVK-VLEK report accepted | Cross-label, altered chain/report/TCB/measurement rejected |
| VM sizing | Requests deterministically select approved tier and quota counts VM | Unsupported/oversized/non-allowlisted type rejected before launch |
| Key release | Correct measured release obtains only named resources | Wrong tenant/runtime/policy/image/measurement denied |
| Storage | Guest opens LUKS and survives restart/replacement | Snapshot/worker/wrong key yields no plaintext; ambiguous media not formatted |
| CSI integrity | Reviewed pinned image enforces tenant/volume binding | Forged/stale/cross-tenant attach rejected |
| Image pull | Guest pulls/verifies/decrypts approved digest | Endpoint/credential/signature/digest/decryption failure closes |
| Credential secrecy | Tenant-private credential enters only attested guest | Marker absent from worker/Kubernetes/user-data/logs |
| Network | Tenant TLS terminates inside guest; Trustee CA validates | MITM/invalid CA/plaintext endpoint rejected |
| Hosted lifecycle | PaaS creates through deletes via its single AWS CAP | Partial create cleans up with actionable failure |
| Recovery | Metadata and volume restore under approved policy | Restore cannot bypass attestation or reformat data |

## 10. Rollout and rollback rules

1. Use immutable image digests and a signed profile-specific platform release.
2. Deploy `enclava-init` before a CAP API that emits a changed KBS artifact/schema.
3. Update/test PaaS before an incompatible CAP internal API response.
4. Update operations manifests and verify rendered/live workload fields whenever CAP changes storage, sidecars, runtime, or images.
5. Roll a failed confidentiality release back as a complete set: CAP, init, policy, sidecars, image policy, PodVM, and measurement.
6. Keep database migrations backward compatible through the rollback window or provide a tested restore/forward fix.
7. Never delete tenant data as part of application/platform rollback; retention remains explicit.
8. CAA/AWS failure queues or fails honestly. Never fall back to a normal runtime or the bare-metal installation.
9. Roll PodVM AMI, fixed services, measurement, evidence policy, and release metadata together.
10. Roll instance allowlist, request-to-tier mapping, peer-VM quota, PaaS billing, and alarms together.
11. Roll CSI commit/digest, RBAC/IAM, and attach/detach compatibility together; never detach/reformat ambiguous media.
12. Rotate worker-visible platform registry credentials with an overlap canary; never temporarily copy tenant-private credentials into Kubernetes Secrets.
13. Rollback of the AWS installation disables new deployment traffic but preserves management and recovery of existing AWS workloads. It does not redirect them to bare metal.

## 11. Review questions

1. Does the confidentiality contract match the public product claim and acknowledged metadata leakage?
2. Does PaaS/CAP ever receive tenant plaintext before attestation?
3. Is reusing the independently operated Trustee/signing plane acceptable for the AWS installation?
4. Does the RuntimeClass alias work with the pinned CAA/runtime variant?
5. Does the fixed PodVM configuration supply the exact AA/CDH/proxy path used by `enclava-init`?
6. Which `m6a` tiers and sidecar headroom are offered, and is VM-tier billing acceptable?
7. Is loss of application cgroup limits acceptable when the VM is the paid/isolation boundary?
8. Does the LUKS-file storage experiment meet confidentiality, integrity, durability, recovery, and performance requirements?
9. Who owns the CSI dependency, and what failure threshold activates raw-device passthrough?
10. Which images/credentials are public, platform-visible, tenant-private, or encrypted?
11. Have the exact ARK-ASVK-VLEK rules and fixtures received independent security review?
12. Which repository owns AWS IaC?
13. Which endpoints may terminate TLS outside a peer VM?
14. Which PaaS dependencies deploy on EKS versus use an existing managed/external service?
15. What cohort and observation window are required before calling the AWS profile production-ready?
16. Who owns signing-key recovery, and who may authorize an emergency release without an insecure bypass?

## 12. External references

- [Confidential Containers AWS example](https://confidentialcontainers.org/docs/examples/aws-simple/)
- [CAA 0.22.0 release](https://github.com/confidential-containers/cloud-api-adaptor/releases/tag/v0.22.0)
- [CAA peer-pod architecture](https://github.com/confidential-containers/cloud-api-adaptor/blob/v0.22.0/docs/architecture.md)
- [CAA instance selection](https://github.com/confidential-containers/cloud-api-adaptor/blob/v0.22.0/src/cloud-api-adaptor/docs/instance-selection.md)
- [CAA peer-pod resource management](https://github.com/confidential-containers/cloud-api-adaptor/blob/v0.22.0/src/cloud-api-adaptor/docs/resource-management.md)
- [CAA registry authentication and worker visibility](https://github.com/confidential-containers/cloud-api-adaptor/blob/v0.22.0/src/cloud-api-adaptor/docs/registries-authentication.md)
- [Kata 4.0.0 Go remote configuration](https://github.com/kata-containers/kata-containers/blob/4.0.0/src/runtime/config/configuration-remote.toml.in)
- [Kata 4.0.0 Rust remote configuration](https://github.com/kata-containers/kata-containers/blob/4.0.0/src/runtime-rs/config/configuration-remote.toml.in)
- [CAA PodVM REST service](https://github.com/confidential-containers/cloud-api-adaptor/blob/v0.22.0/src/cloud-api-adaptor/podvm/files/etc/systemd/system/api-server-rest.service)
- [Pinned Guest Components REST/socket topology](https://github.com/confidential-containers/guest-components/blob/dcd55ea16ea4f4bcb87c1420f16af92e9eb15f2f/api-server-rest/src/main.rs)
- [Guest Components KBS registry credential example](https://github.com/confidential-containers/guest-components/blob/main/confidential-data-hub/example.config.toml)
- [AWS EC2 AMD SEV-SNP](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sev-snp.html)
- [AWS EC2 SNP attestation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snp-attestation.html)
- [CAA CSI block driver](https://github.com/confidential-devhub/caa-csi-block-driver)
- [CAA CSI raw-block rejection](https://github.com/confidential-devhub/caa-csi-block-driver/blob/main/pkg/driver/controllerserver.go#L540-L545)
- [Amazon EKS EBS CSI](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html)
- [Amazon ECR VPC endpoints](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html)
- [Amazon ECR authorization token](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetAuthorizationToken.html)
- [AWS Load Balancer Controller](https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html)
- [RDS PostgreSQL TLS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)
- [RDS Multi-AZ clusters](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/multi-az-db-clusters-concepts.html)
- Repository production checklist: [DEPLOYMENT.md](DEPLOYMENT.md)

## 13. Definition of done

The project is complete when:

- One documented deployment selector produces either a complete bare-metal installation or a complete AWS installation, never a mixed manifest.
- The current bare-metal profile retains its VCEK, raw-block, runtime, storage, and hosted lifecycle regression behavior.
- A fresh AWS installation runs one PaaS connected to one AWS CAP through the existing single-client contract.
- Every tenant container and sidecar runs inside an approved `m6a` SNP peer VM, and no tenant process runs on an EKS worker.
- Genuine VLEK is fully verified through ARK-ASVK-VLEK, while VCEK remains valid only through ARK-ASK-VCEK.
- The measured PodVM fixed services provide AA/CDH through `api-server-rest` on `127.0.0.1:8006`; unlock does not rely on an ignored kernel annotation.
- Every offered request maps to an approved VM tier; quota, capacity, and billing use VM tier/count.
- Persistent data survives replacement and is unreadable from workers, outer EBS, snapshots, logs, and databases.
- CSI is pinned, reviewed, owned, and adversarially tested, or replaced by the proven raw-device path.
- Images are pulled and verified inside the guest; tenant-private registry credentials never traverse the worker path.
- Trustee releases only to the correct signed runtime, PodVM, policy, init, and sidecar set.
- No debug AMI, staging verifier, broad IAM, mutable image, raw signing key, HTTP KBS, or normal-runtime fallback remains.
- RDS, trust metadata, and encrypted volumes have passed recovery; failure injection and orphan cleanup pass; monitoring is actionable.
- Documentation explicitly says that bare-metal/AWS coordination and migration are deferred rather than implied.
- Security, CAP, PaaS, operations, and trust-plane owners sign off on evidence, not only manifests.
