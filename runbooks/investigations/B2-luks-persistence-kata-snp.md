# B2: LUKS mount handoff in Kata SEV-SNP

**Status:** Resolved by live test with design pivot.
**Gates:** Phase 5 workload startup/mount ordering.
**Date:** 2026-04-27; superseded by live cluster validation on 2026-04-28.

## Verdict

dm-crypt/LUKS works inside the live Kata SEV-SNP guest: `luksFormat`,
`luksOpen`, `mkfs.ext4`, and `mount` all succeed against a Longhorn Block PVC.

The stale conclusion was that CAP could mount from a one-shot init container
and then start regular workload containers. Live testing showed that creating a
regular container after the LUKS mount exists fails with Kata/containerd
`EINVAL`. The same failure also happens with a native-sidecar initContainer
that gates app startup until after the mount.

The viable contract is:

1. Start workload containers first under a small wait wrapper. For CAP
   stateful pods, this means no initContainers in the Block PVC/LUKS path.
2. Each workload wrapper writes `/run/enclava/containers/<name>` and waits for
   `/run/enclava/init-ready`.
3. The privileged `enclava-init` mounter sidecar waits for those sentinels,
   opens/mounts LUKS, writes seeds, writes `/run/enclava/init-ready`, and stays
   alive as the mount propagation source.
4. Workload wrappers `exec "$@"` after the ready file appears.

`runbooks/validate-kata-dm-crypt.yml` now validates this contract live.

## Runtime Findings

- The live `kata-qemu-snp` handler reads
  `/opt/kata/share/defaults/kata-containers/configuration-qemu-snp.toml`.
  The older `runtimes/qemu-snp/configuration-qemu-snp.toml` path is not the
  active handler config.
- `dm_mod` and `dm_crypt` are built into the current guest kernel. Do not set
  `io.katacontainers.config.agent.kernel_modules` or `[agent.kata]
  kernel_modules` for this runtime; doing so makes kata-agent try to modprobe
  built-in-only features and breaks sandbox startup.
- The pod still needs the deployed KBS kernel params annotation:
  `io.katacontainers.config.hypervisor.kernel_params:
  agent.aa_kbc_params=cc_kbc::<kbs-url> agent.guest_components_rest_api=all`.

## Implication for Phase 5 Design

- Do not keep the one-shot init-container mount handoff as the target design.
- Do not use a native-sidecar startup probe to delay workload creation until
  after the mount; that hits the same `EINVAL` failure.
- Use the app/caddy-starts-first wait-wrapper plus long-running mounter sidecar
  pattern.
- Keep app/caddy unprivileged and without raw block devices.
- Workload images, and platform sidecar images that CAP wraps, must include an
  executable at `/usr/local/bin/enclava-wait-exec`.
- Add this smoke as a CI/manual gate for each Kata or guest-kernel version bump.

## Sources

- Live validation: `../enclava-infra/ansible/playbooks/validate-kata-dm-crypt.yml`
- Kata Containers Architecture: https://kata-containers.github.io/kata-containers/design/architecture/
- Kubernetes Pod Lifecycle: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
- CoCo attestation background: https://www.redhat.com/en/blog/understanding-confidential-containers-attestation-flow
