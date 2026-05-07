# CAP Development Notes

## Stateful Kata SEV-SNP Pods

- Stateful confidential workloads must use normal long-running containers only.
  Do not put `attestation-proxy` or helper installation into `initContainers`
  for the raw Block PVC/LUKS path.
- `attestation-proxy` runs as a regular sidecar. App, tenant-ingress, and
  `enclava-init` also start as regular containers.
- Do not use Kubernetes `mountPropagation` for decrypted state on the SNP
  runtime. The worker runtime must use `shared_fs = "virtio-9p"` plus
  `disable_block_device_use = false`: `virtio-fs` fails on the current
  QEMU/IOMMU path, while `shared_fs = "none"` makes ordinary ConfigMap/EmptyDir
  mounts hit Kata direct-volume filename limits. CAP uses
  `shareProcessNamespace: true`: wait-exec writes each workload PID, and
  `enclava-init` bind-mounts decrypted LUKS paths into those mount namespaces
  inside the guest.
- Customer workload images must include an executable at
  `/usr/local/bin/enclava-wait-exec`. CAP sets the app command to that path; the
  helper writes the started sentinel with its PID, waits for
  `/run/enclava/init-ready`, then execs the workload command.
- The helper must make `/run/enclava/containers` a shared writable sticky
  directory (`chmod 1777`) before writing its sentinel. App and tenant-ingress
  run under different non-root UIDs, so the first helper to create the
  directory cannot leave it at the default `0755` mode.
- Platform sidecar images that CAP wraps, currently `caddy-ingress`, must also
  include `/usr/local/bin/enclava-wait-exec`.
