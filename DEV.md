# CAP Development Notes

## Stateful Kata SEV-SNP Pods

- Stateful confidential workloads must use normal long-running containers only.
  Do not put `attestation-proxy` or helper installation into `initContainers`
  for the raw Block PVC/LUKS path.
- `attestation-proxy` runs as a regular sidecar. App, tenant-ingress, and
  `enclava-init` also start as regular containers.
- Decrypted state is exposed at `/state`. Workloads must use paths under
  `/state` directly, for example `/state/data`; do not rely on arbitrary
  per-app bind mounts such as `/data`. The current Kata runtime rejects
  Kubernetes `subPath` mounts and the guest-side namespace bind path failed
  live with `EINVAL`.
- The worker runtime must use `shared_fs = "virtio-9p"` plus
  `disable_block_device_use = false`: `virtio-fs` fails on the current
  QEMU/IOMMU path, while `shared_fs = "none"` makes ordinary ConfigMap/EmptyDir
  mounts hit Kata direct-volume filename limits.
- CAP uses `shareProcessNamespace: true`: wait-exec writes each workload PID,
  `enclava-init` opens the encrypted state, and the `/state` EmptyDir is mounted
  with propagation so app containers can see the decrypted filesystem. The app
  container uses `HostToContainer` on `/state`; `enclava-init` uses
  `Bidirectional` on `/state` and `/state/tls-state`.
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

## Fast Nutshell Contract Gate

- Run `scripts/nutshell-fast-contract.sh` before building/pushing API,
  signing-service, or Nutshell images for live testing. It validates the
  Nutshell `enclava.toml` and Dockerfile state contract, then runs the focused
  CAP and signing-service tests that catch descriptor/runtime/policy drift.
- Only use the live cluster after this local gate passes. Keep the customer
  StatefulSet scaled to zero between live attempts and inspect the rendered pod
  spec before unlocking so simple command/port/mount mistakes do not boot a TEE
  VM.
