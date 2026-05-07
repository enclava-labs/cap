# CAP Development Notes

## Stateful Kata SEV-SNP Pods

- Stateful confidential workloads must use normal long-running containers only.
  Do not put `attestation-proxy` or helper installation into `initContainers`
  for the raw Block PVC/LUKS path.
- `attestation-proxy` runs as a regular sidecar. App, tenant-ingress, and
  `enclava-init` also start as regular containers.
- Customer workload images must include an executable at
  `/usr/local/bin/enclava-wait-exec`. CAP sets the app command to that path; the
  helper writes the started sentinel, waits for `/run/enclava/init-ready`, then
  execs the workload command.
- Platform sidecar images that CAP wraps, currently `caddy-ingress`, must also
  include `/usr/local/bin/enclava-wait-exec`.
