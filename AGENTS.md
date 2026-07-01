# Agent Notes

## Cluster Access
- The Kubernetes cluster is reachable by SSH through `control1.encl`.
  Do instead: run cluster checks with commands such as
  `ssh control1.encl kubectl ...` when local `kubectl` or kubeconfig is not
  available.
