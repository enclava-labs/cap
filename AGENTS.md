# Agent Notes

## Cluster Access
- The Kubernetes cluster is reachable by SSH through `control1.encl`.
  Do instead: run cluster checks with commands such as
  `ssh control1.encl kubectl ...` when local `kubectl` or kubeconfig is not
  available.

## Cross-Project Dependency Schema

Use this schema before changing runtime contracts, image references, template
metadata, KBS policy/artifact formats, internal APIs, or CLI-visible behavior.

```yaml
project: cap
role: confidential workload platform
produces:
  - name: enclava-api
    image: ghcr.io/enclava-labs/enclava-api
    consumed_by:
      - enclava-ops-manifests: overlays/preprod/cap-api.yaml
      - enclava-paas: CAP internal service API and deployment/status DTOs
  - name: enclava-init
    image: ghcr.io/enclava-labs/enclava-init
    consumed_by:
      - enclava-ops-manifests: CAP ENCLAVA_INIT_IMAGE and policy-signing-service ENCLAVA_INIT_IMAGE
      - tenant workloads: unlock, KBS policy verification, config handoff
  - name: enclava-cli
    consumed_by:
      - operators and hosted users
      - enclava-paas: hosted CLI API compatibility expectations
  - name: platform release metadata
    consumed_by:
      - enclava-paas template deploy flows
      - enclava-ops-manifests platform-release.json
depends_on:
  - enclava-ops-manifests: GitOps deployment, image digests, cluster rollout order
  - enclava-paas: hosted product API assumptions and template metadata
blocking_rollout_rules:
  - If KBS policy/artifact schema parsing changes, deploy enclava-init first,
    verify the new digest is live in CAP workload manifests, then deploy
    enclava-api that emits the new schema.
  - If CAP internal API response shape changes, update and test enclava-paas
    before deploying CAP API.
  - If `/.well-known/enclava` or its `auth_methods` values (`device_code`,
    `email`, `nostr`) change, update and test enclava-cli and enclava-paas
    together before rollout.
  - If workload manifest fields or sidecar images change, update
    enclava-ops-manifests image references and verify live tenant pods.
required_checks:
  - rustup run stable cargo fmt --all -- --check
  - rustup run stable cargo clippy --workspace --all-targets -- -D warnings
  - rustup run stable cargo test --workspace
  - rustup run stable cargo test --doc
  - rustup run stable cargo audit --ignore RUSTSEC-2023-0071
  - rustup run stable cargo deny check advisories sources
  - rustup run stable cargo build --workspace
  - ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release --bin enclava-api
  - ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release --bin enclava
  - ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=... rustup run stable cargo build --release -p enclava-init --features prod-strict
  - sudo docker build -f crates/enclava-init/Dockerfile -t enclava-init:local .
  - sudo docker build -f crates/enclava-api/Dockerfile -t enclava-api:local .
```
