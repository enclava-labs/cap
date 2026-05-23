# enclava-init

`enclava-init` is the in-TEE runtime sidecar for CAP workloads. It runs inside
the Kata guest, opens encrypted volumes, verifies the workload trust chain,
prepares tenant TLS state, creates app bind mounts, and signals the app and
tenant ingress containers through `/run/enclava/init-ready`.

## Build Dependencies

`libcryptsetup-rs` links to system `libcryptsetup` through pkg-config and
bindgen.

| Distro | Packages |
| --- | --- |
| Debian/Ubuntu | `pkg-config libcryptsetup-dev clang libclang-dev` |
| Fedora/RHEL | `cryptsetup-devel libuuid-devel device-mapper-devel json-c-devel clang` |

The runtime image also needs `libcryptsetup.so.12`, `mkfs.ext4`, and
`/usr/local/bin/enclava-wait-exec`. The checked-in Dockerfile installs the
runtime libraries and copies the wait helper.

## Configuration

The sidecar reads `/etc/enclava-init/config.toml`, or the path in
`ENCLAVA_INIT_CONFIG`. CAP generates that file from
`crates/enclava-engine/src/manifest/enclava_init_config.rs`.

Core fields:

| Field | Purpose |
| --- | --- |
| `mode` | `password` or `autounlock`. |
| `state` | App-data block device, mapper name, mount path, and HKDF label. |
| `tls-state` | TLS-state block device, mapper name, mount path, and HKDF label. |
| `argon2-salt-hex` | Per-app salt committed by `cc_init_data`. |
| `trustee-policy-read-available` | Enables the supported Trustee policy verification path. |
| `workload-artifacts-url` | Descriptor/keyring/policy artifact source. |
| `trustee-policy-url` | Active Trustee policy body source. |
| `tls-certificate-broker-url` | Optional DNS-01 certificate broker endpoint. |
| `tls-certificate-hostnames` | Hostnames covered by brokered certificates. |
| `app-bind-mounts` | App storage path bindings created after LUKS open. |

The generated runtime uses:

- `/dev/csi0` -> `cap-state` -> `/state`
- `/dev/csi1` -> `cap-tls-state` -> `/state/tls-state`
- `/run/enclava-unlock/unlock.sock` for password unlock handoff
- `/run/enclava/init-ready` as the readiness handoff for `enclava-wait-exec`

## Modes

Password mode:

- receives the owner password over the local unlock socket;
- rate limits failed attempts at 5 per 60 seconds;
- derives the owner seed with Argon2id;
- prints the recovery mnemonic only through the ownership flow.

Auto-unlock mode:

- fetches the wrap key through the local Kata CDH resource endpoint;
- uses the configured owner resource path;
- still runs the same runtime verification path before seed release.

## Verification Chain

When policy-read mode is enabled, `enclava-init` verifies:

1. `cc_init_data` hash committed by the deployment descriptor;
2. descriptor signature and descriptor core hash;
3. org keyring membership and deploy authority;
4. generated agent policy hash;
5. signed policy artifact and rendered Trustee policy;
6. runtime identity and artifact bindings.

Any mismatch fails startup before seeds are released.

## TLS State

Tenant Caddy receives seed and certificate material from the TLS-state volume.
When DNS-01 broker mode is configured, `enclava-init` generates the private key
inside the TEE, submits a CSR to CAP's workload-attested broker endpoint, and
writes the returned certificate chain into the shared Caddy runtime directory.

## Tests

```bash
cargo test -p enclava-init --lib
```

LUKS round-trip tests require loopback-device access:

```bash
cargo test -p enclava-init --features luks-integration -- --ignored
```
