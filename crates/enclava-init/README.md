# enclava-init

`enclava-init` is the in-TEE runtime sidecar for CAP workloads. It runs inside
the Kata guest, verifies the workload trust chain, opens encrypted volumes,
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

## Volume Initialization

`state` and `tls-state` devices are LUKS2 volumes. On every boot the sidecar
checks for a LUKS2 header; if one exists it opens the volume and no probe or
scan runs — already-provisioned volumes (including sub-floor ones from
before the 32 MiB minimum, which activate fine) are never re-scanned.

When no header is found, `blank=true` would authorize `luksFormat`, so the
device must be proven all-zero before the first format: the entire device is
read in 1 MiB chunks (a short or failed read never counts as blank).
The scan is O(device size). Progress is logged every 30 s with scanned/total
bytes and a completion duration. Initialization time depends on actual guest
and Longhorn throughput; do not infer it from the raw volume's zero contents.
this fresh-format floor for unproven claims. Existing ordinal-zero claims are
grandfathered per volume only with positive LIVE initialization evidence: the
exact ordinal-0 pod non-terminating, Ready, mounting the exact claim, and
created in a later whole second than it — the workload observably running on
the initialized device. Deployment history is deliberately not consulted:
database and Kubernetes clocks cannot order a row against a claim, and a
password-timeout redeploy can publish healthy without opening storage, so no
historical status is proof. The availability cost is deliberate: a genuinely
initialized legacy sub-floor volume with no live proof is refused until the
workload regains readiness (or the volume is resized above the floor), never
formatted. Missing or terminating claims, wrong ordinals, same-second pairs,
and bare PVC existence cannot grant the exemption. External Kubernetes-admin
claim deletions are outside CAP's mutation-fence serialization and read as
fresh — the in-guest blank-scan still refuses to format a non-zero device, and
CAP does not offer atomic cross-resource guarantees. Existing LUKS2 volumes
are opened without reformatting; orchestration evidence never authorizes
formatting.

The rollout budget adds two sequential passes to the configured base
timeout only for claims that lack positive initialization evidence —
already-initialized volumes only open, so ordinary redeploys and
domain-only reapplies keep the base deadline. The allowance assumes at
least 32 MiB/s per pass for scanning and integrity-tag initialization.
This is a bounded estimate, not a throughput guarantee: qualify the
intended storage sizes and lower that assumption if measurements are
slower. The API computes the budget once, before the first provider
apply, and persists it next to the observation anchor; durable observers
resume that recorded deadline verbatim across restarts and release worker
slots after each 90-second observation slice. Password owner wait remains
separately nonterminal.

## Verification Chain

When policy-read mode is enabled, `enclava-init` verifies:

1. `cc_init_data` hash committed by the deployment descriptor;
2. descriptor signature and descriptor core hash;
3. org keyring membership and deploy authority;
4. generated agent policy hash;
5. signed policy artifact and rendered Trustee policy;
6. runtime identity and artifact bindings.

Any mismatch fails startup before encrypted volumes are opened or seeds are
released. The check consumes the same signed `cc_init_data` bytes as the
ConfigMap transport cross-check.

## TLS State

Tenant Caddy receives seed and certificate material from the TLS-state volume.
When DNS-01 broker mode is configured, `enclava-init` generates the private key
inside the TEE, submits a CSR to CAP's workload-attested broker endpoint, and
writes the returned certificate chain into the shared Caddy runtime directory.

## Volume Integrity

Fresh LUKS2 volumes are formatted AES-256-XTS with `hmac(sha256)` integrity
(dm-integrity), so ciphertext tampering turns into an I/O error at read time.
Both format paths request it: `cryptsetup luksFormat --integrity hmac-sha256`
and the libcryptsetup fallback. The fallback initializes tags through a
temporary private, no-journal mapping, then closes it; normal opens retain
journaled integrity. Both paths write the entire data area at first format.

Volumes formatted before integrity support stay as they are: they are
detected by their LUKS2 header and opened without reformatting.

Encryption makes the initial zeros non-sparse: reserve the full requested
capacity on every Longhorn replica, not just the filesystem's used bytes.
Use native Longhorn scheduling without logical overprovisioning and retain
its free-space reserve. Header, journal and tag overhead also reduce usable
capacity. With 512-byte sectors, the 32-byte tags alone add 6.25% overhead.

Before changing an environment's init pin, qualify its exact Kata guest
kernel with `cryptsetup --integrity hmac-sha256` on a disposable block PVC,
including close/reopen and data persistence. `CONFIG_DM_INTEGRITY=y`, or a
loadable target plus its matching module, is required separately from
dm-crypt. A healthy existing volume is not proof: it needs no new integrity
target. Do not enable mandatory integrity in an unqualified environment.

If first-boot initialization is interrupted after the LUKS header is
committed (during the tag initialization or before mkfs), the volume is left
formatted but never initialized and later boots open it and fail at mount.
That fail-closed state is deliberate: no on-disk marker may authorize
re-running wipe or mkfs, since a replayed marker over a populated volume
would destroy data. Operator recovery is to delete and recreate the
never-ready volume.

## Tests

```bash
cargo test -p enclava-init --lib
```

LUKS integration tests need root, `/dev/mapper` control, dm-crypt and
dm-integrity kernel support, `cryptsetup`, `mkfs.ext4`/`e2fsck`, and a
writable `/run/enclava`. They use disposable backing files and random
per-test mapper names and close their mappings even on failure:

```bash
sudo cargo test -p enclava-init --features luks-integration
```
