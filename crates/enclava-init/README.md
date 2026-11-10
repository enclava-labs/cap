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
bytes and a completion duration. Initialization time depends on the guest and
the selected storage backend (currently Longhorn on qualified guests). Do not
infer it from the raw volume's zero contents, and do not treat the rollout
budget below as a universal throughput SLA.

Devices below 32 MiB are refused before scanning. The API and engine enforce
this fresh-format floor for unproven claims. The admission signal the
security review called `expects_fresh_volume` is a `true` bit of
`FreshVolumeClaims` (`app_data` for the `state` claim, `tls_data` for
`tls-state`), produced by `inspect_fresh_volume_claims`. It is set for a new
(absent) claim, an unproven claim (present, including Bound, but without
live proof), a recreated or terminating claim, a claim with no creation
timestamp, and a same-second pod/claim pair. State and TLS are independent,
so a mixed render can mark only one claim fresh. Positive live evidence
clears the bit: the exact surviving ordinal-zero PVC `<vct>-<workload>-0`
with a creation timestamp, and the live ordinal-zero pod non-terminating and
Ready, mounting that exact claim, created in a later whole second than the
claim — the workload observably running on the initialized device.
Deployment history is deliberately not consulted: database and Kubernetes
clocks cannot order a row against a claim, and a password-timeout redeploy
can publish healthy without opening storage, so no historical status is
proof. The availability cost is deliberate: a genuinely initialized legacy
sub-floor volume with no live proof is refused until the workload regains
readiness (or the volume is resized above the floor), never formatted.
Wrong ordinals and bare PVC existence cannot grant the exemption. External
Kubernetes-admin claim deletions are outside CAP's mutation-fence
serialization and read as fresh — the in-guest blank-scan still refuses to
format a non-zero device, and CAP does not offer atomic cross-resource
guarantees. Existing LUKS2 volumes are opened without reformatting;
orchestration evidence never authorizes formatting. This signal is not the
signed volume-provenance claim proposed in cap#249, which would let the
guest skip the zero scan. The scan remains authoritative for destructive
formatting; the signal only controls the size floor and the rollout budget.

The default rollout baseline is 600s (`ApplyConfig::rollout_timeout`). A
fresh claim adds a capacity-derived allowance on top of that baseline: two
sequential passes at 32 MiB/s, rounded up (`ceil(size_MiB / 16)` seconds).
An already-initialized redeploy, including a domain-only reapply, keeps the
ordinary 600s budget and does not inherit the allowance. The 32 MiB/s figure
is a qualified estimate for the selected backend, not a universal SLA: lower
the assumption if measurements on that backend are slower. The API computes
the budget once, before the first provider apply, and persists it as
`deployments.rollout_timeout_millis` next to `observing_since`. Observer
restarts reuse that recorded generation deadline verbatim — they do not
recompute it from later pod or volume state — and release worker slots after
each 90-second observation slice. Password owner wait remains separately
nonterminal.

### Numeric volume profiling

`/run/enclava/init-stats.json` retains its version-1 boot fields and adds
`volume_profile_version: 1` and `volume_profiles.state` / `volume_profiles.tls`.
Read it through the tenant's authenticated connection, not Kubernetes workload
logs. Ordinary boot failures also attempt to publish the summary; process
termination cannot guarantee a final record. Check `init_start_unix` before
using a retained file as evidence for a particular boot.

Each volume has `device_bytes`, `scanned_bytes`, `initialized_bytes`, and a
fixed twelve-entry `stages` array. Its indices are:

| Index | Stage | Nesting |
| --- | --- | --- |
| 0 | Header probe / existing-keyslot inspection | Top level |
| 1 | Full-device blank scan | Top level; fresh devices only |
| 2 | Cryptsetup CLI format | Top level; includes the CLI's internal integrity work |
| 3 | Libcryptsetup fallback | Top level; only after CLI failure |
| 4 | Libcryptsetup format | Inside fallback |
| 5 | Fallback keyslot creation | Inside fallback |
| 6 | Fallback integrity initialization | Inside fallback |
| 7 | Fallback integrity final sync | Reserved, always 0: the final device sync runs inside the libcryptsetup wipe counted at index 6 |
| 8 | Header validation and sealing | Top level |
| 9 | Authenticated open | Top level |
| 10 | Filesystem creation | Top level; fresh devices only |
| 11 | Mount | Top level |

Entries record `calls`, `failures`, `elapsed_us`, self and reaped-child
user/system CPU microseconds, combined `input_blocks` / `output_blocks` from
`getrusage`, and init-cgroup throttled periods/microseconds. These block
counters are not application bytes or a count of physical Longhorn replica
writes. Self CPU includes other init-process threads; child usage includes
waited-for helpers. The profiler never resets counters or falls back to an
ancestor cgroup.

`counters_available` is a bitmask: 1 = self usage, 2 = child usage, 4 = cgroup
throttling. Combined block deltas require both usage bits. A missing bit means
unavailable, not observed zero; `calls=0` means the stage was not reached.
Zero `device_bytes` means its best-effort size observation was unavailable.
`initialized_bytes` counts explicit fallback writes only: zero does not prove
that the CLI skipped integrity initialization. No paths, formatter output,
error text, headers, keys or tenant data enter this numeric schema.
Per-volume elapsed time is recorded on ordinary errors as well as success.
`volume_formatted=1` means fresh formatting and header sealing completed, even
if a later open, mkfs or mount failed. Zero never proves an untouched device:
a failed formatting attempt can already have changed storage. These fields
are diagnostics, never authorization to reformat or reuse a failed volume.

Stage elapsed time excludes its own counter-sampling overhead. Nested stages
are not additive with their parents; compare top-level sums with the existing
per-volume duration and retain the residual. Profiling does not change volume
format/open decisions, cryptographic parameters, readiness or error handling.

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

Attestation-agent token responses are capped at 512 KiB before typed JSON
decoding, for both declared-length and streamed bodies. EAR tokens include
signed policy claims; larger workload commands can exceed 64 KiB without
exceeding the supported policy size.

## TLS State

Tenant Caddy receives seed and certificate material from the TLS-state volume.
When DNS-01 broker mode is configured, `enclava-init` generates the private key
inside the TEE, submits a CSR to CAP's workload-attested broker endpoint, and
writes the returned certificate chain into the shared Caddy runtime directory.

## Volume Integrity

Fresh LUKS2 volumes use 4096-byte sectors, AES-256-XTS and `hmac(sha256)`
integrity (dm-integrity), so ciphertext tampering becomes a read-time I/O error.
Both format paths request the same layout: the cryptsetup CLI
and the libcryptsetup fallback. The fallback initializes tags through a
temporary private, no-journal mapping, then closes it; normal opens retain
journaled integrity. Both paths write the entire data area at first format.

Both format paths use a fixed Argon2id keyslot budget: **4 passes, 262144 KiB
(256 MiB), one lane**, with benchmarking disabled. The CLI uses
`--pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 262144 --pbkdf-parallel 1`;
the library sets the same budget for format and keyslot creation with
`CRYPT_PBKDF_NO_BENCHMARK`. CPU throttling therefore cannot change the chosen
work factors or add per-volume calibration. Password-to-owner-seed derivation
is unchanged. The 512-MiB init container limit must cover the KDF plus the
remaining process and header material.

This is a greenfield format cutover: only 4096-byte, HMAC-integrity headers
are accepted. Older 512-byte and non-integrity layouts fail closed; there is
no conversion or compatibility path. Existing nonblank devices are never
automatically reformatted or deleted.

Encryption makes the initial zeros non-sparse: reserve the full requested
capacity on every Longhorn replica, not just the filesystem's used bytes.
Use native Longhorn scheduling without logical overprovisioning and retain
its free-space reserve. Header, journal and tag overhead also reduce usable
capacity. With 4096-byte sectors, 32-byte tags alone add 0.78125% overhead.

Before changing an environment's init pin, qualify its exact Kata guest
kernel with the 4096-byte integrity layout on disposable block storage,
including both format paths, ext4 persistence, authenticated close/reopen and
corruption rejection. `CONFIG_DM_INTEGRITY=y`, or a
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

Run LUKS integration tests in an isolated disposable VM: they need root,
`/dev/mapper` control, loop devices, dm-crypt and dm-integrity kernel support,
cryptsetup 2.8.1 or newer at `/usr/local/sbin/cryptsetup`, `mkfs.ext4`, and
tmpfs-backed `/run/enclava-luks`. They create disposable backing files and
test mapper names. Missing prerequisites cause skips, not storage validation:

```bash
sudo cargo test -p enclava-init --features luks-integration
```
