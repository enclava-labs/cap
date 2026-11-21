# Running Your Own CAP Installation

This guide is for operators who want to run CAP outside Enclava's own
environments. It explains what the repository assumes, what a fork has to
replace, and where the rest of the documentation picks up.

## Read This First

CAP is not a turnkey install. Two facts shape everything below:

- **The trust roots are compiled in.** Every CLI and API binary embeds
  `crates/enclava-common/platform-release-profiles.json`, a bundle with exactly
  three profiles (`dev`, `preprod`, `production`). Each profile lists the API
  origins it applies to, a root public key, and a signed baseline release. The
  CLI selects a profile from the API origin it talks to and refuses any origin
  that is not listed. Binaries and images released from
  `github.com/enclava-labs/cap` therefore work with Enclava's installations
  only.
- **The repository is the control-plane core, not the platform.** It contains
  the API, CLI, manifest engine, and in-guest sidecar. The confidential
  runtime, key broker, policy signing service, and tenant edge are separate
  components that you install and operate.

An independent installation is a fork that carries its own trust bundle and
builds its own CLI, API image, and `enclava-init` image.

## Platform Prerequisites

CAP expects the following to exist in the target cluster before the API can
deploy a workload. Names in code font are what CAP renders or looks up today.

| Component | What CAP expects |
| --- | --- |
| Hardware and runtime | AMD SEV-SNP hosts running Kata Containers, exposed as the RuntimeClass named in the signed platform release (`kata-qemu-snp` in the committed fixtures). |
| Trustee KBS | A reachable HTTPS Trustee KBS for guest attestation, plus the callback endpoints listed under Required Environment in [DEPLOYMENT.md](../DEPLOYMENT.md). CAP can manage the KBS resource policy ConfigMap (`resource-policy` in `trustee-operator-system` by default). Source: [enclava-labs/trustee](https://github.com/enclava-labs/trustee). |
| Policy signing service | Generates and signs the Kata agent policy for each deployment, using the `genpolicy` version pinned in the platform release. Source: [enclava-labs/policy-templates](https://github.com/enclava-labs/policy-templates). |
| Platform sidecar images | Digest-pinned `attestation-proxy` and `caddy-ingress` images, cosign-signed, plus the `enclava-init` image built from this repository. Sources: [enclava-labs/attestation-proxy](https://github.com/enclava-labs/attestation-proxy), [enclava-labs/caddy-ingress](https://github.com/enclava-labs/caddy-ingress). |
| Cilium | CAP renders a `CiliumNetworkPolicy` (`cilium.io/v2`) for every tenant namespace. |
| Envoy Gateway | CAP renders `Gateway`, `TLSRoute`, and `EnvoyProxy` objects per tenant and references the GatewayClass `envoy-gateway-tenant`. |
| Tenant edge HAProxy | A DaemonSet and ConfigMap (both `haproxy-tenant` in namespace `tenant-envoy` by default) that CAP rewrites to route tenant SNI. Override with `TENANT_HAPROXY_NAMESPACE`, `TENANT_HAPROXY_CONFIGMAP`, `TENANT_HAPROXY_DAEMONSET`. |
| API ingress | The reference overlay assumes ingress-nginx and cert-manager for the API's own hostname. Any ingress works if you adapt `deploy/api/ingress.yaml` and the trusted-proxy settings. |
| PostgreSQL | One database for API state. |
| DNS | Cloudflare is the only DNS provider CAP manages. Without it, tenant hostnames must be provisioned by other means and `DNS_MANAGEMENT_REQUIRED` left unset. |
| Workload images | Tenant images must be cosign-signed by the identity given at `enclava create --signer-subject`. They need no CAP-specific contents: `enclava-wait-exec` is copied into each pod from the `enclava-init` image. |

Installing and operating these components is outside the scope of this
repository.

## What a Fork Replaces

These are the places where Enclava's installation is written into the tree. A
fork changes each of them.

| Location | What to change |
| --- | --- |
| `crates/enclava-common/platform-release-profiles.json` | The trust bundle: root public keys, API origins, and signed baselines for your installations. See [Build Your Trust Bundle](#build-your-trust-bundle). |
| Repository secret `ENCLAVA_PLATFORM_RELEASE_PROFILES_JSON` | The release workflows overwrite the committed bundle with this secret before building. Set it to your bundle, or the tag and manual builds fail. |
| `.github/workflows/*.yml`, `scripts/render-api-release-manifest.sh`, `scripts/verify-api-image-ref.bash` | Image names under `ghcr.io/enclava-labs/`, and the signer identity `https://github.com/enclava-labs/cap/.github/workflows/api-image.yml@...`. The render script rejects any other API image name, and the publish workflow runs the verifier script, which accepts only Enclava's image and workflow identity. |
| `deploy/api/` | Hostname, platform domain, DNS zone, release profile, image, and secrets. See [deploy/api/README.md](../deploy/api/README.md). |
| `crates/enclava-cli/src/config.rs` | The CLI's default API URL (`https://api.enclava.dev`). Users can override it in `~/.enclava/config.toml`, but a fork should default to its own API. |
| `crates/enclava-engine/src/manifest/ingress.rs` | The ACME account contact email rendered into every tenant's Caddy configuration. |
| `scripts/install.sh`, `scripts/install.ps1` | The repository the installers download releases from, and the cosign identity they verify. |
| `PLATFORM_DOMAIN`, `CLOUDFLARE_ZONE_NAME` | Both default to `enclava.dev` in the API and the API image. Always set them explicitly. |

Annotation and label keys such as `enclava.dev/tenant` and
`cap.enclava.dev/...` are API identifiers, not configuration. Leave them as
they are: live workloads and signed artifacts depend on them.

## Build Your Trust Bundle

The bundle format requires all three profile names. An installation with a
single environment still fills in `dev`, `preprod`, and `production`; each
profile needs its own API origins, and profiles that share a root key need
distinct installation identities (signing-service key and Trustee CA).

For each profile:

1. Generate a root key offline, and separate keys for the policy signing
   service and the platform trustee policy authority. The trustee policy key
   must differ from the signing-service key.
2. Write the release payload: sidecar image digests, Trustee KBS URL and CA,
   signing-service URL and key, trustee policy key, runtime class, genpolicy
   version, and policy template.
3. Sign it with the `platform-release` example in `crates/enclava-cli`
   (`cargo run --locked -p enclava-cli --example platform-release -- sign`).

The exact commands, including how to keep the seed out of shell history, are
in the "Rotating the production root" section of
[DEPLOYMENT.md](../DEPLOYMENT.md). Verify the finished bundle with:

```bash
cargo run --locked -p enclava-cli --example platform-release -- \
  verify-profiles crates/enclava-common/platform-release-profiles.json
```

The bundle committed to this repository is signed with a public fixture root.
Builds with the `prod-strict` feature reject it, so a release build cannot ship
with the fixture by accident.

A bundle contains public keys and signed data only. Never commit a private key
or seed.

## Build and Publish

With the bundle in place, build the three artifacts from your fork:

```bash
# CLI
cargo build --release --bin enclava --features prod-strict

# API image (release stage) and the in-guest sidecar image
docker build -f crates/enclava-api/Dockerfile --target runtime-release -t <registry>/enclava-api .
docker build -f crates/enclava-init/Dockerfile -t <registry>/enclava-init .
```

Push the images, sign them with cosign, and reference them by digest. The
workflows in `.github/workflows/` do the same and are the reference for the
exact build arguments.

Because the launch measurement and the signed policy bind to image digests, an
installation that builds its own `enclava-init` has its own measurements. Your
Trustee reference values must be produced from your builds, not copied from
Enclava's.

## Deploy the API

1. Read [deploy/api/README.md](../deploy/api/README.md) and adapt the overlay.
2. Provide the environment described in [DEPLOYMENT.md](../DEPLOYMENT.md):
   Required Environment, the policy-read variables, and whichever optional
   integrations you use. Two settings are easy to miss because the signed
   release does not carry them:
   - `ENCLAVA_INIT_IMAGE`, the digest-pinned `enclava-init` image you built.
     Release builds panic while rendering a workload if it is unset or not
     pinned with `@sha256:`.
   - The signer of each sidecar image. For `attestation-proxy` set
     `ATTESTATION_PROXY_SIGNER_SUBJECT` and `ATTESTATION_PROXY_SIGNER_ISSUER`
     (keyless), or `ATTESTATION_PROXY_SIGNER_PUBLIC_KEY_PEM`; for
     `caddy-ingress` set the matching `CADDY_INGRESS_SIGNER_*` variables.
     Signing the images is not enough: the API refuses to start without the
     identity to verify them against.
3. Apply database migrations. The reference overlay sets
   `DATABASE_MIGRATION_MODE=verify`, which expects migrations to have been
   applied already by running `cap-migrate` from the API image with
   `DATABASE_URL` set. Removing that variable makes the API apply migrations at
   startup instead.
4. Start with `CAP_DEPLOYMENT_DISPATCH_ENABLED=false`, confirm `/readyz`, then
   enable dispatch. While it is `false`, the API rejects app and deployment
   changes with HTTP 503 `deploy_blocked`; nothing is queued.

## Accept the Installation

Health endpoints do not show that confidential deploys work. Run the user flow
end to end with a CLI built from your fork:

```bash
enclava signup --email
enclava login --email
enclava init
enclava create --signer-subject <cosign-subject>
enclava deploy --image <registry>/<image>@sha256:<digest>
enclava status
```

`enclava signup` uses the CLI's configured API URL, which is why the fork
changes the default. Use email (or `--nostr`) authentication. A plain `enclava login` starts the
device flow, which sends the browser to a `/cli/login` approval page. This API
does not serve that page; it belongs to a separate console, located by
`ENCLAVA_DASHBOARD_URL`.

Then confirm the ownership claim, the public HTTPS endpoint, and that data
survives a redeploy.

## Try It Locally First

The development stack needs none of the platform components and runs against
the committed fixture bundle:

```bash
docker compose up --build
curl http://localhost:3000/health
```

It is enough for API and CLI work. It cannot deploy a confidential workload.
See [DEV.md](../DEV.md).

## Staying Current

Upstream changes regularly carry rollout-order requirements: a migration that
must run before the API starts, a sidecar that must be live before the API
emits a new schema, or signed artifacts that must be re-signed. Read the
upgrade notes at the end of [DEPLOYMENT.md](../DEPLOYMENT.md) and the
migration files in `crates/enclava-api/migrations/` before taking a new
upstream version.
