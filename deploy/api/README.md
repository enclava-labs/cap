# CAP API reference overlay

This Kustomize overlay is the reference deployment of the CAP API. It is the
input to `scripts/render-api-release-manifest.sh`, which pins the image digest
and produces the manifest attached to each API image build.

It is written for Enclava's installation and is not complete on its own.
Applying it unchanged to another cluster does not produce a working API. Use it
as the template for your own overlay, together with
[docs/self-hosting.md](../../docs/self-hosting.md) and
[DEPLOYMENT.md](../../DEPLOYMENT.md).

## Values specific to Enclava's installation

| File | Value | Replace with |
| --- | --- | --- |
| `deployment.yaml` | `API_URL=https://cap.enclava.dev` | Your public API URL. It must be an origin listed in the selected release profile. |
| `deployment.yaml` | `ENCLAVA_PLATFORM_RELEASE_PROFILE=production` | The profile in your trust bundle that matches `API_URL`. |
| `deployment.yaml` | `PLATFORM_DOMAIN`, `CLOUDFLARE_ZONE_NAME` = `enclava.dev` | Your tenant hostname suffix and managed DNS zone. |
| `deployment.yaml` | `DNS_MANAGEMENT_REQUIRED=true`, `CLOUDFLARE_API_TOKEN`, `TENANT_DNS_TARGET` | If CAP does not manage DNS in your installation, remove all three. The last two are required Secret references, so the pod cannot start while they point at missing keys. |
| `deployment.yaml` | `AMD_KDS_BASE_URL` pointing at an in-cluster `amd-kds-relay` | Your own AMD KDS relay, or remove it to use `https://kdsintf.amd.com/vcek/v1`. |
| `deployment.yaml` | `TRUSTED_PROXY_CIDRS=10.0.0.0/8` | The address range of your ingress controllers. |
| `deployment.yaml` | `imagePullSecrets: ghcr-login` | A pull secret for your registry, or remove it for a public image. |
| `deployment.yaml`, `kustomization.yaml` | `ghcr.io/enclava-labs/enclava-api`, with an all-zero digest placeholder | Your API image, pinned by digest. |
| `ingress.yaml` | Host `cap.enclava.dev`, issuer `letsencrypt-prod`, class `nginx` | Your hostname, certificate issuer, and ingress class. |
| `network-policy.yaml` | Ingress rule for the `enclava-paas` namespace | Remove it unless you run a service that calls `/internal/paas/*`. |
| `network-policy.yaml` | Ingress rule for the `ingress-nginx` namespace | The namespace and labels of your ingress controller. |
| `rbac.yaml` | Role in namespace `tenant-envoy` for `haproxy-tenant` | The namespace and object names of your tenant edge. |

## What the overlay does not include

- **Secrets.** `api-secrets` (keys `database-url`, `trusted-proxy-secret`,
  `cloudflare-api-token`, `tenant-dns-target`) and `ghcr-login` are referenced
  but not defined. Create them with your secret-management system.
- **Most required environment.** The API signing key, session HMAC key, API-key
  pepper, `TRUSTEE_POLICY_READ_AVAILABLE`, the `TRUSTEE_*` endpoints, the
  signing-service settings, and the signed platform release are all absent. See
  Required Environment in [DEPLOYMENT.md](../../DEPLOYMENT.md).
- **A migration step.** `DATABASE_MIGRATION_MODE=verify` makes the API refuse
  to start against a schema that is not current. Run `cap-migrate` from the API
  image with `DATABASE_URL` set before each rollout, or remove the variable to
  let the API migrate at startup.
- **RBAC for tenant resources.** `rbac.yaml` grants only `get` on Services and
  access to the tenant edge objects. The API also creates and updates
  Namespaces, StatefulSets, Services, ServiceAccounts, Secrets, ConfigMaps,
  ResourceQuotas, `CiliumNetworkPolicy`, `Gateway`, `TLSRoute`, and
  `EnvoyProxy` objects for tenants, and can manage the Trustee policy
  ConfigMap and Deployment. Grant those permissions for your cluster, scoped as
  tightly as it allows.
- **Deployment dispatch.** `CAP_DEPLOYMENT_DISPATCH_ENABLED` is `false`: the
  API rejects app and deployment changes with HTTP 503 `deploy_blocked` until a
  later rollout sets it to `true`.

## Other files

`cap-paas-internal-logs.contract.yaml` is not a Kubernetes manifest and is not
part of the Kustomization. It is the contract for the internal log route,
checked by `crates/enclava-api/tests/contract_files.rs`.

[runbooks/cap-api-network-policy-rollout.md](../../runbooks/cap-api-network-policy-rollout.md)
lists the checks to run on a
cluster before enabling the NetworkPolicy and the trusted-proxy settings.
