# CAP API NetworkPolicy + trusted-proxy rollout checks

Owner: cap (this repo) + enclava-ops-manifests (live overlays)
Scope: PR #172 — device-auth rate limiting and the API ingress NetworkPolicy.

This runbook lists the checks that MUST pass on a target cluster before the
`cap-api-ingress-only` NetworkPolicy and the `TRUSTED_PROXY_CIDRS` /
rate-limit keying model are enabled there. The in-repo
`deploy/api/network-policy.yaml` is the reference; the live overlay in
enclava-ops-manifests is what actually rolls out — mirror any change to both.

## 1. Selector labels exist on the target cluster

```sh
kubectl get ns ingress-nginx   # must carry kubernetes.io/metadata.name=ingress-nginx (automatic)
kubectl get pods -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx   # must list the controllers
kubectl get ns enclava-paas    # PaaS namespace; pods must carry app.kubernetes.io/name=enclava-paas
kubectl get ns -l enclava.dev/tenant   # must list every CAP-rendered tenant namespace
```

If any selector is empty, traffic for that class is DROPPED once the policy is
enforced. Adjust the selectors in the overlay to the cluster's actual labels
before applying.

## 2. Tenant workload egress path is intact

Deploy (or exec into) a tenant pod and confirm the two enclava-init routes on
the CAP API service answer:

```sh
# from a tenant namespace pod:
wget -qO- --header="Authorization: Bearer <workload token>" \
  http://cap-api.enclava-platform.svc.cluster.local:3000/api/v1/workload/artifacts
```

A timeout here means the tenant ingress rule (namespace label
`enclava.dev/tenant: Exists`) is not matching — workload unlock will hang.

## 3. Ingress controller forwarded-header behavior (rate-limit keying)

The rate limiter prefers `X-Real-IP` from trusted peers. ingress-nginx only
overwrites that header with the connecting address when
`use-forwarded-headers=false` (the default) — the property that makes it
unspoofable. Verify the live controller config:

```sh
kubectl -n ingress-nginx get deploy -o yaml | grep -A2 use-forwarded-headers
kubectl -n ingress-nginx get cm ingress-nginx-controller -o yaml | grep -i forwarded
```

- `use-forwarded-headers: false` (or unset) → desired: X-Real-IP is the
  address that actually connected; client-supplied values are overwritten.
- `use-forwarded-headers: true` → the controller TRUSTS client-supplied
  X-Real-IP/XFF, and the rate-limit key becomes client-choosable. In that
  case either set it to false for the CAP host, or narrow
  TRUSTED_PROXY_CIDRS to exclude the class of clients that can reach it.

End-to-end check from an external client:

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://api.<cluster>/.well-known/enclava \
  -H 'X-Real-IP: 1.2.3.4' -H 'X-Forwarded-For: 1.2.3.4'
# then without the headers, repeatedly — both must behave identically
# (headers must not change the rate-limit outcome).
```

## 4. PaaS internal path and SAN trust boundary

```sh
# from an enclava-paas pod, direct to the ClusterIP (not via ingress):
curl -s http://cap-api.enclava-platform.svc.cluster.local:3000/internal/paas/health \
  -H 'Authorization: Bearer <service token>' \
  -H 'x-enclava-internal-client-san: <allowed SAN>'
```

Confirm a pod in the namespace WITHOUT the `app.kubernetes.io/name=enclava-paas`
label is refused (NetworkPolicy drop). If the mTLS handshake terminates at a
proxy in front of the PaaS rather than at the PaaS client itself, set
`CAP_INTERNAL_TRUSTED_PROXY_SECRET` so SAN assertions are pinned to the
verified proxy.
