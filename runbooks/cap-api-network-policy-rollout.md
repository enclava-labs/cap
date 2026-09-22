# CAP API NetworkPolicy + trusted-proxy rollout checks

Owner: cap (this repo) + enclava-ops-manifests (live overlays)
Scope: PR #172 — device-auth rate limiting and the API ingress NetworkPolicy.

This runbook lists the checks that MUST pass on a target cluster before the
`cap-api-ingress-only` NetworkPolicy and the `TRUSTED_PROXY_CIDRS` /
rate-limit keying model are enabled there. The in-repo
`deploy/api/network-policy.yaml` is the reference; the live overlay in
enclava-ops-manifests is what actually rolls out — mirror any change to both.

Service coordinates used below: `deploy/api/service.yaml` defines a Service
named `enclava-api` (namespace `enclava-platform`) on service port 80 →
targetPort 3000, so in-cluster callers use
`http://enclava-api.enclava-platform.svc.cluster.local` (port 80 implied;
`:3000` would fail DNS/service routing since the Service does not expose it).

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
# from a tenant namespace pod (Service name enclava-api, service port 80):
wget -qO- --header="Authorization: Bearer <token>" \
  http://enclava-api.enclava-platform.svc.cluster.local:80/api/v1/workload/artifacts
```

A timeout here means the tenant ingress rule (namespace label
`enclava.dev/tenant: Exists`) is not matching — workload unlock will hang.
Note `wget -qO-` writes any fetched document to stdout; if the endpoint
ever returns a body, prefer `-qO /dev/null` so the output cannot be
mistaken for command success. An exit status of 4 (network failure)
also fails the check — do not judge this step by output presence alone.

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

End-to-end check from an external client, against a GOVERNED route
(`/.well-known/enclava` is not registered by this API — an outer-router 404
never reaches the governor; `POST /auth/device/start` is registered and
carries the tight 1 r/s burst-10 governor):

```sh
# 15 rapid starts WITH rotating spoofed headers — if the ingress overwrote
# them correctly, all requests share ONE per-IP budget and this must produce
# 429s within ~10 requests:
for i in $(seq 1 15); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.<cluster>/auth/device/start \
    -H 'Content-Type: application/json' -d '{}' \
    -H "X-Real-IP: 198.51.100.$i" -H "X-Forwarded-For: 198.51.100.$i"
done | sort | uniq -c
# Expect a handful of 200/4xx (before the budget drains) and then 429s
# (or 503s — the device-start Ingress's own limit-rps may fire first;
# see the disambiguation note in §3c).
# If all 15 succeed, the spoofed headers are being honored as distinct
# rate-limit keys — STOP the rollout and re-check the controller config.
# Then repeat the loop WITHOUT the spoofed headers: the 429 threshold must
# be the same (headers must not change the rate-limit outcome).
```

Note: each 200 inserts a device-login session row; the reaper purges expired
rows hourly, so this smoke test is self-cleaning.

## 3b. Narrow TRUSTED_PROXY_CIDRS to the ingress controllers (mandatory)

The in-repo default `TRUSTED_PROXY_CIDRS=10.0.0.0/8` trusts the whole pod
network because a static manifest cannot know where the target cluster's
ingress controllers run. Tenant workload pods (which this PR's NetworkPolicy
intentionally admits for artifact/certificate fetches) then sit inside the
trusted range: a malicious tenant could set `X-Real-IP` directly against the
ClusterIP and rotate rate-limit keys. Closing that completely requires
per-cluster knowledge, so before enabling the policy on a target cluster:

```sh
kubectl get pods -n ingress-nginx -o wide   # controller pod IPs / nodes
kubectl get nodes -o wide                   # map pod IPs to the node+pod CIDR in use
```

Set `TRUSTED_PROXY_CIDRS` in the live overlay to the smallest CIDR (or
explicit IP list) covering ONLY the ingress-nginx controller pods.

How to verify the narrowing depends on whether the proxy secret (§3c) is
already wired:

- **With `TRUSTED_PROXY_SECRET` configured (the mandatory end state):** a
  direct tenant-pod connection carries no proxy secret, so the extractor
  ignores its forwarding headers and keys by the pod IP whether that pod
  sits inside `10.0.0.0/8` or outside the narrowed CIDR — a spoofed-header
  loop hits 429 either way and CANNOT distinguish wide from narrow trust.
  The secret gate is what actually defeats tenant-pod spoofing; the CIDR
  narrowing is defense-in-depth (it limits blast radius if the secret
  leaks or the injection is misconfigured). Verify the narrowing itself
  by inspecting the live value against the controller pod IPs:

```sh
kubectl -n enclava-platform get deploy enclava-api -o jsonpath=\
  '{.spec.template.spec.containers[0].env[?(@.name=="TRUSTED_PROXY_CIDRS")].value}'
kubectl get pods -n ingress-nginx -o wide   # every controller IP must fall
                                            # inside the printed CIDR(s), and
                                            # tenant pod CIDRs must NOT
```

- **Without the secret (e.g. a staging cluster before §3c):** re-run the
  §3-style spoofed-header check from a tenant pod directly against the
  ClusterIP, where the CIDR IS the only gate:

```sh
# from a tenant pod — spoofed headers must NOT buy extra /auth/device/start
# budget once the pod's own IP is the rate-limit key:
for i in $(seq 1 15); do
  wget -qO /dev/null --server-response \
    --header="X-Real-IP: 198.51.100.$i" \
    --post-data='{}' \
    http://enclava-api.enclava-platform.svc.cluster.local:80/auth/device/start 2>&1 \
    | grep 'HTTP/1.1' | tail -1
done | sort | uniq -c
# 429s within ~10 requests = good (keyed by the pod's own address).
# All 15 succeeding = the tenant pod's headers are still trusted = the CIDR
# is too wide — do not enable the policy until it is narrowed.
# EMPTY output = wget failed before issuing the request (DNS/service
# unreachable); treat that as a FAILED check, not a pass — the pipeline
# has no pipefail, so do not rely on the loop's exit status.
```

If the cluster cannot pin controller addresses (fully dynamic pools), split
the API into a proxy-facing and a workload-facing port and scope header trust
to the proxy-facing port — tracked as follow-up hardening.

## 3c. Provision TRUSTED_PROXY_SECRET and the ingress header injection (mandatory)

The deployment references `secretKeyRef: api-secrets / trusted-proxy-secret`.
Both halves must be in place BEFORE the new API revision rolls out:

1. Create the secret key in the API namespace:

```sh
kubectl -n enclava-platform create secret generic api-secrets \
  --from-literal=trusted-proxy-secret="$(head -c32 /dev/urandom | base64)" \
  --dry-run=client -o yaml | kubectl label --local -f - \
  app.kubernetes.io/part-of=cap --dry-run=client -o yaml | kubectl apply -f -
# (if api-secrets already exists, `kubectl patch secret api-secrets -p
#  '{"stringData":{"trusted-proxy-secret":"<value>"}}'` instead)
```

2. Configure ingress-nginx to inject the same value as a request header on
   every proxied request, overwriting anything the client sent. With the
   controller's global `proxy-set-headers` ConfigMap:

```sh
kubectl -n ingress-nginx get cm ingress-nginx-controller -o yaml
# ensure `data["proxy-set-headers"]` points at a ConfigMap containing:
#   data:
#     x-enclava-proxy-secret: "<same value as trusted-proxy-secret>"
```

3. **Verify the secret actually reaches CAP** (critical sanity check):

Directly reading the header CAP receives is not possible via `curl -v`
(that shows the request as *curl sent it* — the injected header exists
only on the ingress→CAP leg), and there is no debug endpoint exposing
request headers. Verify behaviorally instead, with a POSITIVE control:

```sh
# Two clients on DIFFERENT public source IPs (e.g. two networks, a VPN
# hop, or a second cloud instance). Each drives the same rapid loop:
for i in $(seq 1 15); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST \
    https://api.<cluster>/auth/device/start \
    -H 'Content-Type: application/json' -d '{}'
done | sort | uniq -c
#
# PASS (secret honored, per-client keying):
#   - first IP: 200/4xx for ~10 requests, then 429s
#   - second IP starts FRESH: ~10 non-429 responses of its own
#     (its own bucket), NOT immediate 429s.
# FAIL (secret missing/mismatched — every public request is keyed by
#   the ingress controller pod IP, one shared bucket for all clients):
#   - the second IP gets 429 IMMEDIATELY (its requests land in the
#     same drained bucket the first IP just exhausted).
# DISAMBIGUATION: the device-start Ingress has its own limit-rps
#   annotation, so the ingress limiter can fire BEFORE CAP's governor
#   and mask CAP's answer. ingress-nginx throttling returns 503, CAP's
#   governor returns 429 — distinguish the tiers by status code, and
#   count only 429s as evidence about the secret wiring.
# Do NOT enable the policy on a FAIL.
```

The direction of the signal matters: if the second IP retains its own
budget, the secret is being honored; if it is throttled instantly, it is
not. (A second-IP FAIL here is also the observable signature of the §3
spoofing regression.)

Optionally, to distinguish "secret honored" from "ingress not injecting
but CIDR trusts it anyway", repeat one loop WITH a spoofed
`X-Real-IP` per request (§3 style): with the secret honored the outcome
must be identical to the unspoofed loop, because ingress-nginx
overwrites `X-Real-IP` with the true client address either way.

Verifying the wiring is the FIRST thing to do if per-client rate limiting
regresses: if the controller does not inject the header (or the values
differ), every public request arrives secret-less from a trusted CIDR peer
and is keyed by the controller pod IP — one shared bucket for all public
clients. The §3 spoofed-header check exercises exactly this path: with the
secret correctly wired, spoofed and unspoofed loops must behave identically
and both must hit 429s.

## 4. PaaS internal path and SAN trust boundary

Use the registered cluster-status route (`/internal/paas/status`; there is no
`/internal/paas/health` — an unregistered path 404s at the router and never
reaches the `InternalAuth` extractor):

```sh
# from an enclava-paas pod, direct to the ClusterIP (not via ingress):
curl -s -w '\n%{http_code}\n' \
  http://enclava-api.enclava-platform.svc.cluster.local/internal/paas/status \
  -H 'Authorization: Bearer <internal service token>' \
  -H 'x-enclava-internal-client-san: <allowed SAN>'
# Expect 200 with a JSON body (extractor accepted token + SAN).

# Denied case — an SAN not in CAP_INTERNAL_ALLOWED_CLIENT_SANS must be 401:
curl -s -o /dev/null -w '%{http_code}\n' \
  http://enclava-api.enclava-platform.svc.cluster.local/internal/paas/status \
  -H 'Authorization: Bearer <internal service token>' \
  -H 'x-enclava-internal-client-san: not-allowed.example'
# Expect 401.

# Denied case — missing token must be 401:
curl -s -o /dev/null -w '%{http_code}\n' \
  http://enclava-api.enclava-platform.svc.cluster.local/internal/paas/status \
  -H 'x-enclava-internal-client-san: <allowed SAN>'
# Expect 401.
```

Confirm a pod in the namespace WITHOUT the `app.kubernetes.io/name=enclava-paas`
label is refused (NetworkPolicy drop). If the mTLS handshake terminates at a
proxy in front of the PaaS rather than at the PaaS client itself, set
`CAP_INTERNAL_TRUSTED_PROXY_SECRET` so SAN assertions are pinned to the
verified proxy.

## 5. Rate-limit budget is per replica

The governors are in-process (tower-governor): each API pod keeps its own
counters, so with N replicas a single client gets N × (1 r/s, burst 10) on
`/auth/device/start` — the budget multiplies with scale. The aggregate cap
belongs at the ingress tier where it is enforced once; if the cluster runs
multiple API replicas, add an nginx `limit-rps` annotation (or equivalent) on
the `/auth/device/start` path in the live overlay, e.g.:

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/limit-rps: "1"
```

Caveat: `limit-rps` state is controller-local, so with M ingress-nginx
controller replicas the effective sustained allowance is the annotation
value × M. Size the annotation accordingly (annotation = target / M) or use
a cluster-wide limiter if the target cluster runs multiple controllers;
verify the effective aggregate by driving §3's spoofed-header loop through
the threshold after configuring it.

The in-process governor then remains as defense-in-depth for direct
ClusterIP callers that bypass the ingress.
