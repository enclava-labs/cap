# Kubernetes mutation fence recovery

CAP sets `external_resource_mutation_leases.reclaim_after` to PostgreSQL
`infinity` for the `kubernetes_namespace` scope immediately before the first
Kubernetes write. The normal final database transaction clears the row only
after the complete operation converges. A timeout, process loss, or lost
response intentionally leaves the namespace poisoned because the API server
may still complete a request after CAP stopped awaiting it.

This is a fail-closed incident procedure. Do not clear the fence just because
`locked_until` expired, a CAP pod restarted, or one Kubernetes GET returned
`NotFound`. Never use customer `pods/log`, ConfigMap data, Secret data, or
workload payloads as recovery evidence.

## 1. Quiesce the owning writers

Pause the deployment worker and every CAP API replica that can mutate the
affected app or delete its namespace. Record the incident, the stopped
replicas, and the time. Do not proceed while the owning request/process could
still be alive.

Capture the exact resource owner, its app owner, and every other provider
resource held by the same token:

```sql
SELECT resource_scope, resource_key, generation, owner_token,
       operation_kind, operation_id, locked_until, reclaim_after, updated_at
  FROM external_resource_mutation_leases
 WHERE resource_scope = 'kubernetes_namespace'
   AND resource_key = '<namespace>';

SELECT app_id, generation, owner_token, operation_kind, operation_id,
       locked_until, reclaim_after, updated_at
  FROM app_mutation_leases
 WHERE owner_token = '<captured-owner-token>'::uuid;

SELECT resource_scope, resource_key, generation, owner_token,
       operation_kind, operation_id, locked_until, reclaim_after
  FROM external_resource_mutation_leases
 WHERE owner_token = '<captured-owner-token>'::uuid
 ORDER BY resource_scope, resource_key;

SELECT job.deployment_id, job.app_id, job.state, job.lock_token,
       job.locked_until, deployment.status, app.status AS app_status,
       app.namespace
  FROM deployment_apply_jobs AS job
  JOIN deployments AS deployment ON deployment.id = job.deployment_id
  JOIN apps AS app ON app.id = job.app_id
 WHERE job.deployment_id = '<captured-operation-id>'::uuid;
```

For `app_delete`, the operation ID is the app ID and the deployment query can
return no rows. Verify the app is still in its durable deleting state. All
captured owner fields must agree, and `locked_until` must be expired. A token
can own DNS and Kubernetes fences in the same operation; reconcile every
`dns_hostname` row with
[DNS mutation reconciliation](dns-mutation-reconciliation.md) before clearing
the app owner. Do not clear only one provider and then clear the app owner.

Confirm through Kubernetes API-server audit/request telemetry that all
accepted writes for this CAP identity and namespace have completed and that no
new writes appear while the CAP writers are paused. An arbitrary sleep or two
identical reads does not prove quiescence. If the API server cannot establish
that there is no accepted work still running, leave the row at infinity and
escalate.

## 2. Enumerate the complete Kubernetes state

List names only across every namespaced API so an unexpected CRD or
controller-created object is not missed. This does not authorize reading pod
logs or object data:

```bash
NS='<namespace>'

kubectl get namespace "$NS" \
  -o 'custom-columns=KIND:.kind,NAME:.metadata.name,UID:.metadata.uid,RV:.metadata.resourceVersion,GEN:.metadata.annotations.enclava\.dev/cap-provider-mutation-generation' \
  --ignore-not-found

kubectl api-resources --namespaced=true --verbs=list -o name | while read -r resource; do
  kubectl -n "$NS" get "$resource" -o name --ignore-not-found 2>/dev/null
done | sort -u

for resource in \
  serviceaccounts resourcequotas services configmaps statefulsets.apps \
  ciliumnetworkpolicies.cilium.io \
  envoyproxies.gateway.envoyproxy.io \
  gateways.gateway.networking.k8s.io \
  tlsroutes.gateway.networking.k8s.io; do
  kubectl -n "$NS" get "$resource" \
    -l app.kubernetes.io/managed-by=enclava-platform \
    -o 'custom-columns=KIND:.kind,NAME:.metadata.name,UID:.metadata.uid,RV:.metadata.resourceVersion,GEN:.metadata.annotations.enclava\.dev/cap-provider-mutation-generation' \
    --ignore-not-found
done

kubectl -n "$NS" get pods,persistentvolumeclaims,controllerrevisions.apps \
  -o 'custom-columns=KIND:.kind,NAME:.metadata.name,UID:.metadata.uid,RV:.metadata.resourceVersion,OWNER_KIND:.metadata.ownerReferences[0].kind,OWNER_NAME:.metadata.ownerReferences[0].name' \
  --ignore-not-found
```

The directly applied set is the Namespace, ServiceAccount, ResourceQuota,
Service, SNI-route ConfigMap, bootstrap ConfigMap, startup ConfigMap, tenant
ingress ConfigMap, enclava-init ConfigMap, CiliumNetworkPolicy, EnvoyProxy,
Gateway, both TLSRoutes, and StatefulSet. Pods, PVCs, ControllerRevisions, and
Gateway-controller children are derived state but must also be accounted for.
PVCs do not carry CAP's generation annotation; identify them by namespace,
StatefulSet volume-claim template, and owner/name relationship.

Reject recovery if any directly applied live object has
`enclava.dev/cap-provider-mutation-generation` greater than the captured row
generation. That proves authority advanced and the captured operation must not
overwrite it.

## 3. Converge one authoritative outcome

Choose and record exactly one database-authoritative target:

- For a confirmed `app_delete`, the namespace and every namespaced object must
  be absent. Wait for namespace deletion to reach `NotFound`; do not treat a
  Namespace in `Terminating` as convergence.
- For a deployment that remains authoritative, render from the immutable
  `deployment_apply_jobs.payload` for the selected deployment using the same
  reviewed CAP revision. Reconcile the entire directly applied set above in
  CAP's normal order, with the captured mutation generation, then wait for
  StatefulSet and controller-derived state to converge.
- For a terminally failed/canceled deployment, restore the complete manifest
  set from the latest database-authoritative healthy deployment payload. If no
  healthy deployment exists, the incident owner must explicitly choose and
  document deletion; do not invent a hybrid manifest set.

Use CAP's manifest generator and generation-aware apply/delete implementation;
do not hand-patch individual fields. Compare UID, resourceVersion, generation
annotation, owner references, desired replica count, and rollout status after
the final reconciliation. Metadata is sufficient; do not inspect customer
logs, Secret values, ConfigMap contents, or workload payloads. Reconfirm in
API-server telemetry that the reconciliation writes have completed and the
paused identity is quiescent.

If the exact immutable payload/revision is unavailable, any object cannot be
accounted for, a higher generation exists, or provider quiescence cannot be
proved, stop and leave the fence at infinity.

## 4. Unpoison with an exact CAS

Only after the provider is quiescent and the complete target is converged,
clear the exact namespace row. Substitute values captured in step 1. Run this
interactively with autocommit disabled; the `UPDATE ... RETURNING` must return
exactly one row. Zero rows or changed values mean authority moved: `ROLLBACK`
and restart the investigation.

```sql
BEGIN;

SELECT resource_scope, resource_key, generation, owner_token,
       operation_kind, operation_id, locked_until, reclaim_after
  FROM external_resource_mutation_leases
 WHERE resource_scope = 'kubernetes_namespace'
   AND resource_key = '<namespace>'
 FOR UPDATE;

UPDATE external_resource_mutation_leases
   SET owner_token = NULL,
       operation_kind = NULL,
       operation_id = NULL,
       locked_until = NULL,
       reclaim_after = NULL,
       updated_at = clock_timestamp()
 WHERE resource_scope = 'kubernetes_namespace'
   AND resource_key = '<namespace>'
   AND generation = <captured-resource-generation>
   AND owner_token = '<captured-owner-token>'::uuid
   AND operation_kind = '<captured-operation-kind>'
   AND operation_id = '<captured-operation-id>'::uuid
   AND reclaim_after = 'infinity'::timestamptz
   AND locked_until <= clock_timestamp()
 RETURNING resource_scope, resource_key, generation;

-- Stop and ROLLBACK unless the preceding UPDATE returned exactly one row.
-- Reconcile and CAS-clear every other external row held by this token first.

UPDATE app_mutation_leases AS app
   SET owner_token = NULL,
       operation_kind = NULL,
       operation_id = NULL,
       locked_until = NULL,
       reclaim_after = NULL,
       updated_at = clock_timestamp()
 WHERE app.app_id = '<captured-app-id>'::uuid
   AND app.generation = <captured-app-generation>
   AND app.owner_token = '<captured-owner-token>'::uuid
   AND app.operation_kind = '<captured-operation-kind>'
   AND app.operation_id = '<captured-operation-id>'::uuid
   AND app.locked_until <= clock_timestamp()
   AND NOT EXISTS (
       SELECT 1
         FROM external_resource_mutation_leases AS resource
        WHERE resource.owner_token = app.owner_token
   )
 RETURNING app_id, generation;

-- If an app row was captured, this UPDATE must also return exactly one row.
-- Otherwise ROLLBACK. A ResourceMutationLease-only incident legitimately has
-- no app row and must omit this statement.

COMMIT;
```

Resume CAP writers, retry the original operation, and verify the new mutation
generation, final deployment/app state, complete Kubernetes object set, and
that no row for the operation remains owned or at infinity. Preserve the SQL
results, Kubernetes metadata-only inventory, API-server quiescence evidence,
and retry result with the incident.
