# Creation-ledger activation

CAP records creation POST response UIDs in `resource_creation_ledger`. By default, an unrecorded object has no destructive-cleanup authority, regardless of its age or client-selected field manager. Existing installations must plan migration before enabling this binary: absent legacy migration, old CAP-created resources remain unresolved rather than being deleted.

## Coordinated migration

1. Quiesce CAP mutations and tenant namespace writers. Drain every old writer and in-flight operation before selecting a boundary; do not use the build date, migration execution date, or midnight as a substitute for activation.
2. Apply the database migrations and install ledger-enabled binaries on every writer while mutations remain paused. Do not run old and new writers concurrently after activation.
3. Independently audit legacy objects and their ownership. The legacy annotation plus `enclava-platform` field-manager string is forgeable. A timestamp cannot distinguish an old tenant forgery from a CAP creation. Do not enable legacy trust unless this bounded risk is accepted and the objects have been audited.
4. Record the actual coordinated activation instant as an absolute timestamp. Configure `CAP_CREATION_LEDGER_ACTIVATED_AT` to that exact value consistently on every API replica, then restart replicas and resume writes. For example, use the recorded RFC3339 UTC instant, not a computed future rollout deadline. Invalid or future values fail ledger loading closed. Missing configuration selects strict ledger-only behavior.
5. Preserve this value unchanged across upgrades and restarts. It is snapshotted per process, not stored or pinned in the database. Configuration management must prevent changing it: advancing it expands destructive legacy trust to additional UIDs. Replacements created after this instant always need a server-recorded UID.

Legacy trust is not a one-time deletion grant. It remains valid for a pre-activation UID's lifetime, subject to the normal annotation, generation, and cleanup checks. Operators unwilling to accept legacy trust must leave the setting unset and recover old resources through independently audited provenance or manual remediation; they must not advance a cutoff to unblock cleanup.

All comparisons use full parsed instants, including fractional seconds and offsets. Missing or malformed object timestamps never establish legacy provenance.

## Failed persistence and cleanup

Every apply step, including partially failed multi-object steps and ingress-only reapply, drains creation observations before propagating its result. Failed ledger persistence fails the operation and attempts UID-pinned compensation. Namespace compensation durably retains its namespace fence before issuing DELETE: acceptance is not absence. A still-live terminating namespace cannot release that fence; reconciliation must observe absence before releasing it.

Ledger facts belong to the app lifetime. App deletion cascades ledger rows only after the existing deletion path has completed teardown. Deployment deletion does not remove lineage needed by subsequent generations.
