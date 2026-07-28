//! One-time, exact clean-cut retirement for contained legacy authority.
//!
//! This is deliberately not a compatibility path. It exists to remove an
//! explicitly reviewed, complete set of pre-cutover apps after the normal CAP
//! API/dispatcher has been scaled to zero. Every database and Kubernetes
//! identity is supplied in a reviewed plan and compared exactly before stale
//! database authority is retired. Provider resources are deliberately retained
//! for the ordinary, fenced app DELETE path.

use std::collections::BTreeSet;

use k8s_openapi::api::{
    apps::v1::{Deployment, StatefulSet},
    core::v1::{Namespace, PersistentVolume, PersistentVolumeClaim, Pod},
};
use kube::{Api, Client, ResourceExt, api::ListParams, core::Selector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{mutation_leases::RECLAIM_QUARANTINE_SECONDS, runtime_authority::RuntimeAuthority};

const PLAN_VERSION: u32 = 1;
const REQUIRED_SCHEMA_VERSION: i64 = 47;
const OWNER_TOKEN_HASH_DOMAIN: &[u8] = b"enclava-cap-clean-cut-owner-token-v1\0";
const CAP_MANAGED_BY_LABEL: &str = "enclava-platform";
const MUTATION_GENERATION_ANNOTATION: &str =
    enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanCutPlan {
    pub version: u32,
    pub expected_restore_generation: i64,
    pub quiet_period_seconds: i64,
    pub containment: ContainmentPlan,
    pub targets: Vec<CleanCutTarget>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentPlan {
    pub namespace: String,
    pub deployment_name: String,
    pub deployment_uid: Uuid,
    pub pod_label_selector: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanCutTarget {
    pub app_id: Uuid,
    pub org_id: Uuid,
    pub app_name: String,
    pub namespace: String,
    pub namespace_uid: Uuid,
    pub tenant_label: String,
    pub domain: String,
    pub tee_domain: String,
    pub deployment_id: Uuid,
    pub job_generation: i64,
    pub payload_version: i32,
    pub payload_sha256: String,
    pub artifact_descriptor_core_hash: String,
    pub manifest_hash: String,
    pub owner_token_sha256: String,
    pub app_lease_generation: i64,
    pub statefulset: ExpectedStatefulSet,
    pub persistent_volume_claims: Vec<ExpectedPersistentVolumeClaim>,
    pub dns_records: Vec<ExpectedDnsRecord>,
    pub resources: Vec<ExpectedResourceLease>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedStatefulSet {
    pub name: String,
    pub uid: Uuid,
    pub mutation_generation: i64,
    pub manifest_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPersistentVolumeClaim {
    pub name: String,
    pub uid: Uuid,
    pub requested_storage: String,
    pub volume_name: String,
    pub persistent_volume_uid: Uuid,
    pub reclaim_policy: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDnsRecord {
    pub id: Uuid,
    pub hostname: String,
    pub zone_id: String,
    pub record_id: String,
    pub record_type: String,
    pub target: String,
    pub is_custom: bool,
    pub provider: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedResourceLease {
    pub scope: String,
    pub key: String,
    pub generation: i64,
    pub reclaim_after_infinity: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanCutResult {
    pub plan_sha256: String,
    pub mode: &'static str,
    pub status: &'static str,
    pub target_count: usize,
    pub namespaces: Vec<NamespaceRetirement>,
    pub planned_pvc_count: usize,
    pub authority: RuntimeAuthorityWitness,
    pub transaction_id: Option<String>,
    pub kbs_revocation_generation: Option<i64>,
    pub receipts: Vec<TargetRetirementReceipt>,
    pub kbs: KbsReconciliationWitness,
}

struct CleanCutResultDetails {
    mode: &'static str,
    status: &'static str,
    authority: RuntimeAuthorityWitness,
    transaction_id: Option<String>,
    kbs_revocation_generation: Option<i64>,
    receipts: Vec<TargetRetirementReceipt>,
    kbs: KbsReconciliationWitness,
}

#[derive(Clone, Debug, Serialize)]
pub struct NamespaceRetirement {
    pub namespace: String,
    pub expected_uid: Uuid,
    pub state: &'static str,
    pub persistent_volume_claims: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetRetirementReceipt {
    pub audit_id: i64,
    pub app_id: Uuid,
    pub deployment_id: Uuid,
    pub namespace: String,
    pub namespace_uid: Uuid,
    pub kubernetes_observed_generation: i64,
    pub database_retired_generation: i64,
    pub persistent_volume_claims: Vec<ExpectedPersistentVolumeClaim>,
    pub dns_records: Vec<ExpectedDnsRecord>,
    pub resources: Vec<ExpectedResourceLease>,
    pub provider_cleanup_state: &'static str,
}

/// Exact, non-secret target identity persisted in the append-only receipt.
///
/// The lease owner token is intentionally excluded: it is a one-time
/// precondition capability from the reviewed input plan, not receipt data.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredTargetIdentity {
    pub app_id: Uuid,
    pub org_id: Uuid,
    pub app_name: String,
    pub namespace: String,
    pub namespace_uid: Uuid,
    pub tenant_label: String,
    pub domain: String,
    pub tee_domain: String,
    pub deployment_id: Uuid,
    pub job_generation: i64,
    pub payload_version: i32,
    pub payload_sha256: String,
    pub artifact_descriptor_core_hash: String,
    pub manifest_hash: String,
    pub owner_token_sha256: String,
    pub app_lease_generation: i64,
    pub statefulset: ExpectedStatefulSet,
    pub persistent_volume_claims: Vec<ExpectedPersistentVolumeClaim>,
    pub dns_records: Vec<ExpectedDnsRecord>,
    pub resources: Vec<ExpectedResourceLease>,
}

impl From<&CleanCutTarget> for RetiredTargetIdentity {
    fn from(target: &CleanCutTarget) -> Self {
        Self {
            app_id: target.app_id,
            org_id: target.org_id,
            app_name: target.app_name.clone(),
            namespace: target.namespace.clone(),
            namespace_uid: target.namespace_uid,
            tenant_label: target.tenant_label.clone(),
            domain: target.domain.clone(),
            tee_domain: target.tee_domain.clone(),
            deployment_id: target.deployment_id,
            job_generation: target.job_generation,
            payload_version: target.payload_version,
            payload_sha256: target.payload_sha256.clone(),
            artifact_descriptor_core_hash: target.artifact_descriptor_core_hash.clone(),
            manifest_hash: target.manifest_hash.clone(),
            owner_token_sha256: target.owner_token_sha256.clone(),
            app_lease_generation: target.app_lease_generation,
            statefulset: target.statefulset.clone(),
            persistent_volume_claims: target.persistent_volume_claims.clone(),
            dns_records: target.dns_records.clone(),
            resources: target.resources.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeAuthorityWitness {
    pub epoch: Uuid,
    pub restore_generation: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KbsReconciliationWitness {
    pub desired_generation: i64,
    pub configmap_generation: i64,
    pub applied_generation: i64,
    pub configmap_policy_sha256: Option<String>,
    pub applied_policy_sha256: Option<String>,
    pub converged: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanCutRetirementStatus {
    pub plan_sha256: String,
    pub status: &'static str,
    pub provider_cleanup_complete: bool,
    pub transaction_id: String,
    pub authority: RuntimeAuthorityWitness,
    pub kbs_revocation_generation: i64,
    pub kbs: KbsReconciliationWitness,
    pub targets: Vec<CleanCutTargetStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanCutTargetStatus {
    pub audit_id: i64,
    pub target: RetiredTargetIdentity,
    pub provider_cleanup_state: &'static str,
    pub database_cleanup_state: &'static str,
    pub app_status: Option<String>,
    pub deployment_status: Option<String>,
    pub job_state: Option<String>,
    pub normal_delete_audit_id: Option<i64>,
    pub owned_authority_count: i64,
    pub namespace_state: &'static str,
    pub persistent_storage: Vec<PersistentStorageStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentStorageStatus {
    pub persistent_volume_claim: String,
    pub persistent_volume_claim_uid: Uuid,
    pub persistent_volume: String,
    pub persistent_volume_uid: Uuid,
    pub persistent_volume_claim_state: &'static str,
    pub persistent_volume_state: &'static str,
}

#[derive(Debug, thiserror::Error)]
pub enum CleanCutError {
    #[error("invalid clean-cut plan: {0}")]
    InvalidPlan(String),
    #[error("clean-cut precondition failed: {0}")]
    Precondition(String),
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("Kubernetes error")]
    Kubernetes(#[from] kube::Error),
}

#[derive(Debug, sqlx::FromRow)]
struct DatabaseTarget {
    app_id: Uuid,
    org_id: Uuid,
    app_name: String,
    namespace: String,
    domain: String,
    tee_domain: Option<String>,
    app_status: String,
    deployment_id: Uuid,
    deployment_status: String,
    manifest_hash: Option<String>,
    job_generation: i64,
    payload_version: i32,
    payload_sha256: Vec<u8>,
    job_state: String,
    job_unlocked: bool,
    next_attempt_infinity: bool,
    signed_required: bool,
    artifact_deployment_id: Option<Uuid>,
    artifact_descriptor_core_hash: Option<Vec<u8>>,
    stored_artifact_hash: Option<Vec<u8>>,
    source_deployment_id: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
struct AppLease {
    app_id: Uuid,
    generation: i64,
    owner_token: Uuid,
    operation_kind: String,
    operation_id: Uuid,
    expired: bool,
    quiet: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, sqlx::FromRow)]
struct ResourceLease {
    resource_scope: String,
    resource_key: String,
    generation: i64,
    owner_token: Uuid,
    operation_kind: String,
    operation_id: Uuid,
    expired: bool,
    quiet: bool,
    reclaim_after_infinity: bool,
}

#[derive(Debug)]
struct NamespaceEvidence {
    namespace: String,
    expected_uid: Uuid,
    absent: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, sqlx::FromRow)]
struct StoredDnsRecord {
    id: Uuid,
    app_id: Uuid,
    hostname: String,
    zone_id: Option<String>,
    record_id: Option<String>,
    record_type: String,
    target: String,
    is_custom: bool,
    provider: String,
}

#[derive(Debug, sqlx::FromRow)]
struct RetirementTargetDatabaseRow {
    app_status: Option<String>,
    deployment_status: Option<String>,
    job_state: Option<String>,
    artifact_present: bool,
    dns_count: i64,
}

impl CleanCutPlan {
    pub fn validate(&self) -> Result<(), CleanCutError> {
        if self.version != PLAN_VERSION {
            return Err(CleanCutError::InvalidPlan(format!(
                "version must be {PLAN_VERSION}"
            )));
        }
        if self.expected_restore_generation != 1 {
            return Err(CleanCutError::InvalidPlan(
                "the clean cut is valid only for initial restore-generation adoption 1".into(),
            ));
        }
        if self.quiet_period_seconds < RECLAIM_QUARANTINE_SECONDS {
            return Err(CleanCutError::InvalidPlan(format!(
                "quiet_period_seconds must be at least {RECLAIM_QUARANTINE_SECONDS}"
            )));
        }
        if self.containment.namespace.trim().is_empty()
            || self.containment.deployment_name.trim().is_empty()
            || self.containment.pod_label_selector.trim().is_empty()
            || self.containment.deployment_uid.is_nil()
        {
            return Err(CleanCutError::InvalidPlan(
                "containment identities must be non-empty".into(),
            ));
        }
        if self.targets.is_empty() {
            return Err(CleanCutError::InvalidPlan(
                "at least one exact retirement target is required".into(),
            ));
        }

        let mut apps = BTreeSet::new();
        let mut deployments = BTreeSet::new();
        let mut namespaces = BTreeSet::new();
        let mut token_hashes = BTreeSet::new();
        let mut resources = BTreeSet::new();
        for target in &self.targets {
            if target.app_id.is_nil()
                || target.org_id.is_nil()
                || target.deployment_id.is_nil()
                || target.namespace_uid.is_nil()
                || target.app_name.trim().is_empty()
                || target.namespace.trim().is_empty()
                || target.tenant_label.trim().is_empty()
                || target.domain.trim().is_empty()
                || target.tee_domain.trim().is_empty()
                || target.job_generation <= 0
                || target.payload_version <= 0
                || target.app_lease_generation <= 0
            {
                return Err(CleanCutError::InvalidPlan(
                    "target identities and generations must be complete".into(),
                ));
            }
            for digest in [
                &target.payload_sha256,
                &target.artifact_descriptor_core_hash,
                &target.manifest_hash,
                &target.owner_token_sha256,
            ] {
                validate_sha256(digest)?;
            }
            if !apps.insert(target.app_id)
                || !deployments.insert(target.deployment_id)
                || !namespaces.insert(target.namespace.clone())
                || !token_hashes.insert(target.owner_token_sha256.clone())
            {
                return Err(CleanCutError::InvalidPlan(
                    "app, deployment, namespace, and owner-token hashes must be unique".into(),
                ));
            }
            if target.statefulset.name != target.app_name
                || target.statefulset.uid.is_nil()
                || target.statefulset.mutation_generation <= 0
                || target.statefulset.manifest_hash != target.manifest_hash
            {
                return Err(CleanCutError::InvalidPlan(
                    "StatefulSet identity must exactly bind the target app and manifest".into(),
                ));
            }
            let mut pvc_names = BTreeSet::new();
            for pvc in &target.persistent_volume_claims {
                if pvc.name.trim().is_empty()
                    || pvc.uid.is_nil()
                    || pvc.requested_storage.trim().is_empty()
                    || pvc.volume_name.trim().is_empty()
                    || pvc.persistent_volume_uid.is_nil()
                    || pvc.reclaim_policy != "Delete"
                    || !pvc_names.insert(pvc.name.clone())
                {
                    return Err(CleanCutError::InvalidPlan(
                        "PVC/PV identities must be complete, unique, and reclaimPolicy=Delete"
                            .into(),
                    ));
                }
            }
            if target.persistent_volume_claims.is_empty() {
                return Err(CleanCutError::InvalidPlan(
                    "destructive PVC inventory must be explicit".into(),
                ));
            }
            let mut dns_hostnames = BTreeSet::new();
            for record in &target.dns_records {
                if record.id.is_nil()
                    || record.hostname.trim().is_empty()
                    || record.zone_id.trim().is_empty()
                    || record.record_id.trim().is_empty()
                    || record.record_type.trim().is_empty()
                    || record.target.trim().is_empty()
                    || record.provider != "cloudflare"
                    || record.is_custom
                    || !dns_hostnames.insert(record.hostname.clone())
                {
                    return Err(CleanCutError::InvalidPlan(
                        "managed DNS identities must be complete, Cloudflare-owned, and unique"
                            .into(),
                    ));
                }
            }
            if dns_hostnames != BTreeSet::from([target.domain.clone(), target.tee_domain.clone()]) {
                return Err(CleanCutError::InvalidPlan(
                    "DNS plan must bind exactly the app and TEE hostnames".into(),
                ));
            }
            let mut has_namespace_poison = false;
            for resource in &target.resources {
                if resource.scope.trim().is_empty()
                    || resource.key.trim().is_empty()
                    || resource.generation <= 0
                    || !resources.insert((resource.scope.clone(), resource.key.clone()))
                {
                    return Err(CleanCutError::InvalidPlan(
                        "resource identities must be complete and globally unique".into(),
                    ));
                }
                if resource.scope == "kubernetes_namespace"
                    && resource.key == target.namespace
                    && resource.reclaim_after_infinity
                {
                    has_namespace_poison = true;
                }
            }
            if !has_namespace_poison {
                return Err(CleanCutError::InvalidPlan(format!(
                    "{} does not bind its poisoned namespace resource",
                    target.namespace
                )));
            }
        }
        Ok(())
    }
}

fn validate_sha256(value: &str) -> Result<(), CleanCutError> {
    if value.len() != 64 || hex::decode(value).is_err() {
        return Err(CleanCutError::InvalidPlan(
            "SHA-256 values must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(CleanCutError::InvalidPlan(
            "SHA-256 values must use lowercase hexadecimal".into(),
        ));
    }
    Ok(())
}

/// Hash the 16 RFC 4122 UUID bytes behind an explicit protocol domain.
///
/// Plan producers must compute:
/// `SHA256("enclava-cap-clean-cut-owner-token-v1\\0" || uuid_bytes)`.
/// The plaintext lease token never leaves PostgreSQL.
fn owner_token_sha256(owner_token: Uuid) -> String {
    let mut digest = Sha256::new();
    digest.update(OWNER_TOKEN_HASH_DOMAIN);
    digest.update(owner_token.as_bytes());
    hex::encode(digest.finalize())
}

fn owner_token_matches(owner_token: Uuid, expected_sha256: &str) -> bool {
    owner_token_sha256(owner_token) == expected_sha256
}

pub async fn required_schema_present(pool: &PgPool) -> Result<(), CleanCutError> {
    let version: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(pool)
            .await?;
    if version.unwrap_or_default() < REQUIRED_SCHEMA_VERSION {
        return Err(CleanCutError::Precondition(format!(
            "schema migration {REQUIRED_SCHEMA_VERSION} must be installed before clean-cut retirement"
        )));
    }
    Ok(())
}

pub async fn stored_runtime_authority(pool: &PgPool) -> Result<RuntimeAuthority, CleanCutError> {
    let (epoch, restore_generation): (Uuid, i64) = sqlx::query_as(
        "SELECT authority_epoch, restore_generation
           FROM cap_runtime_authority
          WHERE singleton",
    )
    .fetch_one(pool)
    .await?;
    Ok(RuntimeAuthority {
        epoch,
        restore_generation,
    })
}

pub async fn run(
    pool: &PgPool,
    client: Client,
    plan: &CleanCutPlan,
    plan_sha256: &str,
    execute: bool,
) -> Result<CleanCutResult, CleanCutError> {
    plan.validate()?;
    validate_sha256(plan_sha256)?;
    verify_containment(client.clone(), &plan.containment).await?;

    if let Some(stored) = retirement_status(pool, client.clone(), plan_sha256).await? {
        require_no_owned_workload_authority(pool).await?;
        let expected_targets: BTreeSet<RetiredTargetIdentity> = plan
            .targets
            .iter()
            .map(RetiredTargetIdentity::from)
            .collect();
        let stored_targets: BTreeSet<RetiredTargetIdentity> = stored
            .targets
            .iter()
            .map(|target| target.target.clone())
            .collect();
        if stored_targets != expected_targets {
            return Err(CleanCutError::Precondition(
                "stored clean-cut receipt does not match the reviewed plan".into(),
            ));
        }
        return Ok(CleanCutResult {
            plan_sha256: plan_sha256.to_string(),
            mode: if execute { "execute" } else { "dry-run" },
            status: stored.status,
            target_count: plan.targets.len(),
            namespaces: stored
                .targets
                .iter()
                .map(|status| NamespaceRetirement {
                    namespace: status.target.namespace.clone(),
                    expected_uid: status.target.namespace_uid,
                    state: if status.namespace_state == "absent" {
                        "provider_cleanup_complete"
                    } else {
                        "retained_for_normal_delete"
                    },
                    persistent_volume_claims: status
                        .target
                        .persistent_volume_claims
                        .iter()
                        .map(|pvc| pvc.name.clone())
                        .collect(),
                })
                .collect(),
            planned_pvc_count: plan
                .targets
                .iter()
                .map(|target| target.persistent_volume_claims.len())
                .sum(),
            authority: stored.authority,
            transaction_id: Some(stored.transaction_id),
            kbs_revocation_generation: Some(stored.kbs_revocation_generation),
            receipts: stored
                .targets
                .into_iter()
                .map(|status| {
                    let namespace_generation = status
                        .target
                        .resources
                        .iter()
                        .find(|resource| {
                            resource.scope == "kubernetes_namespace"
                                && resource.key == status.target.namespace
                        })
                        .expect("validated receipt has namespace resource")
                        .generation;
                    TargetRetirementReceipt {
                        audit_id: status.audit_id,
                        app_id: status.target.app_id,
                        deployment_id: status.target.deployment_id,
                        namespace: status.target.namespace,
                        namespace_uid: status.target.namespace_uid,
                        kubernetes_observed_generation: namespace_generation,
                        database_retired_generation: namespace_generation + 1,
                        persistent_volume_claims: status.target.persistent_volume_claims,
                        dns_records: status.target.dns_records,
                        resources: status.target.resources,
                        provider_cleanup_state: status.provider_cleanup_state,
                    }
                })
                .collect(),
            kbs: stored.kbs,
        });
    }

    let namespace_evidence = inspect_namespaces(client.clone(), &plan.targets, false).await?;
    let mut tx = pool.begin().await?;
    set_transaction_timeouts(&mut tx).await?;
    let stored_authority = lock_and_verify_runtime_authority(&mut tx).await?;
    verify_database_authority(&mut tx, plan).await?;

    if !execute {
        let kbs = load_kbs_witness_in_tx(&mut tx).await?;
        tx.rollback().await?;
        return Ok(result_from_evidence(
            plan,
            plan_sha256,
            &namespace_evidence,
            CleanCutResultDetails {
                mode: "dry-run",
                status: "validated",
                authority: authority_witness(stored_authority),
                transaction_id: None,
                kbs_revocation_generation: None,
                receipts: Vec::new(),
                kbs,
            },
        ));
    }

    let authority =
        crate::runtime_authority::establish_epoch_with(&mut tx, plan.expected_restore_generation)
            .await
            .map_err(|error| CleanCutError::Precondition(error.to_string()))?;
    if authority.epoch != stored_authority.epoch {
        return Err(CleanCutError::Precondition(
            "initial authority adoption unexpectedly rotated the epoch".into(),
        ));
    }

    verify_containment(client.clone(), &plan.containment).await?;
    let retained_evidence = inspect_namespaces(client, &plan.targets, false).await?;
    verify_database_authority(&mut tx, plan).await?;

    let (transaction_id, receipts, kbs_revocation_generation, kbs) =
        retire_exact_database_authority(&mut tx, authority, plan, plan_sha256).await?;
    tx.commit().await?;

    Ok(result_from_evidence(
        plan,
        plan_sha256,
        &retained_evidence,
        CleanCutResultDetails {
            mode: "execute",
            status: "authority_retired",
            authority: authority_witness(authority),
            transaction_id: Some(transaction_id),
            kbs_revocation_generation,
            receipts,
            kbs,
        },
    ))
}

async fn require_no_owned_workload_authority(pool: &PgPool) -> Result<(), CleanCutError> {
    let owned: i64 = sqlx::query_scalar(
        "SELECT
             (SELECT count(*) FROM app_mutation_leases WHERE owner_token IS NOT NULL)
           + (SELECT count(*) FROM external_resource_mutation_leases
               WHERE owner_token IS NOT NULL)",
    )
    .fetch_one(pool)
    .await?;
    if owned != 0 {
        return Err(CleanCutError::Precondition(
            "clean-cut replay found newly owned workload authority".into(),
        ));
    }
    Ok(())
}

fn result_from_evidence(
    plan: &CleanCutPlan,
    plan_sha256: &str,
    evidence: &[NamespaceEvidence],
    details: CleanCutResultDetails,
) -> CleanCutResult {
    CleanCutResult {
        plan_sha256: plan_sha256.to_string(),
        mode: details.mode,
        status: details.status,
        target_count: plan.targets.len(),
        namespaces: evidence
            .iter()
            .zip(&plan.targets)
            .map(|(evidence, target)| NamespaceRetirement {
                namespace: evidence.namespace.clone(),
                expected_uid: evidence.expected_uid,
                state: if evidence.absent {
                    "provider_cleanup_complete"
                } else {
                    "retained_for_normal_delete"
                },
                persistent_volume_claims: target
                    .persistent_volume_claims
                    .iter()
                    .map(|pvc| pvc.name.clone())
                    .collect(),
            })
            .collect(),
        planned_pvc_count: plan
            .targets
            .iter()
            .map(|target| target.persistent_volume_claims.len())
            .sum(),
        authority: details.authority,
        transaction_id: details.transaction_id,
        kbs_revocation_generation: details.kbs_revocation_generation,
        receipts: details.receipts,
        kbs: details.kbs,
    }
}

fn authority_witness(authority: RuntimeAuthority) -> RuntimeAuthorityWitness {
    RuntimeAuthorityWitness {
        epoch: authority.epoch,
        restore_generation: authority.restore_generation,
    }
}

async fn verify_containment(
    client: Client,
    containment: &ContainmentPlan,
) -> Result<(), CleanCutError> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), &containment.namespace);
    let deployment = deployments.get(&containment.deployment_name).await?;
    let pod_selector = contained_deployment_pod_selector(&deployment)?;
    let uid = deployment
        .metadata
        .uid
        .as_deref()
        .and_then(|uid| uid.parse::<Uuid>().ok());
    if uid != Some(containment.deployment_uid) {
        return Err(CleanCutError::Precondition(
            "contained CAP Deployment UID does not match the reviewed plan".into(),
        ));
    }
    let desired = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas)
        .unwrap_or(1);
    let status = deployment.status.as_ref();
    let observed = [
        status.and_then(|value| value.replicas).unwrap_or_default(),
        status
            .and_then(|value| value.ready_replicas)
            .unwrap_or_default(),
        status
            .and_then(|value| value.available_replicas)
            .unwrap_or_default(),
        status
            .and_then(|value| value.updated_replicas)
            .unwrap_or_default(),
    ];
    if desired != 0 || observed.into_iter().any(|replicas| replicas != 0) {
        return Err(CleanCutError::Precondition(
            "CAP API/dispatcher Deployment is not fully scaled to zero".into(),
        ));
    }

    let pods: Api<Pod> = Api::namespaced(client, &containment.namespace);
    let active_pods: Vec<String> = pods
        .list(&ListParams::default().labels_from(&pod_selector))
        .await?
        .items
        .into_iter()
        .filter(|pod| {
            !matches!(
                pod.status
                    .as_ref()
                    .and_then(|status| status.phase.as_deref()),
                Some("Succeeded" | "Failed")
            )
        })
        .map(|pod| pod.name_any())
        .collect();
    if !active_pods.is_empty() {
        return Err(CleanCutError::Precondition(format!(
            "CAP API/dispatcher pods are still active: {}",
            active_pods.join(",")
        )));
    }
    Ok(())
}

fn contained_deployment_pod_selector(deployment: &Deployment) -> Result<Selector, CleanCutError> {
    let selector: Selector = deployment
        .spec
        .as_ref()
        .ok_or_else(|| CleanCutError::Precondition("contained CAP Deployment has no spec".into()))?
        .selector
        .clone()
        .try_into()
        .map_err(|error| {
            CleanCutError::Precondition(format!(
                "contained CAP Deployment has an invalid pod selector: {error}"
            ))
        })?;
    if selector.selects_all() {
        return Err(CleanCutError::Precondition(
            "contained CAP Deployment pod selector must not select every pod".into(),
        ));
    }
    Ok(selector)
}

async fn inspect_namespaces(
    client: Client,
    targets: &[CleanCutTarget],
    require_absent: bool,
) -> Result<Vec<NamespaceEvidence>, CleanCutError> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let mut evidence = Vec::with_capacity(targets.len());
    for target in targets {
        let namespace = match namespaces.get(&target.namespace).await {
            Ok(namespace) => namespace,
            Err(kube::Error::Api(error)) if error.code == 404 => {
                inspect_target_persistent_volumes(client.clone(), target, true).await?;
                evidence.push(NamespaceEvidence {
                    namespace: target.namespace.clone(),
                    expected_uid: target.namespace_uid,
                    absent: true,
                });
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if require_absent {
            return Err(CleanCutError::Precondition(format!(
                "namespace {} still exists after exact deletion",
                target.namespace
            )));
        }
        inspect_target_persistent_volumes(client.clone(), target, false).await?;
        let uid = namespace
            .metadata
            .uid
            .as_deref()
            .and_then(|uid| uid.parse::<Uuid>().ok());
        let managed_by = namespace
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get("app.kubernetes.io/managed-by"))
            .map(String::as_str);
        let tenant = namespace
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get("enclava.dev/tenant"))
            .map(String::as_str);
        let mutation_generation = namespace
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION))
            .and_then(|value| value.parse::<i64>().ok());
        let expected_namespace_generation = target.resources.iter().find_map(|resource| {
            (resource.scope == "kubernetes_namespace" && resource.key == target.namespace)
                .then_some(resource.generation)
        });
        if uid != Some(target.namespace_uid)
            || managed_by != Some(CAP_MANAGED_BY_LABEL)
            || tenant != Some(target.tenant_label.as_str())
            || mutation_generation != expected_namespace_generation
        {
            return Err(CleanCutError::Precondition(format!(
                "namespace {} identity, ownership, or mutation generation changed",
                target.namespace
            )));
        }

        let statefulsets: Api<StatefulSet> = Api::namespaced(client.clone(), &target.namespace);
        let observed_statefulsets = statefulsets.list(&ListParams::default()).await?;
        if observed_statefulsets.items.len() != 1 {
            return Err(CleanCutError::Precondition(format!(
                "namespace {} must contain exactly one reviewed StatefulSet",
                target.namespace
            )));
        }
        let statefulset = &observed_statefulsets.items[0];
        let statefulset_uid = statefulset
            .metadata
            .uid
            .as_deref()
            .and_then(|uid| uid.parse::<Uuid>().ok());
        let statefulset_generation = statefulset
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION))
            .and_then(|value| value.parse::<i64>().ok());
        let statefulset_manifest = statefulset
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get("enclava.dev/manifest-hash"))
            .map(String::as_str);
        if statefulset.name_any() != target.statefulset.name
            || statefulset_uid != Some(target.statefulset.uid)
            || statefulset_generation != Some(target.statefulset.mutation_generation)
            || statefulset_manifest != Some(target.statefulset.manifest_hash.as_str())
        {
            return Err(CleanCutError::Precondition(format!(
                "StatefulSet authority changed in namespace {}",
                target.namespace
            )));
        }

        let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &target.namespace);
        let mut observed_pvcs = pvcs
            .list(&ListParams::default())
            .await?
            .items
            .into_iter()
            .map(|pvc| {
                let name = pvc.name_any();
                let uid = pvc
                    .metadata
                    .uid
                    .as_deref()
                    .and_then(|uid| uid.parse::<Uuid>().ok())
                    .ok_or_else(|| {
                        CleanCutError::Precondition(format!("PVC {name} has no valid UID"))
                    })?;
                let requested_storage = pvc
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.resources.as_ref())
                    .and_then(|resources| resources.requests.as_ref())
                    .and_then(|requests| requests.get("storage"))
                    .map(|quantity| quantity.0.clone())
                    .ok_or_else(|| {
                        CleanCutError::Precondition(format!("PVC {name} has no requested storage"))
                    })?;
                let volume_name = pvc
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.volume_name.clone())
                    .ok_or_else(|| {
                        CleanCutError::Precondition(format!("PVC {name} is not bound"))
                    })?;
                let expected = target
                    .persistent_volume_claims
                    .iter()
                    .find(|expected| expected.name == name)
                    .ok_or_else(|| {
                        CleanCutError::Precondition(format!(
                            "PVC {name} is not present in the reviewed plan"
                        ))
                    })?;
                Ok(ExpectedPersistentVolumeClaim {
                    name,
                    uid,
                    requested_storage,
                    volume_name,
                    persistent_volume_uid: expected.persistent_volume_uid,
                    reclaim_policy: expected.reclaim_policy.clone(),
                })
            })
            .collect::<Result<Vec<_>, CleanCutError>>()?;
        observed_pvcs.sort();
        let mut expected_pvcs = target.persistent_volume_claims.clone();
        expected_pvcs.sort();
        if observed_pvcs != expected_pvcs {
            return Err(CleanCutError::Precondition(format!(
                "destructive PVC inventory changed in namespace {}",
                target.namespace
            )));
        }
        evidence.push(NamespaceEvidence {
            namespace: target.namespace.clone(),
            expected_uid: target.namespace_uid,
            absent: false,
        });
    }
    Ok(evidence)
}

async fn inspect_target_persistent_volumes(
    client: Client,
    target: &CleanCutTarget,
    allow_absent: bool,
) -> Result<(), CleanCutError> {
    let volumes: Api<PersistentVolume> = Api::all(client);
    for expected in &target.persistent_volume_claims {
        let volume = match volumes.get(&expected.volume_name).await {
            Ok(volume) => volume,
            Err(kube::Error::Api(error)) if error.code == 404 && allow_absent => continue,
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return Err(CleanCutError::Precondition(format!(
                    "reviewed persistent volume {} is absent before namespace deletion",
                    expected.volume_name
                )));
            }
            Err(error) => return Err(error.into()),
        };
        let uid = volume
            .metadata
            .uid
            .as_deref()
            .and_then(|uid| uid.parse::<Uuid>().ok());
        let spec = volume.spec.as_ref().ok_or_else(|| {
            CleanCutError::Precondition(format!(
                "persistent volume {} has no spec",
                expected.volume_name
            ))
        })?;
        let claim = spec.claim_ref.as_ref();
        if uid != Some(expected.persistent_volume_uid)
            || spec.persistent_volume_reclaim_policy.as_deref()
                != Some(expected.reclaim_policy.as_str())
            || claim.and_then(|claim| claim.namespace.as_deref()) != Some(target.namespace.as_str())
            || claim.and_then(|claim| claim.name.as_deref()) != Some(expected.name.as_str())
            || claim
                .and_then(|claim| claim.uid.as_deref())
                .and_then(|uid| uid.parse::<Uuid>().ok())
                != Some(expected.uid)
        {
            return Err(CleanCutError::Precondition(format!(
                "persistent volume {} identity, claim, or reclaim policy changed",
                expected.volume_name
            )));
        }
    }
    Ok(())
}

async fn set_transaction_timeouts(tx: &mut Transaction<'_, Postgres>) -> Result<(), CleanCutError> {
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '30s'")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn lock_and_verify_runtime_authority(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<RuntimeAuthority, CleanCutError> {
    let observed: (Uuid, i64) = sqlx::query_as(
        "SELECT authority_epoch, restore_generation
           FROM cap_runtime_authority
          WHERE singleton
          FOR UPDATE",
    )
    .fetch_one(&mut **tx)
    .await?;
    if !matches!(observed.1, 0 | 1) {
        return Err(CleanCutError::Precondition(
            "runtime authority is not pre-adoption 0 or initial generation 1".into(),
        ));
    }
    Ok(RuntimeAuthority {
        epoch: observed.0,
        restore_generation: observed.1,
    })
}

async fn verify_database_authority(
    tx: &mut Transaction<'_, Postgres>,
    plan: &CleanCutPlan,
) -> Result<(), CleanCutError> {
    let expected_app_ids: BTreeSet<Uuid> =
        plan.targets.iter().map(|target| target.app_id).collect();
    let expected_deployment_ids: BTreeSet<Uuid> = plan
        .targets
        .iter()
        .map(|target| target.deployment_id)
        .collect();
    let observed_app_ids: BTreeSet<Uuid> =
        sqlx::query_scalar("SELECT id FROM apps ORDER BY id FOR UPDATE")
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .collect();
    let observed_deployment_ids: BTreeSet<Uuid> =
        sqlx::query_scalar("SELECT id FROM deployments ORDER BY id FOR UPDATE")
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .collect();
    let observed_job_ids: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT deployment_id FROM deployment_apply_jobs ORDER BY deployment_id FOR UPDATE",
    )
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect();
    let observed_artifact_ids: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT deploy_id FROM workload_artifacts ORDER BY deploy_id FOR UPDATE",
    )
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect();
    if observed_app_ids != expected_app_ids
        || observed_deployment_ids != expected_deployment_ids
        || observed_job_ids != expected_deployment_ids
        || observed_artifact_ids != expected_deployment_ids
    {
        return Err(CleanCutError::Precondition(
            "the plan is not the complete app/deployment/job/artifact authority set".into(),
        ));
    }

    let observed_dns: BTreeSet<StoredDnsRecord> = sqlx::query_as(
        "SELECT id,
                app_id,
                hostname,
                zone_id,
                record_id,
                record_type,
                target,
                is_custom,
                provider
           FROM dns_records
          ORDER BY hostname
          FOR UPDATE",
    )
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect();
    let expected_dns: BTreeSet<StoredDnsRecord> = plan
        .targets
        .iter()
        .flat_map(|target| {
            target.dns_records.iter().map(|record| StoredDnsRecord {
                id: record.id,
                app_id: target.app_id,
                hostname: record.hostname.clone(),
                zone_id: Some(record.zone_id.clone()),
                record_id: Some(record.record_id.clone()),
                record_type: record.record_type.clone(),
                target: record.target.clone(),
                is_custom: record.is_custom,
                provider: record.provider.clone(),
            })
        })
        .collect();
    if observed_dns != expected_dns {
        return Err(CleanCutError::Precondition(
            "the plan is not the complete exact provider-tracked DNS authority set".into(),
        ));
    }

    let active_owner_binding_app_ids: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT app_id
           FROM kbs_owner_bindings
          WHERE deleted_at IS NULL
          ORDER BY app_id
          FOR UPDATE",
    )
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect();
    let active_tls_binding_app_ids: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT app_id
           FROM kbs_tls_bindings
          WHERE deleted_at IS NULL
          ORDER BY app_id
          FOR UPDATE",
    )
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect();
    let active_legacy_binding_app_ids: BTreeSet<Uuid> = active_owner_binding_app_ids
        .union(&active_tls_binding_app_ids)
        .copied()
        .collect();
    if !active_legacy_binding_app_ids.is_subset(&expected_app_ids) {
        return Err(CleanCutError::Precondition(
            "active legacy KBS authority exists outside the complete clean-cut target set".into(),
        ));
    }

    for target in &plan.targets {
        let observed: DatabaseTarget = sqlx::query_as(
            "SELECT app.id AS app_id,
                    app.org_id,
                    app.name AS app_name,
                    app.namespace,
                    app.domain,
                    app.tee_domain,
                    app.status::text AS app_status,
                    deployment.id AS deployment_id,
                    deployment.status::text AS deployment_status,
                    deployment.manifest_hash,
                    job.generation AS job_generation,
                    job.payload_version,
                    job.payload_sha256,
                    job.state AS job_state,
                    (job.lock_token IS NULL AND job.locked_until IS NULL) AS job_unlocked,
                    (job.next_attempt_at = 'infinity'::timestamptz)
                        AS next_attempt_infinity,
                    job.signed_required,
                    job.artifact_deployment_id,
                    job.artifact_descriptor_core_hash,
                    artifact.descriptor_core_hash AS stored_artifact_hash,
                    job.source_deployment_id
               FROM apps AS app
               JOIN deployments AS deployment
                 ON deployment.app_id = app.id
               JOIN deployment_apply_jobs AS job
                 ON job.deployment_id = deployment.id
                AND job.app_id = app.id
                AND job.org_id = app.org_id
               JOIN workload_artifacts AS artifact
                 ON artifact.deploy_id = job.artifact_deployment_id
                AND artifact.app_id = app.id
              WHERE app.id = $1
                AND deployment.id = $2
              FOR UPDATE OF app, deployment, job, artifact",
        )
        .bind(target.app_id)
        .bind(target.deployment_id)
        .fetch_one(&mut **tx)
        .await?;
        if observed.app_id != target.app_id
            || observed.org_id != target.org_id
            || observed.app_name != target.app_name
            || observed.namespace != target.namespace
            || observed.domain != target.domain
            || observed.tee_domain.as_deref() != Some(target.tee_domain.as_str())
            || observed.app_status != "creating"
            || observed.deployment_id != target.deployment_id
            || observed.deployment_status != "watching"
            || observed.manifest_hash.as_deref() != Some(target.manifest_hash.as_str())
            || observed.job_generation != target.job_generation
            || observed.payload_version != target.payload_version
            || hex::encode(observed.payload_sha256) != target.payload_sha256
            || observed.job_state != "pending"
            || !observed.job_unlocked
            || !observed.next_attempt_infinity
            || !observed.signed_required
            || observed.artifact_deployment_id != Some(target.deployment_id)
            || observed.source_deployment_id != target.deployment_id
            || observed
                .artifact_descriptor_core_hash
                .as_deref()
                .map(hex::encode)
                .as_deref()
                != Some(target.artifact_descriptor_core_hash.as_str())
            || observed
                .stored_artifact_hash
                .as_deref()
                .map(hex::encode)
                .as_deref()
                != Some(target.artifact_descriptor_core_hash.as_str())
        {
            return Err(CleanCutError::Precondition(format!(
                "durable deployment authority changed for {}",
                target.namespace
            )));
        }
    }

    let app_leases: Vec<AppLease> = sqlx::query_as(
        "SELECT app_id,
                generation,
                owner_token,
                operation_kind,
                operation_id,
                locked_until < clock_timestamp() AS expired,
                updated_at <= clock_timestamp()
                    - ($1::bigint * interval '1 second') AS quiet
           FROM app_mutation_leases
          WHERE owner_token IS NOT NULL
          ORDER BY app_id
          FOR UPDATE",
    )
    .bind(plan.quiet_period_seconds)
    .fetch_all(&mut **tx)
    .await?;
    if app_leases.len() != plan.targets.len() {
        return Err(CleanCutError::Precondition(
            "the plan is not the complete owned app-lease set".into(),
        ));
    }
    for target in &plan.targets {
        let Some(lease) = app_leases
            .iter()
            .find(|lease| lease.app_id == target.app_id)
        else {
            return Err(CleanCutError::Precondition(format!(
                "app lease is absent for {}",
                target.namespace
            )));
        };
        if lease.generation != target.app_lease_generation
            || !owner_token_matches(lease.owner_token, &target.owner_token_sha256)
            || lease.operation_kind != "deployment_apply"
            || lease.operation_id != target.deployment_id
            || !lease.expired
            || !lease.quiet
        {
            return Err(CleanCutError::Precondition(format!(
                "app lease changed or is not quiet for {}",
                target.namespace
            )));
        }
    }

    let observed_resources: Vec<ResourceLease> = sqlx::query_as(
        "SELECT resource_scope,
                resource_key,
                generation,
                owner_token,
                operation_kind,
                operation_id,
                locked_until < clock_timestamp() AS expired,
                updated_at <= clock_timestamp()
                    - ($1::bigint * interval '1 second') AS quiet,
                reclaim_after = 'infinity'::timestamptz AS reclaim_after_infinity
           FROM external_resource_mutation_leases
          WHERE owner_token IS NOT NULL
          ORDER BY resource_scope, resource_key
          FOR UPDATE",
    )
    .bind(plan.quiet_period_seconds)
    .fetch_all(&mut **tx)
    .await?;
    let mut expected_resource_count = 0usize;
    for target in &plan.targets {
        for expected in &target.resources {
            expected_resource_count += 1;
            let Some(observed) = observed_resources.iter().find(|observed| {
                observed.resource_scope == expected.scope && observed.resource_key == expected.key
            }) else {
                return Err(CleanCutError::Precondition(format!(
                    "resource lease {}/{} is absent",
                    expected.scope, expected.key
                )));
            };
            if observed.generation != expected.generation
                || !owner_token_matches(observed.owner_token, &target.owner_token_sha256)
                || observed.operation_kind != "deployment_apply"
                || observed.operation_id != target.deployment_id
                || !observed.expired
                || !observed.quiet
                || observed.reclaim_after_infinity != expected.reclaim_after_infinity
            {
                return Err(CleanCutError::Precondition(format!(
                    "resource lease {}/{} changed or is not quiet",
                    expected.scope, expected.key
                )));
            }
        }
    }
    if observed_resources.len() != expected_resource_count {
        return Err(CleanCutError::Precondition(
            "the plan is not the complete owned provider-resource set".into(),
        ));
    }
    Ok(())
}

async fn retire_exact_database_authority(
    tx: &mut Transaction<'_, Postgres>,
    authority: RuntimeAuthority,
    plan: &CleanCutPlan,
    plan_sha256: &str,
) -> Result<
    (
        String,
        Vec<TargetRetirementReceipt>,
        Option<i64>,
        KbsReconciliationWitness,
    ),
    CleanCutError,
> {
    let transaction_id: String = sqlx::query_scalar("SELECT pg_current_xact_id()::text")
        .fetch_one(&mut **tx)
        .await?;
    for target in &plan.targets {
        sqlx::query(
            "UPDATE kbs_owner_bindings
                SET deleted_at = COALESCE(deleted_at, clock_timestamp()),
                    updated_at = clock_timestamp()
              WHERE app_id = $1
                AND deleted_at IS NULL",
        )
        .bind(target.app_id)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE kbs_tls_bindings
                SET deleted_at = COALESCE(deleted_at, clock_timestamp()),
                    updated_at = clock_timestamp()
              WHERE app_id = $1
                AND deleted_at IS NULL",
        )
        .bind(target.app_id)
        .execute(&mut **tx)
        .await?;

        let owner_token: Uuid = sqlx::query_scalar(
            "SELECT owner_token
               FROM app_mutation_leases
              WHERE app_id = $1
                AND generation = $2
                AND owner_token IS NOT NULL
              FOR UPDATE",
        )
        .bind(target.app_id)
        .bind(target.app_lease_generation)
        .fetch_one(&mut **tx)
        .await?;
        if !owner_token_matches(owner_token, &target.owner_token_sha256) {
            return Err(CleanCutError::Precondition(format!(
                "owner-token hash changed for {}",
                target.namespace
            )));
        }
        for resource in &target.resources {
            let retired = sqlx::query(
                "UPDATE external_resource_mutation_leases
                    SET generation = generation + 1,
                        owner_token = NULL,
                        operation_kind = NULL,
                        operation_id = NULL,
                        locked_until = NULL,
                        reclaim_after = NULL,
                        updated_at = clock_timestamp()
                  WHERE resource_scope = $1
                    AND resource_key = $2
                    AND generation = $3
                    AND owner_token = $4
                    AND operation_kind = 'deployment_apply'
                    AND operation_id = $5",
            )
            .bind(&resource.scope)
            .bind(&resource.key)
            .bind(resource.generation)
            .bind(owner_token)
            .bind(target.deployment_id)
            .execute(&mut **tx)
            .await?;
            if retired.rows_affected() != 1 {
                return Err(CleanCutError::Precondition(format!(
                    "lost resource authority for {}/{}",
                    resource.scope, resource.key
                )));
            }
        }

        let retired_app_lease = sqlx::query(
            "UPDATE app_mutation_leases
                SET generation = generation + 1,
                    owner_token = NULL,
                    operation_kind = NULL,
                    operation_id = NULL,
                    locked_until = NULL,
                    reclaim_after = NULL,
                    updated_at = clock_timestamp()
              WHERE app_id = $1
                AND generation = $2
                AND owner_token = $3
                AND operation_kind = 'deployment_apply'
                AND operation_id = $4",
        )
        .bind(target.app_id)
        .bind(target.app_lease_generation)
        .bind(owner_token)
        .bind(target.deployment_id)
        .execute(&mut **tx)
        .await?;
        if retired_app_lease.rows_affected() != 1 {
            return Err(CleanCutError::Precondition(format!(
                "lost app lease authority for {}",
                target.namespace
            )));
        }

        let job = sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'failed',
                    lock_token = NULL,
                    locked_until = NULL,
                    next_attempt_at = clock_timestamp(),
                    last_error_code = 'deployment_superseded',
                    updated_at = clock_timestamp()
              WHERE deployment_id = $1
                AND app_id = $2
                AND org_id = $3
                AND state = 'pending'
                AND lock_token IS NULL
                AND next_attempt_at = 'infinity'::timestamptz",
        )
        .bind(target.deployment_id)
        .bind(target.app_id)
        .bind(target.org_id)
        .execute(&mut **tx)
        .await?;
        let deployment = sqlx::query(
            "UPDATE deployments
                SET status = 'failed'::deploy_status_enum,
                    error_message = 'deployment_superseded',
                    completed_at = clock_timestamp()
              WHERE id = $1
                AND app_id = $2
                AND org_id = $3
                AND status = 'watching'::deploy_status_enum",
        )
        .bind(target.deployment_id)
        .bind(target.app_id)
        .bind(target.org_id)
        .execute(&mut **tx)
        .await?;
        let app = sqlx::query(
            "UPDATE apps
                SET status = 'failed'::app_status_enum,
                    updated_at = clock_timestamp()
              WHERE id = $1
                AND org_id = $2
                AND name = $3
                AND namespace = $4
                AND status = 'creating'::app_status_enum",
        )
        .bind(target.app_id)
        .bind(target.org_id)
        .bind(&target.app_name)
        .bind(&target.namespace)
        .execute(&mut **tx)
        .await?;
        if job.rows_affected() != 1 || deployment.rows_affected() != 1 || app.rows_affected() != 1 {
            return Err(CleanCutError::Precondition(format!(
                "lost terminal publication authority for {}",
                target.namespace
            )));
        }
    }

    let remaining_authority: i64 = sqlx::query_scalar(
        "SELECT
             (SELECT count(*) FROM apps
               WHERE status <> 'failed'::app_status_enum)
           + (SELECT count(*) FROM deployments
               WHERE status <> 'failed'::deploy_status_enum)
           + (SELECT count(*) FROM deployment_apply_jobs
               WHERE state <> 'failed')
           + (SELECT count(*) FROM app_mutation_leases WHERE owner_token IS NOT NULL)
           + (SELECT count(*) FROM external_resource_mutation_leases
               WHERE owner_token IS NOT NULL)
           + (SELECT count(*) FROM kbs_owner_bindings WHERE deleted_at IS NULL)
           + (SELECT count(*) FROM kbs_tls_bindings WHERE deleted_at IS NULL)",
    )
    .fetch_one(&mut **tx)
    .await?;
    if remaining_authority != 0 {
        return Err(CleanCutError::Precondition(
            "clean-cut retirement did not reach terminal, unowned workload authority".into(),
        ));
    }

    // The target terminal states and this revocation intent are committed in
    // one transaction. Startup can never observe the failed apps without also
    // seeing the generation that removes their signed-policy artifacts.
    let kbs_revocation_generation = crate::kbs::enqueue_signed_policy_revocation_if_active(tx)
        .await
        .map_err(|error| CleanCutError::Precondition(error.to_string()))?;
    let kbs = load_kbs_witness_in_tx(tx).await?;
    if kbs_revocation_generation != Some(kbs.desired_generation) {
        return Err(CleanCutError::Precondition(
            "clean-cut KBS revocation generation was not durably witnessed".into(),
        ));
    }

    let target_app_ids: Vec<Uuid> = plan.targets.iter().map(|target| target.app_id).collect();
    let target_deployment_ids: Vec<Uuid> = plan
        .targets
        .iter()
        .map(|target| target.deployment_id)
        .collect();
    let mut receipts = Vec::with_capacity(plan.targets.len());
    for target in &plan.targets {
        let retired_namespace_generation = target
            .resources
            .iter()
            .find_map(|resource| {
                (resource.scope == "kubernetes_namespace" && resource.key == target.namespace)
                    .then_some(resource.generation + 1)
            })
            .ok_or_else(|| {
                CleanCutError::InvalidPlan(format!(
                    "{} has no namespace resource",
                    target.namespace
                ))
            })?;
        let (audit_id,): (i64,) = sqlx::query_as(
            "INSERT INTO audit_log(org_id, app_id, user_id, action, detail)
             VALUES ($1, $2, NULL, 'app.clean_cut_retire', $3)
             RETURNING id",
        )
        .bind(target.org_id)
        .bind(target.app_id)
        .bind(serde_json::json!({
            "plan_sha256": plan_sha256,
            "transaction_id": transaction_id,
            "status": "authority_retired",
            "provider_cleanup_state": "provider_cleanup_pending",
            "target_count": plan.targets.len(),
            "target_app_ids": &target_app_ids,
            "target_deployment_ids": &target_deployment_ids,
            "target": RetiredTargetIdentity::from(target),
            "runtime_authority": {
                "epoch": authority.epoch,
                "restore_generation": authority.restore_generation,
            },
            "kbs_revocation_generation": kbs_revocation_generation,
            "deployment_id": target.deployment_id,
            "namespace": target.namespace,
            "namespace_uid": target.namespace_uid,
            "namespace_retained_for_normal_delete": true,
            "kubernetes_observed_generation": retired_namespace_generation - 1,
            "database_retired_generation": retired_namespace_generation,
            "persistent_volume_claims_retained_for_normal_delete":
                target.persistent_volume_claims,
            "dns_records_retained_for_normal_delete": target.dns_records,
            "retired_resource_leases": target.resources,
            "app_status": "failed",
            "deployment_status": "failed",
            "job_state": "failed",
            "provider_cleanup_required": [
                "dns",
                "edge",
                "kbs",
                "kubernetes_namespace",
                "persistent_volume_claims",
                "persistent_volumes"
            ],
            "kbs": kbs,
        }))
        .fetch_one(&mut **tx)
        .await?;
        receipts.push(TargetRetirementReceipt {
            audit_id,
            app_id: target.app_id,
            deployment_id: target.deployment_id,
            namespace: target.namespace.clone(),
            namespace_uid: target.namespace_uid,
            kubernetes_observed_generation: retired_namespace_generation - 1,
            database_retired_generation: retired_namespace_generation,
            persistent_volume_claims: target.persistent_volume_claims.clone(),
            dns_records: target.dns_records.clone(),
            resources: target.resources.clone(),
            provider_cleanup_state: "provider_cleanup_pending",
        });
    }

    Ok((transaction_id, receipts, kbs_revocation_generation, kbs))
}

/// Load the durable clean-cut receipt and current provider-cleanup state.
///
/// This function is read-only. A receipt becomes `provider_cleanup_complete`
/// only after the ordinary app DELETE has committed its audit row and database
/// cascade, the exact namespaces/PVCs/PVs are absent, and KBS has converged at
/// or beyond the retirement revocation generation.
pub async fn retirement_status(
    pool: &PgPool,
    client: Client,
    plan_sha256: &str,
) -> Result<Option<CleanCutRetirementStatus>, CleanCutError> {
    validate_sha256(plan_sha256)?;
    let rows: Vec<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT id, detail
           FROM audit_log
          WHERE action = 'app.clean_cut_retire'
            AND detail ->> 'plan_sha256' = $1
          ORDER BY id",
    )
    .bind(plan_sha256)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(None);
    }

    let first = &rows[0].1;
    let target_count = first
        .get("target_count")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            CleanCutError::Precondition("clean-cut receipt has no valid target count".into())
        })?;
    let expected_app_ids = receipt_uuid_set(first, "target_app_ids")?;
    let expected_deployment_ids = receipt_uuid_set(first, "target_deployment_ids")?;
    if target_count == 0
        || rows.len() != target_count
        || expected_app_ids.len() != target_count
        || expected_deployment_ids.len() != target_count
    {
        return Err(CleanCutError::Precondition(
            "clean-cut receipt target set is duplicate or incomplete".into(),
        ));
    }

    let mut transaction_id: Option<String> = None;
    let mut authority: Option<RuntimeAuthorityWitness> = None;
    let mut kbs_revocation_generation: Option<i64> = None;
    let mut observed_app_ids = BTreeSet::new();
    let mut observed_deployment_ids = BTreeSet::new();
    let mut targets = Vec::with_capacity(target_count);

    for (audit_id, detail) in rows {
        if json_has_key(&detail, "owner_token") {
            return Err(CleanCutError::Precondition(
                "clean-cut receipt contains prohibited plaintext authority".into(),
            ));
        }
        if detail.get("status").and_then(serde_json::Value::as_str) != Some("authority_retired")
            || detail
                .get("provider_cleanup_state")
                .and_then(serde_json::Value::as_str)
                != Some("provider_cleanup_pending")
            || detail
                .get("namespace_retained_for_normal_delete")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            || detail.get("app_status").and_then(serde_json::Value::as_str) != Some("failed")
            || detail
                .get("deployment_status")
                .and_then(serde_json::Value::as_str)
                != Some("failed")
            || detail.get("job_state").and_then(serde_json::Value::as_str) != Some("failed")
            || detail
                .get("target_count")
                .and_then(serde_json::Value::as_u64)
                != Some(target_count as u64)
            || receipt_uuid_set(&detail, "target_app_ids")? != expected_app_ids
            || receipt_uuid_set(&detail, "target_deployment_ids")? != expected_deployment_ids
            || receipt_string_set(&detail, "provider_cleanup_required")?
                != BTreeSet::from([
                    "dns".to_string(),
                    "edge".to_string(),
                    "kbs".to_string(),
                    "kubernetes_namespace".to_string(),
                    "persistent_volume_claims".to_string(),
                    "persistent_volumes".to_string(),
                ])
        {
            return Err(CleanCutError::Precondition(
                "clean-cut receipt invariants are inconsistent".into(),
            ));
        }

        let target: RetiredTargetIdentity =
            serde_json::from_value(detail.get("target").cloned().ok_or_else(|| {
                CleanCutError::Precondition("clean-cut receipt has no exact target identity".into())
            })?)
            .map_err(|_| {
                CleanCutError::Precondition("clean-cut receipt target identity is malformed".into())
            })?;
        validate_retired_target_identity(&target)?;
        if !observed_app_ids.insert(target.app_id)
            || !observed_deployment_ids.insert(target.deployment_id)
            || !expected_app_ids.contains(&target.app_id)
            || !expected_deployment_ids.contains(&target.deployment_id)
            || detail
                .get("deployment_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok())
                != Some(target.deployment_id)
            || detail.get("namespace").and_then(serde_json::Value::as_str)
                != Some(target.namespace.as_str())
            || detail
                .get("namespace_uid")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok())
                != Some(target.namespace_uid)
        {
            return Err(CleanCutError::Precondition(
                "clean-cut receipt target bindings are inconsistent".into(),
            ));
        }
        let namespace_generation = target
            .resources
            .iter()
            .find_map(|resource| {
                (resource.scope == "kubernetes_namespace" && resource.key == target.namespace)
                    .then_some(resource.generation)
            })
            .ok_or_else(|| {
                CleanCutError::Precondition(
                    "clean-cut receipt target has no namespace generation".into(),
                )
            })?;
        if detail
            .get("kubernetes_observed_generation")
            .and_then(serde_json::Value::as_i64)
            != Some(namespace_generation)
            || detail
                .get("database_retired_generation")
                .and_then(serde_json::Value::as_i64)
                != Some(namespace_generation + 1)
        {
            return Err(CleanCutError::Precondition(
                "clean-cut receipt namespace generations are inconsistent".into(),
            ));
        }

        let receipt_transaction = detail
            .get("transaction_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CleanCutError::Precondition("clean-cut receipt has no transaction ID".into())
            })?
            .to_string();
        if transaction_id
            .replace(receipt_transaction.clone())
            .is_some_and(|previous| previous != receipt_transaction)
        {
            return Err(CleanCutError::Precondition(
                "clean-cut receipt spans multiple transactions".into(),
            ));
        }
        let receipt_authority: RuntimeAuthorityWitness =
            serde_json::from_value(detail.get("runtime_authority").cloned().ok_or_else(|| {
                CleanCutError::Precondition("clean-cut receipt has no runtime authority".into())
            })?)
            .map_err(|_| {
                CleanCutError::Precondition(
                    "clean-cut receipt runtime authority is malformed".into(),
                )
            })?;
        if authority
            .replace(receipt_authority.clone())
            .is_some_and(|previous| previous != receipt_authority)
        {
            return Err(CleanCutError::Precondition(
                "clean-cut receipt has inconsistent runtime authority".into(),
            ));
        }
        let receipt_kbs_generation = detail
            .get("kbs_revocation_generation")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                CleanCutError::Precondition(
                    "clean-cut receipt has no KBS revocation generation".into(),
                )
            })?;
        if kbs_revocation_generation
            .replace(receipt_kbs_generation)
            .is_some_and(|previous| previous != receipt_kbs_generation)
        {
            return Err(CleanCutError::Precondition(
                "clean-cut receipt has inconsistent KBS generations".into(),
            ));
        }

        let database: RetirementTargetDatabaseRow = sqlx::query_as(
            "SELECT
                 (SELECT status::text FROM apps WHERE id = $1) AS app_status,
                 (SELECT status::text FROM deployments WHERE id = $2) AS deployment_status,
                 (SELECT state FROM deployment_apply_jobs WHERE deployment_id = $2)
                     AS job_state,
                 EXISTS(
                     SELECT 1 FROM workload_artifacts
                      WHERE app_id = $1 AND deploy_id = $2
                 ) AS artifact_present,
                 (SELECT count(*) FROM dns_records WHERE app_id = $1) AS dns_count",
        )
        .bind(target.app_id)
        .bind(target.deployment_id)
        .fetch_one(pool)
        .await?;
        let normal_delete_audit_id: Option<i64> = sqlx::query_scalar::<_, i64>(
            "SELECT id
               FROM audit_log
              WHERE action = 'app.delete'
                AND app_id = $1
                AND id > $2
              ORDER BY id DESC
              LIMIT 1",
        )
        .bind(target.app_id)
        .bind(audit_id)
        .fetch_optional(pool)
        .await?;
        let owned_authority_count = target_owned_authority_count(pool, &target).await?;

        let database_cleanup_state = if database.app_status.as_deref() == Some("failed")
            && database.deployment_status.as_deref() == Some("failed")
            && database.job_state.as_deref() == Some("failed")
            && database.artifact_present
            && database.dns_count == target.dns_records.len() as i64
            && normal_delete_audit_id.is_none()
            && owned_authority_count == 0
        {
            "authority_retired"
        } else if database.app_status.is_none()
            && database.deployment_status.is_none()
            && database.job_state.is_none()
            && !database.artifact_present
            && database.dns_count == 0
            && normal_delete_audit_id.is_some()
            && owned_authority_count == 0
        {
            "removed_by_normal_delete"
        } else if database.app_status.as_deref() == Some("deleting")
            && normal_delete_audit_id.is_none()
        {
            "normal_delete_in_progress"
        } else {
            return Err(CleanCutError::Precondition(format!(
                "clean-cut target {} is outside the retired/delete lifecycle",
                target.app_id
            )));
        };

        let (namespace_state, persistent_storage, provider_objects_absent) =
            provider_object_status(
                client.clone(),
                &target,
                database_cleanup_state == "authority_retired",
            )
            .await?;
        let target_complete =
            database_cleanup_state == "removed_by_normal_delete" && provider_objects_absent;
        targets.push(CleanCutTargetStatus {
            audit_id,
            target,
            provider_cleanup_state: if target_complete {
                "provider_cleanup_complete"
            } else {
                "provider_cleanup_pending"
            },
            database_cleanup_state,
            app_status: database.app_status,
            deployment_status: database.deployment_status,
            job_state: database.job_state,
            normal_delete_audit_id,
            owned_authority_count,
            namespace_state,
            persistent_storage,
        });
    }

    if observed_app_ids != expected_app_ids || observed_deployment_ids != expected_deployment_ids {
        return Err(CleanCutError::Precondition(
            "clean-cut receipt target set is incomplete".into(),
        ));
    }
    let authority = authority.expect("non-empty receipt has authority");
    let stored_authority = authority_witness(stored_runtime_authority(pool).await?);
    if stored_authority != authority {
        return Err(CleanCutError::Precondition(
            "runtime authority no longer matches the clean-cut receipt".into(),
        ));
    }
    let kbs_revocation_generation =
        kbs_revocation_generation.expect("non-empty receipt has KBS generation");
    let kbs = load_kbs_witness(pool).await?;
    let provider_cleanup_complete = targets
        .iter()
        .all(|target| target.provider_cleanup_state == "provider_cleanup_complete")
        && kbs.converged
        && kbs.desired_generation >= kbs_revocation_generation;

    Ok(Some(CleanCutRetirementStatus {
        plan_sha256: plan_sha256.to_string(),
        status: if provider_cleanup_complete {
            "provider_cleanup_complete"
        } else {
            "authority_retired"
        },
        provider_cleanup_complete,
        transaction_id: transaction_id.expect("non-empty receipt has transaction"),
        authority,
        kbs_revocation_generation,
        kbs,
        targets,
    }))
}

fn receipt_uuid_set(
    detail: &serde_json::Value,
    field: &str,
) -> Result<BTreeSet<Uuid>, CleanCutError> {
    serde_json::from_value(
        detail
            .get(field)
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| CleanCutError::Precondition(format!("clean-cut receipt {field} is malformed")))
}

fn receipt_string_set(
    detail: &serde_json::Value,
    field: &str,
) -> Result<BTreeSet<String>, CleanCutError> {
    serde_json::from_value(
        detail
            .get(field)
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| CleanCutError::Precondition(format!("clean-cut receipt {field} is malformed")))
}

fn json_has_key(value: &serde_json::Value, prohibited: &str) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            object.contains_key(prohibited)
                || object.values().any(|value| json_has_key(value, prohibited))
        }
        serde_json::Value::Array(values) => {
            values.iter().any(|value| json_has_key(value, prohibited))
        }
        _ => false,
    }
}

fn validate_retired_target_identity(target: &RetiredTargetIdentity) -> Result<(), CleanCutError> {
    if target.app_id.is_nil()
        || target.org_id.is_nil()
        || target.deployment_id.is_nil()
        || target.namespace_uid.is_nil()
        || target.app_name.trim().is_empty()
        || target.namespace.trim().is_empty()
        || target.tenant_label.trim().is_empty()
        || target.domain.trim().is_empty()
        || target.tee_domain.trim().is_empty()
        || target.job_generation <= 0
        || target.payload_version <= 0
        || target.app_lease_generation <= 0
    {
        return Err(CleanCutError::Precondition(
            "clean-cut receipt target identity is incomplete".into(),
        ));
    }
    for digest in [
        &target.payload_sha256,
        &target.artifact_descriptor_core_hash,
        &target.manifest_hash,
        &target.owner_token_sha256,
    ] {
        validate_sha256(digest).map_err(|_| {
            CleanCutError::Precondition("clean-cut receipt target digest is invalid".into())
        })?;
    }
    if target.statefulset.name != target.app_name
        || target.statefulset.uid.is_nil()
        || target.statefulset.mutation_generation <= 0
        || target.statefulset.manifest_hash != target.manifest_hash
        || target.persistent_volume_claims.is_empty()
    {
        return Err(CleanCutError::Precondition(
            "clean-cut receipt workload identity is invalid".into(),
        ));
    }
    let mut pvc_names = BTreeSet::new();
    for pvc in &target.persistent_volume_claims {
        if pvc.name.trim().is_empty()
            || pvc.uid.is_nil()
            || pvc.requested_storage.trim().is_empty()
            || pvc.volume_name.trim().is_empty()
            || pvc.persistent_volume_uid.is_nil()
            || pvc.reclaim_policy != "Delete"
            || !pvc_names.insert(pvc.name.clone())
        {
            return Err(CleanCutError::Precondition(
                "clean-cut receipt PVC/PV identity is invalid".into(),
            ));
        }
    }
    let dns_hostnames: BTreeSet<&str> = target
        .dns_records
        .iter()
        .map(|record| record.hostname.as_str())
        .collect();
    if target.dns_records.len() != 2
        || dns_hostnames != BTreeSet::from([target.domain.as_str(), target.tee_domain.as_str()])
        || target.dns_records.iter().any(|record| {
            record.id.is_nil()
                || record.zone_id.trim().is_empty()
                || record.record_id.trim().is_empty()
                || record.provider != "cloudflare"
                || record.is_custom
        })
    {
        return Err(CleanCutError::Precondition(
            "clean-cut receipt DNS identity is invalid".into(),
        ));
    }
    let namespace_resources = target
        .resources
        .iter()
        .filter(|resource| {
            resource.scope == "kubernetes_namespace"
                && resource.key == target.namespace
                && resource.generation > 0
                && resource.reclaim_after_infinity
        })
        .count();
    if namespace_resources != 1 {
        return Err(CleanCutError::Precondition(
            "clean-cut receipt namespace authority is invalid".into(),
        ));
    }
    Ok(())
}

async fn target_owned_authority_count(
    pool: &PgPool,
    target: &RetiredTargetIdentity,
) -> Result<i64, CleanCutError> {
    let mut count: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM app_mutation_leases
          WHERE app_id = $1
            AND owner_token IS NOT NULL",
    )
    .bind(target.app_id)
    .fetch_one(pool)
    .await?;
    for resource in &target.resources {
        let resource_count: i64 = sqlx::query_scalar(
            "SELECT count(*)
               FROM external_resource_mutation_leases
              WHERE resource_scope = $1
                AND resource_key = $2
                AND owner_token IS NOT NULL",
        )
        .bind(&resource.scope)
        .bind(&resource.key)
        .fetch_one(pool)
        .await?;
        count += resource_count;
    }
    Ok(count)
}

async fn provider_object_status(
    client: Client,
    target: &RetiredTargetIdentity,
    require_retained_exact: bool,
) -> Result<(&'static str, Vec<PersistentStorageStatus>, bool), CleanCutError> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace_present = match namespaces.get(&target.namespace).await {
        Ok(namespace) => {
            if namespace
                .metadata
                .uid
                .as_deref()
                .and_then(|uid| uid.parse::<Uuid>().ok())
                != Some(target.namespace_uid)
            {
                return Err(CleanCutError::Precondition(format!(
                    "replacement namespace {} occupies retired identity",
                    target.namespace
                )));
            }
            true
        }
        Err(kube::Error::Api(error)) if error.code == 404 => false,
        Err(error) => return Err(error.into()),
    };

    let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &target.namespace);
    let pvs: Api<PersistentVolume> = Api::all(client.clone());
    let mut storage = Vec::with_capacity(target.persistent_volume_claims.len());
    let mut all_absent = !namespace_present;
    for expected in &target.persistent_volume_claims {
        let pvc_present = match pvcs.get(&expected.name).await {
            Ok(pvc) => {
                if pvc
                    .metadata
                    .uid
                    .as_deref()
                    .and_then(|uid| uid.parse::<Uuid>().ok())
                    != Some(expected.uid)
                {
                    return Err(CleanCutError::Precondition(format!(
                        "replacement PVC {}/{} occupies retired identity",
                        target.namespace, expected.name
                    )));
                }
                true
            }
            Err(kube::Error::Api(error)) if error.code == 404 => false,
            Err(error) => return Err(error.into()),
        };
        let pv_present = match pvs.get(&expected.volume_name).await {
            Ok(pv) => {
                if pv
                    .metadata
                    .uid
                    .as_deref()
                    .and_then(|uid| uid.parse::<Uuid>().ok())
                    != Some(expected.persistent_volume_uid)
                {
                    return Err(CleanCutError::Precondition(format!(
                        "replacement PV {} occupies retired identity",
                        expected.volume_name
                    )));
                }
                true
            }
            Err(kube::Error::Api(error)) if error.code == 404 => false,
            Err(error) => return Err(error.into()),
        };
        all_absent &= !pvc_present && !pv_present;
        storage.push(PersistentStorageStatus {
            persistent_volume_claim: expected.name.clone(),
            persistent_volume_claim_uid: expected.uid,
            persistent_volume: expected.volume_name.clone(),
            persistent_volume_uid: expected.persistent_volume_uid,
            persistent_volume_claim_state: if pvc_present {
                "retained_exact"
            } else {
                "absent"
            },
            persistent_volume_state: if pv_present {
                "retained_exact"
            } else {
                "absent"
            },
        });
    }
    if require_retained_exact {
        if !namespace_present
            || storage.iter().any(|item| {
                item.persistent_volume_claim_state != "retained_exact"
                    || item.persistent_volume_state != "retained_exact"
            })
        {
            return Err(CleanCutError::Precondition(format!(
                "retired provider resources for {} changed before normal DELETE",
                target.namespace
            )));
        }
        let exact_target = CleanCutTarget {
            app_id: target.app_id,
            org_id: target.org_id,
            app_name: target.app_name.clone(),
            namespace: target.namespace.clone(),
            namespace_uid: target.namespace_uid,
            tenant_label: target.tenant_label.clone(),
            domain: target.domain.clone(),
            tee_domain: target.tee_domain.clone(),
            deployment_id: target.deployment_id,
            job_generation: target.job_generation,
            payload_version: target.payload_version,
            payload_sha256: target.payload_sha256.clone(),
            artifact_descriptor_core_hash: target.artifact_descriptor_core_hash.clone(),
            manifest_hash: target.manifest_hash.clone(),
            owner_token_sha256: target.owner_token_sha256.clone(),
            app_lease_generation: target.app_lease_generation,
            statefulset: target.statefulset.clone(),
            persistent_volume_claims: target.persistent_volume_claims.clone(),
            dns_records: target.dns_records.clone(),
            resources: target.resources.clone(),
        };
        inspect_namespaces(client, &[exact_target], false).await?;
    }
    Ok((
        if namespace_present {
            "retained_exact"
        } else {
            "absent"
        },
        storage,
        all_absent,
    ))
}

async fn load_kbs_witness(pool: &PgPool) -> Result<KbsReconciliationWitness, CleanCutError> {
    let row: (i64, i64, i64, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT desired_generation,
                configmap_generation,
                applied_generation,
                configmap_policy_sha256,
                applied_policy_sha256
           FROM kbs_signed_policy_reconciliation
          WHERE singleton",
    )
    .fetch_one(pool)
    .await?;
    Ok(kbs_witness(row))
}

async fn load_kbs_witness_in_tx(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<KbsReconciliationWitness, CleanCutError> {
    let row: (i64, i64, i64, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT desired_generation,
                configmap_generation,
                applied_generation,
                configmap_policy_sha256,
                applied_policy_sha256
           FROM kbs_signed_policy_reconciliation
          WHERE singleton
          FOR SHARE",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(kbs_witness(row))
}

fn kbs_witness(row: (i64, i64, i64, Option<Vec<u8>>, Option<Vec<u8>>)) -> KbsReconciliationWitness {
    let (desired, configmap, applied, configmap_hash, applied_hash) = row;
    let converged = desired == configmap
        && configmap == applied
        && configmap_hash.is_some()
        && configmap_hash == applied_hash;
    KbsReconciliationWitness {
        desired_generation: desired,
        configmap_generation: configmap,
        applied_generation: applied,
        configmap_policy_sha256: configmap_hash.map(hex::encode),
        applied_policy_sha256: applied_hash.map(hex::encode),
        converged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn database_test_pool() -> Option<PgPool> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect clean-cut test database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate clean-cut test database");
        Some(pool)
    }

    fn target(namespace: &str, suffix: u128) -> CleanCutTarget {
        let app_id = Uuid::from_u128(suffix + 1);
        let deployment_id = Uuid::from_u128(suffix + 2);
        let owner_token = Uuid::from_u128(suffix + 3);
        CleanCutTarget {
            app_id,
            org_id: Uuid::from_u128(suffix + 4),
            app_name: namespace.trim_start_matches("cap-admin3-").to_string(),
            namespace: namespace.to_string(),
            namespace_uid: Uuid::from_u128(suffix + 5),
            tenant_label: "admin3".into(),
            domain: format!("{namespace}.example.test"),
            tee_domain: format!("{namespace}.tee.example.test"),
            deployment_id,
            job_generation: 1,
            payload_version: 1,
            payload_sha256: "11".repeat(32),
            artifact_descriptor_core_hash: "22".repeat(32),
            manifest_hash: "33".repeat(32),
            owner_token_sha256: owner_token_sha256(owner_token),
            app_lease_generation: 1,
            statefulset: ExpectedStatefulSet {
                name: namespace.trim_start_matches("cap-admin3-").to_string(),
                uid: Uuid::from_u128(suffix + 6),
                mutation_generation: 1,
                manifest_hash: "33".repeat(32),
            },
            persistent_volume_claims: vec![ExpectedPersistentVolumeClaim {
                name: format!("state-{}-0", namespace.trim_start_matches("cap-admin3-")),
                uid: Uuid::from_u128(suffix + 7),
                requested_storage: "10Gi".into(),
                volume_name: format!("pvc-{}", Uuid::from_u128(suffix + 7)),
                persistent_volume_uid: Uuid::from_u128(suffix + 8),
                reclaim_policy: "Delete".into(),
            }],
            dns_records: vec![
                ExpectedDnsRecord {
                    id: Uuid::from_u128(suffix + 9),
                    hostname: format!("{namespace}.example.test"),
                    zone_id: "zone".into(),
                    record_id: format!("record-{suffix}-app"),
                    record_type: "A".into(),
                    target: "192.0.2.1".into(),
                    is_custom: false,
                    provider: "cloudflare".into(),
                },
                ExpectedDnsRecord {
                    id: Uuid::from_u128(suffix + 10),
                    hostname: format!("{namespace}.tee.example.test"),
                    zone_id: "zone".into(),
                    record_id: format!("record-{suffix}-tee"),
                    record_type: "A".into(),
                    target: "192.0.2.1".into(),
                    is_custom: false,
                    provider: "cloudflare".into(),
                },
            ],
            resources: vec![ExpectedResourceLease {
                scope: "kubernetes_namespace".into(),
                key: namespace.into(),
                generation: 1,
                reclaim_after_infinity: true,
            }],
        }
    }

    fn plan() -> CleanCutPlan {
        CleanCutPlan {
            version: PLAN_VERSION,
            expected_restore_generation: 1,
            quiet_period_seconds: RECLAIM_QUARANTINE_SECONDS,
            containment: ContainmentPlan {
                namespace: "control".into(),
                deployment_name: "cap-api".into(),
                deployment_uid: Uuid::from_u128(100),
                pod_label_selector: "app.kubernetes.io/name=cap-api".into(),
            },
            targets: vec![
                target("cap-admin3-smoke2", 200),
                target("cap-admin3-smoke3", 300),
            ],
        }
    }

    #[test]
    fn containment_derives_a_nonempty_pod_selector_from_the_deployment() {
        let deployment = Deployment {
            spec: Some(k8s_openapi::api::apps::v1::DeploymentSpec {
                selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                    match_labels: Some(std::collections::BTreeMap::from([
                        ("app".to_string(), "enclava-api".to_string()),
                        ("component".to_string(), "control-plane".to_string()),
                    ])),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let selector =
            contained_deployment_pod_selector(&deployment).expect("derive Deployment selector");
        assert_eq!(
            selector.to_string(),
            "app=enclava-api,component=control-plane"
        );

        let select_all = Deployment {
            spec: Some(Default::default()),
            ..Default::default()
        };
        assert!(matches!(
            contained_deployment_pod_selector(&select_all),
            Err(CleanCutError::Precondition(_))
        ));
    }

    #[test]
    fn exact_clean_cut_plan_requires_full_quarantine_and_poisoned_namespace() {
        let mut value = plan();
        value.validate().expect("valid exact plan");

        value.quiet_period_seconds = RECLAIM_QUARANTINE_SECONDS - 1;
        assert!(matches!(
            value.validate(),
            Err(CleanCutError::InvalidPlan(_))
        ));

        value.quiet_period_seconds = RECLAIM_QUARANTINE_SECONDS;
        value.targets[0].resources[0].reclaim_after_infinity = false;
        assert!(matches!(
            value.validate(),
            Err(CleanCutError::InvalidPlan(_))
        ));
    }

    #[test]
    fn exact_clean_cut_plan_rejects_duplicate_global_authority() {
        let mut value = plan();
        value.targets[1].resources[0] = value.targets[0].resources[0].clone();
        assert!(matches!(
            value.validate(),
            Err(CleanCutError::InvalidPlan(_))
        ));
    }

    #[test]
    fn owner_token_hash_is_domain_separated_and_mismatch_fails_closed() {
        let token = Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        let expected = owner_token_sha256(token);

        assert_eq!(expected.len(), 64);
        assert!(expected.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(owner_token_matches(token, &expected));
        assert!(!owner_token_matches(
            Uuid::from_u128(0x00112233445566778899aabbccddee00),
            &expected
        ));

        let mut undomained = Sha256::new();
        undomained.update(token.as_bytes());
        assert_ne!(expected, hex::encode(undomained.finalize()));
    }

    #[test]
    fn reviewed_plan_and_receipt_identity_never_serialize_plaintext_owner_token() {
        let value = serde_json::to_value(plan()).expect("serialize exact plan");
        assert!(!json_has_key(&value, "owner_token"));
        assert!(json_has_key(&value, "owner_token_sha256"));

        let receipt = serde_json::to_value(RetiredTargetIdentity::from(&plan().targets[0]))
            .expect("serialize receipt target");
        assert!(!json_has_key(&receipt, "owner_token"));
        assert!(json_has_key(&receipt, "owner_token_sha256"));
    }

    #[test]
    fn retirement_execute_path_has_no_provider_delete_primitive() {
        let source = include_str!("clean_cut.rs");
        let execute_path = source
            .split("pub async fn run")
            .nth(1)
            .and_then(|source| source.split("fn result_from_evidence").next())
            .expect("clean-cut run implementation remains explicit");

        assert!(execute_path.contains("inspect_namespaces"));
        assert!(execute_path.contains("retire_exact_database_authority"));
        assert!(!execute_path.contains(".delete("));
        assert!(!execute_path.contains("DeleteParams"));
        assert!(!execute_path.contains("delete_exact_namespace"));
        assert!(!execute_path.contains("wait_exact_persistent_volumes_absent"));
    }

    #[test]
    fn migration_and_retirement_binaries_are_shipped_in_every_image_profile() {
        let dockerfile = include_str!("../Dockerfile");
        for binary in ["enclava-api", "cap-clean-cut-retire", "cap-migrate"] {
            assert!(
                dockerfile.matches(&format!("--bin {binary}")).count() >= 2,
                "{binary} must be built in debug and release profiles"
            );
            assert!(
                dockerfile
                    .matches(&format!("/usr/local/bin/{binary}"))
                    .count()
                    >= 4,
                "{binary} must be copied and permissioned in both runtime images"
            );
        }

        let migrator = include_str!("bin/cap_migrate.rs");
        assert!(migrator.contains("run_migrations"));
        assert!(!migrator.contains("establish_epoch"));
        assert!(!migrator.contains("clean_cut::run"));
        for source in [migrator, include_str!("bin/cap_clean_cut_retire.rs")] {
            assert!(
                source.contains("install_default_rustls_crypto_provider();"),
                "one-shot binaries must choose a rustls provider before TLS clients are built"
            );
        }
    }

    #[test]
    fn receipt_route_is_internal_authenticated_and_read_only() {
        let router = include_str!("lib.rs");
        assert!(router.contains(
            "\"/internal/paas/clean-cut-retirements/{plan_sha256}\",\n            \
             axum::routing::get(routes::internal::get_clean_cut_retirement)"
        ));

        let routes = include_str!("routes/internal.rs");
        let handler = routes
            .split("pub async fn get_clean_cut_retirement")
            .nth(1)
            .and_then(|source| {
                source
                    .split("#[derive(Debug, Serialize, Deserialize)]")
                    .next()
            })
            .expect("clean-cut receipt handler remains explicit");
        assert!(handler.contains("_auth: InternalAuth"));
        assert!(handler.contains("retirement_status"));
        for mutation in [".post(", ".put(", ".patch(", ".delete("] {
            assert!(
                !handler.contains(mutation),
                "receipt handler must remain read-only: {mutation}"
            );
        }
    }

    #[tokio::test]
    async fn database_retirement_is_atomic_redacted_and_hash_fenced() {
        let Some(pool) = database_test_pool().await else {
            return;
        };
        let value = plan();
        let target = &value.targets[0];
        let owner_token = Uuid::from_u128(203);
        let mut tx = pool.begin().await.expect("begin clean-cut fixture");
        sqlx::query(
            "INSERT INTO organizations(id, name, cust_slug)
             VALUES ($1, $2, $3)",
        )
        .bind(target.org_id)
        .bind(format!("clean-cut-{}", target.org_id))
        .bind("deadbeef")
        .execute(&mut *tx)
        .await
        .expect("insert clean-cut organization");
        sqlx::query(
            "INSERT INTO apps(
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, unlock_mode, domain, tee_domain,
                 status, egress_allowlist, egress_mode
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, 'auto'::unlock_enum,
                 $10, $11, 'creating'::app_status_enum, '[]'::jsonb, 'restricted'
             )",
        )
        .bind(target.app_id)
        .bind(target.org_id)
        .bind(&target.app_name)
        .bind(&target.namespace)
        .bind(format!("instance-{}", target.app_id))
        .bind(&target.tenant_label)
        .bind(format!("{}-sa", target.app_name))
        .bind("44".repeat(32))
        .bind("55".repeat(32))
        .bind(&target.domain)
        .bind(&target.tee_domain)
        .execute(&mut *tx)
        .await
        .expect("insert clean-cut app");
        sqlx::query(
            "INSERT INTO kbs_owner_bindings(
                 app_id, binding_key, namespace, service_account,
                 tenant_instance_identity_hash
             ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(target.app_id)
        .bind(format!("clean-cut-owner-{}", target.app_id))
        .bind(&target.namespace)
        .bind(format!("{}-sa", target.app_name))
        .bind("55".repeat(32))
        .execute(&mut *tx)
        .await
        .expect("insert target legacy KBS owner binding");
        sqlx::query(
            "INSERT INTO kbs_tls_bindings(
                 app_id, binding_key, namespace, service_account,
                 tenant_instance_identity_hash
             ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(target.app_id)
        .bind(format!("clean-cut-tls-{}", target.app_id))
        .bind(&target.namespace)
        .bind(format!("{}-sa", target.app_name))
        .bind("55".repeat(32))
        .execute(&mut *tx)
        .await
        .expect("insert target legacy KBS TLS binding");
        sqlx::query(
            "INSERT INTO deployments(
                 id, org_id, app_id, trigger, status, spec_snapshot,
                 manifest_hash, image_digest
             ) VALUES (
                 $1, $2, $3, 'api'::trigger_enum, 'watching'::deploy_status_enum,
                 '{}'::jsonb, $4, $5
             )",
        )
        .bind(target.deployment_id)
        .bind(target.org_id)
        .bind(target.app_id)
        .bind(&target.manifest_hash)
        .bind(format!("sha256:{}", "66".repeat(32)))
        .execute(&mut *tx)
        .await
        .expect("insert clean-cut deployment");
        sqlx::query(
            "INSERT INTO workload_artifacts(
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             ) VALUES (
                 $1, $2, $3, '{}'::jsonb, $4, 'clean-cut-test',
                 '{}'::jsonb, $5, '{}'::jsonb
             )",
        )
        .bind(
            hex::decode(&target.artifact_descriptor_core_hash)
                .expect("decode artifact descriptor hash"),
        )
        .bind(target.app_id)
        .bind(target.deployment_id)
        .bind(vec![0_u8; 64])
        .bind(vec![0_u8; 64])
        .execute(&mut *tx)
        .await
        .expect("insert clean-cut artifact");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs(
                 deployment_id, generation, app_id, org_id,
                 source_deployment_id, payload_version, payload,
                 payload_sha256, cleanup_app_on_setup_failure,
                 signed_required, artifact_deployment_id,
                 artifact_descriptor_core_hash, log_encryption, state,
                 next_attempt_at
             ) OVERRIDING SYSTEM VALUE VALUES (
                 $1, $2, $3, $4, $1, $5,
                 jsonb_build_object('version', $5, 'log_encryption', NULL),
                 $6, false, true, $1, $7, NULL, 'pending', 'infinity'
             )",
        )
        .bind(target.deployment_id)
        .bind(target.job_generation)
        .bind(target.app_id)
        .bind(target.org_id)
        .bind(target.payload_version)
        .bind(hex::decode(&target.payload_sha256).expect("decode payload hash"))
        .bind(hex::decode(&target.artifact_descriptor_core_hash).expect("decode job artifact hash"))
        .execute(&mut *tx)
        .await
        .expect("insert clean-cut apply job");
        for record in &target.dns_records {
            sqlx::query(
                "INSERT INTO dns_records(
                     id, app_id, hostname, zone_id, record_id, record_type,
                     target, is_custom, provider
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(record.id)
            .bind(target.app_id)
            .bind(&record.hostname)
            .bind(&record.zone_id)
            .bind(&record.record_id)
            .bind(&record.record_type)
            .bind(&record.target)
            .bind(record.is_custom)
            .bind(&record.provider)
            .execute(&mut *tx)
            .await
            .expect("insert clean-cut DNS record");
        }
        sqlx::query(
            "INSERT INTO app_mutation_leases(
                 app_id, generation, owner_token, operation_kind, operation_id,
                 locked_until, reclaim_after, updated_at
             ) VALUES (
                 $1, $2, $3, 'deployment_apply', $4,
                 clock_timestamp() - interval '20 minutes', 'infinity',
                 clock_timestamp() - interval '20 minutes'
             )",
        )
        .bind(target.app_id)
        .bind(target.app_lease_generation)
        .bind(owner_token)
        .bind(target.deployment_id)
        .execute(&mut *tx)
        .await
        .expect("insert clean-cut app lease");
        for resource in &target.resources {
            sqlx::query(
                "INSERT INTO external_resource_mutation_leases(
                     resource_scope, resource_key, generation, owner_token,
                     operation_kind, operation_id, locked_until, reclaim_after,
                     updated_at
                 ) VALUES (
                     $1, $2, $3, $4, 'deployment_apply', $5,
                     clock_timestamp() - interval '20 minutes',
                     CASE WHEN $6 THEN 'infinity'::timestamptz
                          ELSE clock_timestamp() - interval '10 minutes' END,
                     clock_timestamp() - interval '20 minutes'
                 )",
            )
            .bind(&resource.scope)
            .bind(&resource.key)
            .bind(resource.generation)
            .bind(owner_token)
            .bind(target.deployment_id)
            .bind(resource.reclaim_after_infinity)
            .execute(&mut *tx)
            .await
            .expect("insert clean-cut resource lease");
        }

        let single_target_plan = CleanCutPlan {
            targets: vec![target.clone()],
            ..value.clone()
        };
        let mut wrong_hash_plan = single_target_plan.clone();
        wrong_hash_plan.targets[0].owner_token_sha256 = "00".repeat(32);
        let mismatch = verify_database_authority(&mut tx, &wrong_hash_plan)
            .await
            .expect_err("wrong owner-token hash must fail closed");
        assert!(
            matches!(mismatch, CleanCutError::Precondition(_)),
            "unexpected mismatch error: {mismatch:?}"
        );
        verify_database_authority(&mut tx, &single_target_plan)
            .await
            .expect("exact clean-cut database authority validates");

        let (epoch, restore_generation): (Uuid, i64) = sqlx::query_as(
            "SELECT authority_epoch, restore_generation
               FROM cap_runtime_authority
              WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("load clean-cut runtime authority");
        let authority = RuntimeAuthority {
            epoch,
            restore_generation,
        };
        let plan_sha256 = "77".repeat(32);
        let (_, receipts, kbs_generation, _) =
            retire_exact_database_authority(&mut tx, authority, &single_target_plan, &plan_sha256)
                .await
                .expect("retire exact clean-cut database authority");
        assert_eq!(receipts.len(), 1);
        assert!(kbs_generation.is_some());

        let terminal: (String, String, String, bool, bool) = sqlx::query_as(
            "SELECT app.status::text, deployment.status::text, job.state,
                    app_lease.owner_token IS NULL,
                    resource_lease.owner_token IS NULL
               FROM apps AS app
               JOIN deployments AS deployment ON deployment.app_id = app.id
               JOIN deployment_apply_jobs AS job
                 ON job.deployment_id = deployment.id
               JOIN app_mutation_leases AS app_lease
                 ON app_lease.app_id = app.id
               JOIN external_resource_mutation_leases AS resource_lease
                 ON resource_lease.operation_id IS NULL
                AND resource_lease.resource_scope = 'kubernetes_namespace'
                AND resource_lease.resource_key = app.namespace
              WHERE app.id = $1",
        )
        .bind(target.app_id)
        .fetch_one(&mut *tx)
        .await
        .expect("load terminal clean-cut state");
        assert_eq!(
            terminal,
            (
                "failed".into(),
                "failed".into(),
                "failed".into(),
                true,
                true
            )
        );
        let legacy_kbs_retired: (bool, bool) = sqlx::query_as(
            "SELECT
                 (SELECT deleted_at IS NOT NULL
                    FROM kbs_owner_bindings
                   WHERE app_id = $1),
                 (SELECT deleted_at IS NOT NULL
                    FROM kbs_tls_bindings
                   WHERE app_id = $1)",
        )
        .bind(target.app_id)
        .fetch_one(&mut *tx)
        .await
        .expect("load retired legacy KBS bindings");
        assert_eq!(
            legacy_kbs_retired,
            (true, true),
            "clean-cut must retire legacy Trustee authority atomically"
        );
        let audit: serde_json::Value = sqlx::query_scalar(
            "SELECT detail
               FROM audit_log
              WHERE action = 'app.clean_cut_retire'
                AND detail ->> 'plan_sha256' = $1",
        )
        .bind(&plan_sha256)
        .fetch_one(&mut *tx)
        .await
        .expect("load clean-cut audit");
        assert_eq!(
            audit
                .get("provider_cleanup_state")
                .and_then(serde_json::Value::as_str),
            Some("provider_cleanup_pending")
        );
        assert!(!json_has_key(&audit, "owner_token"));
        assert!(json_has_key(&audit, "owner_token_sha256"));

        tx.rollback().await.expect("rollback clean-cut fixture");
    }
}
