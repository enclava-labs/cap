//! Resume an in-flight template deploy instead of signing a second one.
//!
//! `template deploy` derives its `Idempotency-Key` from the signed blobs. Those
//! blobs embed a fresh `deploy_id` and `created_at` on every signing, so a
//! retry of an interrupted deploy used to POST a new key and race the
//! deployment already in flight (cap#292). The hold budget is already
//! normalized so a retry *can* keep one key; this module is what actually
//! keeps the signed request byte-stable until that deployment is terminal.
//!
//! A fresh deploy id remains correct once the previous deployment has reached
//! a terminal status — an intentional redeploy, or a retry after a definitive
//! rejection, must not replay the old operation.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::api_client::template_instance_idempotency_key;
use crate::api_types::CreateTemplateInstanceRequest;
use crate::config::{self, CliPaths};

const STORED_ATTEMPT_VERSION: u32 = 1;

/// Settings that identify "the same template deploy command". The signed blobs
/// are deliberately not part of this: they are the volatile half the retry
/// must reuse, not a reason to start over.
#[derive(Debug, Clone, PartialEq)]
pub struct StableTemplateDeployInputs {
    pub template_slug: String,
    pub instance_name: String,
    pub config: serde_json::Value,
    pub bootstrap_pubkey_hash: Option<String>,
}

/// One row from `GET /apps/{name}/deployments`.
///
/// `reconciled_status` is the stored row status. `status` may be a projection
/// (`stale`, `partial`, …) that does not mean the rollout is still live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedTemplateDeployment {
    pub id: String,
    pub status: String,
    pub reconciled_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentListing {
    Listed(Vec<ObservedTemplateDeployment>),
    /// The list call failed. Do not treat that as "nothing is in flight".
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadedTemplateDeployAttempt {
    Absent,
    /// A file exists but cannot be trusted (corrupt, wrong version, wrong app).
    Unreadable,
    Ready(Box<StoredTemplateDeployAttempt>),
}

/// What this run should POST.
#[derive(Debug)]
pub enum TemplateDeployAttempt {
    /// No in-flight deployment to resume. Sign a new descriptor.
    Fresh,
    /// Re-POST this exact request so the idempotency key hits the in-flight operation.
    Replay {
        request: CreateTemplateInstanceRequest,
        deploy_id: String,
    },
    /// A second signed request would race an in-flight deployment. Do not POST.
    Refuse(String),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredTemplateDeployAttempt {
    version: u32,
    scope: String,
    app_id: String,
    deploy_id: String,
    template_slug: String,
    instance_name: String,
    config: serde_json::Value,
    bootstrap_pubkey_hash: Option<String>,
    customer_descriptor_blob: String,
    org_keyring_blob: String,
    signed_policy_artifact: String,
    customer_config_roll_hold_seconds: Option<u32>,
    /// Set only after this command finished. A later list outage must not
    /// replay a finished request into a new server generation.
    #[serde(default)]
    completed: bool,
}

impl StoredTemplateDeployAttempt {
    pub fn deploy_id(&self) -> &str {
        &self.deploy_id
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    fn matches_inputs(&self, stable: &StableTemplateDeployInputs) -> bool {
        self.template_slug == stable.template_slug
            && self.instance_name == stable.instance_name
            && self.config == stable.config
            && self.bootstrap_pubkey_hash == stable.bootstrap_pubkey_hash
    }

    fn into_request(self) -> CreateTemplateInstanceRequest {
        CreateTemplateInstanceRequest {
            template_slug: self.template_slug,
            instance_name: self.instance_name,
            config: self.config,
            bootstrap_pubkey_hash: self.bootstrap_pubkey_hash,
            customer_descriptor_blob: Some(self.customer_descriptor_blob),
            org_keyring_blob: Some(self.org_keyring_blob),
            signed_policy_artifact: Some(self.signed_policy_artifact),
            customer_config_roll_hold_seconds: self.customer_config_roll_hold_seconds,
        }
    }
}

/// Scope the on-disk attempt so two orgs (or two API origins) cannot resume
/// each other's signed request for the same app name.
pub fn template_deploy_scope(
    active_org_id: Option<&str>,
    config_org_id: Option<&str>,
    active_org_name: Option<&str>,
    api_origin: &str,
) -> String {
    let org = [active_org_id, config_org_id, active_org_name]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or("unknown");
    // Origin is always part of the scope: two API URLs can share an org id.
    format!("org:{org}\norigin:{api_origin}")
}

pub fn select_template_deploy_attempt(
    loaded: LoadedTemplateDeployAttempt,
    stable: &StableTemplateDeployInputs,
    current_app_id: &str,
    deployments: &DeploymentListing,
) -> TemplateDeployAttempt {
    let unreadable = matches!(loaded, LoadedTemplateDeployAttempt::Unreadable);
    let usable = match loaded {
        LoadedTemplateDeployAttempt::Ready(stored)
            if stored.app_id == current_app_id && stored.instance_name == stable.instance_name =>
        {
            Some(stored)
        }
        _ => None,
    };

    let Some(rows) = listed_rows(deployments) else {
        return attempt_without_listing(usable, unreadable, stable);
    };

    let inflight: Vec<&ObservedTemplateDeployment> = rows
        .iter()
        .filter(|deployment| deployment_is_in_flight(deployment))
        .collect();
    let cached_terminal = usable.as_ref().is_some_and(|stored| {
        rows.iter().any(|deployment| {
            deployment.id == stored.deploy_id && deployment_is_terminal(deployment)
        })
    });

    if let Some(stored) = usable {
        if cached_terminal && inflight.is_empty() {
            return TemplateDeployAttempt::Fresh;
        }
        if cached_terminal {
            return TemplateDeployAttempt::Refuse(inflight_refuse_message(
                stable,
                inflight[0],
                "an earlier signed request for this app already finished, and another deployment is still in flight. A new deploy was not started. Wait for the in-flight deployment to finish, or destroy the app, then deploy again.",
            ));
        }
        if stored.matches_inputs(stable) {
            // An in-flight row whose id is not the signed deploy id is a
            // different deployment. Replaying a request the server has never
            // seen would reserve a second one beside it. An empty list can
            // still replay: the row may not be visible yet.
            let ours_visible = inflight
                .iter()
                .any(|deployment| deployment.id == stored.deploy_id);
            if inflight.is_empty() || ours_visible {
                // A finished attempt whose signed id is not a live row must
                // not be replayed: after the server's replay window that key
                // opens a new generation carrying the old deploy id. An
                // unfinished empty list still replays (the row may not be
                // visible yet).
                if stored.completed && !ours_visible {
                    return TemplateDeployAttempt::Fresh;
                }
                let deploy_id = stored.deploy_id.clone();
                return TemplateDeployAttempt::Replay {
                    request: (*stored).into_request(),
                    deploy_id,
                };
            }
            return TemplateDeployAttempt::Refuse(inflight_refuse_message(
                stable,
                inflight[0],
                "its id is not the deployment this machine signed, so the stored request was not sent (that would start a second deployment). Retry this command once the in-flight deployment's id is visible — that resumes it. Destroy the app only if it stays stuck.",
            ));
        }
        if let Some(deployment) = inflight.first().copied() {
            return TemplateDeployAttempt::Refuse(inflight_refuse_message(
                stable,
                deployment,
                "this command's template settings differ from the signed request that started it. Retry the original command to resume that deployment. Destroy the app before changing the template, endpoint, or bootstrap settings.",
            ));
        }
        // Nothing visible is in flight and the stored request does not match
        // this command. The previous POST did not land a live deployment, so
        // signing a new one cannot race it.
        return TemplateDeployAttempt::Fresh;
    }

    if let Some(deployment) = inflight.first().copied() {
        let why = if unreadable {
            "the stored signed request on this machine is unreadable, so it cannot be resumed. A new deployment was not started. Retry from the machine that started it, wait for it to finish, or destroy the app and deploy again."
        } else {
            "this machine does not have the original signed request to resume it. A new deployment was not started. Retry from the machine that started it, wait for it to finish, or destroy the app and deploy again."
        };
        return TemplateDeployAttempt::Refuse(inflight_refuse_message(stable, deployment, why));
    }
    TemplateDeployAttempt::Fresh
}

fn attempt_without_listing(
    usable: Option<Box<StoredTemplateDeployAttempt>>,
    unreadable: bool,
    stable: &StableTemplateDeployInputs,
) -> TemplateDeployAttempt {
    if let Some(stored) = usable {
        if stored.matches_inputs(stable) {
            if stored.completed {
                return TemplateDeployAttempt::Refuse(format!(
                    "the previous template deploy for `{}` already finished on this machine, and deployments could not be listed to confirm it is safe to start another. A new deployment was not started. Retry when deployment status is available.",
                    stable.instance_name
                ));
            }
            let deploy_id = stored.deploy_id.clone();
            return TemplateDeployAttempt::Replay {
                request: (*stored).into_request(),
                deploy_id,
            };
        }
        return TemplateDeployAttempt::Refuse(format!(
            "could not list deployments for `{}` to confirm the previous template deploy finished, and this command's settings differ from the stored request. Retry the original command to resume it. A new deployment was not started.",
            stable.instance_name
        ));
    }
    if unreadable {
        return TemplateDeployAttempt::Refuse(format!(
            "could not list deployments for `{}`, and the stored template deploy request is unreadable. A new deployment was not started. Retry when deployment status is available, or destroy the app and deploy again.",
            stable.instance_name
        ));
    }
    // No local attempt to resume. A list outage must not block a first deploy.
    TemplateDeployAttempt::Fresh
}

fn listed_rows(deployments: &DeploymentListing) -> Option<&[ObservedTemplateDeployment]> {
    match deployments {
        DeploymentListing::Listed(rows) => Some(rows),
        DeploymentListing::Unavailable => None,
    }
}

fn inflight_refuse_message(
    stable: &StableTemplateDeployInputs,
    deployment: &ObservedTemplateDeployment,
    why: &str,
) -> String {
    format!(
        "a template deployment for `{}` is still in flight ({}); {why}",
        stable.instance_name,
        describe_deployment(deployment),
    )
}

fn describe_deployment(deployment: &ObservedTemplateDeployment) -> String {
    let status = lifecycle_status(deployment);
    if deployment.id.is_empty() {
        format!("status {status}")
    } else {
        format!("deployment {}, status {status}", deployment.id)
    }
}

/// Stored row status when the server sent one; otherwise the projected status.
pub fn lifecycle_status(deployment: &ObservedTemplateDeployment) -> &str {
    deployment
        .reconciled_status
        .as_deref()
        .map(str::trim)
        .filter(|status| !status.is_empty())
        .unwrap_or(deployment.status.as_str())
}

pub fn deployment_is_terminal(deployment: &ObservedTemplateDeployment) -> bool {
    matches!(
        lifecycle_status(deployment),
        "healthy" | "failed" | "rolled_back" | "superseded"
    )
}

/// True only when the row is evidence of a live rollout a second POST would race.
///
/// A projected `stale`/`partial` status with no reconciled row status is not
/// that evidence: a healthy app often looks stale when observation lags, and
/// treating it as in-flight would block an intentional redeploy.
pub fn deployment_is_in_flight(deployment: &ObservedTemplateDeployment) -> bool {
    if deployment_is_terminal(deployment) {
        return false;
    }
    // Allowlist, not "anything that is not terminal". A future stored status
    // this CLI does not know (PaaS today only stores pending/applying/healthy/
    // failed) must not block an intentional redeploy forever.
    matches!(
        lifecycle_status(deployment),
        "pending" | "applying" | "watching" | "creating" | "deploying"
    )
}

/// A consumed template-deploy key must not be replayed: PaaS stores that
/// rejection and serves it again for the replay window. A failed placeholder
/// row has no `cap_deployment_id`, so the next run would otherwise Replay the
/// dead key.
///
/// Retire when the body says the key is consumed (`idempotency_disposition =
/// completed`), or when the code is a terminal rejection PaaS replays even
/// without that stamp. Keep the stored request on `deferred`, and on the
/// pre-handler gates (401, `invalid_cli_session`, `email_not_verified`,
/// `deploy_apps`) even if a confused body also carries a stamp — those are
/// raised before any rejection is recorded. `deploy_blocked` /
/// `entitlement_blocked` retire only when stamped `completed`: a pre-lease
/// 403 must not delete the resume file.
pub fn template_instance_rejection_retires_attempt(error: &crate::api_client::ApiError) -> bool {
    use crate::api_client::ApiError;
    let ApiError::Api {
        status,
        code,
        idempotency_disposition,
        ..
    } = error
    else {
        return false;
    };
    if *status == 401
        || matches!(
            code.as_deref(),
            Some("invalid_cli_session" | "email_not_verified" | "deploy_apps")
        )
    {
        return false;
    }
    match idempotency_disposition.as_deref() {
        Some("completed") => return true,
        Some("deferred") => return false,
        _ => {}
    }
    // The sanitizer rewrites every non-allowlisted code to this bucket,
    // including 403s and 503s that PaaS does not record as a rejection.
    // Retire it only on the statuses `is_permanent_cap_rejection` stores.
    if code.as_deref() == Some("cap_operation_rejected") {
        return unstamped_cap_rejection_is_permanent(*status);
    }
    // No stamp. Only codes PaaS stores and replays as a consumed key.
    // Unknown codes and in-progress conflicts stay. Unstamped
    // `deploy_blocked` / `entitlement_blocked` also stay: those 403s are
    // pre-lease unless the body says `completed`.
    matches!(
        code.as_deref(),
        Some(
            "entitlement_app_limit"
                | "entitlement_app_limit_exceeded"
                | "idempotency_recovery_required"
                | "idempotency_conflict"
                | "idempotency_key_reused"
                | "idempotency_capability_expired"
                | "idempotency_resource_conflict"
                | "hosted_operation_failed_drift"
                | "template_policy_rejected"
                | "deployment_policy_rejected"
                | "signed_artifact_mismatch"
                | "app_name_conflict"
                | "app name already taken in this org"
                | "start the stopped app before deploying"
                | "stale_owner_seed"
        )
    )
}

/// Statuses for which PaaS records an unstamped CAP rejection and replays it.
/// Mirrors `is_permanent_cap_rejection` when the body has no disposition:
/// 400-499, except the pre-lease and retryable statuses.
fn unstamped_cap_rejection_is_permanent(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 401 | 403 | 408 | 425 | 429)
}

/// A 404 is "no deployments" only when this machine has nothing stored.
/// With a stored or unreadable attempt, 404 is not evidence the rollout is
/// absent — current PaaS returns 200 [] for an app with no rows.
pub fn deployment_listing_for_list_error(
    loaded: &LoadedTemplateDeployAttempt,
    status: Option<u16>,
) -> DeploymentListing {
    if status == Some(404) && matches!(loaded, LoadedTemplateDeployAttempt::Absent) {
        return DeploymentListing::Listed(Vec::new());
    }
    DeploymentListing::Unavailable
}

pub fn save_template_deploy_attempt(
    paths: &CliPaths,
    scope: &str,
    app_id: &str,
    deploy_id: &str,
    request: &CreateTemplateInstanceRequest,
) -> Result<(), String> {
    let (customer_descriptor_blob, org_keyring_blob, signed_policy_artifact) = match (
        request.customer_descriptor_blob.as_deref(),
        request.org_keyring_blob.as_deref(),
        request.signed_policy_artifact.as_deref(),
    ) {
        (Some(descriptor), Some(keyring), Some(policy))
            if !descriptor.is_empty() && !keyring.is_empty() && !policy.is_empty() =>
        {
            (descriptor, keyring, policy)
        }
        _ => {
            return Err(
                "refusing to store a template deploy request that is missing signed artifacts"
                    .to_string(),
            );
        }
    };
    let stored = StoredTemplateDeployAttempt {
        version: STORED_ATTEMPT_VERSION,
        scope: scope.to_string(),
        app_id: app_id.to_string(),
        deploy_id: deploy_id.to_string(),
        template_slug: request.template_slug.clone(),
        instance_name: request.instance_name.clone(),
        config: request.config.clone(),
        bootstrap_pubkey_hash: request.bootstrap_pubkey_hash.clone(),
        customer_descriptor_blob: customer_descriptor_blob.to_string(),
        org_keyring_blob: org_keyring_blob.to_string(),
        signed_policy_artifact: signed_policy_artifact.to_string(),
        customer_config_roll_hold_seconds: request.customer_config_roll_hold_seconds,
        completed: false,
    };
    let bytes = serde_json::to_vec(&stored).map_err(|err| err.to_string())?;
    paths.ensure_dirs().map_err(|err| err.to_string())?;
    let path = attempt_path(paths, scope, &request.instance_name);
    config::write_secret_atomic(&path, &bytes).map_err(|err| err.to_string())
}

pub fn load_template_deploy_attempt(
    paths: &CliPaths,
    scope: &str,
    instance_name: &str,
) -> LoadedTemplateDeployAttempt {
    let path = attempt_path(paths, scope, instance_name);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return LoadedTemplateDeployAttempt::Absent;
        }
        Err(_) => return LoadedTemplateDeployAttempt::Unreadable,
    };
    match serde_json::from_slice::<StoredTemplateDeployAttempt>(&bytes) {
        Ok(stored)
            if stored.version == STORED_ATTEMPT_VERSION
                && stored.scope == scope
                && stored.instance_name == instance_name
                && !stored.deploy_id.is_empty()
                && !stored.app_id.is_empty() =>
        {
            LoadedTemplateDeployAttempt::Ready(Box::new(stored))
        }
        _ => LoadedTemplateDeployAttempt::Unreadable,
    }
}

pub fn clear_template_deploy_attempt(
    paths: &CliPaths,
    scope: &str,
    instance_name: &str,
) -> Result<(), String> {
    let path = attempt_path(paths, scope, instance_name);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "could not discard the stored template deploy request at {}: {err}",
            path.display()
        )),
    }
}

/// Remember that this command finished, so a later list outage does not
/// replay the finished request into a new server generation.
pub fn mark_template_deploy_attempt_completed(
    paths: &CliPaths,
    scope: &str,
    instance_name: &str,
) -> Result<(), String> {
    let LoadedTemplateDeployAttempt::Ready(mut stored) =
        load_template_deploy_attempt(paths, scope, instance_name)
    else {
        return Ok(());
    };
    stored.completed = true;
    let bytes = serde_json::to_vec(&stored).map_err(|err| err.to_string())?;
    paths.ensure_dirs().map_err(|err| err.to_string())?;
    config::write_secret_atomic(&attempt_path(paths, scope, instance_name), &bytes)
        .map_err(|err| err.to_string())
}

fn attempt_path(paths: &CliPaths, scope: &str, instance_name: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update((scope.len() as u64).to_be_bytes());
    hasher.update(scope.as_bytes());
    hasher.update((instance_name.len() as u64).to_be_bytes());
    hasher.update(instance_name.as_bytes());
    let digest = hex::encode(hasher.finalize());
    paths
        .sessions_dir
        .join(format!("template-deploy-{}.json", &digest[..32]))
}

/// Same key the CLI sends. Exposed for the resume tests; production signing
/// still goes through `ApiClient::create_template_instance`.
pub fn idempotency_key_for_request(request: &CreateTemplateInstanceRequest) -> String {
    template_instance_idempotency_key(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_client::ApiError;

    fn stable() -> StableTemplateDeployInputs {
        StableTemplateDeployInputs {
            template_slug: "debian-ssh-frp".to_string(),
            instance_name: "shell".to_string(),
            config: serde_json::json!({}),
            bootstrap_pubkey_hash: Some("ab".repeat(32)),
        }
    }

    fn request_from(
        stable: &StableTemplateDeployInputs,
        descriptor: &str,
    ) -> CreateTemplateInstanceRequest {
        CreateTemplateInstanceRequest {
            template_slug: stable.template_slug.clone(),
            instance_name: stable.instance_name.clone(),
            config: stable.config.clone(),
            bootstrap_pubkey_hash: stable.bootstrap_pubkey_hash.clone(),
            customer_descriptor_blob: Some(descriptor.to_string()),
            org_keyring_blob: Some("keyring-a".to_string()),
            signed_policy_artifact: Some("policy-a".to_string()),
            customer_config_roll_hold_seconds: Some(600),
        }
    }

    fn stored(stable: &StableTemplateDeployInputs, deploy_id: &str) -> StoredTemplateDeployAttempt {
        let request = request_from(stable, "descriptor-a");
        StoredTemplateDeployAttempt {
            version: STORED_ATTEMPT_VERSION,
            scope: "org:org-1".to_string(),
            app_id: "app-uuid".to_string(),
            deploy_id: deploy_id.to_string(),
            template_slug: request.template_slug,
            instance_name: request.instance_name,
            config: request.config,
            bootstrap_pubkey_hash: request.bootstrap_pubkey_hash,
            customer_descriptor_blob: request.customer_descriptor_blob.unwrap(),
            org_keyring_blob: request.org_keyring_blob.unwrap(),
            signed_policy_artifact: request.signed_policy_artifact.unwrap(),
            customer_config_roll_hold_seconds: request.customer_config_roll_hold_seconds,
            completed: false,
        }
    }

    fn row(id: &str, status: &str, reconciled: Option<&str>) -> ObservedTemplateDeployment {
        ObservedTemplateDeployment {
            id: id.to_string(),
            status: status.to_string(),
            reconciled_status: reconciled.map(str::to_string),
        }
    }

    fn listed(rows: Vec<ObservedTemplateDeployment>) -> DeploymentListing {
        DeploymentListing::Listed(rows)
    }

    #[test]
    fn in_flight_retry_reuses_the_signed_request_and_its_idempotency_key() {
        let stable = stable();
        let stored = stored(&stable, "deploy-1");
        let original = stored.clone().into_request();
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            "app-uuid",
            &listed(vec![row("deploy-1", "applying", Some("applying"))]),
        );
        let TemplateDeployAttempt::Replay { request, deploy_id } = attempt else {
            panic!("in-flight retry must replay the stored request, not sign a new one");
        };
        assert_eq!(deploy_id, "deploy-1");
        assert_eq!(
            idempotency_key_for_request(&request),
            idempotency_key_for_request(&original),
            "replay must keep the idempotency key of the in-flight request"
        );
        let mut resigned = original.clone();
        resigned.customer_descriptor_blob = Some("descriptor-b".to_string());
        assert_ne!(
            idempotency_key_for_request(&original),
            idempotency_key_for_request(&resigned),
            "a freshly signed descriptor must not collide with the in-flight key"
        );
    }

    #[test]
    fn retry_before_any_deployment_row_is_visible_still_reuses_the_request() {
        let stable = stable();
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            "app-uuid",
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Replay { .. }));
    }

    #[test]
    fn terminal_deployment_signs_a_new_request() {
        let stable = stable();
        for status in ["healthy", "failed", "rolled_back", "superseded"] {
            let attempt = select_template_deploy_attempt(
                LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
                &stable,
                "app-uuid",
                &listed(vec![row("deploy-1", status, Some(status))]),
            );
            assert!(
                matches!(attempt, TemplateDeployAttempt::Fresh),
                "{status} must not replay"
            );
        }
    }

    #[test]
    fn stale_observation_of_a_healthy_row_does_not_block_redeploy() {
        let stable = stable();
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            "app-uuid",
            &listed(vec![row("deploy-1", "stale", Some("healthy"))]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn in_flight_without_a_stored_request_is_refused() {
        let stable = stable();
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Absent,
            &stable,
            "app-uuid",
            &listed(vec![row("deploy-9", "pending", None)]),
        );
        let TemplateDeployAttempt::Refuse(message) = attempt else {
            panic!("missing stored request must not start a second deployment");
        };
        assert!(message.contains("deploy-9"), "{message}");
        assert!(message.contains("was not started"), "{message}");
    }

    #[test]
    fn changed_settings_do_not_race_an_in_flight_deployment() {
        let stable = stable();
        let mut changed = stable.clone();
        changed.config = serde_json::json!({"NGROK_TCP_URL": "6.tcp.eu.ngrok.io:1"});
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &changed,
            "app-uuid",
            &listed(vec![row("other-id", "watching", Some("watching"))]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Refuse(_)));
    }

    #[test]
    fn changed_settings_with_nothing_in_flight_may_sign_fresh() {
        let stable = stable();
        let mut changed = stable.clone();
        changed.bootstrap_pubkey_hash = Some("cd".repeat(32));
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &changed,
            "app-uuid",
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn recreated_app_does_not_replay_the_previous_descriptor() {
        let stable = stable();
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            "new-app-uuid",
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn list_outage_replays_a_matching_stored_request_and_does_not_block_a_first_deploy() {
        let stable = stable();
        let replay = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            "app-uuid",
            &DeploymentListing::Unavailable,
        );
        assert!(matches!(replay, TemplateDeployAttempt::Replay { .. }));
        let first = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Absent,
            &stable,
            "app-uuid",
            &DeploymentListing::Unavailable,
        );
        assert!(matches!(first, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn projected_stale_without_a_row_status_is_not_in_flight() {
        let deployment = row("deploy-1", "stale", None);
        assert!(!deployment_is_in_flight(&deployment));
        assert!(deployment_is_in_flight(&row("deploy-1", "watching", None)));
    }

    fn api_rejection(status: u16, code: &str, disposition: Option<&str>) -> ApiError {
        ApiError::Api {
            status,
            code: Some(code.to_string()),
            message: code.to_string(),
            idempotency_disposition: disposition.map(str::to_string),
        }
    }

    #[test]
    fn definitive_rejection_retires_the_stored_request_but_in_progress_does_not() {
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            403,
            "entitlement_app_limit",
            None
        )));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(409, "idempotency_request_in_progress", None)
        ));
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            409,
            "idempotency_recovery_required",
            None
        )));
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            409,
            "idempotency_conflict",
            None
        )));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(401, "invalid_cli_session", None)
        ));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(403, "email_not_verified", None)
        ));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(403, "deploy_apps", None)
        ));
        // A stray completed stamp on a pre-handler gate must not delete the file.
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(401, "invalid_cli_session", Some("completed"))
        ));
        assert!(!template_instance_rejection_retires_attempt(
            &ApiError::NotAuthenticated
        ));
    }

    #[test]
    fn consumed_key_retires_and_deferred_body_keeps_the_attempt() {
        // PaaS-local / unsanitized terminals that have no disposition.
        for code in [
            "template_policy_rejected",
            "deployment_policy_rejected",
            "signed_artifact_mismatch",
            "app_name_conflict",
            "app name already taken in this org",
            "cap_operation_rejected",
            "hosted_operation_failed_drift",
            "stale_owner_seed",
        ] {
            assert!(
                template_instance_rejection_retires_attempt(&api_rejection(422, code, None)),
                "{code} without a stamp must retire"
            );
        }
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            409,
            "start the stopped app before deploying",
            Some("completed")
        )));
        // Disposition wins over the code allowlist.
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(422, "template_policy_rejected", Some("deferred"))
        ));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(409, "cap_operation_rejected", Some("deferred"))
        ));
        // Unstamped entitlement blocks are pre-lease unless the server says
        // the key was consumed.
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(403, "deploy_blocked", None)
        ));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(403, "entitlement_blocked", None)
        ));
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            403,
            "deploy_blocked",
            Some("completed")
        )));
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            403,
            "entitlement_blocked",
            Some("completed")
        )));
        // An unknown code with no stamp is not evidence the key was consumed.
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(422, "something_new", None)
        ));
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            422,
            "something_new",
            Some("completed")
        )));
        // `cap_operation_rejected` is the sanitizer's rewrite bucket, not a
        // terminal code by itself. A 403/503 with that code is not recorded.
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(403, "cap_operation_rejected", None)
        ));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(503, "cap_operation_rejected", None)
        ));
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            422,
            "cap_operation_rejected",
            None
        )));
        assert!(template_instance_rejection_retires_attempt(&api_rejection(
            403,
            "cap_operation_rejected",
            Some("completed")
        )));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(408, "cap_operation_rejected", None)
        ));
        assert!(!template_instance_rejection_retires_attempt(
            &api_rejection(429, "cap_operation_rejected", None)
        ));
    }

    #[test]
    fn stored_request_does_not_replay_beside_a_different_in_flight_deployment() {
        let stable = stable();
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            "app-uuid",
            &listed(vec![row("deploy-2", "applying", Some("applying"))]),
        );
        let TemplateDeployAttempt::Refuse(message) = attempt else {
            panic!("a stored request must not be sent beside a different in-flight deployment");
        };
        assert!(message.contains("deploy-2"), "{message}");
        assert!(message.contains("was not sent"), "{message}");
        assert!(
            message.contains("once the in-flight deployment's id is visible"),
            "{message}"
        );
    }

    #[test]
    fn list_404_is_empty_only_when_nothing_is_stored() {
        assert!(matches!(
            deployment_listing_for_list_error(&LoadedTemplateDeployAttempt::Absent, Some(404)),
            DeploymentListing::Listed(rows) if rows.is_empty()
        ));
        assert!(matches!(
            deployment_listing_for_list_error(&LoadedTemplateDeployAttempt::Unreadable, Some(404)),
            DeploymentListing::Unavailable
        ));
        assert!(matches!(
            deployment_listing_for_list_error(
                &LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable(), "deploy-1"))),
                Some(404)
            ),
            DeploymentListing::Unavailable
        ));
    }

    #[test]
    fn finished_attempt_is_not_replayed_when_the_list_is_unavailable() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.completed = true;
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            "app-uuid",
            &DeploymentListing::Unavailable,
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Refuse(_)));
    }

    #[test]
    fn finished_attempt_with_no_rows_signs_fresh_instead_of_replaying() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.completed = true;
        let attempt = select_template_deploy_attempt(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            "app-uuid",
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn unknown_reconciled_status_does_not_count_as_in_flight() {
        assert!(!deployment_is_in_flight(&row(
            "deploy-1",
            "cancelled",
            Some("cancelled")
        )));
    }

    #[test]
    fn stored_request_round_trips_without_changing_the_idempotency_key_or_body() {
        let dir = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(dir.path().to_path_buf()).unwrap();
        let stable = stable();
        let request = request_from(&stable, "descriptor-a");
        let body = serde_json::to_vec(&request).unwrap();
        save_template_deploy_attempt(&paths, "org:org-1", "app-uuid", "deploy-1", &request)
            .unwrap();
        let LoadedTemplateDeployAttempt::Ready(stored) =
            load_template_deploy_attempt(&paths, "org:org-1", "shell")
        else {
            panic!("stored request must load");
        };
        let restored = (*stored).into_request();
        assert_eq!(
            idempotency_key_for_request(&restored),
            idempotency_key_for_request(&request)
        );
        assert_eq!(serde_json::to_vec(&restored).unwrap(), body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = attempt_path(&paths, "org:org-1", "shell");
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "stored signed request must be owner-only");
        }
        clear_template_deploy_attempt(&paths, "org:org-1", "shell").unwrap();
        assert!(matches!(
            load_template_deploy_attempt(&paths, "org:org-1", "shell"),
            LoadedTemplateDeployAttempt::Absent
        ));
    }

    #[test]
    fn scope_includes_the_api_origin_even_when_the_org_id_matches() {
        assert_eq!(
            template_deploy_scope(Some("org-1"), None, Some("acme"), "https://api.example"),
            "org:org-1\norigin:https://api.example"
        );
        assert_ne!(
            template_deploy_scope(Some("org-1"), None, None, "https://a.example"),
            template_deploy_scope(Some("org-1"), None, None, "https://b.example")
        );
        assert_eq!(
            template_deploy_scope(None, None, None, "https://api.example"),
            "org:unknown\norigin:https://api.example"
        );
    }
}
