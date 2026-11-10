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
//! rejection, must not replay the old operation. An empty history list is not
//! that evidence while the saved request is still inside PaaS's replay window:
//! the first POST can be running before its row appears.
//!
//! A list outage is also not evidence the key is still replayable. PaaS keeps
//! a hosted-operation replay for 24h (`replay_expires_at = now() + interval
//! '24 hours'`). Replaying past that window starts another rollout with the
//! original signed deployment id, so an attempt with no in-window timestamp
//! fails closed when history cannot be listed.
//!
//! A destroy-and-recreate keeps the app name and replaces the id. The stored
//! descriptor is bound to the old id and must not be replayed against the
//! replacement. An id change that is not proof of a new row is also not proof
//! the first POST settled, so that case refuses until the deployment is listed
//! or the replay window has passed.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::api_client::template_instance_idempotency_key;
use crate::api_types::CreateTemplateInstanceRequest;
use crate::config::{self, CliPaths};

const STORED_ATTEMPT_VERSION: u32 = 1;

/// Stay an hour inside PaaS's 24h replay window so client/server clock skew
/// cannot turn a forgotten key into a new rollout.
pub const TEMPLATE_DEPLOY_REPLAY_WINDOW_SECS: u64 = 23 * 60 * 60;

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

/// Workflow the CLI must repeat on replay. The create response echoes the
/// catalog at response time, which can change while a deployment is in flight.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredTemplateWorkflow {
    pub unlock_mode: String,
    pub paas_managed_config_keys: Vec<String>,
}

/// Log-key output from the invocation that signed the request. A retry that
/// died before printing still has to report the key the descriptor contains.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredTemplateLogKey {
    pub key_id: String,
    pub private_key_file: Option<String>,
}

/// Metadata captured with a newly signed request. Not part of the POST body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTemplateDeployAttempt {
    pub unlock_mode: String,
    pub paas_managed_config_keys: Vec<String>,
    pub log_key_id: Option<String>,
    pub log_private_key_file: Option<String>,
}

/// What this run should POST.
#[derive(Debug)]
pub enum TemplateDeployAttempt {
    /// No in-flight deployment to resume. Sign a new descriptor.
    Fresh,
    /// Re-POST this exact request so the idempotency key hits the in-flight operation.
    Replay {
        request: Box<CreateTemplateInstanceRequest>,
        deploy_id: String,
        workflow: Option<StoredTemplateWorkflow>,
        log_key: Option<StoredTemplateLogKey>,
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
    /// Unix seconds when the request was signed, before the POST. `0` means
    /// the file predates this field and must not be replayed without a live row.
    #[serde(default)]
    created_at_unix: u64,
    /// Set once the POST returned success, even if later CLI steps did not finish.
    #[serde(default)]
    post_accepted: bool,
    #[serde(default)]
    post_accepted_at_unix: Option<u64>,
    /// Catalog workflow used when this request was signed. Absent on files
    /// written before this field existed.
    #[serde(default)]
    workflow: Option<StoredTemplateWorkflow>,
    #[serde(default)]
    log_key: Option<StoredTemplateLogKey>,
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

/// Exclusive lock covering load/list/sign/save/POST for one app. Dropping it
/// releases the lock, including on process death.
#[must_use = "dropping the guard releases the template deploy lock"]
pub struct TemplateDeployLock {
    _guard: crate::fslock::FileLockGuard,
}

/// Scope the on-disk attempt so two orgs (or two API origins) cannot resume
/// each other's signed request for the same app name.
///
/// `selected_org` is `CliConfig::org`, the name `X-Enclava-Org` actually
/// sends. `org switch` updates that name and leaves the credential org id
/// pointing at the previous login, so the id alone must not be the scope.
pub fn template_deploy_scope(
    active_org_id: Option<&str>,
    config_org_id: Option<&str>,
    active_org_name: Option<&str>,
    selected_org: Option<&str>,
    api_origin: &str,
) -> String {
    let org_id = [active_org_id, config_org_id]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or("unknown");
    let selected = [selected_org, active_org_name]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or("-");
    // Origin is always part of the scope: two API URLs can share an org id.
    // The selected name is always part of it too: a switch must not reuse the
    // previous org's resume file just because the credential id is stale.
    format!("org:{org_id}\nselected:{selected}\norigin:{api_origin}")
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// The app this command will sign for.
///
/// A destroy-and-recreate keeps the name and replaces the id. A still-live
/// deploy can also change the id the platform serves before its row is listed.
/// Those are not the same decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentTemplateApp {
    pub id: String,
    /// Platform `created_at` as unix seconds. `None` when it could not be parsed.
    pub created_at_unix: Option<u64>,
}

/// Server clock ahead of this machine must not look like a new app row.
/// A replacement row is created when the user destroys and recreates, which
/// is later than this margin. A same-row id change is not.
const APP_RECREATE_SKEW_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredAppIdentity {
    Same,
    /// This app row was created after the stored request. The descriptor is
    /// bound to a destroyed app and must not be replayed.
    Recreated,
    /// Ids differ, but this may still be a presentation change on the same
    /// row while the first POST is in flight.
    Unproven,
}

fn stored_app_identity(
    stored: &StoredTemplateDeployAttempt,
    current: &CurrentTemplateApp,
) -> StoredAppIdentity {
    if stored.app_id == current.id {
        return StoredAppIdentity::Same;
    }
    // An undated file cannot prove the row is newer. Fail closed.
    if let Some(created) = current.created_at_unix
        && stored.created_at_unix != 0
        && created
            > stored
                .created_at_unix
                .saturating_add(APP_RECREATE_SKEW_SECS)
    {
        return StoredAppIdentity::Recreated;
    }
    StoredAppIdentity::Unproven
}

/// Hash to compare against a stored request.
///
/// `template_bootstrap_pubkey_hash` follows the catalog's current
/// `unlock_mode`: password mode derives a key, other modes do not. Using that
/// value in `matches_inputs` rejects the stored request before the replay
/// branch can restore the signed unlock mode. Match the hash the stored
/// request was signed with. A fresh sign still uses the catalog-derived hash.
pub fn bootstrap_hash_for_resume_match(
    loaded: &LoadedTemplateDeployAttempt,
    catalog_derived: Option<String>,
) -> Option<String> {
    match loaded {
        LoadedTemplateDeployAttempt::Ready(stored) => stored.bootstrap_pubkey_hash.clone(),
        _ => catalog_derived,
    }
}

/// Whether this run must satisfy password-mode gates before selection.
///
/// A stored request signed for a non-password unlock mode must not be blocked
/// by the catalog's current mode. The replay branch restores the signed mode
/// after selection. No stored workflow follows the catalog.
pub fn resume_expects_password_preflight(
    loaded: &LoadedTemplateDeployAttempt,
    catalog_unlock_mode: &str,
) -> bool {
    match loaded {
        LoadedTemplateDeployAttempt::Ready(stored) => stored
            .workflow
            .as_ref()
            .map(|workflow| workflow.unlock_mode == "password")
            .unwrap_or(catalog_unlock_mode == "password"),
        _ => catalog_unlock_mode == "password",
    }
}

pub fn select_template_deploy_attempt(
    loaded: LoadedTemplateDeployAttempt,
    stable: &StableTemplateDeployInputs,
    current_app: &CurrentTemplateApp,
    deployments: &DeploymentListing,
    now_unix: u64,
) -> TemplateDeployAttempt {
    let unreadable = matches!(loaded, LoadedTemplateDeployAttempt::Unreadable);
    let usable = match loaded {
        LoadedTemplateDeployAttempt::Ready(stored)
            if stored.instance_name == stable.instance_name =>
        {
            Some(stored)
        }
        _ => None,
    };

    let Some(rows) = listed_rows(deployments) else {
        return attempt_without_listing(usable, unreadable, stable, current_app, now_unix);
    };

    let inflight: Vec<&ObservedTemplateDeployment> = rows
        .iter()
        .filter(|deployment| deployment_is_in_flight(deployment))
        .collect();

    if let Some(stored) = usable {
        return select_stored_attempt(stored, stable, current_app, rows, &inflight, now_unix);
    }

    // The deploy id is inside the file. Without it, a settled row can be an
    // older rollout while the interrupted POST is still missing from history.
    // A list outage already refuses this case; a successful list must too.
    if unreadable {
        if let Some(deployment) = inflight.first().copied() {
            return TemplateDeployAttempt::Refuse(inflight_refuse_message(
                stable,
                deployment,
                "the stored signed request on this machine is unreadable, so it cannot be resumed. A new deployment was not started. Retry from the machine that started it, wait for it to finish, or destroy the app and deploy again. Destroying the app removes the stored request.",
            ));
        }
        return TemplateDeployAttempt::Refuse(format!(
            "the stored template deploy request for `{}` is unreadable, so it is not safe to sign a new one. A new deployment was not started. Retry when that request can be read, or destroy the app and deploy again. Destroying the app removes the stored request.",
            stable.instance_name
        ));
    }

    if let Some(deployment) = inflight.first().copied() {
        return TemplateDeployAttempt::Refuse(inflight_refuse_message(
            stable,
            deployment,
            "this machine does not have the original signed request to resume it. A new deployment was not started. Retry from the machine that started it, wait for it to finish, or destroy the app and deploy again.",
        ));
    }
    TemplateDeployAttempt::Fresh
}

fn select_stored_attempt(
    stored: Box<StoredTemplateDeployAttempt>,
    stable: &StableTemplateDeployInputs,
    current_app: &CurrentTemplateApp,
    rows: &[ObservedTemplateDeployment],
    inflight: &[&ObservedTemplateDeployment],
    now_unix: u64,
) -> TemplateDeployAttempt {
    // `deliver_managed_template_config` is app-scoped. Continuing the stored
    // workflow while a different deployment is live can enqueue the old
    // template's configuration for the newer rollout. Refuse even when the
    // stored row is also still in flight.
    if let Some(deployment) = inflight
        .iter()
        .copied()
        .find(|deployment| deployment.id != stored.deploy_id)
    {
        return TemplateDeployAttempt::Refuse(inflight_refuse_message(
            stable,
            deployment,
            "another deployment is in flight, so the stored request was not sent. Resuming it could apply this template's configuration to the newer rollout, and a new deployment was not started. Wait for every in-flight deployment to finish, or destroy the app, then deploy again.",
        ));
    }

    match stored_app_identity(&stored, current_app) {
        StoredAppIdentity::Recreated => TemplateDeployAttempt::Fresh,
        StoredAppIdentity::Unproven => {
            select_unproven_app_mismatch(stored, stable, current_app, rows, now_unix)
        }
        StoredAppIdentity::Same => select_same_app_attempt(stored, stable, rows, now_unix),
    }
}

fn select_same_app_attempt(
    stored: Box<StoredTemplateDeployAttempt>,
    stable: &StableTemplateDeployInputs,
    rows: &[ObservedTemplateDeployment],
    now_unix: u64,
) -> TemplateDeployAttempt {
    let our_row = rows
        .iter()
        .find(|deployment| deployment.id == stored.deploy_id);
    let ours_inflight = our_row.is_some_and(deployment_is_in_flight);

    // A visible row that is not live is not "absent". Replaying it after the
    // server forgets the key restarts a deployment the user cancelled or that
    // a projection already shows as stale. A competing in-flight row was
    // already refused above, so nothing else is rolling out.
    if our_row.is_some() && !ours_inflight {
        return TemplateDeployAttempt::Fresh;
    }

    if stored.matches_inputs(stable) {
        if stored.completed && !ours_inflight {
            return TemplateDeployAttempt::Fresh;
        }
        // A live row is affirmative evidence the operation still exists.
        // An absent row may replay only while the key is still inside the
        // server window; after that, the same key opens a new generation.
        if ours_inflight || replay_within_window(&stored, now_unix) {
            return replay(stored);
        }
        if !replay_window_known(&stored) {
            return TemplateDeployAttempt::Refuse(format!(
                "the stored template deploy request for `{}` has no timestamp and its deployment is not visible yet. Replaying or replacing it could race the original request. A new deployment was not started. Retry once that deployment is listed, or destroy the app and deploy again.",
                stable.instance_name
            ));
        }
        return TemplateDeployAttempt::Fresh;
    }

    if let Some(deployment) = our_row.filter(|_| ours_inflight) {
        return TemplateDeployAttempt::Refuse(inflight_refuse_message(
            stable,
            deployment,
            "this command's template settings differ from the signed request that started it. Retry the original command to resume that deployment. Destroy the app before changing the template, endpoint, or bootstrap settings.",
        ));
    }
    // Nothing visible is in flight and the stored request does not match this
    // command. An empty list is not proof the previous POST settled: the row
    // can still be missing while that request runs. Keep the saved attempt
    // authoritative until it is past the replay window.
    if !stored.completed && replay_within_window(&stored, now_unix) {
        return TemplateDeployAttempt::Refuse(format!(
            "a previous template deploy for `{}` was signed on this machine and is not visible in deployment history yet. This command's settings differ from that signed request, so a new deployment was not started (the first request may still be running). Retry the original command to resume it.",
            stable.instance_name
        ));
    }
    if !stored.completed && !replay_window_known(&stored) {
        return TemplateDeployAttempt::Refuse(format!(
            "a previous template deploy for `{}` is stored on this machine without a timestamp, and deployment history does not show it. This command's settings differ, so a new deployment was not started. Retry the original command, or destroy the app and deploy again.",
            stable.instance_name
        ));
    }
    TemplateDeployAttempt::Fresh
}

fn select_unproven_app_mismatch(
    stored: Box<StoredTemplateDeployAttempt>,
    stable: &StableTemplateDeployInputs,
    current_app: &CurrentTemplateApp,
    rows: &[ObservedTemplateDeployment],
    now_unix: u64,
) -> TemplateDeployAttempt {
    let our_row = rows
        .iter()
        .find(|deployment| deployment.id == stored.deploy_id);
    let ours_inflight = our_row.is_some_and(deployment_is_in_flight);

    // The signed deployment is on this app, so the id change is a presentation
    // change during a live operation, not a recreate. Resume it.
    if ours_inflight && stored.matches_inputs(stable) {
        return replay(stored);
    }
    if let Some(deployment) = our_row.filter(|_| ours_inflight) {
        return TemplateDeployAttempt::Refuse(inflight_refuse_message(
            stable,
            deployment,
            "this command's template settings differ from the signed request that started it. Retry the original command to resume that deployment. Destroy the app before changing the template, endpoint, or bootstrap settings.",
        ));
    }
    if our_row.is_some() {
        return TemplateDeployAttempt::Fresh;
    }
    // Not listed on this app. Do not replay a descriptor bound to a different
    // id (the platform can return the old operation's cached response). Do not
    // sign fresh while that request may still be running on this row.
    if !stored.completed
        && (replay_within_window(&stored, now_unix) || !replay_window_known(&stored))
    {
        return TemplateDeployAttempt::Refuse(format!(
            "the stored template deploy request for `{}` was signed for app id `{}`, but this app's id is `{}` and deployment `{}` is not listed. The stored request was not sent, and a new deployment was not started. Retry once that deployment is listed, or destroy the app and deploy again.",
            stable.instance_name, stored.app_id, current_app.id, stored.deploy_id
        ));
    }
    TemplateDeployAttempt::Fresh
}

fn attempt_without_listing(
    usable: Option<Box<StoredTemplateDeployAttempt>>,
    unreadable: bool,
    stable: &StableTemplateDeployInputs,
    current_app: &CurrentTemplateApp,
    now_unix: u64,
) -> TemplateDeployAttempt {
    if let Some(stored) = usable {
        match stored_app_identity(&stored, current_app) {
            // The replacement app has no stored attempt of its own. A list
            // outage must not block that first deploy, and the old descriptor
            // must not be replayed against it.
            StoredAppIdentity::Recreated => return TemplateDeployAttempt::Fresh,
            StoredAppIdentity::Unproven => {
                return TemplateDeployAttempt::Refuse(format!(
                    "could not list deployments for `{}`, and the stored template deploy request was signed for app id `{}` while this app's id is `{}`. The stored request was not sent, and a new deployment was not started. Retry when deployment status is available, or destroy the app and deploy again.",
                    stable.instance_name, stored.app_id, current_app.id
                ));
            }
            StoredAppIdentity::Same => {}
        }
        if stored.matches_inputs(stable) {
            if stored.completed {
                return TemplateDeployAttempt::Refuse(format!(
                    "the previous template deploy for `{}` already finished on this machine, and deployments could not be listed to confirm it is safe to start another. A new deployment was not started. Retry when deployment status is available.",
                    stable.instance_name
                ));
            }
            if replay_within_window(&stored, now_unix) {
                return replay(stored);
            }
            let accepted = if stored.post_accepted {
                " The platform already accepted this request."
            } else {
                ""
            };
            return TemplateDeployAttempt::Refuse(format!(
                "the stored template deploy request for `{}` is outside the platform's replay window, or it has no timestamp, and deployments could not be listed. Replaying it could start another rollout with the original deployment id.{accepted} A new deployment was not started. Retry when deployment status is available.",
                stable.instance_name
            ));
        }
        return TemplateDeployAttempt::Refuse(format!(
            "could not list deployments for `{}` to confirm the previous template deploy finished, and this command's settings differ from the stored request. Retry the original command to resume it. A new deployment was not started.",
            stable.instance_name
        ));
    }
    if unreadable {
        return TemplateDeployAttempt::Refuse(format!(
            "could not list deployments for `{}`, and the stored template deploy request is unreadable. A new deployment was not started. Retry when deployment status is available, or destroy the app and deploy again. Destroying the app removes the stored request.",
            stable.instance_name
        ));
    }
    // No local attempt to resume. A list outage must not block a first deploy.
    TemplateDeployAttempt::Fresh
}

fn replay(stored: Box<StoredTemplateDeployAttempt>) -> TemplateDeployAttempt {
    let deploy_id = stored.deploy_id.clone();
    let workflow = stored.workflow.clone();
    let log_key = stored.log_key.clone();
    TemplateDeployAttempt::Replay {
        request: Box::new((*stored).into_request()),
        deploy_id,
        workflow,
        log_key,
    }
}

fn replay_window_known(stored: &StoredTemplateDeployAttempt) -> bool {
    stored.created_at_unix != 0
}

fn replay_within_window(stored: &StoredTemplateDeployAttempt, now_unix: u64) -> bool {
    let created = stored.created_at_unix;
    created != 0 && now_unix.saturating_sub(created) <= TEMPLATE_DEPLOY_REPLAY_WINDOW_SECS
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
        "healthy" | "failed" | "rolled_back" | "superseded" | "cancelled"
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

pub fn try_acquire_template_deploy_lock(
    paths: &CliPaths,
    scope: &str,
    instance_name: &str,
) -> Result<Option<TemplateDeployLock>, String> {
    paths.ensure_dirs().map_err(|err| err.to_string())?;
    let path = lock_path(paths, scope, instance_name);
    crate::fslock::try_acquire_file_lock(&path)
        .map(|guard| guard.map(|guard| TemplateDeployLock { _guard: guard }))
        .map_err(|err| lock_error(instance_name, &err))
}

pub fn acquire_template_deploy_lock(
    paths: &CliPaths,
    scope: &str,
    instance_name: &str,
) -> Result<TemplateDeployLock, String> {
    paths.ensure_dirs().map_err(|err| err.to_string())?;
    let path = lock_path(paths, scope, instance_name);
    crate::fslock::acquire_file_lock(&path)
        .map(|guard| TemplateDeployLock { _guard: guard })
        .map_err(|err| lock_error(instance_name, &err))
}

fn lock_error(instance_name: &str, err: &std::io::Error) -> String {
    format!("could not lock template deploy state for `{instance_name}`: {err}")
}

pub fn save_template_deploy_attempt(
    paths: &CliPaths,
    scope: &str,
    app_id: &str,
    deploy_id: &str,
    request: &CreateTemplateInstanceRequest,
    record: &NewTemplateDeployAttempt,
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
        created_at_unix: unix_now(),
        post_accepted: false,
        post_accepted_at_unix: None,
        workflow: Some(StoredTemplateWorkflow {
            unlock_mode: record.unlock_mode.clone(),
            paas_managed_config_keys: record.paas_managed_config_keys.clone(),
        }),
        log_key: stored_log_key(record),
        completed: false,
    };
    write_stored(paths, &stored)
}

fn stored_log_key(record: &NewTemplateDeployAttempt) -> Option<StoredTemplateLogKey> {
    let key_id = record
        .log_key_id
        .as_deref()
        .map(str::trim)
        .filter(|key_id| !key_id.is_empty())?;
    Some(StoredTemplateLogKey {
        key_id: key_id.to_string(),
        private_key_file: record
            .log_private_key_file
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(str::to_string),
    })
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

/// Remember that the platform accepted the POST, separately from the CLI
/// finishing config delivery. A later history outage must not treat "the
/// command did not finish" as "the key was never sent".
pub fn mark_template_deploy_attempt_posted(
    paths: &CliPaths,
    scope: &str,
    instance_name: &str,
) -> Result<(), String> {
    let LoadedTemplateDeployAttempt::Ready(mut stored) =
        load_template_deploy_attempt(paths, scope, instance_name)
    else {
        return Err(
            "template deploy was accepted but the stored request is missing, so a retry cannot resume it safely"
                .to_string(),
        );
    };
    if stored.post_accepted {
        return Ok(());
    }
    stored.post_accepted = true;
    stored.post_accepted_at_unix = Some(unix_now());
    write_stored(paths, &stored)
}

/// Remember that this command finished, so a later list outage does not
/// replay the finished request into a new server generation.
pub fn mark_template_deploy_attempt_completed(
    paths: &CliPaths,
    scope: &str,
    instance_name: &str,
    deploy_id: &str,
) -> Result<(), String> {
    let LoadedTemplateDeployAttempt::Ready(mut stored) =
        load_template_deploy_attempt(paths, scope, instance_name)
    else {
        return Ok(());
    };
    // A later invocation may have replaced this file after our POST. Stamping
    // that newer attempt completed would make the next retry sign a fresh key
    // while its row is still invisible.
    if stored.deploy_id != deploy_id {
        return Ok(());
    }
    stored.completed = true;
    write_stored(paths, &stored)
}

fn write_stored(paths: &CliPaths, stored: &StoredTemplateDeployAttempt) -> Result<(), String> {
    let bytes = serde_json::to_vec(stored).map_err(|err| err.to_string())?;
    paths.ensure_dirs().map_err(|err| err.to_string())?;
    config::write_secret_atomic(
        &attempt_path(paths, &stored.scope, &stored.instance_name),
        &bytes,
    )
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

fn lock_path(paths: &CliPaths, scope: &str, instance_name: &str) -> PathBuf {
    attempt_path(paths, scope, instance_name).with_extension("lock")
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

    const NOW: u64 = 1_700_000_000;

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
            created_at_unix: NOW,
            post_accepted: false,
            post_accepted_at_unix: None,
            workflow: Some(StoredTemplateWorkflow {
                unlock_mode: "password".to_string(),
                paas_managed_config_keys: vec!["NGROK_AUTHTOKEN".to_string()],
            }),
            log_key: Some(StoredTemplateLogKey {
                key_id: "shell-logs".to_string(),
                private_key_file: Some("/keys/shell-logs.x25519".to_string()),
            }),
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

    fn current_app() -> CurrentTemplateApp {
        CurrentTemplateApp {
            id: "app-uuid".to_string(),
            // Well before any stored attempt in these tests, so an id mismatch
            // is not mistaken for a recreate.
            created_at_unix: Some(NOW - 86_400),
        }
    }

    fn select(
        loaded: LoadedTemplateDeployAttempt,
        stable: &StableTemplateDeployInputs,
        deployments: &DeploymentListing,
    ) -> TemplateDeployAttempt {
        select_for(loaded, stable, &current_app(), deployments)
    }

    fn select_for(
        loaded: LoadedTemplateDeployAttempt,
        stable: &StableTemplateDeployInputs,
        current: &CurrentTemplateApp,
        deployments: &DeploymentListing,
    ) -> TemplateDeployAttempt {
        select_template_deploy_attempt(loaded, stable, current, deployments, NOW)
    }

    fn record() -> NewTemplateDeployAttempt {
        NewTemplateDeployAttempt {
            unlock_mode: "password".to_string(),
            paas_managed_config_keys: vec!["NGROK_AUTHTOKEN".to_string()],
            log_key_id: Some("shell-logs".to_string()),
            log_private_key_file: Some("/keys/shell-logs.x25519".to_string()),
        }
    }

    #[test]
    fn in_flight_retry_reuses_the_signed_request_and_its_idempotency_key() {
        let stable = stable();
        let stored = stored(&stable, "deploy-1");
        let original = stored.clone().into_request();
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            &listed(vec![row("deploy-1", "applying", Some("applying"))]),
        );
        let TemplateDeployAttempt::Replay {
            request,
            deploy_id,
            workflow,
            log_key,
        } = attempt
        else {
            panic!("in-flight retry must replay the stored request, not sign a new one");
        };
        let request = *request;
        assert_eq!(deploy_id, "deploy-1");
        assert_eq!(
            workflow
                .expect("replay must keep the signed workflow")
                .unlock_mode,
            "password"
        );
        assert_eq!(
            log_key.expect("replay must keep the signed log key").key_id,
            "shell-logs"
        );
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
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Replay { .. }));
    }

    #[test]
    fn terminal_deployment_signs_a_new_request() {
        let stable = stable();
        for status in [
            "healthy",
            "failed",
            "rolled_back",
            "superseded",
            "cancelled",
        ] {
            let attempt = select(
                LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
                &stable,
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
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &listed(vec![row("deploy-1", "stale", Some("healthy"))]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn visible_inactive_row_signs_fresh_instead_of_replaying() {
        let stable = stable();
        for (status, reconciled) in [("cancelled", None), ("stale", None), ("partial", None)] {
            let attempt = select(
                LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
                &stable,
                &listed(vec![row("deploy-1", status, reconciled)]),
            );
            assert!(
                matches!(attempt, TemplateDeployAttempt::Fresh),
                "{status} is visible and not live, so it must not be replayed"
            );
        }
    }

    #[test]
    fn in_flight_without_a_stored_request_is_refused() {
        let stable = stable();
        let attempt = select(
            LoadedTemplateDeployAttempt::Absent,
            &stable,
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
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &changed,
            &listed(vec![row("other-id", "watching", Some("watching"))]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Refuse(_)));
    }

    #[test]
    fn changed_settings_with_an_unseen_recent_request_do_not_sign_fresh() {
        let stable = stable();
        let mut changed = stable.clone();
        changed.bootstrap_pubkey_hash = Some("cd".repeat(32));
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &changed,
            &listed(vec![]),
        );
        let TemplateDeployAttempt::Refuse(message) = attempt else {
            panic!("changed settings must not replace a request whose row is not visible yet");
        };
        assert!(message.contains("not visible"), "{message}");
        assert!(message.contains("was not started"), "{message}");
    }

    #[test]
    fn changed_settings_may_sign_fresh_once_the_unseen_request_is_past_the_replay_window() {
        let stable = stable();
        let mut changed = stable.clone();
        changed.bootstrap_pubkey_hash = Some("cd".repeat(32));
        let mut stored = stored(&stable, "deploy-1");
        stored.created_at_unix = NOW - TEMPLATE_DEPLOY_REPLAY_WINDOW_SECS - 1;
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &changed,
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn expired_matching_request_with_an_empty_list_signs_fresh_instead_of_replaying() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.created_at_unix = NOW - TEMPLATE_DEPLOY_REPLAY_WINDOW_SECS - 1;
        stored.post_accepted = true;
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn app_id_flip_before_the_row_is_visible_does_not_replay_or_sign_fresh() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.app_id = "cap-app-uuid".to_string();
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            &listed(vec![]),
        );
        let TemplateDeployAttempt::Refuse(message) = attempt else {
            panic!("an unproven app id change must not replay the old descriptor or sign fresh");
        };
        assert!(message.contains("cap-app-uuid"), "{message}");
        assert!(message.contains("was not sent"), "{message}");
        assert!(message.contains("was not started"), "{message}");
    }

    #[test]
    fn app_id_flip_with_the_signed_deployment_in_flight_still_replays() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.app_id = "cap-app-uuid".to_string();
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            &listed(vec![row("deploy-1", "applying", Some("applying"))]),
        );
        assert!(
            matches!(attempt, TemplateDeployAttempt::Replay { .. }),
            "a live row for the signed deployment is an id transition, not a recreate"
        );
    }

    #[test]
    fn recreated_app_does_not_replay_the_previous_descriptor() {
        let stable = stable();
        let current = CurrentTemplateApp {
            id: "new-app-uuid".to_string(),
            created_at_unix: Some(NOW + APP_RECREATE_SKEW_SECS + 1),
        };
        let attempt = select_for(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &current,
            &listed(vec![]),
        );
        assert!(
            matches!(attempt, TemplateDeployAttempt::Fresh),
            "a row created after the stored request must not replay the destroyed app's descriptor"
        );
        let during_outage = select_for(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &current,
            &DeploymentListing::Unavailable,
        );
        assert!(
            matches!(during_outage, TemplateDeployAttempt::Fresh),
            "a recreated app's first deploy must not be blocked by a list outage"
        );
    }

    #[test]
    fn recreated_app_within_clock_skew_does_not_replay() {
        let stable = stable();
        let current = CurrentTemplateApp {
            id: "new-app-uuid".to_string(),
            created_at_unix: Some(NOW + APP_RECREATE_SKEW_SECS),
        };
        let attempt = select_for(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &current,
            &listed(vec![]),
        );
        assert!(
            matches!(attempt, TemplateDeployAttempt::Refuse(_)),
            "a created_at inside the skew margin is not proof of a new row"
        );
    }

    #[test]
    fn same_app_id_replays_even_if_created_at_is_later() {
        let stable = stable();
        let current = CurrentTemplateApp {
            id: "app-uuid".to_string(),
            created_at_unix: Some(NOW + 86_400),
        };
        let attempt = select_for(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &current,
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Replay { .. }));
    }

    #[test]
    fn app_id_mismatch_past_the_replay_window_may_sign_fresh() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.app_id = "old-app-uuid".to_string();
        stored.created_at_unix = NOW - TEMPLATE_DEPLOY_REPLAY_WINDOW_SECS - 1;
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            &listed(vec![]),
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn unreadable_resume_file_does_not_sign_fresh_beside_a_settled_row() {
        let stable = stable();
        for deployments in [
            listed(vec![]),
            listed(vec![row("older", "healthy", Some("healthy"))]),
        ] {
            let attempt = select(
                LoadedTemplateDeployAttempt::Unreadable,
                &stable,
                &deployments,
            );
            let TemplateDeployAttempt::Refuse(message) = attempt else {
                panic!("an unreadable resume file must not be treated as absent");
            };
            assert!(message.contains("unreadable"), "{message}");
            assert!(message.contains("was not started"), "{message}");
        }
    }

    #[test]
    fn list_outage_replays_a_matching_stored_request_and_does_not_block_a_first_deploy() {
        let stable = stable();
        let replay = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &DeploymentListing::Unavailable,
        );
        assert!(matches!(replay, TemplateDeployAttempt::Replay { .. }));
        let first = select(
            LoadedTemplateDeployAttempt::Absent,
            &stable,
            &DeploymentListing::Unavailable,
        );
        assert!(matches!(first, TemplateDeployAttempt::Fresh));
    }

    #[test]
    fn list_outage_refuses_an_attempt_outside_the_replay_window() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.created_at_unix = NOW - TEMPLATE_DEPLOY_REPLAY_WINDOW_SECS - 1;
        stored.post_accepted = true;
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            &DeploymentListing::Unavailable,
        );
        let TemplateDeployAttempt::Refuse(message) = attempt else {
            panic!("an expired key must not be replayed while history is unavailable");
        };
        assert!(message.contains("replay window"), "{message}");
        assert!(message.contains("already accepted"), "{message}");
        assert!(message.contains("was not started"), "{message}");
    }

    #[test]
    fn list_outage_refuses_a_stored_request_with_no_timestamp() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.created_at_unix = 0;
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            &DeploymentListing::Unavailable,
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Refuse(_)));
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
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &listed(vec![row("deploy-2", "applying", Some("applying"))]),
        );
        let TemplateDeployAttempt::Refuse(message) = attempt else {
            panic!("a stored request must not be sent beside a different in-flight deployment");
        };
        assert!(message.contains("deploy-2"), "{message}");
        assert!(message.contains("was not sent"), "{message}");
        assert!(
            message.contains("another deployment is in flight"),
            "{message}"
        );
    }

    #[test]
    fn stored_request_is_not_replayed_when_another_deployment_is_also_in_flight() {
        let stable = stable();
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1"))),
            &stable,
            &listed(vec![
                row("deploy-1", "applying", Some("applying")),
                row("deploy-2", "pending", Some("pending")),
            ]),
        );
        let TemplateDeployAttempt::Refuse(message) = attempt else {
            panic!("a competing in-flight row must not replay the stored request");
        };
        assert!(message.contains("deploy-2"), "{message}");
        assert!(message.contains("was not sent"), "{message}");
        assert!(message.contains("was not started"), "{message}");
    }

    #[test]
    fn resume_match_uses_the_stored_bootstrap_hash_not_the_catalog_hash() {
        let stable = stable();
        let catalog = Some("ff".repeat(32));
        let loaded = LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1")));
        assert_eq!(
            bootstrap_hash_for_resume_match(&loaded, catalog.clone()),
            Some("ab".repeat(32))
        );
        let mut auto = stored(&stable, "deploy-1");
        auto.bootstrap_pubkey_hash = None;
        auto.workflow = Some(StoredTemplateWorkflow {
            unlock_mode: "auto".to_string(),
            paas_managed_config_keys: Vec::new(),
        });
        assert_eq!(
            bootstrap_hash_for_resume_match(
                &LoadedTemplateDeployAttempt::Ready(Box::new(auto)),
                catalog.clone()
            ),
            None,
            "an auto-mode stored request must not match a password-mode catalog hash"
        );
        assert_eq!(
            bootstrap_hash_for_resume_match(&LoadedTemplateDeployAttempt::Absent, catalog.clone()),
            catalog
        );
    }

    #[test]
    fn password_preflight_follows_the_stored_unlock_mode() {
        let stable = stable();
        let password = LoadedTemplateDeployAttempt::Ready(Box::new(stored(&stable, "deploy-1")));
        assert!(resume_expects_password_preflight(&password, "auto"));
        let mut auto = stored(&stable, "deploy-1");
        auto.workflow = Some(StoredTemplateWorkflow {
            unlock_mode: "auto".to_string(),
            paas_managed_config_keys: Vec::new(),
        });
        let auto = LoadedTemplateDeployAttempt::Ready(Box::new(auto));
        assert!(!resume_expects_password_preflight(&auto, "password"));
        assert!(resume_expects_password_preflight(
            &LoadedTemplateDeployAttempt::Absent,
            "password"
        ));
        assert!(!resume_expects_password_preflight(
            &LoadedTemplateDeployAttempt::Absent,
            "auto"
        ));
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
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
            &DeploymentListing::Unavailable,
        );
        assert!(matches!(attempt, TemplateDeployAttempt::Refuse(_)));
    }

    #[test]
    fn finished_attempt_with_no_rows_signs_fresh_instead_of_replaying() {
        let stable = stable();
        let mut stored = stored(&stable, "deploy-1");
        stored.completed = true;
        let attempt = select(
            LoadedTemplateDeployAttempt::Ready(Box::new(stored)),
            &stable,
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
        save_template_deploy_attempt(
            &paths,
            "org:org-1",
            "app-uuid",
            "deploy-1",
            &request,
            &record(),
        )
        .unwrap();
        let LoadedTemplateDeployAttempt::Ready(stored) =
            load_template_deploy_attempt(&paths, "org:org-1", "shell")
        else {
            panic!("stored request must load");
        };
        assert!(stored.created_at_unix != 0, "a saved attempt must be dated");
        assert!(!stored.post_accepted);
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
        mark_template_deploy_attempt_posted(&paths, "org:org-1", "shell").unwrap();
        let LoadedTemplateDeployAttempt::Ready(posted) =
            load_template_deploy_attempt(&paths, "org:org-1", "shell")
        else {
            panic!("posted request must still load");
        };
        assert!(posted.post_accepted);
        assert!(posted.post_accepted_at_unix.is_some());
        assert_eq!(
            serde_json::to_vec(&posted.clone().into_request()).unwrap(),
            body,
            "recording POST acceptance must not change the signed request"
        );
        clear_template_deploy_attempt(&paths, "org:org-1", "shell").unwrap();
        assert!(matches!(
            load_template_deploy_attempt(&paths, "org:org-1", "shell"),
            LoadedTemplateDeployAttempt::Absent
        ));
    }

    #[test]
    fn completion_does_not_stamp_a_newer_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(dir.path().to_path_buf()).unwrap();
        let stable = stable();
        let request = request_from(&stable, "descriptor-a");
        save_template_deploy_attempt(
            &paths,
            "org:org-1",
            "app-uuid",
            "deploy-1",
            &request,
            &record(),
        )
        .unwrap();
        save_template_deploy_attempt(
            &paths,
            "org:org-1",
            "app-uuid",
            "deploy-2",
            &request,
            &record(),
        )
        .unwrap();
        mark_template_deploy_attempt_completed(&paths, "org:org-1", "shell", "deploy-1").unwrap();
        let LoadedTemplateDeployAttempt::Ready(stored) =
            load_template_deploy_attempt(&paths, "org:org-1", "shell")
        else {
            panic!("newer attempt must still load");
        };
        assert_eq!(stored.deploy_id, "deploy-2");
        assert!(!stored.completed);
        mark_template_deploy_attempt_completed(&paths, "org:org-1", "shell", "deploy-2").unwrap();
        let LoadedTemplateDeployAttempt::Ready(stored) =
            load_template_deploy_attempt(&paths, "org:org-1", "shell")
        else {
            panic!("completed attempt must still load");
        };
        assert!(stored.completed);
    }

    #[test]
    fn scope_includes_the_selected_org_and_the_api_origin() {
        assert_eq!(
            template_deploy_scope(
                Some("org-1"),
                None,
                Some("acme"),
                None,
                "https://api.example"
            ),
            "org:org-1\nselected:acme\norigin:https://api.example"
        );
        assert_eq!(
            template_deploy_scope(
                Some("org-1"),
                None,
                Some("acme"),
                Some("beta"),
                "https://api.example"
            ),
            "org:org-1\nselected:beta\norigin:https://api.example"
        );
        assert_ne!(
            template_deploy_scope(
                Some("org-1"),
                None,
                Some("acme"),
                Some("beta"),
                "https://api.example"
            ),
            template_deploy_scope(
                Some("org-1"),
                None,
                Some("acme"),
                Some("acme"),
                "https://api.example"
            ),
            "org switch must not reuse the previous org's resume file"
        );
        assert_ne!(
            template_deploy_scope(Some("org-1"), None, None, None, "https://a.example"),
            template_deploy_scope(Some("org-1"), None, None, None, "https://b.example")
        );
        assert_eq!(
            template_deploy_scope(None, None, None, None, "https://api.example"),
            "org:unknown\nselected:-\norigin:https://api.example"
        );
    }

    #[test]
    fn template_deploy_lock_serializes_a_second_acquire() {
        let dir = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(dir.path().to_path_buf()).unwrap();
        let first = acquire_template_deploy_lock(&paths, "org:1", "shell").unwrap();
        assert!(
            try_acquire_template_deploy_lock(&paths, "org:1", "shell")
                .unwrap()
                .is_none(),
            "a second acquire of the same app must not proceed while the first holds the lock"
        );
        assert!(
            try_acquire_template_deploy_lock(&paths, "org:1", "other")
                .unwrap()
                .is_some(),
            "a different app must not share the lock"
        );
        drop(first);
        assert!(
            try_acquire_template_deploy_lock(&paths, "org:1", "shell")
                .unwrap()
                .is_some()
        );
    }
}
