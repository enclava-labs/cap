use super::*;

async fn restore_target_apply_snapshot(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    app_id: Uuid,
    snapshot: &crate::deploy::DeploymentApplySnapshot,
) -> Result<bool, sqlx::Error> {
    if snapshot.resources.app_id != app_id
        || snapshot.containers.is_empty()
        || snapshot
            .containers
            .iter()
            .any(|container| container.app_id != app_id)
        || snapshot
            .containers
            .iter()
            .filter(|container| container.is_primary)
            .count()
            != 1
    {
        return Ok(false);
    }

    sqlx::query("DELETE FROM app_containers WHERE app_id = $1")
        .bind(app_id)
        .execute(&mut **tx)
        .await?;
    for container in &snapshot.containers {
        sqlx::query(
            "INSERT INTO app_containers (
                 id, app_id, name, image_ref, image_digest, port, command,
                 storage_paths, workload_security_profile, is_primary
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(container.id)
        .bind(container.app_id)
        .bind(&container.name)
        .bind(&container.image_ref)
        .bind(container.image_digest.as_deref())
        .bind(container.port)
        .bind(container.command.as_deref())
        .bind(container.storage_paths.as_ref())
        .bind(container.workload_security_profile.as_deref())
        .bind(container.is_primary)
        .execute(&mut **tx)
        .await?;
    }
    let updated_resources = sqlx::query(
        "UPDATE app_resources
            SET cpu_limit = $1,
                memory_limit = $2,
                app_data_size = $3,
                tls_data_size = $4
          WHERE app_id = $5",
    )
    .bind(&snapshot.resources.cpu_limit)
    .bind(&snapshot.resources.memory_limit)
    .bind(&snapshot.resources.app_data_size)
    .bind(&snapshot.resources.tls_data_size)
    .bind(app_id)
    .execute(&mut **tx)
    .await?;
    Ok(updated_resources.rows_affected() == 1)
}

async fn latest_implicit_rollback_target(
    pool: &sqlx::PgPool,
    app_id: Uuid,
) -> Result<Option<Deployment>, sqlx::Error> {
    sqlx::query_as(
        "SELECT deployment.*
           FROM deployments AS deployment
           JOIN deployment_apply_jobs AS apply_job
             ON apply_job.deployment_id = deployment.id
          WHERE deployment.app_id = $1
            AND deployment.status = 'healthy'
            AND deployment.id <> (
                SELECT latest.deployment_id
                  FROM deployment_apply_jobs AS latest
                 WHERE latest.app_id = $1
                 ORDER BY latest.generation DESC
                 LIMIT 1
            )
         ORDER BY apply_job.generation DESC
         LIMIT 1",
    )
    .bind(app_id)
    .fetch_optional(pool)
    .await
}

async fn latest_implicit_rollback_target_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    app_id: Uuid,
) -> Result<Option<Deployment>, sqlx::Error> {
    sqlx::query_as(
        "SELECT deployment.*
           FROM deployments AS deployment
           JOIN deployment_apply_jobs AS apply_job
             ON apply_job.deployment_id = deployment.id
          WHERE deployment.app_id = $1
            AND deployment.status = 'healthy'
            AND deployment.id <> (
                SELECT latest.deployment_id
                  FROM deployment_apply_jobs AS latest
                 WHERE latest.app_id = $1
                 ORDER BY latest.generation DESC
                 LIMIT 1
            )
         ORDER BY apply_job.generation DESC
         LIMIT 1",
    )
    .bind(app_id)
    .fetch_optional(&mut **tx)
    .await
}

/// POST /apps/{name}/rollback -- rollback to a previous deployment.
pub async fn rollback(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<RollbackRequest>,
) -> Result<(StatusCode, Json<RollbackResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;
    if let Some(error) = super::runtime_reapply_status_error(app.status) {
        return Err(json_error(StatusCode::CONFLICT, error));
    }
    // A stored-auto app must not roll back into an auto-unlock workload;
    // refuse before queueing anything.
    if app.unlock_mode == crate::models::UnlockMode::Auto {
        return Err(crate::routes::apps::auto_unlock_disabled_response());
    }

    let implicit_target = body.deployment_id.is_none();
    let prev: Deployment = if let Some(deployment_id) = body.deployment_id {
        sqlx::query_as(
            "SELECT * FROM deployments
             WHERE app_id = $1 AND id = $2 AND status = 'healthy'",
        )
        .bind(app.id)
        .bind(deployment_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({"error": "rollback target deployment not found or not healthy"}),
            ),
        ))?
    } else {
        latest_implicit_rollback_target(&state.db, app.id)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?
            .ok_or((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "no previous deployment to rollback to"})),
            ))?
    };

    let target_authority = crate::deployment_jobs::load_stored_deployment_apply_authority(
        &state.db, prev.id, app.id, app.org_id,
    )
    .await
    .map_err(|_| {
        json_error(
            StatusCode::CONFLICT,
            "rollback target has no valid immutable apply snapshot",
        )
    })?;
    let target_primary = target_authority
        .payload
        .snapshot
        .containers
        .iter()
        .find(|container| container.is_primary)
        .ok_or_else(|| {
            json_error(
                StatusCode::CONFLICT,
                "rollback target has no primary container snapshot",
            )
        })?;
    let image = target_primary.image_ref.clone();
    let image_digest = target_primary.image_digest.clone().ok_or_else(|| {
        json_error(
            StatusCode::CONFLICT,
            "rollback target primary image is not digest-pinned",
        )
    })?;
    let target_resources = target_authority.payload.snapshot.resources.clone();
    let target_profile = target_primary
        .workload_security_profile
        .as_deref()
        .unwrap_or("restricted")
        .parse::<WorkloadSecurityProfile>()
        .map_err(|_| {
            json_error(
                StatusCode::CONFLICT,
                "rollback target workload security profile is invalid",
            )
        })?;

    // Follow the immutable target job's artifact/source binding. A healthy
    // rollback generation can itself point at an older signed source; loading
    // artifacts by the operation deployment ID would silently lose that
    // authority on a rollback-of-rollback.
    let rollback_artifacts = match (
        target_authority.artifact_deployment_id,
        target_authority.artifact_descriptor_core_hash,
    ) {
        (Some(artifact_deployment_id), Some(descriptor_core_hash)) => Some(
            crate::signing_service::load_workload_artifacts_exact(
                &state.db,
                app.id,
                artifact_deployment_id,
                descriptor_core_hash,
            )
            .await
            .map_err(signing_error_response)?
            .ok_or_else(|| {
                signing_error_response(crate::signing_service::SigningServiceError::Mismatch(
                    "stored artifact binding".into(),
                ))
            })?,
        ),
        (None, None) => None,
        _ => {
            return Err(signing_error_response(
                crate::signing_service::SigningServiceError::Mismatch(
                    "stored artifact binding".into(),
                ),
            ));
        }
    };
    if rollback_artifacts.as_ref().is_some_and(|artifacts| {
        artifacts.descriptor.org_id != app.org_id
            || artifacts.descriptor.app_id != app.id
            || Some(artifacts.descriptor.deploy_id) != target_authority.artifact_deployment_id
    }) {
        return Err(signing_error_response(
            crate::signing_service::SigningServiceError::Mismatch(
                "stored descriptor identity".into(),
            ),
        ));
    }

    let signed_required = customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    );
    let rollback_signed_required = signed_required || target_authority.signed_required;
    if rollback_signed_required && rollback_artifacts.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "rollback target has no stored signed policy artifact"
            })),
        ));
    }
    let rollback_log_encryption =
        validate_log_encryption_config(target_authority.payload.log_encryption.clone())?;

    let authority_containers: Vec<crate::models::AppContainer> =
        sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC")
            .bind(app.id)
            .fetch_all(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;
    let authority_resources: crate::models::AppResources =
        sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(app.id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;
    let authority_snapshot = crate::deploy::ExistingAppAuthoritySnapshot::new(
        app.updated_at,
        authority_containers,
        authority_resources.clone(),
    );
    // Live claim evidence for the rollback target's resource sizes, computed
    // before the lanes so no kube I/O runs under them (and none at all for
    // at/above-floor sizes): a proven-initialized sub-floor claim keeps
    // operating; a missing/terminating/unproven one is a fresh format and
    // must meet the floor.
    let fresh_volume_claims =
        super::fresh_volume_claims(&state.kube_client, &app, &target_resources)
            .await
            .map_err(|_| {
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "volume provisioning state could not be verified; retry the rollback",
                )
            })?;

    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, auth.org_id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if rollback_artifacts.is_some() {
        crate::signing_service::lock_org_signing_authority_lane(&mut tx, auth.org_id)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    }
    let current_role = crate::auth::scopes::lock_and_read_active_membership_role_in_tx(
        &mut tx,
        auth.org_id,
        auth.user_id,
    )
    .await?;
    crate::auth::scopes::require_admin_role(current_role)?;
    crate::deploy::lock_app_deployment_lane(&mut tx, app.id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let current_status: crate::models::AppStatus =
        sqlx::query_scalar("SELECT status FROM apps WHERE id = $1")
            .bind(app.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if let Some(error) = super::runtime_reapply_status_error(current_status) {
        return Err(json_error(StatusCode::CONFLICT, error));
    }
    if crate::mutation_leases::desired_state_mutation_in_progress(&mut tx, app.id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "app mutation already in progress",
        ));
    }

    if implicit_target {
        let selected = latest_implicit_rollback_target_in_tx(&mut tx, app.id)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
        if selected.as_ref().map(|deployment| deployment.id) != Some(prev.id) {
            return Err(json_error(
                StatusCode::CONFLICT,
                "rollback target changed while validating; retry the rollback",
            ));
        }
    }
    let locked_target: Option<Deployment> = sqlx::query_as(
        "SELECT * FROM deployments
          WHERE id = $1
            AND app_id = $2
            AND org_id = $3
            AND status = 'healthy'::deploy_status_enum
          FOR UPDATE",
    )
    .bind(prev.id)
    .bind(app.id)
    .bind(app.org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let Some(locked_target) = locked_target else {
        return Err(json_error(
            StatusCode::CONFLICT,
            "rollback target authority changed; retry the rollback",
        ));
    };
    if locked_target.spec_snapshot != prev.spec_snapshot
        || locked_target.image_digest != prev.image_digest
        || locked_target.source_provider != prev.source_provider
        || locked_target.source_repository != prev.source_repository
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "rollback target authority changed; retry the rollback",
        ));
    }
    let locked_job = sqlx::query_as::<_, (Uuid, bool, Option<Uuid>, Option<Vec<u8>>, Vec<u8>)>(
        "SELECT source_deployment_id, signed_required,
                artifact_deployment_id, artifact_descriptor_core_hash,
                payload_sha256
           FROM deployment_apply_jobs
          WHERE deployment_id = $1
            AND app_id = $2
            AND org_id = $3
          FOR UPDATE",
    )
    .bind(prev.id)
    .bind(app.id)
    .bind(app.org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let Some((source_id, signed_required_now, artifact_id, artifact_hash, payload_hash)) =
        locked_job
    else {
        return Err(json_error(
            StatusCode::CONFLICT,
            "rollback target has no valid immutable apply snapshot",
        ));
    };
    if source_id != target_authority.source_deployment_id
        || signed_required_now != target_authority.signed_required
        || artifact_id != target_authority.artifact_deployment_id
        || artifact_hash.as_deref()
            != target_authority
                .artifact_descriptor_core_hash
                .as_ref()
                .map(|hash| hash.as_slice())
        || payload_hash.as_slice() != target_authority.payload_sha256
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "rollback target authority changed; retry the rollback",
        ));
    }
    super::enforce_authoritative_entitlement(
        &mut tx,
        auth.org_id,
        &target_resources,
        false,
        // Rollback re-applies an accepted snapshot's resources against live
        // claim evidence: surviving sub-floor claims keep operating, missing
        // or terminating ones are fresh formats and must meet the floor.
        fresh_volume_claims,
    )
    .await?;
    if let Some(artifacts) = rollback_artifacts.as_ref() {
        let signing_service_pubkey_hex = state
            .attestation
            .as_ref()
            .and_then(|config| config.signing_service_pubkey_hex.as_deref())
            .ok_or_else(|| {
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "platform signing-service pubkey required for rollback verification",
                )
            })?;
        artifacts
            .validate_stored_authority(
                &state.db,
                &app,
                &image_digest,
                &crate::auth::jwt::public_key_base64(&state.signing_key),
                signing_service_pubkey_hex,
                &crate::signing_service::descriptor_platform_binding_for(
                    &state,
                    &target_resources.memory_limit,
                )
                .map_err(signing_error_response)?,
            )
            .await
            .map_err(signing_error_response)?;
        let signed_profile =
            super::signed_descriptor_profile(&artifacts.descriptor).ok_or_else(|| {
                signing_error_response(crate::signing_service::SigningServiceError::Mismatch(
                    "workload_security_profile".to_string(),
                ))
            })?;
        if signed_profile != target_profile {
            return Err(signing_error_response(
                crate::signing_service::SigningServiceError::Mismatch(
                    "workload_security_profile".to_string(),
                ),
            ));
        }
        // #424 admission: a group-bearing signed target is refused before
        // restore_target_apply_snapshot replaces the app's stored rows (the
        // operator-rollback hazard: the app would be committed to a target
        // the worker cannot apply). The transaction is already open: return
        // the refusal and drop it — no commit, nothing written yet.
        crate::routes::platform::admit_pod_supplemental_groups(
            artifacts.descriptor.pod_supplemental_groups.as_deref(),
            crate::routes::platform::pod_supplemental_groups_supported(),
        )
        .map_err(|admission| admission.refusal())?;
    }
    if !crate::deploy::lock_and_verify_existing_app_authority(&mut tx, app.id, &authority_snapshot)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "app deployment inputs changed while rollback was validating; retry the rollback",
        ));
    }
    if super::app_has_incomplete_deployment_setup(&mut tx, app.id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "an earlier deployment is still completing setup; retry after setup is reconciled",
        ));
    }
    if !restore_target_apply_snapshot(&mut tx, app.id, &target_authority.payload.snapshot)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "rollback target has an invalid exact runtime snapshot",
        ));
    }

    let deploy_id = Uuid::new_v4();
    crate::deploy::recover_unpublished_workload_spec(
        &state.db,
        &state.kube_client,
        app.id,
        &app.namespace,
        &app.name,
        crate::deploy::PublicationRecoveryMode::BeforeSupersession,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            app_id = %app.id,
            error = %error,
            "refusing rollback supersession until workload publication can be classified"
        );
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "live workload publication could not be verified; retry the rollback",
        )
    })?;
    crate::deploy::supersede_incomplete_deployments(&mut tx, app.id)
        .await
        .map_err(|error| match error {
            crate::deploy::SupersedeDeploymentError::Busy => json_error(
                StatusCode::CONFLICT,
                "deployment mutation is still in progress; retry rollback",
            ),
            crate::deploy::SupersedeDeploymentError::Database(_) => {
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error")
            }
        })?;
    let mut rollback_spec_snapshot = prev.spec_snapshot.clone();
    rollback_spec_snapshot[DEPLOYMENT_SETUP_STATE] =
        serde_json::json!(crate::deployment_jobs::DEPLOYMENT_SETUP_ACCEPTED);
    rollback_spec_snapshot["rollback_to"] = serde_json::json!(prev.id);
    rollback_spec_snapshot["source_generation"] =
        serde_json::json!(target_authority.source_deployment_id);
    rollback_spec_snapshot["image"] = serde_json::json!(&image);
    rollback_spec_snapshot["image_digest"] = serde_json::json!(&image_digest);
    rollback_spec_snapshot["resolved_resources"] = serde_json::json!({
        "cpu": &target_resources.cpu_limit,
        "memory": &target_resources.memory_limit,
        "storage": &target_resources.app_data_size,
        "tls_storage": &target_resources.tls_data_size,
    });
    rollback_spec_snapshot["workload_security_profile"] =
        serde_json::json!(target_profile.as_str());
    rollback_spec_snapshot["log_encryption"] = serde_json::to_value(&rollback_log_encryption)
        .map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "rollback snapshot serialization failed",
            )
        })?;
    rollback_spec_snapshot["signed_descriptor_core_hash"] = serde_json::to_value(
        target_authority
            .artifact_descriptor_core_hash
            .map(hex::encode),
    )
    .map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rollback snapshot serialization failed",
        )
    })?;
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot, image_digest, source_provider, source_repository)
         VALUES ($1, $2, $3, 'rollback', $4, $5, $6, $7)",
    )
    .bind(deploy_id)
    .bind(auth.org_id)
    .bind(app.id)
    .bind(&rollback_spec_snapshot)
    .bind(Some(&image_digest))
    .bind(prev.source_provider.as_deref())
    .bind(prev.source_repository.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    super::insert_transaction_audit(
        &mut tx,
        auth.org_id,
        app.id,
        auth.user_id,
        "app.rollback",
        serde_json::json!({"rollback_to": prev.id, "deployment_id": deploy_id}),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    // Capture the exact rows restored above while this transaction still owns
    // the app lane. The new operation ID is distinct, while its immutable
    // signed source/artifact binding remains the target job's historical one.
    let apply_payload = super::build_accepted_apply_payload(
        &mut tx,
        app.id,
        state.attestation.clone(),
        crate::auth::jwt::public_key_base64(&state.signing_key),
        state.api_url.clone(),
        target_authority.artifact_deployment_id,
        target_authority.artifact_descriptor_core_hash,
        rollback_log_encryption.clone(),
        false,
    )
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if let Some(artifacts) = rollback_artifacts.as_ref() {
        let attestation = state.attestation.as_ref().ok_or_else(|| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "attestation runtime configuration required for signed rollback",
            )
        })?;
        let mut app_spec = crate::deploy::build_confidential_app_from_rows(
            &apply_payload.app,
            deploy_id,
            attestation,
            &crate::auth::jwt::public_key_base64(&state.signing_key),
            &state.api_url,
            &apply_payload.snapshot.containers,
            &apply_payload.snapshot.resources,
        )
        .map_err(|_| {
            json_error(
                StatusCode::CONFLICT,
                "rollback target workload runtime is invalid",
            )
        })?;
        app_spec.workload_artifact_binding = Some(artifacts.binding.clone());
        app_spec.log_encryption = rollback_log_encryption.clone();
        super::select_local_signed_artifact_delivery(&mut app_spec.attestation);
        let policy_sha256: [u8; 32] =
            hex::decode(&artifacts.signed_policy_artifact.agent_policy_sha256)
                .map_err(|_| {
                    signing_error_response(crate::signing_service::SigningServiceError::Mismatch(
                        "agent_policy_sha256".to_string(),
                    ))
                })?
                .try_into()
                .map_err(|_: Vec<u8>| {
                    signing_error_response(crate::signing_service::SigningServiceError::Mismatch(
                        "agent_policy_sha256".to_string(),
                    ))
                })?;
        app_spec.generated_agent_policy = Some(enclava_engine::types::GeneratedAgentPolicy {
            policy_text: artifacts.signed_policy_artifact.agent_policy_text.clone(),
            policy_sha256,
            genpolicy_version_pin: artifacts
                .signed_policy_artifact
                .metadata
                .genpolicy_version_pin
                .clone(),
        });
        // Accept either the modern render (with the log_encryption_json claim)
        // or, for artifacts signed before the claim existed, the legacy render
        // without it; a legacy match pins the app to the legacy byte layout.
        artifacts
            .validate_and_pin_cc_init_data_render(&mut app_spec)
            .map_err(signing_error_response)?;
    }
    crate::deployment_jobs::insert_ready_job(
        &mut tx,
        deploy_id,
        target_authority.source_deployment_id,
        &apply_payload,
        rollback_signed_required,
    )
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if rollback_artifacts.is_some() {
        crate::kbs::enqueue_signed_policy_reconciliation(&mut tx)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    } else {
        crate::kbs::enqueue_signed_policy_revocation_if_active(&mut tx)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    }
    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(RollbackResponse {
            deployment_id: deploy_id,
            rolled_back_to: prev.id,
            status: "deploying".to_string(),
        }),
    ))
}

#[cfg(test)]
mod exact_snapshot_tests {
    use super::*;

    async fn database_test_pool() -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect rollback regression database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate rollback regression database");
        pool
    }

    async fn insert_rollback_test_app(pool: &sqlx::PgPool) -> App {
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let app_name = format!("rollback-{}", &suffix[..12]);
        sqlx::query(
            "INSERT INTO organizations (id, name, cust_slug)
             VALUES ($1, $2, $3)",
        )
        .bind(org_id)
        .bind(format!("rollback-test-{suffix}"))
        .bind(&suffix[..8])
        .execute(pool)
        .await
        .expect("insert rollback test organization");
        sqlx::query(
            "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, domain, tee_domain,
                 status
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 'running'::app_status_enum
             )",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(&app_name)
        .bind(format!("cap-{app_name}"))
        .bind(format!("instance-{suffix}"))
        .bind(&suffix[..8])
        .bind(format!("cap-{app_name}-sa"))
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind(format!("{app_name}.{}.enclava.dev", &suffix[..8]))
        .bind(format!("{app_name}.{}.tee.enclava.dev", &suffix[..8]))
        .execute(pool)
        .await
        .expect("insert rollback test app");
        sqlx::query(
            "INSERT INTO app_containers (
                 id, app_id, name, image_ref, image_digest, port, command,
                 storage_paths, workload_security_profile, is_primary
             ) VALUES ($1, $2, 'web', $3, $4, 9999, $5, $6, $7, true)",
        )
        .bind(Uuid::new_v4())
        .bind(app_id)
        .bind(format!("ghcr.io/acme/current@sha256:{}", "cc".repeat(32)))
        .bind(format!("sha256:{}", "cc".repeat(32)))
        .bind("[\"/current\"]")
        .bind(vec!["/current-data".to_string()])
        .bind("restricted")
        .execute(pool)
        .await
        .expect("insert current rollback container");
        sqlx::query(
            "INSERT INTO app_resources (
                 app_id, cpu_limit, memory_limit, app_data_size, tls_data_size
             ) VALUES ($1, '8', '8Gi', '80Gi', '8Gi')",
        )
        .bind(app_id)
        .execute(pool)
        .await
        .expect("insert current rollback resources");
        sqlx::query_as("SELECT * FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(pool)
            .await
            .expect("load rollback test app")
    }

    fn exact_target_snapshot(app_id: Uuid, signed: bool) -> crate::deploy::DeploymentApplySnapshot {
        let marker = if signed { "signed" } else { "unsigned" };
        crate::deploy::DeploymentApplySnapshot::new(
            vec![AppContainer {
                id: Uuid::new_v4(),
                app_id,
                name: "web".to_string(),
                image_ref: format!(
                    "ghcr.io/acme/{marker}@sha256:{}",
                    if signed { "aa" } else { "bb" }.repeat(32)
                ),
                image_digest: Some(format!(
                    "sha256:{}",
                    if signed { "aa" } else { "bb" }.repeat(32)
                )),
                port: Some(if signed { 8443 } else { 8080 }),
                command: Some(format!("[\"/{marker}-target\",\"--serve\"]")),
                storage_paths: Some(vec![format!("/{marker}-data"), "/shared".to_string()]),
                workload_security_profile: Some(
                    if signed { "restricted" } else { "rootful-sudo" }.to_string(),
                ),
                is_primary: true,
            }],
            AppResources {
                app_id,
                cpu_limit: if signed { "2" } else { "1" }.to_string(),
                memory_limit: if signed { "3Gi" } else { "2Gi" }.to_string(),
                app_data_size: if signed { "7Gi" } else { "6Gi" }.to_string(),
                tls_data_size: "2Gi".to_string(),
            },
        )
    }

    async fn insert_generation(pool: &sqlx::PgPool, app: &App, status: &str) -> Uuid {
        let deployment_id = Uuid::new_v4();
        let snapshot = exact_target_snapshot(app.id, false);
        let digest = snapshot.containers[0]
            .image_digest
            .clone()
            .expect("target digest");
        let payload = crate::deployment_jobs::DeploymentApplyJobPayload::new(
            app.clone(),
            snapshot,
            None,
            "test-api-key".to_string(),
            "https://api.example.test".to_string(),
            None,
            None,
            None,
            false,
        );
        let mut tx = pool.begin().await.expect("begin rollback generation");
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, trigger, spec_snapshot, image_digest
             ) VALUES ($1, $2, $3, 'api', $4, $5)",
        )
        .bind(deployment_id)
        .bind(app.org_id)
        .bind(app.id)
        .bind(serde_json::json!({
            "image": &payload.snapshot.containers[0].image_ref,
            "image_digest": &digest,
            "signed_descriptor_core_hash": null,
            "log_encryption": null,
            "setup_state": crate::deployment_jobs::DEPLOYMENT_SETUP_ACCEPTED,
        }))
        .bind(&digest)
        .execute(&mut *tx)
        .await
        .expect("insert rollback generation deployment");
        crate::deployment_jobs::insert_ready_job(
            &mut tx,
            deployment_id,
            deployment_id,
            &payload,
            false,
        )
        .await
        .expect("insert rollback generation job");
        sqlx::query(
            "UPDATE deployments
                SET status = $2::deploy_status_enum,
                    completed_at = clock_timestamp(),
                    error_message = CASE
                        WHEN $2 = 'failed' THEN 'deployment_apply_failed'
                        ELSE NULL
                    END
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(status)
        .execute(&mut *tx)
        .await
        .expect("terminalize rollback generation");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = CASE WHEN $2 = 'failed' THEN 'failed' ELSE 'completed' END,
                    last_error_code = CASE
                        WHEN $2 = 'failed' THEN 'deployment_apply_failed'
                        ELSE NULL
                    END,
                    updated_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .bind(status)
        .execute(&mut *tx)
        .await
        .expect("terminalize rollback generation job");
        tx.commit().await.expect("commit rollback generation");
        deployment_id
    }

    /// #424 T2 fixture authority: the owner key that signs the descriptor
    /// and the org keyring, plus the DB rows that make it a stored signer.
    struct GroupBearingAuthority {
        owner_key: ed25519_dalek::SigningKey,
        user_id: Uuid,
        signing_key_id: Uuid,
        member_added_at: chrono::DateTime<chrono::Utc>,
    }

    fn signed_test_keyring(
        org_id: Uuid,
        authority: &GroupBearingAuthority,
        version: u64,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> (serde_json::Value, serde_json::Value, Vec<u8>) {
        use ed25519_dalek::Signer as _;
        use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
        let pubkey = authority.owner_key.verifying_key().to_bytes();
        let added_at = authority.member_added_at.to_rfc3339();
        let member_hash = ce_v1_hash(&[
            ("user_id", authority.user_id.as_bytes().as_slice()),
            ("pubkey", pubkey.as_slice()),
            ("role", b"owner"),
            ("added_at", added_at.as_bytes()),
        ]);
        let user_id_label = authority.user_id.to_string();
        let members_hash = ce_v1_hash(&[(user_id_label.as_str(), member_hash.as_slice())]);
        let version_bytes = version.to_be_bytes();
        let updated_at_text = updated_at.to_rfc3339();
        let canonical = ce_v1_bytes(&[
            ("purpose", b"enclava-org-keyring-v1"),
            ("org_id", org_id.as_bytes().as_slice()),
            ("version", &version_bytes),
            ("members", &members_hash),
            ("updated_at", updated_at_text.as_bytes()),
        ]);
        let signature = authority.owner_key.sign(&canonical).to_bytes().to_vec();
        let keyring = serde_json::json!({
            "org_id": org_id,
            "version": version,
            "members": [{
                "user_id": authority.user_id,
                "pubkey": hex::encode(pubkey),
                "role": "owner",
                "added_at": authority.member_added_at,
            }],
            "updated_at": updated_at,
        });
        let envelope = serde_json::json!({
            "keyring": keyring,
            "signature": hex::encode(&signature),
            "signing_pubkey": hex::encode(pubkey),
        });
        (keyring, envelope, signature)
    }

    async fn insert_test_keyring_version(
        pool: &sqlx::PgPool,
        org_id: Uuid,
        authority: &GroupBearingAuthority,
        version: u64,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> serde_json::Value {
        let (keyring, envelope, signature) =
            signed_test_keyring(org_id, authority, version, updated_at);
        sqlx::query(
            "INSERT INTO org_keyrings (
                 org_id, version, keyring_payload, signature, signing_key_id
             ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(org_id)
        .bind(version as i64)
        .bind(serde_json::to_vec(&keyring).expect("serialize test keyring"))
        .bind(signature)
        .bind(authority.signing_key_id)
        .execute(pool)
        .await
        .expect("insert test keyring version");
        envelope
    }

    /// #424 T2: turn `insert_job_fixture`'s unsigned deployment into a
    /// healthy target whose stored signed descriptor carries
    /// `pod_supplemental_groups`, so `rollback` reaches the admission
    /// decision with a group-bearing authority to refuse. The shape mirrors
    /// deployment_jobs.rs's signed rollback fixture (the same production
    /// adapters: decode_optional_blobs, cc_init_data, the policy artifact
    /// contract), with the one field under test added.
    async fn mark_group_bearing_signed_healthy_target(
        pool: &sqlx::PgPool,
        deployment_id: Uuid,
        mut payload: crate::deployment_jobs::DeploymentApplyJobPayload,
        state: &mut crate::state::AppState,
    ) {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        use ed25519_dalek::Signer as _;
        use enclava_common::descriptor::descriptor_core_hash;
        use enclava_engine::types::{GeneratedAgentPolicy, WorkloadArtifactBinding};
        use sha2::{Digest, Sha256};

        payload.app.signer_identity_subject = Some(
            "https://github.com/acme/app/.github/workflows/deploy.yml@refs/heads/main".to_string(),
        );
        payload.app.signer_identity_issuer =
            Some("https://token.actions.githubusercontent.com".to_string());
        payload.app.signer_identity_set_at = Some(chrono::Utc::now());
        sqlx::query(
            "UPDATE apps
                SET signer_identity_subject = $2,
                    signer_identity_issuer = $3,
                    signer_identity_set_at = $4
              WHERE id = $1",
        )
        .bind(payload.app.id)
        .bind(payload.app.signer_identity_subject.as_deref())
        .bind(payload.app.signer_identity_issuer.as_deref())
        .bind(payload.app.signer_identity_set_at)
        .execute(pool)
        .await
        .expect("record cap424 fixture identity");
        let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x41; 32]);
        let platform_key = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]);
        let user_id = Uuid::new_v4();
        let signing_key_id = Uuid::new_v4();
        let member_added_at = chrono::Utc::now();
        let authority = GroupBearingAuthority {
            owner_key,
            user_id,
            signing_key_id,
            member_added_at,
        };
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'cap424 signer')")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("insert cap424 signer user");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner'::role_enum)",
        )
        .bind(user_id)
        .bind(payload.app.org_id)
        .execute(pool)
        .await
        .expect("insert cap424 signer membership");
        sqlx::query(
            "INSERT INTO user_signing_keys (id, user_id, pubkey)
             VALUES ($1, $2, $3)",
        )
        .bind(signing_key_id)
        .bind(user_id)
        .bind(authority.owner_key.verifying_key().to_bytes().to_vec())
        .execute(pool)
        .await
        .expect("insert cap424 signer key");
        let keyring_envelope =
            insert_test_keyring_version(pool, payload.app.org_id, &authority, 1, member_added_at)
                .await;

        let platform_pubkey_hex = hex::encode(platform_key.verifying_key().to_bytes());
        state
            .attestation
            .as_mut()
            .expect("cap424 fixture attestation")
            .signing_service_pubkey_hex = Some(platform_pubkey_hex.clone());
        state.require_customer_signed_policy_artifact = true;
        payload.attestation_config = state.attestation.clone();

        let image_digest = payload.snapshot.containers[0]
            .image_digest
            .clone()
            .expect("cap424 fixture image digest");
        let agent_policy_text =
            "package agent_policy\n\ndefault CreateContainerRequest := true\n".to_string();
        let rego_text = "package policy\n\ndefault allow := false\n".to_string();
        let agent_policy_hash: [u8; 32] = Sha256::digest(agent_policy_text.as_bytes()).into();
        let rego_hash: [u8; 32] = Sha256::digest(rego_text.as_bytes()).into();
        use enclava_common::descriptor::{
            Capabilities, DeploymentDescriptor, OciRuntimeSpec, Resources, SecurityContext,
            Sidecars, SignerIdentity,
        };
        let mut descriptor = DeploymentDescriptor {
            pod_supplemental_groups: Some(vec![0, 6]),
            schema_version: "v1".to_string(),
            org_id: payload.app.org_id,
            org_slug: payload.app.tenant_id.clone(),
            app_id: payload.app.id,
            app_name: payload.app.name.clone(),
            deploy_id: deployment_id,
            created_at: chrono::Utc::now(),
            nonce: [0x13; 32],
            app_domain: payload.app.domain.clone(),
            tee_domain: payload
                .app
                .tee_domain
                .clone()
                .unwrap_or_else(|| payload.app.domain.clone()),
            custom_domains: payload.app.custom_domain.clone().into_iter().collect(),
            namespace: payload.app.namespace.clone(),
            service_account: payload.app.service_account.clone(),
            identity_hash: hex::decode(&payload.app.tenant_instance_identity_hash)
                .expect("decode fixture identity hash")
                .try_into()
                .expect("fixture identity hash length"),
            image_ref: format!("ghcr.io/acme/app@{image_digest}"),
            image_digest: image_digest.clone(),
            signer_identity: SignerIdentity {
                subject: payload
                    .app
                    .signer_identity_subject
                    .clone()
                    .unwrap_or_default(),
                issuer: payload
                    .app
                    .signer_identity_issuer
                    .clone()
                    .unwrap_or_default(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec![
                    enclava_engine::manifest::containers::ENCLAVA_WAIT_EXEC_PATH.to_string(),
                ],
                args: vec!["/usr/local/bin/app".to_string()],
                env: vec![],
                ports: vec![],
                mounts: vec![],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest: format!("sha256:{}", "11".repeat(32)),
                caddy_digest: format!("sha256:{}", "22".repeat(32)),
            },
            api_signing_pubkey: payload.api_signing_pubkey.clone(),
            independent_verification: true,
            expected_firmware_measurement: [3; 32].into(),
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: format!(
                "default/{}-{}-owner/seed-encrypted",
                payload.app.namespace, payload.app.name
            ),
            unlock_mode: "password".to_string(),
            policy_template_id: "enclava-kbs-policy-v1".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "cap-test".to_string(),
            expected_agent_policy_hash: agent_policy_hash,
            expected_cc_init_data_hash: [0; 32],
            expected_kbs_policy_hash: rego_hash,
        };
        let descriptor_hash = descriptor_core_hash(&descriptor);
        let provisional_descriptor_blob = serde_json::json!({
            "descriptor": descriptor,
            "signature": hex::encode(
                authority
                    .owner_key
                    .sign(&enclava_common::descriptor::descriptor_canonical_bytes(&descriptor))
                    .to_bytes()
            ),
            "signing_key_id": "cap424-owner",
            "signing_pubkey": hex::encode(authority.owner_key.verifying_key().to_bytes()),
        })
        .to_string();
        let provisional = crate::signing_service::decode_optional_blobs(
            Some(provisional_descriptor_blob),
            Some(keyring_envelope.to_string()),
        )
        .expect("decode cap424 provisional signed fixture")
        .expect("cap424 provisional signed fixture exists");
        let binding = provisional.binding();
        assert_eq!(binding.descriptor_core_hash, descriptor_hash);

        let mut app_spec = crate::deploy::build_confidential_app_from_rows(
            &payload.app,
            deployment_id,
            payload
                .attestation_config
                .as_ref()
                .expect("cap424 fixture payload attestation"),
            &payload.api_signing_pubkey,
            &payload.api_url,
            &payload.snapshot.containers,
            &payload.snapshot.resources,
        )
        .expect("build cap424 signed fixture runtime");
        app_spec.workload_artifact_binding = Some(WorkloadArtifactBinding {
            descriptor_core_hash: binding.descriptor_core_hash,
            descriptor_signing_pubkey: binding.descriptor_signing_pubkey,
            org_keyring_fingerprint: binding.org_keyring_fingerprint,
            omit_log_encryption_claim: false,
            legacy_collapsed_trustee_key: false,
            omit_luks2_header_seal_claim: false,
            omit_log_spool_bind_claim: false,
        });
        crate::routes::deployments::select_local_signed_artifact_delivery(
            &mut app_spec.attestation,
        );
        app_spec.generated_agent_policy = Some(GeneratedAgentPolicy {
            policy_text: agent_policy_text.clone(),
            policy_sha256: agent_policy_hash,
            genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
        });
        let (_, cc_init_data_hash) =
            enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app_spec);
        descriptor.expected_cc_init_data_hash = hex::decode(cc_init_data_hash)
            .expect("decode cap424 fixture cc-init hash")
            .try_into()
            .expect("cap424 fixture cc-init hash length");

        let descriptor_signature =
            authority
                .owner_key
                .sign(&enclava_common::descriptor::descriptor_canonical_bytes(
                    &descriptor,
                ));
        let descriptor_blob = serde_json::json!({
            "descriptor": descriptor,
            "signature": hex::encode(descriptor_signature.to_bytes()),
            "signing_key_id": "cap424-owner",
            "signing_pubkey": hex::encode(authority.owner_key.verifying_key().to_bytes()),
        })
        .to_string();
        let artifacts = crate::signing_service::decode_optional_blobs(
            Some(descriptor_blob),
            Some(keyring_envelope.to_string()),
        )
        .expect("decode cap424 signed fixture")
        .expect("cap424 signed fixture exists");
        artifacts
            .validate_customer_authority(pool)
            .await
            .expect("validate cap424 signed fixture authority");

        let metadata = crate::signing_service::PolicyMetadata {
            app_id: payload.app.id.to_string(),
            deploy_id: deployment_id.to_string(),
            descriptor_core_hash: hex::encode(artifacts.descriptor_core_hash),
            descriptor_signing_pubkey: hex::encode(artifacts.descriptor_signing_pubkey),
            platform_release_version: artifacts.descriptor.platform_release_version.clone(),
            policy_template_id: artifacts.descriptor.policy_template_id.clone(),
            policy_template_sha256: hex::encode(artifacts.descriptor.policy_template_sha256),
            agent_policy_sha256: hex::encode(agent_policy_hash),
            genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
            signed_at: "2026-07-17T00:00:00+00:00".to_string(),
            key_id: "cap424-policy-key".to_string(),
        };
        let metadata_hash = enclava_common::canonical::ce_v1_hash(&[
            ("app_id", payload.app.id.as_bytes().as_slice()),
            ("deploy_id", deployment_id.as_bytes().as_slice()),
            ("descriptor_core_hash", &artifacts.descriptor_core_hash),
            (
                "descriptor_signing_pubkey",
                &artifacts.descriptor_signing_pubkey,
            ),
            (
                "platform_release_version",
                metadata.platform_release_version.as_bytes(),
            ),
            ("policy_template_id", metadata.policy_template_id.as_bytes()),
            (
                "policy_template_sha256",
                &artifacts.descriptor.policy_template_sha256,
            ),
            ("agent_policy_sha256", &agent_policy_hash),
            (
                "genpolicy_version_pin",
                metadata.genpolicy_version_pin.as_bytes(),
            ),
            ("signed_at", metadata.signed_at.as_bytes()),
            ("key_id", metadata.key_id.as_bytes()),
        ]);
        let signing_input = enclava_common::canonical::ce_v1_bytes(&[
            ("purpose", b"enclava-policy-artifact-v1"),
            ("metadata", &metadata_hash),
            ("rego_sha256", &rego_hash),
        ]);
        let mut signed_policy_artifact = crate::signing_service::SignedPolicyArtifact {
            metadata,
            rego_text,
            rego_sha256: hex::encode(rego_hash),
            agent_policy_text,
            agent_policy_sha256: hex::encode(agent_policy_hash),
            signature: hex::encode(platform_key.sign(&signing_input).to_bytes()),
            verify_pubkey_b64: B64.encode(platform_key.verifying_key().to_bytes()),
            org_keyring: None,
        };
        artifacts
            .validate_signed_artifact(&signed_policy_artifact, &platform_pubkey_hex)
            .expect("validate cap424 signed fixture policy");
        artifacts
            .attach_customer_authority(&mut signed_policy_artifact)
            .expect("attach cap424 signed fixture authority");

        payload.artifact_deployment_id = Some(deployment_id);
        payload.artifact_descriptor_core_hash = Some(artifacts.descriptor_core_hash);
        let mut tx = pool.begin().await.expect("begin cap424 signed target");
        sqlx::query("DELETE FROM deployments WHERE id = $1")
            .bind(deployment_id)
            .execute(&mut *tx)
            .await
            .expect("delete unsigned target before cap424 recreation");
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, trigger, status, spec_snapshot, image_digest
             ) VALUES (
                 $1, $2, $3, 'api'::trigger_enum, 'pending'::deploy_status_enum, $4, $5
             )",
        )
        .bind(deployment_id)
        .bind(payload.app.org_id)
        .bind(payload.app.id)
        .bind(serde_json::json!({
            "image": &payload.snapshot.containers[0].image_ref,
            "image_digest": &image_digest,
            "signed_descriptor_core_hash": hex::encode(artifacts.descriptor_core_hash),
            "log_encryption": serde_json::Value::Null,
            "setup_state": crate::deployment_jobs::DEPLOYMENT_SETUP_ACCEPTED,
        }))
        .bind(&image_digest)
        .execute(&mut *tx)
        .await
        .expect("insert cap424 signed target deployment");
        crate::signing_service::insert_workload_artifact_fixture(
            &mut tx,
            payload.app.id,
            deployment_id,
            &artifacts,
            &signed_policy_artifact,
        )
        .await
        .expect("persist cap424 signed fixture");
        crate::deployment_jobs::insert_setup_job(
            &mut tx,
            deployment_id,
            deployment_id,
            &payload,
            true,
            None,
        )
        .await
        .expect("insert cap424 signed durable job");
        sqlx::query(
            "UPDATE deployments SET status = 'healthy', completed_at = now() WHERE id = $1",
        )
        .bind(deployment_id)
        .execute(&mut *tx)
        .await
        .expect("mark cap424 target healthy");
        sqlx::query(
            "UPDATE deployment_apply_jobs SET state = 'completed' WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&mut *tx)
        .await
        .expect("complete cap424 target job");
        tx.commit().await.expect("commit cap424 signed target");
    }

    #[tokio::test]
    async fn group_bearing_signed_rollback_target_is_refused_before_persistence() {
        // T2 (#424): with the capability off (the default — the variable is
        // unset in this process), a healthy rollback target whose stored
        // signed descriptor declares pod supplemental groups is refused with
        // the admission code BEFORE restore_target_apply_snapshot replaces
        // the app's stored rows.
        let _gate_lock = crate::test_support::POD_SUPPLEMENTAL_GROUPS_GATE_LOCK
            .lock()
            .await;
        let (_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap424_rollback").await;
        let (app, source_id, _lease, mut payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        payload.api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
        payload.api_url = state.api_url.clone();
        mark_group_bearing_signed_healthy_target(&pool, source_id, payload, &mut state).await;
        sqlx::query("UPDATE apps SET status = 'running' WHERE id = $1")
            .bind(app.id)
            .execute(&pool)
            .await
            .expect("mark cap424 app running");

        let before: serde_json::Value = sqlx::query_scalar::<_, sqlx::types::Json<serde_json::Value>>(
            "SELECT jsonb_build_object(
                'apps', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM apps a WHERE a.id = $1),
                'app_containers', (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.id), '[]'::jsonb)
                                     FROM app_containers c WHERE c.app_id = $1),
                'app_resources', (SELECT to_jsonb(r) FROM app_resources r WHERE r.app_id = $1),
                'deployments', (SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id), '[]'::jsonb)
                                  FROM deployments d WHERE d.app_id = $1),
                'jobs', (SELECT coalesce(jsonb_agg(to_jsonb(j) ORDER BY j.deployment_id, j.generation), '[]'::jsonb)
                           FROM deployment_apply_jobs j WHERE j.app_id = $1),
                'audit', (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.id), '[]'::jsonb)
                            FROM audit_log x WHERE x.app_id = $1)
            )",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("snapshot rows before rollback")
        .0;

        let auth_user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'cap424 caller')")
            .bind(auth_user_id)
            .execute(&pool)
            .await
            .expect("insert cap424 caller user");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner'::role_enum)",
        )
        .bind(auth_user_id)
        .bind(app.org_id)
        .execute(&pool)
        .await
        .expect("insert cap424 caller membership");
        let result = super::rollback(
            crate::auth::middleware::AuthContext {
                user_id: auth_user_id,
                org_id: app.org_id,
                org_name: "cap424-rollback-test".to_string(),
                role: crate::models::Role::Owner,
                api_key: None,
                management_origin: crate::auth::middleware::ManagementOrigin::Public,
            },
            axum::extract::State(state),
            axum::extract::Path(app.name.clone()),
            axum::Json(super::RollbackRequest {
                deployment_id: Some(source_id),
            }),
        )
        .await;
        let (status, axum::Json(body)) =
            result.expect_err("group-bearing target must refuse the rollback");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            body["code"], "pod_supplemental_groups_not_supported",
            "the refusal body carries the admission code"
        );

        let after: serde_json::Value = sqlx::query_scalar::<_, sqlx::types::Json<serde_json::Value>>(
            "SELECT jsonb_build_object(
                'apps', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM apps a WHERE a.id = $1),
                'app_containers', (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.id), '[]'::jsonb)
                                     FROM app_containers c WHERE c.app_id = $1),
                'app_resources', (SELECT to_jsonb(r) FROM app_resources r WHERE r.app_id = $1),
                'deployments', (SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id), '[]'::jsonb)
                                  FROM deployments d WHERE d.app_id = $1),
                'jobs', (SELECT coalesce(jsonb_agg(to_jsonb(j) ORDER BY j.deployment_id, j.generation), '[]'::jsonb)
                           FROM deployment_apply_jobs j WHERE j.app_id = $1),
                'audit', (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.id), '[]'::jsonb)
                            FROM audit_log x WHERE x.app_id = $1)
            )",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("snapshot rows after rollback")
        .0;
        assert_eq!(
            before, after,
            "a refused rollback must leave every row byte-identical"
        );
    }

    #[tokio::test]
    async fn group_bearing_signed_rollback_target_is_admitted_when_the_gate_is_on() {
        // T3, rollback control (#424): with the capability on, the same
        // healthy group-bearing target is admitted exactly as before the
        // admission existed — the rollback is accepted (201) and proceeds.
        let _gate_lock = crate::test_support::POD_SUPPLEMENTAL_GROUPS_GATE_LOCK
            .lock()
            .await;
        let _gate = crate::test_support::PodSupplementalGroupsGateGuard::enable();
        let (_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap424_rollback_on").await;
        let (app, source_id, _lease, mut payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        payload.api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
        payload.api_url = state.api_url.clone();
        mark_group_bearing_signed_healthy_target(&pool, source_id, payload, &mut state).await;
        sqlx::query("UPDATE apps SET status = 'running' WHERE id = $1")
            .bind(app.id)
            .execute(&pool)
            .await
            .expect("mark cap424-on app running");
        let auth_user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'cap424-on caller')")
            .bind(auth_user_id)
            .execute(&pool)
            .await
            .expect("insert cap424-on caller user");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner'::role_enum)",
        )
        .bind(auth_user_id)
        .bind(app.org_id)
        .execute(&pool)
        .await
        .expect("insert cap424-on caller membership");
        let (status, axum::Json(accepted)) = super::rollback(
            crate::auth::middleware::AuthContext {
                user_id: auth_user_id,
                org_id: app.org_id,
                org_name: "cap424-rollback-on-test".to_string(),
                role: crate::models::Role::Owner,
                api_key: None,
                management_origin: crate::auth::middleware::ManagementOrigin::Public,
            },
            axum::extract::State(state),
            axum::extract::Path(app.name.clone()),
            axum::Json(super::RollbackRequest {
                deployment_id: Some(source_id),
            }),
        )
        .await
        .expect("gate on: the group-bearing rollback target is admitted");
        assert_eq!(status, axum::http::StatusCode::CREATED);
        assert_eq!(accepted.rolled_back_to, source_id);
    }

    #[tokio::test]
    async fn restores_exact_signed_and_unsigned_command_storage_profile_and_resources() {
        let pool = database_test_pool().await;
        for signed in [false, true] {
            let app = insert_rollback_test_app(&pool).await;
            let target = exact_target_snapshot(app.id, signed);
            let mut tx = pool.begin().await.expect("begin exact target restore");
            crate::deploy::lock_app_deployment_lane(&mut tx, app.id)
                .await
                .expect("lock exact target app lane");
            assert!(
                restore_target_apply_snapshot(&mut tx, app.id, &target)
                    .await
                    .expect("restore exact target snapshot")
            );
            tx.commit().await.expect("commit exact target restore");

            let restored_containers: Vec<AppContainer> = sqlx::query_as(
                "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC, id",
            )
            .bind(app.id)
            .fetch_all(&pool)
            .await
            .expect("load restored target containers");
            let restored_resources: AppResources =
                sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
                    .bind(app.id)
                    .fetch_one(&pool)
                    .await
                    .expect("load restored target resources");
            assert_eq!(restored_containers, target.containers);
            assert_eq!(restored_resources, target.resources);

            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(app.org_id)
                .execute(&pool)
                .await
                .expect("delete exact rollback fixture");
        }
    }

    #[tokio::test]
    async fn implicit_target_excludes_only_the_latest_accepted_generation() {
        let pool = database_test_pool().await;
        let app = insert_rollback_test_app(&pool).await;
        let oldest_healthy = insert_generation(&pool, &app, "healthy").await;
        let newest_healthy = insert_generation(&pool, &app, "healthy").await;
        let latest_failed = insert_generation(&pool, &app, "failed").await;

        let selected_after_failure = latest_implicit_rollback_target(&pool, app.id)
            .await
            .expect("select target after failed latest generation")
            .expect("healthy recovery target exists");
        assert_eq!(selected_after_failure.id, newest_healthy);
        assert_ne!(selected_after_failure.id, oldest_healthy);
        assert_ne!(selected_after_failure.id, latest_failed);

        let latest_healthy = insert_generation(&pool, &app, "healthy").await;
        let selected_after_success = latest_implicit_rollback_target(&pool, app.id)
            .await
            .expect("select target after healthy latest generation")
            .expect("previous healthy target exists");
        assert_eq!(selected_after_success.id, newest_healthy);
        assert_ne!(selected_after_success.id, latest_healthy);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete implicit rollback target fixture");
    }
}
