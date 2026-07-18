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
    if app.status == crate::models::AppStatus::Deleting {
        return Err(json_error(
            StatusCode::CONFLICT,
            "app deletion is in progress",
        ));
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
    let current_role =
        crate::auth::scopes::active_membership_role_in_tx(&mut tx, auth.org_id, auth.user_id)
            .await?;
    crate::auth::scopes::require_admin_role(current_role)?;
    crate::deploy::lock_app_deployment_lane(&mut tx, app.id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

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
    super::enforce_authoritative_entitlement(&mut tx, auth.org_id, &target_resources, false)
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
        let (_encoded, cc_init_data_hash) =
            enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app_spec);
        artifacts
            .validate_rendered_cc_init_data_hash(&cc_init_data_hash)
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
