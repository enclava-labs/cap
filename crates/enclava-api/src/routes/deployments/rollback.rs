use super::*;

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
        sqlx::query_as(
            "SELECT * FROM deployments
             WHERE app_id = $1 AND status = 'healthy'
             ORDER BY created_at DESC
             OFFSET 1 LIMIT 1",
        )
        .bind(app.id)
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
            Json(serde_json::json!({"error": "no previous deployment to rollback to"})),
        ))?
    };

    let image = prev
        .spec_snapshot
        .get("image")
        .and_then(serde_json::Value::as_str)
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "rollback target is missing image in spec snapshot"})),
        ))?
        .to_string();
    let image_digest = prev.image_digest.clone().ok_or((
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "rollback target is missing image digest"})),
    ))?;

    // Load and validate the unique authoritative row once before mutating the
    // app. The durable worker later reloads this exact hash/app/deployment
    // binding from its immutable payload.
    let rollback_artifacts =
        crate::signing_service::load_workload_artifacts_for_deployment(&state.db, app.id, prev.id)
            .await
            .map_err(signing_error_response)?;
    if rollback_artifacts
        .as_ref()
        .is_some_and(|artifacts| artifacts.descriptor.org_id != app.org_id)
    {
        return Err(signing_error_response(
            crate::signing_service::SigningServiceError::Mismatch(
                "stored descriptor org_id".into(),
            ),
        ));
    }

    let signed_required = customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    );
    if signed_required && rollback_artifacts.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "rollback target has no stored signed policy artifact"
            })),
        ));
    }
    let rollback_workload_command = match rollback_artifacts.as_ref() {
        Some(artifacts) => {
            crate::deploy::serialize_workload_command(&artifacts.descriptor.oci_runtime_spec.args)
                .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "command serialization error"})),
                )
            })?
        }
        None => None,
    };
    let rollback_container_port = rollback_artifacts
        .as_ref()
        .and_then(|artifacts| crate::deploy::descriptor_primary_port(&artifacts.descriptor));
    let rollback_storage_paths = rollback_artifacts
        .as_ref()
        .map(|artifacts| crate::deploy::descriptor_storage_paths(&artifacts.descriptor));
    if signed_required && rollback_workload_command.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "rollback target has no signed workload command"
            })),
        ));
    }

    let rollback_log_encryption = serde_json::from_value::<Option<LogEncryptionConfig>>(
        prev.spec_snapshot
            .get("log_encryption")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "rollback target has invalid log encryption snapshot",
        )
    })?;
    let rollback_log_encryption = validate_log_encryption_config(rollback_log_encryption)?;

    let container_name = "web";
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;
    sqlx::query(
        "UPDATE app_containers
         SET image_ref = $1,
             image_digest = $2,
             command = COALESCE($3, command),
             port = COALESCE($4, port),
             storage_paths = COALESCE($5, storage_paths)
         WHERE app_id = $6 AND name = $7",
    )
    .bind(&image)
    .bind(Some(&image_digest))
    .bind(rollback_workload_command.as_ref())
    .bind(rollback_container_port)
    .bind(rollback_storage_paths.as_ref())
    .bind(app.id)
    .bind(container_name)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    let deploy_id = Uuid::new_v4();
    let mut rollback_spec_snapshot = prev.spec_snapshot.clone();
    rollback_spec_snapshot[DEPLOYMENT_SETUP_STATE] =
        serde_json::json!(crate::deployment_jobs::DEPLOYMENT_SETUP_ACCEPTED);
    rollback_spec_snapshot["rollback_to"] = serde_json::json!(prev.id);
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot, image_digest, source_provider, source_repository)
         VALUES ($1, $2, $3, 'rollback', $4, $5, $6, $7)",
    )
    .bind(deploy_id)
    .bind(auth.org_id)
    .bind(app.id)
    .bind(&rollback_spec_snapshot)
    .bind(&prev.image_digest)
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

    // Capture the rollback rows while this transaction still owns the target
    // container lock; later deploys cannot alter this queued apply snapshot.
    let apply_containers: Vec<crate::models::AppContainer> =
        sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC")
            .bind(app.id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;
    let apply_resources: crate::models::AppResources =
        sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(app.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;
    let apply_payload = crate::deployment_jobs::DeploymentApplyJobPayload::new(
        app.clone(),
        crate::deploy::DeploymentApplySnapshot::new(apply_containers, apply_resources),
        state.attestation.clone(),
        crate::auth::jwt::public_key_base64(&state.signing_key),
        state.api_url.clone(),
        rollback_artifacts.as_ref().map(|_| prev.id),
        rollback_artifacts
            .as_ref()
            .map(|artifacts| artifacts.descriptor_core_hash),
        rollback_log_encryption,
        false,
    );
    crate::deployment_jobs::insert_ready_job(
        &mut tx,
        deploy_id,
        prev.id,
        &apply_payload,
        signed_required,
    )
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
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
