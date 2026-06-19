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

    let rollback_artifact =
        crate::signing_service::load_workload_artifact_binding(&state.db, app.id, prev.id)
            .await
            .map_err(signing_error_response)?;
    let rollback_descriptor =
        crate::signing_service::load_workload_descriptor(&state.db, app.id, prev.id)
            .await
            .map_err(signing_error_response)?;

    if customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    ) && rollback_artifact.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "rollback target has no stored signed policy artifact"
            })),
        ));
    }

    let rollback_workload_command = match rollback_descriptor.as_ref() {
        Some(descriptor) => crate::deploy::serialize_workload_command(
            &descriptor.oci_runtime_spec.args,
        )
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "command serialization error"})),
            )
        })?,
        None => None,
    };
    let rollback_container_port = rollback_descriptor
        .as_ref()
        .and_then(crate::deploy::descriptor_primary_port);
    let rollback_storage_paths = rollback_descriptor
        .as_ref()
        .map(crate::deploy::descriptor_storage_paths);
    if customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    ) && rollback_workload_command.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "rollback target has no signed workload command"
            })),
        ));
    }

    let container_name = "web";
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
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    let deploy_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot, image_digest, source_provider, source_repository)
         VALUES ($1, $2, $3, 'rollback', $4, $5, $6, $7)",
    )
    .bind(deploy_id)
    .bind(auth.org_id)
    .bind(app.id)
    .bind(&prev.spec_snapshot)
    .bind(&prev.image_digest)
    .bind(prev.source_provider.as_deref())
    .bind(prev.source_repository.as_deref())
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    // Audit
    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail) VALUES ($1, $2, $3, 'app.rollback', $4)",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .bind(serde_json::json!({"rollback_to": prev.id, "deployment_id": deploy_id}))
    .execute(&state.db)
    .await;

    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    let local_verification_artifacts =
        crate::signing_service::load_workload_artifacts_json(&state.db, app.id, prev.id)
            .await
            .map_err(signing_error_response)?;
    let db = state.db.clone();
    let attestation = state.attestation.clone();
    let kbs_policy = state.kbs_policy.clone();
    let api_url = state.api_url.clone();
    let apply_app = app.clone();
    let apply_permits = state.deployment_apply_permits.clone();
    let (workload_artifact_binding, signed_policy_artifact) = rollback_artifact.unzip();
    let (local_workload_artifacts_json, local_trustee_policy_json) =
        local_verification_artifacts.unzip();
    let signed_descriptor = rollback_descriptor.clone();
    tokio::spawn(async move {
        let _apply_permit = match apply_permits.acquire_owned().await {
            Ok(permit) => permit,
            Err(e) => {
                let error_message = format!("deployment apply limiter closed: {}", e);
                let _ = crate::deploy::set_deployment_status(
                    &db,
                    deploy_id,
                    "failed",
                    None,
                    Some(&error_message),
                    true,
                )
                .await;
                let _ = crate::deploy::set_app_status(&db, apply_app.id, "failed").await;
                tracing::error!(
                    app_id = %apply_app.id,
                    deployment_id = %deploy_id,
                    error = %error_message,
                    "failed to acquire rollback apply permit"
                );
                return;
            }
        };

        if let Err(e) = crate::deploy::apply_deployment_manifests(
            crate::deploy::ApplyDeploymentManifestsRequest {
                pool: db.clone(),
                app: apply_app.clone(),
                deployment_id: deploy_id,
                attestation_config: attestation,
                kbs_policy_config: kbs_policy,
                api_signing_pubkey,
                api_url,
                workload_artifact_binding,
                signed_policy_artifact,
                signed_descriptor,
                local_workload_artifacts_json,
                local_trustee_policy_json,
                workload_security_profile: None,
            },
        )
        .await
        {
            let error_message = e.to_string();
            let _ = crate::deploy::set_deployment_status(
                &db,
                deploy_id,
                "failed",
                None,
                Some(&error_message),
                true,
            )
            .await;
            let _ = crate::deploy::set_app_status(&db, apply_app.id, "failed").await;
            tracing::error!(
                app_id = %apply_app.id,
                deployment_id = %deploy_id,
                error = %error_message,
                "failed to apply rollback manifests"
            );
        }
    });

    Ok((
        StatusCode::CREATED,
        Json(RollbackResponse {
            deployment_id: deploy_id,
            rolled_back_to: prev.id,
            status: "deploying".to_string(),
        }),
    ))
}
