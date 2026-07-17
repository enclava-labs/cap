use super::*;

fn target_resources_from_snapshot(
    app_id: Uuid,
    snapshot: &serde_json::Value,
) -> Result<AppResources, (StatusCode, Json<serde_json::Value>)> {
    let resources = snapshot.get("resolved_resources").ok_or_else(|| {
        json_error(
            StatusCode::CONFLICT,
            "rollback target predates exact resource snapshots; deploy a current generation first",
        )
    })?;
    let required = |field: &'static str| {
        resources
            .get(field)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                json_error(
                    StatusCode::CONFLICT,
                    "rollback target has an incomplete resource snapshot",
                )
            })
    };
    Ok(AppResources {
        app_id,
        cpu_limit: required("cpu")?,
        memory_limit: required("memory")?,
        app_data_size: required("storage")?,
        tls_data_size: required("tls_storage")?,
    })
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
    let target_resources = target_resources_from_snapshot(app.id, &prev.spec_snapshot)?;

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
    let locked_primary_profile = authority_containers
        .iter()
        .find(|container| container.is_primary)
        .and_then(|container| container.workload_security_profile.as_deref())
        .unwrap_or("restricted")
        .parse::<WorkloadSecurityProfile>()
        .map_err(|error| json_error(StatusCode::CONFLICT, error))?;
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
    if rollback_artifact.is_some() {
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
    super::enforce_authoritative_entitlement(&mut tx, auth.org_id, &target_resources, false)
        .await?;
    if rollback_artifact.is_some() {
        let artifacts =
            crate::signing_service::load_stored_customer_authority_in_tx(&mut tx, app.id, prev.id)
                .await
                .map_err(signing_error_response)?
                .ok_or_else(|| {
                    signing_error_response(crate::signing_service::SigningServiceError::Mismatch(
                        "rollback target customer authority is missing".to_string(),
                    ))
                })?;
        artifacts
            .validate_customer_authority_in_tx(&mut tx)
            .await
            .map_err(signing_error_response)?;
        artifacts
            .validate_deployment_inputs(
                &app,
                &image_digest,
                &crate::auth::jwt::public_key_base64(&state.signing_key),
            )
            .map_err(signing_error_response)?;
        let signed_profile =
            super::signed_descriptor_profile(&artifacts.descriptor).ok_or_else(|| {
                signing_error_response(crate::signing_service::SigningServiceError::Mismatch(
                    "workload_security_profile".to_string(),
                ))
            })?;
        if signed_profile != locked_primary_profile {
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

    let updated_resources = sqlx::query(
        "UPDATE app_resources
            SET cpu_limit = $1,
                memory_limit = $2,
                app_data_size = $3,
                tls_data_size = $4
          WHERE app_id = $5",
    )
    .bind(&target_resources.cpu_limit)
    .bind(&target_resources.memory_limit)
    .bind(&target_resources.app_data_size)
    .bind(&target_resources.tls_data_size)
    .bind(app.id)
    .execute(&mut *tx)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if updated_resources.rows_affected() != 1 {
        return Err(json_error(
            StatusCode::CONFLICT,
            "app resource authority is missing; retry after reconciliation",
        ));
    }

    let deploy_id = Uuid::new_v4();
    crate::deploy::supersede_incomplete_deployments(&mut tx, app.id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
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
    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

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
    let apply_snapshot =
        crate::deploy::DeploymentApplySnapshot::new(apply_containers, apply_resources);
    let apply_permits = state.deployment_apply_permits.clone();
    let (workload_artifact_binding, signed_policy_artifact) = rollback_artifact.unzip();
    let (local_workload_artifacts_json, local_trustee_policy_json) =
        local_verification_artifacts.unzip();
    tokio::spawn(async move {
        let _apply_permit = match apply_permits.acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                let _ =
                    crate::deploy::fail_deployment_if_active(&db, apply_app.id, deploy_id).await;
                tracing::error!(
                    app_id = %apply_app.id,
                    deployment_id = %deploy_id,
                    error_code = crate::deploy::DEPLOYMENT_APPLY_FAILED_ERROR,
                    "failed to acquire rollback apply permit"
                );
                return;
            }
        };

        if crate::deploy::apply_deployment_manifests(
            crate::deploy::ApplyDeploymentManifestsRequest {
                pool: db.clone(),
                app: apply_app.clone(),
                snapshot: apply_snapshot,
                deployment_id: deploy_id,
                attestation_config: attestation,
                kbs_policy_config: kbs_policy,
                api_signing_pubkey,
                api_url,
                workload_artifact_binding,
                signed_policy_artifact,
                local_workload_artifacts_json,
                local_trustee_policy_json,
                log_encryption: None,
            },
        )
        .await
        .is_err()
        {
            let _ = crate::deploy::fail_deployment_if_active(&db, apply_app.id, deploy_id).await;
            tracing::error!(
                app_id = %apply_app.id,
                deployment_id = %deploy_id,
                error_code = crate::deploy::DEPLOYMENT_APPLY_FAILED_ERROR,
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

#[cfg(test)]
mod resource_snapshot_tests {
    use super::*;

    #[test]
    fn rollback_requires_a_complete_exact_resource_snapshot() {
        let app_id = Uuid::new_v4();
        let exact = target_resources_from_snapshot(
            app_id,
            &serde_json::json!({
                "resources": {"cpu": "2"},
                "resolved_resources": {
                    "cpu": "2",
                    "memory": "3Gi",
                    "storage": "7Gi",
                    "tls_storage": "2Gi"
                }
            }),
        )
        .expect("current snapshot is rollback-safe");
        assert_eq!(exact.app_id, app_id);
        assert_eq!(exact.cpu_limit, "2");
        assert_eq!(exact.memory_limit, "3Gi");
        assert_eq!(exact.app_data_size, "7Gi");
        assert_eq!(exact.tls_data_size, "2Gi");

        let legacy =
            target_resources_from_snapshot(app_id, &serde_json::json!({"resources": {"cpu": "2"}}))
                .expect_err("legacy snapshot must fail closed");
        assert_eq!(legacy.0, StatusCode::CONFLICT);

        let incomplete = target_resources_from_snapshot(
            app_id,
            &serde_json::json!({
                "resolved_resources": {
                    "cpu": "2",
                    "memory": "3Gi",
                    "storage": "7Gi"
                }
            }),
        )
        .expect_err("incomplete snapshot must fail closed");
        assert_eq!(incomplete.0, StatusCode::CONFLICT);
    }
}
