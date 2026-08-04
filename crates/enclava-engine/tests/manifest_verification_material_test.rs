use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::testutil::sample_app;
use enclava_engine::validate::{ValidationError, validate_app};

#[test]
fn verification_material_is_mounted_only_into_proxy() {
    let mut app = sample_app();
    app.attestation.verification_material = Some(vec![7; 716_800]);
    validate_app(&app).unwrap();
    let manifests = generate_all_manifests(&app);
    let configmap = manifests.verification_material_configmap.unwrap();
    assert_eq!(
        configmap.metadata.name.as_deref(),
        Some("test-app-verification")
    );
    assert_eq!(
        configmap.binary_data.unwrap()["verification-material.ce"].0,
        vec![7; 716_800]
    );

    let pod = manifests.statefulset.spec.unwrap().template.spec.unwrap();
    let proxy = pod
        .containers
        .iter()
        .find(|container| container.name == "attestation-proxy")
        .unwrap();
    let proxy_mounts = proxy.volume_mounts.as_ref().unwrap();
    assert!(proxy_mounts.iter().any(|mount| {
        mount.name == "verification-material"
            && mount.mount_path == "/etc/enclava-verification"
            && mount.read_only == Some(true)
    }));
    assert!(
        proxy_mounts
            .iter()
            .all(|mount| mount.name != "tls-state-mount")
    );
    assert!(proxy.env.as_ref().unwrap().iter().any(|variable| {
        variable.name == "PROOF_TLS_CERT_PATH"
            && variable.value.as_deref() == Some("/run/enclava/public-tls/certificates/tls.crt")
    }));
    assert!(
        pod.containers
            .iter()
            .filter(|container| container.name != "attestation-proxy")
            .all(
                |container| container.volume_mounts.as_ref().is_none_or(|mounts| mounts
                    .iter()
                    .all(|mount| mount.name != "verification-material"))
            )
    );
}

#[test]
fn oversized_verification_material_is_rejected() {
    let mut app = sample_app();
    app.attestation.verification_material = Some(vec![0; 716_801]);
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::VerificationMaterialTooLarge)
    ));
}
