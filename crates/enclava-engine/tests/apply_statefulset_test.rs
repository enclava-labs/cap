/// Integration test: requires a running cluster with kata-qemu-snp runtime.
/// Run with: cargo test -- --ignored
#[tokio::test]
#[ignore]
async fn apply_statefulset_creates() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::namespace::apply_namespace;
    use enclava_engine::apply::statefulset::apply_statefulset;
    use enclava_engine::manifest::namespace::generate_namespace;
    use enclava_engine::manifest::statefulset::generate_statefulset;
    use enclava_engine::testutil::sample_app;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();

    let ns = generate_namespace(&app);
    let generation = MutationGeneration::new(1).unwrap();
    apply_namespace(&engine, &ns, generation).await.unwrap();

    let sts = generate_statefulset(&app);
    let result = apply_statefulset(&engine, &app.namespace, &sts, generation)
        .await
        .unwrap();
    assert_eq!(result.metadata.name.as_deref(), Some(&*app.name));

    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}

#[test]
fn statefulset_renders_declared_pod_supplemental_groups() {
    // Contract v1 (policy-templates#23): the descriptor's declared list is
    // rendered at POD level; the platform baseline [0, 6] stays for legacy
    // descriptors; container securityContext is untouched; fsGroup stays
    // 10001.
    use enclava_engine::manifest::statefulset::generate_statefulset;
    use enclava_engine::testutil::sample_app;
    use k8s_openapi::api::apps::v1::StatefulSet;

    let legacy = generate_statefulset(&sample_app());
    let sts: StatefulSet = serde_json::from_value(serde_json::to_value(&legacy).unwrap()).unwrap();
    let pod_sc = sts
        .spec
        .expect("statefulset spec")
        .template
        .spec
        .expect("pod spec")
        .security_context
        .expect("pod securityContext");
    assert_eq!(pod_sc.supplemental_groups, Some(vec![0, 6]));
    assert_eq!(pod_sc.fs_group, Some(10001));

    let mut declared = sample_app();
    declared.pod_supplemental_groups = Some(vec![0, 6, 27]);
    let sts: StatefulSet =
        serde_json::from_value(serde_json::to_value(generate_statefulset(&declared)).unwrap())
            .unwrap();
    let spec = sts
        .spec
        .expect("statefulset spec")
        .template
        .spec
        .expect("pod spec");
    let pod_sc = spec.security_context.expect("pod securityContext");
    assert_eq!(pod_sc.supplemental_groups, Some(vec![0, 6, 27]));
    assert_eq!(pod_sc.fs_group, Some(10001));
    for container in spec
        .containers
        .iter()
        .chain(spec.init_containers.iter().flatten())
    {
        if let Some(sc) = container.security_context.as_ref() {
            assert!(
                serde_json::to_value(sc)
                    .expect("container securityContext")
                    .get("supplementalGroups")
                    .is_none(),
                "{} must not carry container-level supplementalGroups (genpolicy 4.3.1 panics)",
                container.name
            );
        }
    }
    // The container-level runAsUser/runAsGroup profiles are untouched.
    let web = spec
        .containers
        .iter()
        .find(|c| c.name == "app")
        .or_else(|| spec.containers.first())
        .expect("app container");
    let sc = web.security_context.as_ref().expect("web securityContext");
    assert_eq!(sc.run_as_user, Some(10001));
    assert_eq!(sc.run_as_group, Some(10001));
}
