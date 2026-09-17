//! enclava-init: in-TEE Rust replacement for the legacy bootstrap_script.sh.
//!
//! Runs as a long-running mounter sidecar inside a Kata SEV-SNP guest. It
//! waits for app/caddy wait-exec sentinels, performs Argon2id-based password
//! unlock or KBS-fetched autounlock, opens both LUKS devices (state and
//! tls-state), runs the in-TEE Trustee policy verification chain, writes
//! per-component HKDF-derived seeds, marks a readiness sentinel, and stays
//! alive so the decrypted mount propagation source remains present for
//! workload containers. All secret types use Zeroize so key material is wiped
//! on drop.

#[cfg(all(feature = "prod-strict", feature = "luks-integration"))]
compile_error!("prod-strict builds must not enable enclava-init/luks-integration");

/// Debug-only LUKS skip. Always false when `prod-strict` is enabled.
pub fn dev_no_luks_override() -> bool {
    dev_no_luks_override_for(std::env::var("ENCLAVA_INIT_DEV_NO_LUKS").ok().as_deref())
}

fn dev_no_luks_override_for(raw: Option<&str>) -> bool {
    cfg!(all(debug_assertions, not(feature = "prod-strict")))
        && raw
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false)
}

pub mod chown;
pub mod config;
pub mod errors;
pub mod kbs_fetch;
pub mod log_relay;
pub mod luks;
pub mod safe_diagnostics;
pub mod secrets;
pub mod seeds;
pub mod socket;
pub mod tls_certificate;
pub mod trustee_verify;
pub mod unlock;
pub mod writes;

#[cfg(test)]
mod tests {
    #[test]
    fn dockerfile_defaults_to_locked_release_profile() {
        let dockerfile = include_str!("../Dockerfile").replace("\r\n", "\n");
        assert!(
            dockerfile.contains("ARG BUILD_PROFILE=release"),
            "enclava-init image default BUILD_PROFILE must be release"
        );
        assert!(
            !dockerfile.contains("ARG BUILD_PROFILE=debug"),
            "enclava-init image must not default to debug"
        );

        let cargo_build_lines: Vec<&str> = dockerfile
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("cargo build"))
            .collect();
        assert!(
            !cargo_build_lines.is_empty(),
            "Dockerfile must contain cargo build lines"
        );
        for line in cargo_build_lines {
            assert!(
                line.contains("--locked"),
                "cargo build in Dockerfile must use --locked: {line}"
            );
        }
    }

    #[test]
    fn all_crates_dockerfiles_use_locked_builds() {
        let dockerfiles = [
            ("enclava-init", include_str!("../Dockerfile")),
            ("enclava-cli", include_str!("../../enclava-cli/Dockerfile")),
            ("enclava-api", include_str!("../../enclava-api/Dockerfile")),
            (
                "enclava-appraiser",
                include_str!("../../enclava-appraiser/Dockerfile"),
            ),
        ];
        for (name, raw) in dockerfiles {
            let dockerfile = raw.replace("\r\n", "\n");
            let cargo_build_lines: Vec<&str> = dockerfile
                .lines()
                .map(str::trim)
                .filter(|line| line.contains("cargo build"))
                .collect();
            assert!(
                !cargo_build_lines.is_empty(),
                "{name} Dockerfile must contain cargo build lines"
            );
            for line in cargo_build_lines {
                assert!(
                    line.contains("--locked"),
                    "cargo build in {name} Dockerfile must use --locked: {line}"
                );
            }
        }
    }

    #[test]
    fn prod_strict_cannot_skip_luks() {
        let source = include_str!("lib.rs").replace("\r\n", "\n");
        assert!(
            source.contains("cfg!(all(debug_assertions, not(feature = \"prod-strict\")))"),
            "dev_no_luks_override must compile out when prod-strict is enabled"
        );
        assert!(
            source.contains("std::env::var(\"ENCLAVA_INIT_DEV_NO_LUKS\")"),
            "dev_no_luks_override must read the ENCLAVA_INIT_DEV_NO_LUKS env var"
        );
    }

    #[cfg(feature = "prod-strict")]
    #[test]
    fn prod_strict_ignores_dev_no_luks_value() {
        assert!(!super::dev_no_luks_override_for(Some("true")));
        assert!(!super::dev_no_luks_override_for(Some("1")));
        assert!(!super::dev_no_luks_override_for(None));
    }

    #[cfg(all(debug_assertions, not(feature = "prod-strict")))]
    #[test]
    fn dev_builds_honor_dev_no_luks_value() {
        assert!(super::dev_no_luks_override_for(Some("true")));
        assert!(super::dev_no_luks_override_for(Some("TRUE")));
        assert!(super::dev_no_luks_override_for(Some("1")));
        assert!(!super::dev_no_luks_override_for(Some("0")));
        assert!(!super::dev_no_luks_override_for(Some("yes")));
        assert!(!super::dev_no_luks_override_for(None));
    }

    #[test]
    fn init_image_workflow_never_pushes_debug_images() {
        let workflow =
            include_str!("../../../.github/workflows/enclava-init-image.yml").replace("\r\n", "\n");
        let select = workflow
            .split("- name: Select build profile")
            .nth(1)
            .expect("Select build profile step")
            .split("\n      - name:")
            .next()
            .expect("build profile step body");

        assert!(
            select.contains("profile=release"),
            "tags, workflow_dispatch, and main pushes must use BUILD_PROFILE=release"
        );
        if select.contains("profile=debug") {
            assert!(
                select.contains("pull_request"),
                "debug BUILD_PROFILE is only allowed for pull_request builds"
            );
            assert!(
                !select.contains("refs/heads/main"),
                "main branch pushes must not select debug BUILD_PROFILE"
            );
        }

        // The exact gate that must guard every push/sign path: pull_request
        // (debug) builds are never pushed or signed. Pinned by equality, not
        // token absence, so `push: ${{ true }}` or `if: always()` fail the
        // test instead of slipping through.
        const PUSH_GATE: &str = "github.event_name == 'workflow_dispatch' || github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/')";

        let exact_push_gate = "push: ".to_string() + "${{ " + PUSH_GATE + " }}";
        assert!(
            workflow.contains(&exact_push_gate),
            "Build and push must use the exact non-pull_request push gate"
        );
        for step in ["Install cosign", "Sign and verify pushed digest"] {
            let block = workflow
                .split(&format!("- name: {step}"))
                .nth(1)
                .unwrap_or_else(|| panic!("{step} step"))
                .split("\n      - name:")
                .next()
                .unwrap_or_else(|| panic!("{step} step body"));
            assert!(
                block.contains(&format!("if: {PUSH_GATE}")),
                "{step} must be gated on the exact non-pull_request condition"
            );
        }

        assert_eq!(
            workflow.match_indices("push: $").count(),
            1,
            "exactly one push expression is allowed, and it must be the gated one"
        );
        assert!(
            workflow.contains("BUILD_PROFILE=${{ steps.build_profile.outputs.profile }}"),
            "build-args must consume the selected build profile, not a hardcoded one"
        );

        assert!(
            workflow.contains("org.enclava.build-profile="),
            "pushed images must carry an org.enclava.build-profile label so verifiers can reject debug digests"
        );
    }
}
