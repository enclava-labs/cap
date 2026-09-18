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
            let cargo_lines: Vec<&str> = dockerfile
                .lines()
                .map(str::trim)
                .filter(|line| {
                    line.contains("cargo build")
                        || line.contains("cargo run")
                        || line.contains("cargo install")
                })
                .collect();
            assert!(
                !cargo_lines.is_empty(),
                "{name} Dockerfile must contain cargo build lines"
            );
            for line in cargo_lines {
                assert!(
                    line.contains("--locked"),
                    "cargo build/run/install in {name} Dockerfile must use --locked: {line}"
                );
                assert!(
                    line.matches("cargo build").count() <= line.matches("--locked").count(),
                    "every cargo build on a chained RUN line needs its own --locked: {line}"
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
        let wrapper_body = source
            .split("pub fn dev_no_luks_override() -> bool {")
            .nth(1)
            .expect("dev_no_luks_override definition")
            .split('}')
            .next()
            .expect("dev_no_luks_override body")
            .trim();
        assert_eq!(
            wrapper_body,
            "dev_no_luks_override_for(std::env::var(\"ENCLAVA_INIT_DEV_NO_LUKS\").ok().as_deref())",
            "dev_no_luks_override must only delegate to dev_no_luks_override_for"
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

        // Pin the polarity of the profile selection, not just token
        // presence: debug exactly in the pull_request branch, release
        // exactly in the else branch. Swapping the branches must fail.
        let pr_branch = select
            .split("if [ \"${GITHUB_EVENT_NAME}\" = \"pull_request\" ]; then")
            .nth(1)
            .expect("pull_request branch (exact = comparison)")
            .split("else")
            .next()
            .expect("pull_request branch body");
        let else_branch = select
            .split("\n          else")
            .nth(1)
            .expect("else branch")
            .split("\n          fi")
            .next()
            .expect("else branch body");
        assert!(
            pr_branch.contains("profile=debug") && !pr_branch.contains("profile=release"),
            "only pull_request builds may select BUILD_PROFILE=debug"
        );
        assert!(
            else_branch.contains("profile=release") && !else_branch.contains("profile=debug"),
            "tags, workflow_dispatch, and main pushes must select BUILD_PROFILE=release"
        );
        assert_eq!(
            select.matches("profile=debug").count(),
            1,
            "profile=debug may be echoed exactly once, inside the pull_request branch"
        );
        assert_eq!(
            select.matches("profile=release").count(),
            1,
            "profile=release may be echoed exactly once, inside the else branch"
        );

        // The exact gate that must guard every push/sign path: pull_request
        // (debug) builds are never pushed or signed. Pinned by equality, not
        // token absence, so `push: ${{ true }}` or `if: always()` fail the
        // test instead of slipping through.
        const PUSH_GATE: &str = "github.event_name == 'workflow_dispatch' || github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/')";

        let exact_push_gate = "push: ".to_string() + "${{ " + PUSH_GATE + " }}";
        let push_lines: Vec<&str> = workflow
            .lines()
            .filter(|l| l.starts_with("   ") && l.trim_start().starts_with("push:"))
            .collect();
        assert_eq!(
            push_lines.len(),
            1,
            "exactly one push property is allowed (expression or literal), and it must be the gated one"
        );
        assert_eq!(
            push_lines[0].trim(),
            exact_push_gate,
            "the single push property must be the exact non-pull_request gate"
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
                block
                    .lines()
                    .any(|l| l.trim() == format!("if: {PUSH_GATE}")),
                "{step} must be gated on the exact non-pull_request condition"
            );
        }
        assert!(
            !workflow.contains("outputs:"),
            "registry outputs bypass the push gate; only the gated push: property may publish"
        );
        let build_block = workflow
            .split("- name: Build and push")
            .nth(1)
            .expect("Build and push step")
            .split("\n      - name:")
            .next()
            .expect("Build and push step body");
        for (prefix, what) in [
            (
                "BUILD_PROFILE=",
                "build-args must consume the selected build profile, not a hardcoded one",
            ),
            (
                "org.enclava.build-profile=",
                "pushed images must carry an org.enclava.build-profile label derived from the selected profile so verifiers can reject debug digests",
            ),
        ] {
            let lines: Vec<&str> = build_block
                .lines()
                .filter(|l| l.trim_start().starts_with(prefix))
                .collect();
            let expected = prefix.to_string() + "${{ steps.build_profile.outputs.profile }}";
            assert_eq!(lines.len(), 1, "{what}");
            assert_eq!(lines[0].trim(), expected, "{what}");
        }
    }
}
