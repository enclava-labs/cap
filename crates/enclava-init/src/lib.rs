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
    cfg!(all(debug_assertions, not(feature = "prod-strict")))
        && std::env::var("ENCLAVA_INIT_DEV_NO_LUKS")
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
    fn cli_dockerfile_uses_locked_release_build() {
        let dockerfile = include_str!("../../enclava-cli/Dockerfile").replace("\r\n", "\n");
        let cargo_build_lines: Vec<&str> = dockerfile
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("cargo build"))
            .collect();
        assert!(
            !cargo_build_lines.is_empty(),
            "CLI Dockerfile must contain cargo build lines"
        );
        for line in cargo_build_lines {
            assert!(
                line.contains("--locked"),
                "cargo build in CLI Dockerfile must use --locked: {line}"
            );
        }
    }

    #[test]
    fn prod_strict_cannot_skip_luks() {
        let source = include_str!("lib.rs").replace("\r\n", "\n");
        assert!(
            source.contains("cfg!(all(debug_assertions, not(feature = \"prod-strict\")))"),
            "dev_no_luks_override must compile out when prod-strict is enabled"
        );
    }

    #[cfg(feature = "prod-strict")]
    #[test]
    fn prod_strict_ignores_dev_no_luks_env() {
        let previous = std::env::var("ENCLAVA_INIT_DEV_NO_LUKS").ok();
        unsafe {
            std::env::set_var("ENCLAVA_INIT_DEV_NO_LUKS", "1");
        }
        let skipped = super::dev_no_luks_override();
        match previous {
            Some(value) => unsafe { std::env::set_var("ENCLAVA_INIT_DEV_NO_LUKS", value) },
            None => unsafe { std::env::remove_var("ENCLAVA_INIT_DEV_NO_LUKS") },
        }
        assert!(
            !skipped,
            "prod-strict builds must not skip LUKS via ENCLAVA_INIT_DEV_NO_LUKS"
        );
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
    }
}
