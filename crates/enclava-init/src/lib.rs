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
    fn prod_strict_cannot_skip_luks() {
        let source = include_str!("main.rs").replace("\r\n", "\n");
        assert!(
            source.contains("cfg!(all(debug_assertions, not(feature = \"prod-strict\")))"),
            "dev_no_luks_override must compile out when prod-strict is enabled"
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
