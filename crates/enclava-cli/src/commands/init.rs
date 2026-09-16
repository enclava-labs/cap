use dialoguer::Input;
use enclava_cli::app_config::AppConfig;
use std::path::Path;

/// Detect EXPOSE port from a Dockerfile.
pub(crate) fn detect_dockerfile_port(path: &Path) -> Option<u16> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("EXPOSE") {
            // EXPOSE 3000 or EXPOSE 3000/tcp
            let port_str = trimmed
                .strip_prefix("EXPOSE")?
                .trim()
                .split('/')
                .next()?
                .trim();
            return port_str.parse().ok();
        }
    }
    None
}

/// Default app name derived from the current project directory.
fn interactive_session() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

pub(crate) fn default_app_name(cwd: &Path) -> String {
    let raw = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-app")
        .to_lowercase();

    let mut name = String::new();
    let mut previous_was_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            name.push(ch);
            previous_was_dash = false;
        } else if !previous_was_dash && !name.is_empty() {
            name.push('-');
            previous_was_dash = true;
        }
    }

    let trimmed = name.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "my-app".to_string()
    } else {
        trimmed
    }
}

/// Generate enclava.toml content.
pub(crate) fn generate_enclava_toml(name: &str, port: u16) -> String {
    format!(
        r#"[app]
name = "{name}"
port = {port}
command = ["/usr/local/bin/app"]

[storage]
paths = ["/data"]
size = "5Gi"
tls_size = "2Gi"

[unlock]
mode = "password"

[resources]
cpu = "1"
memory = "1Gi"

[health]
path = "/health"
interval = 30
timeout = 5
"#
    )
}

/// Generate a GitHub Actions starter workflow for build + sign.
pub(crate) fn generate_github_workflow(app_name: &str) -> String {
    format!(
        r#"name: Build signed image for {app_name}

on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write
  id-token: write
  attestations: write

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{{{ github.repository }}}}

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ${{{{ env.REGISTRY }}}}
          username: ${{{{ github.actor }}}}
          password: ${{{{ secrets.GITHUB_TOKEN }}}}

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push
        id: build
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}:${{{{ github.sha }}}}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Install cosign
        # v4.1.2 — installs cosign 3.x, which emits portable DSSE
        # material; legacy 2.x `.sig` objects may lack it
        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2

      - name: Sign image with cosign (keyless)
        run: |
          cosign sign --yes \
            ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}@${{{{ steps.build.outputs.digest }}}}

      - name: Attest build provenance
        uses: actions/attest-build-provenance@v2
        with:
          subject-name: ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}
          subject-digest: ${{{{ steps.build.outputs.digest }}}}
          push-to-registry: true

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}@${{{{ steps.build.outputs.digest }}}}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Attest SBOM
        uses: actions/attest-sbom@v2
        with:
          subject-name: ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}
          subject-digest: ${{{{ steps.build.outputs.digest }}}}
          sbom-path: sbom.spdx.json
          push-to-registry: true

      - name: Print manual deploy image
        run: |
          echo "Deploy manually with:"
          echo "enclava deploy --image ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}@${{{{ steps.build.outputs.digest }}}}"
"#
    )
}

#[derive(clap::Args)]
pub struct InitArgs {
    /// App name to write into enclava.toml (non-interactive; defaults to the directory name)
    #[arg(long)]
    pub app_name: Option<String>,
    /// Port to write into enclava.toml (non-interactive; defaults to the Dockerfile EXPOSE or 3000)
    #[arg(long)]
    pub port: Option<u16>,
}

pub async fn init(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;

    // Check if enclava.toml already exists
    let toml_path = cwd.join("enclava.toml");
    if toml_path.exists() {
        return Err("enclava.toml already exists in this directory".into());
    }

    // Detect Dockerfile
    let dockerfile = cwd.join("Dockerfile");
    let detected_port = if dockerfile.exists() {
        let port = detect_dockerfile_port(&dockerfile);
        if let Some(p) = port {
            println!("Detected Dockerfile at ./Dockerfile");
            println!("Detected EXPOSE {p}");
        } else {
            println!("Detected Dockerfile at ./Dockerfile (no EXPOSE found)");
        }
        port
    } else {
        println!("No Dockerfile found.");
        None
    };

    // Get app name (default to directory name; --app-name or a non-interactive
    // session takes the deterministic default instead of prompting). Both the
    // name and port prompts render on stderr (dialoguer 0.11 uses
    // Term::stderr()) and fail when it is redirected, so require terminal
    // stdin AND stderr before prompting — same rule as the password paths.
    let app_name: String = match args.app_name {
        Some(name) => name,
        None if interactive_session() => Input::new()
            .with_prompt("App name")
            .default(default_app_name(&cwd))
            .interact_text()?,
        None => default_app_name(&cwd),
    };

    let port: u16 = match args.port {
        Some(port) => port,
        None if interactive_session() => Input::new()
            .with_prompt("Port")
            .default(detected_port.unwrap_or(3000))
            .interact_text()?,
        None => detected_port.unwrap_or(3000),
    };

    // Validate the name against the canonical app-name rules BEFORE writing
    // anything: an invalid name (from --app-name or the directory-derived
    // default) would otherwise scaffold a project that `create` later rejects,
    // and the existing enclava.toml then blocks a corrected rerun. These are
    // the name-level rules the scaffold can check; the org-dependent
    // namespace budget (cap-{org}-{app} ≤ 63) stays with `create`, which
    // knows both operands and reports an actionable error.
    enclava_common::validate::validate_app_name(&app_name).map_err(|err| {
        format!(
            "invalid app name `{app_name}` ({err}); pass --app-name with a lowercase \
             [a-z0-9-] name: starting with a letter, alphanumeric edges, no consecutive \
             hyphens, at most 63 chars, no reserved system names"
        )
    })?;
    // Kubernetes container ports must be 1-65535; a 0 would only surface as
    // a manifest rejection at deploy time, so fail the scaffold early.
    if port == 0 {
        return Err(format!(
            "invalid port {port} from --port or image EXPOSE: pass --port with a \
             TCP port between 1 and 65535"
        )
        .into());
    }

    // Write enclava.toml
    let toml_content = generate_enclava_toml(&app_name, port);
    // Parse the generated TOML before it lands on disk so a generation bug
    // fails here instead of poisoning the next command that loads it.
    AppConfig::parse(&toml_content)?;
    std::fs::write(&toml_path, &toml_content)?;
    println!();
    println!("Creating enclava.toml... done");

    // Write GitHub Actions starter workflow
    let workflow_dir = cwd.join(".github").join("workflows");
    std::fs::create_dir_all(&workflow_dir)?;
    let workflow_path = workflow_dir.join("enclava-deploy.yml");

    if workflow_path.exists() {
        println!(".github/workflows/enclava-deploy.yml already exists, skipping");
    } else {
        let workflow_content = generate_github_workflow(&app_name);
        std::fs::write(&workflow_path, &workflow_content)?;
        println!("Creating .github/workflows/enclava-deploy.yml... done");
    }

    println!();
    println!("Next steps:");
    println!("  1. Run `enclava login`");
    println!("  2. Run `enclava create --signer-subject <cosign-subject>`");
    println!("  3. Build and sign a public digest-pinned image");
    println!("  4. Run `enclava deploy --image <image>@sha256:<digest>`");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_rejects_names_the_platform_would_reject_and_parses_generated_toml() {
        // The same canonical validator init applies before writing anything:
        // invalid explicit --app-name values and unusable directory-derived
        // defaults must fail BEFORE enclava.toml exists (a written-but-invalid
        // scaffold blocks the corrected rerun).
        for bad in [
            "Bad_Name",              // uppercase + underscore: not a DNS-1123 label
            "-leading-dash",         // leading '-'
            "default",               // reserved system name
            "foo--bar",              // consecutive hyphens
            "1app",                  // digit-led: invalid K8s service name
            "a".repeat(64).as_str(), // over the 63-char limit
        ] {
            assert!(
                enclava_common::validate::validate_app_name(bad).is_err(),
                "{bad} must be rejected before scaffolding"
            );
        }
        assert!(enclava_common::validate::validate_app_name("my-app-1").is_ok());

        // The generated TOML must parse before it is written to disk.
        let toml_content = generate_enclava_toml("my-app-1", 3000);
        AppConfig::parse(&toml_content).expect("generated enclava.toml must parse as AppConfig");
    }

    #[test]
    fn detect_port_from_expose() {
        let tmp = tempfile::tempdir().unwrap();
        let dockerfile = tmp.path().join("Dockerfile");
        std::fs::write(
            &dockerfile,
            "FROM node:20\nWORKDIR /app\nCOPY . .\nEXPOSE 3000\nCMD [\"node\", \"index.js\"]\n",
        )
        .unwrap();
        assert_eq!(detect_dockerfile_port(&dockerfile), Some(3000));
    }

    #[test]
    fn detect_port_with_protocol() {
        let tmp = tempfile::tempdir().unwrap();
        let dockerfile = tmp.path().join("Dockerfile");
        std::fs::write(&dockerfile, "FROM python:3.11\nEXPOSE 8080/tcp\n").unwrap();
        assert_eq!(detect_dockerfile_port(&dockerfile), Some(8080));
    }

    #[test]
    fn no_expose_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let dockerfile = tmp.path().join("Dockerfile");
        std::fs::write(&dockerfile, "FROM ubuntu:22.04\nRUN echo hello\n").unwrap();
        assert_eq!(detect_dockerfile_port(&dockerfile), None);
    }

    #[test]
    fn missing_dockerfile_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("Dockerfile");
        assert_eq!(detect_dockerfile_port(&missing), None);
    }

    #[test]
    fn default_app_name_sanitizes_directory_name() {
        let path = Path::new("/tmp/My App_repo!");
        assert_eq!(default_app_name(path), "my-app-repo");
    }

    #[test]
    fn generated_toml_parses() {
        let toml_str = generate_enclava_toml("test-app", 8080);
        let config = enclava_cli::app_config::AppConfig::parse(&toml_str).unwrap();
        assert_eq!(config.app.name, "test-app");
        assert_eq!(config.app.port, 8080);
    }

    #[test]
    fn generated_workflow_contains_cosign() {
        let workflow = generate_github_workflow("my-app");
        assert!(workflow.contains("cosign"));
        assert!(workflow.contains("attest-build-provenance"));
        assert!(workflow.contains("sbom-action"));
        assert!(workflow.contains("enclava deploy --image"));
        assert!(!workflow.contains("ENCLAVA_API_KEY"));
    }
}
