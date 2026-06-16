use dialoguer::Input;
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
        uses: sigstore/cosign-installer@v3

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

      - name: Write Enclava image artifact
        run: |
          image_ref="${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}@${{{{ steps.build.outputs.digest }}}}"
          jq -n \
            --arg image_ref "$image_ref" \
            --arg image "${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}" \
            --arg digest "${{{{ steps.build.outputs.digest }}}}" \
            --arg signer_subject "${{{{ github.server_url }}}}/${{{{ github.workflow_ref }}}}" \
            --arg signer_issuer "https://token.actions.githubusercontent.com" \
            '{{image_ref:$image_ref,image:$image,digest:$digest,signer_subject:$signer_subject,signer_issuer:$signer_issuer}}' \
            > enclava-image.json
          echo "Deploy manually with:"
          echo "enclava deploy --image-file enclava-image.json"

      - name: Upload Enclava image artifact
        uses: actions/upload-artifact@v4
        with:
          name: enclava-image
          path: enclava-image.json
"#
    )
}

pub async fn init() -> Result<(), Box<dyn std::error::Error>> {
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

    // Get app name (default to directory name)
    let app_name: String = Input::new()
        .with_prompt("App name")
        .default(default_app_name(&cwd))
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("Port")
        .default(detected_port.unwrap_or(3000))
        .interact_text()?;

    // Write enclava.toml
    let toml_content = generate_enclava_toml(&app_name, port);
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
        assert!(workflow.contains("enclava-image.json"));
        assert!(workflow.contains("actions/upload-artifact@v4"));
        assert!(workflow.contains("enclava deploy --image-file enclava-image.json"));
        assert!(!workflow.contains("enclava deploy --image "));
        assert!(!workflow.contains("ENCLAVA_API_KEY"));
    }
}
