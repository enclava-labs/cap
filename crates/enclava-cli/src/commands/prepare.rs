use clap::Args;
use dialoguer::Confirm;
use enclava_cli::app_config::AppConfig;
use serde_yaml::Value as YamlValue;
use std::path::{Path, PathBuf};

use super::init::{
    default_app_name, detect_dockerfile_port, generate_enclava_toml, generate_github_workflow,
};

#[derive(Args, Debug, Clone, Default)]
pub struct PrepareArgs {
    /// Inspect the repository without changing files.
    #[arg(long)]
    pub check: bool,
    /// Replace existing Enclava files without prompting.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FindingLevel {
    Action,
    Warning,
    Info,
}

impl FindingLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Warning => "warning",
            Self::Info => "note",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrepareFinding {
    pub level: FindingLevel,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrepareAssessment {
    pub app_name: String,
    pub dockerfile: Option<String>,
    pub compose_files: Vec<String>,
    pub inferred_port: u16,
    pub port_source: String,
    pub inferred_command: Option<Vec<String>>,
    pub command_source: Option<String>,
    pub findings: Vec<PrepareFinding>,
}

impl Default for PrepareAssessment {
    fn default() -> Self {
        Self {
            app_name: "my-app".to_string(),
            dockerfile: None,
            compose_files: Vec::new(),
            inferred_port: 3000,
            port_source: "default".to_string(),
            inferred_command: None,
            command_source: None,
            findings: Vec::new(),
        }
    }
}

impl PrepareAssessment {
    fn has_actions(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.level == FindingLevel::Action)
    }

    fn push(&mut self, level: FindingLevel, message: impl Into<String>) {
        self.findings.push(PrepareFinding {
            level,
            message: message.into(),
        });
    }

    fn action(&mut self, message: impl Into<String>) {
        self.push(FindingLevel::Action, message);
    }

    fn warning(&mut self, message: impl Into<String>) {
        self.push(FindingLevel::Warning, message);
    }

    fn note(&mut self, message: impl Into<String>) {
        self.push(FindingLevel::Info, message);
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PrepareReport {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub kept_existing: Vec<String>,
    pub assessment: PrepareAssessment,
}

impl PrepareReport {
    fn changed_paths(&self) -> Vec<&str> {
        self.created
            .iter()
            .chain(self.updated.iter())
            .map(String::as_str)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DockerCommand {
    Exec(Vec<String>),
    Shell(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct DockerfileAnalysis {
    exposes: Vec<u16>,
    command: Option<Vec<String>>,
    command_uses_shell: bool,
    volumes: Vec<String>,
    user: Option<String>,
    mentions_localhost: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ComposeAnalysis {
    files: Vec<String>,
    service_count: usize,
    primary_service: Option<String>,
    port: Option<u16>,
    command: Option<Vec<String>>,
    command_uses_shell: bool,
    has_privileged_runtime: bool,
    has_multiple_services: bool,
    has_bind_mounts: bool,
    has_external_primary_image: bool,
}

type ConfirmResult = Result<bool, Box<dyn std::error::Error>>;

fn relative_display(cwd: &Path, path: &Path) -> String {
    path.strip_prefix(cwd).unwrap_or(path).display().to_string()
}

fn existing_app_name(toml_path: &Path, fallback: &str) -> String {
    AppConfig::load(toml_path)
        .map(|config| config.app.name)
        .unwrap_or_else(|_| fallback.to_string())
}

fn write_target(
    cwd: &Path,
    path: &Path,
    content: &str,
    update_existing: bool,
    report: &mut PrepareReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let rel = relative_display(cwd, path);
    if path.exists() {
        if update_existing {
            std::fs::write(path, content)?;
            report.updated.push(rel);
        } else {
            report.kept_existing.push(rel);
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    report.created.push(rel);
    Ok(())
}

fn strip_inline_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => {
                let previous = line[..idx].chars().last();
                if previous.is_none_or(char::is_whitespace) {
                    return &line[..idx];
                }
            }
            _ => {}
        }
    }
    line
}

fn dockerfile_logical_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for raw_line in content.lines() {
        let without_comment = strip_inline_comment(raw_line).trim();
        if without_comment.is_empty() {
            continue;
        }

        let continued = without_comment.ends_with('\\');
        let segment = without_comment.trim_end_matches('\\').trim_end();
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(segment);

        if !continued {
            lines.push(current.trim().to_string());
            current.clear();
        }
    }

    if !current.trim().is_empty() {
        lines.push(current.trim().to_string());
    }

    lines
}

fn parse_docker_instruction(line: &str) -> Option<(&str, &str)> {
    let split = line.find(char::is_whitespace)?;
    let instruction = &line[..split];
    let rest = line[split..].trim();
    if rest.is_empty() {
        return None;
    }
    Some((instruction, rest))
}

fn parse_expose_ports(value: &str) -> Vec<u16> {
    value
        .split_whitespace()
        .filter_map(|part| {
            let port = part.split('/').next()?.trim();
            port.parse().ok()
        })
        .collect()
}

fn parse_volume_paths(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.starts_with('[') {
        return serde_json::from_str::<Vec<String>>(trimmed).unwrap_or_default();
    }
    trimmed
        .split_whitespace()
        .map(str::trim)
        .filter(|path| path.starts_with('/'))
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_docker_command(value: &str) -> Option<DockerCommand> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<String>>(trimmed)
            .ok()
            .filter(|argv| !argv.is_empty())
            .map(DockerCommand::Exec)
    } else {
        Some(DockerCommand::Shell(trimmed.to_string()))
    }
}

fn shell_join(parts: &[String]) -> String {
    parts.join(" ")
}

fn resolve_docker_command(
    entrypoint: Option<DockerCommand>,
    cmd: Option<DockerCommand>,
) -> (Option<Vec<String>>, bool) {
    match (entrypoint, cmd) {
        (Some(DockerCommand::Exec(mut entrypoint)), Some(DockerCommand::Exec(cmd))) => {
            entrypoint.extend(cmd);
            (Some(entrypoint), false)
        }
        (Some(DockerCommand::Exec(mut entrypoint)), Some(DockerCommand::Shell(cmd))) => {
            entrypoint.push(cmd);
            (Some(entrypoint), true)
        }
        (Some(DockerCommand::Exec(entrypoint)), None) => (Some(entrypoint), false),
        (Some(DockerCommand::Shell(entrypoint)), Some(DockerCommand::Exec(cmd))) => (
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!("{entrypoint} {}", shell_join(&cmd)),
            ]),
            true,
        ),
        (Some(DockerCommand::Shell(entrypoint)), Some(DockerCommand::Shell(cmd))) => (
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!("{entrypoint} {cmd}"),
            ]),
            true,
        ),
        (Some(DockerCommand::Shell(entrypoint)), None) => (
            Some(vec!["/bin/sh".to_string(), "-c".to_string(), entrypoint]),
            true,
        ),
        (None, Some(DockerCommand::Exec(cmd))) => (Some(cmd), false),
        (None, Some(DockerCommand::Shell(cmd))) => (
            Some(vec!["/bin/sh".to_string(), "-c".to_string(), cmd]),
            true,
        ),
        (None, None) => (None, false),
    }
}

fn analyze_dockerfile(path: &Path) -> Result<DockerfileAnalysis, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut analysis = DockerfileAnalysis {
        mentions_localhost: content.contains("127.0.0.1") || content.contains("localhost"),
        ..DockerfileAnalysis::default()
    };
    let mut entrypoint = None;
    let mut cmd = None;

    for line in dockerfile_logical_lines(&content) {
        let Some((instruction, value)) = parse_docker_instruction(&line) else {
            continue;
        };

        match instruction.to_ascii_uppercase().as_str() {
            "EXPOSE" => analysis.exposes.extend(parse_expose_ports(value)),
            "ENTRYPOINT" => entrypoint = parse_docker_command(value),
            "CMD" => cmd = parse_docker_command(value),
            "VOLUME" => analysis.volumes.extend(parse_volume_paths(value)),
            "USER" => analysis.user = Some(value.to_string()),
            _ => {}
        }
    }

    let (command, command_uses_shell) = resolve_docker_command(entrypoint, cmd);
    analysis.command = command;
    analysis.command_uses_shell = command_uses_shell;
    Ok(analysis)
}

fn yaml_get<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    value.as_mapping()?.get(YamlValue::String(key.to_string()))
}

fn yaml_string(value: &YamlValue) -> Option<String> {
    match value {
        YamlValue::String(value) => Some(value.clone()),
        YamlValue::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn yaml_bool(value: &YamlValue) -> bool {
    matches!(value, YamlValue::Bool(true))
}

fn compose_builds_current_context(service: &YamlValue) -> bool {
    let Some(build) = yaml_get(service, "build") else {
        return false;
    };

    match build {
        YamlValue::String(value) => value == "." || value == "./",
        YamlValue::Mapping(_) => yaml_get(build, "context")
            .and_then(yaml_string)
            .is_some_and(|context| context == "." || context == "./"),
        _ => false,
    }
}

fn compose_has_external_image(service: &YamlValue) -> bool {
    yaml_get(service, "image").is_some() && yaml_get(service, "build").is_none()
}

fn compose_port_from_value(value: &YamlValue) -> Option<u16> {
    match value {
        YamlValue::Number(number) => number.as_u64().and_then(|port| u16::try_from(port).ok()),
        YamlValue::String(value) => {
            let no_protocol = value.split('/').next().unwrap_or(value);
            no_protocol
                .rsplit(':')
                .next()
                .and_then(|port| port.trim().parse().ok())
        }
        YamlValue::Mapping(_) => yaml_get(value, "target")
            .and_then(yaml_string)
            .and_then(|port| port.parse().ok()),
        _ => None,
    }
}

fn compose_port(service: &YamlValue) -> Option<u16> {
    yaml_get(service, "ports")
        .and_then(YamlValue::as_sequence)
        .and_then(|ports| ports.iter().find_map(compose_port_from_value))
        .or_else(|| {
            yaml_get(service, "expose")
                .and_then(YamlValue::as_sequence)
                .and_then(|ports| ports.iter().find_map(compose_port_from_value))
        })
}

fn compose_command_from_value(value: &YamlValue) -> Option<DockerCommand> {
    match value {
        YamlValue::Sequence(values) => values
            .iter()
            .map(yaml_string)
            .collect::<Option<Vec<_>>>()
            .filter(|argv| !argv.is_empty())
            .map(DockerCommand::Exec),
        YamlValue::String(value) if !value.trim().is_empty() => {
            Some(DockerCommand::Shell(value.trim().to_string()))
        }
        _ => None,
    }
}

fn compose_command(service: &YamlValue) -> (Option<Vec<String>>, bool) {
    resolve_docker_command(
        yaml_get(service, "entrypoint").and_then(compose_command_from_value),
        yaml_get(service, "command").and_then(compose_command_from_value),
    )
}

fn compose_has_bind_mounts(service: &YamlValue) -> bool {
    let Some(volumes) = yaml_get(service, "volumes").and_then(YamlValue::as_sequence) else {
        return false;
    };

    volumes.iter().any(|volume| match volume {
        YamlValue::String(value) => {
            let first = value.split(':').next().unwrap_or(value);
            first.starts_with('.') || first.starts_with('/') || first.starts_with('~')
        }
        YamlValue::Mapping(_) => yaml_get(volume, "type")
            .and_then(yaml_string)
            .is_some_and(|value| value == "bind"),
        _ => false,
    })
}

fn compose_has_privileged_runtime(service: &YamlValue) -> bool {
    yaml_get(service, "privileged").is_some_and(yaml_bool)
        || yaml_get(service, "cap_add").is_some()
        || yaml_get(service, "devices").is_some()
}

fn analyze_compose_file(
    cwd: &Path,
    path: &Path,
    analysis: &mut ComposeAnalysis,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let yaml: YamlValue = serde_yaml::from_str(&content)?;
    let rel = relative_display(cwd, path);
    analysis.files.push(rel.clone());

    let Some(services) = yaml_get(&yaml, "services").and_then(YamlValue::as_mapping) else {
        return Ok(());
    };

    analysis.service_count += services.len();
    analysis.has_multiple_services |= services.len() > 1;

    let service_entries: Vec<(String, &YamlValue)> = services
        .iter()
        .filter_map(|(name, service)| yaml_string(name).map(|name| (name, service)))
        .collect();

    let primary = service_entries
        .iter()
        .find(|(_, service)| compose_builds_current_context(service))
        .or_else(|| {
            if service_entries.len() == 1 {
                service_entries.first()
            } else {
                None
            }
        });

    for (_, service) in &service_entries {
        analysis.has_privileged_runtime |= compose_has_privileged_runtime(service);
        analysis.has_bind_mounts |= compose_has_bind_mounts(service);
    }

    if let Some((name, service)) = primary {
        analysis.primary_service = Some(format!("{rel}:{name}"));
        analysis.port = analysis.port.or_else(|| compose_port(service));
        let (command, uses_shell) = compose_command(service);
        if analysis.command.is_none() {
            analysis.command = command;
            analysis.command_uses_shell = uses_shell;
        }
        analysis.has_external_primary_image |= compose_has_external_image(service);
    }

    Ok(())
}

fn analyze_compose(cwd: &Path, assessment: &mut PrepareAssessment) -> ComposeAnalysis {
    let mut analysis = ComposeAnalysis::default();
    for name in [
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    ] {
        let path = cwd.join(name);
        if !path.exists() {
            continue;
        }
        if let Err(err) = analyze_compose_file(cwd, &path, &mut analysis) {
            assessment.warning(format!("{name} could not be parsed: {err}"));
        }
    }
    analysis
}

fn same_command(a: &[String], b: &[String]) -> bool {
    a == b
}

fn placeholder_command(command: &[String]) -> bool {
    same_command(command, &["/usr/local/bin/app".to_string()])
}

fn app_config_status(cwd: &Path, assessment: &mut PrepareAssessment) {
    let toml_path = cwd.join("enclava.toml");
    if !toml_path.exists() {
        assessment
            .action("Create enclava.toml with app name, container port, and workload command.");
        return;
    }

    match AppConfig::load(&toml_path) {
        Ok(config) => {
            if config.app.command.is_empty() {
                assessment.action(
                    "Set app.command in enclava.toml; CAP overrides the image entrypoint with its startup wrapper.",
                );
            } else if placeholder_command(&config.app.command) {
                assessment.action(
                    "Replace the placeholder app.command in enclava.toml with the real workload argv.",
                );
            }

            if config.app.port != assessment.inferred_port {
                assessment.warning(format!(
                    "enclava.toml app.port is {}, but repository analysis inferred {}; verify the CAP port.",
                    config.app.port, assessment.inferred_port
                ));
            }
        }
        Err(err) => {
            assessment.action(format!("Fix enclava.toml: {err}"));
        }
    }
}

fn workflow_status(cwd: &Path, assessment: &mut PrepareAssessment) {
    let workflow_path = cwd
        .join(".github")
        .join("workflows")
        .join("enclava-deploy.yml");
    if !workflow_path.exists() {
        assessment.action(
            "Create .github/workflows/enclava-deploy.yml to build, attest, and keylessly sign the image.",
        );
        return;
    }

    let Ok(content) = std::fs::read_to_string(&workflow_path) else {
        assessment.warning("Could not read .github/workflows/enclava-deploy.yml.");
        return;
    };

    for (needle, description) in [
        ("id-token: write", "grant GitHub OIDC id-token permission"),
        ("cosign sign --yes", "sign the pushed image with cosign"),
        (
            "attest-build-provenance",
            "publish build provenance attestation",
        ),
        ("attest-sbom", "publish SBOM attestation"),
        (
            "enclava deploy --image",
            "print the digest-pinned deploy command",
        ),
        (
            "org.opencontainers.image.source=https://github.com/",
            "label the image with its source repository so GHCR can connect package access",
        ),
        (
            "org.opencontainers.image.revision=${{ github.sha }}",
            "label the image with the exact source revision",
        ),
    ] {
        if !content.contains(needle) {
            assessment.warning(format!(
                "Existing Enclava workflow does not appear to {description}."
            ));
        }
    }
}

fn assess_project(cwd: &Path) -> PrepareAssessment {
    let mut assessment = PrepareAssessment {
        app_name: default_app_name(cwd),
        ..PrepareAssessment::default()
    };

    let compose = analyze_compose(cwd, &mut assessment);
    assessment.compose_files = compose.files.clone();

    let dockerfile_path = cwd.join("Dockerfile");
    let dockerfile = if dockerfile_path.exists() {
        assessment.dockerfile = Some(relative_display(cwd, &dockerfile_path));
        match analyze_dockerfile(&dockerfile_path) {
            Ok(analysis) => Some(analysis),
            Err(err) => {
                assessment.action(format!("Read Dockerfile: {err}"));
                None
            }
        }
    } else {
        None
    };

    if assessment.dockerfile.is_none() {
        assessment.action(
            "Add a Dockerfile at the repository root or run from the app image build context.",
        );
    }

    if let Some(dockerfile) = dockerfile.as_ref() {
        if let Some(port) = dockerfile.exposes.first().copied() {
            assessment.inferred_port = port;
            assessment.port_source = "Dockerfile EXPOSE".to_string();
            if dockerfile.exposes.len() > 1 {
                assessment.warning(format!(
                    "Dockerfile exposes multiple ports ({:?}); CAP routes one primary app port.",
                    dockerfile.exposes
                ));
            }
        }

        if assessment.inferred_command.is_none() {
            assessment.inferred_command = dockerfile.command.clone();
            if dockerfile.command.is_some() {
                assessment.command_source = Some("Dockerfile ENTRYPOINT/CMD".to_string());
            }
        }

        if dockerfile.command_uses_shell {
            assessment.warning(
                "Dockerfile uses shell-form ENTRYPOINT/CMD; review generated app.command for signal handling and quoting.",
            );
        }

        if !dockerfile.volumes.is_empty() {
            assessment.warning(format!(
                "Dockerfile declares VOLUME {:?}; declare writable persistent paths in [storage].paths.",
                dockerfile.volumes
            ));
        }

        if let Some(user) = dockerfile.user.as_deref() {
            if user != "10001" && user != "10001:10001" {
                assessment.warning(format!(
                    "Dockerfile declares USER {user}; CAP runs the app as uid/gid 10001 with a read-only root filesystem."
                ));
            }
        } else {
            assessment.note(
                "CAP runs the app as uid/gid 10001 with a read-only root filesystem; ensure app files are readable/executable and writes go to [storage].paths.",
            );
        }

        if dockerfile.mentions_localhost {
            assessment.warning(
                "Dockerfile mentions localhost or 127.0.0.1; the app must listen on 0.0.0.0 inside CAP.",
            );
        }
    }

    if assessment.port_source == "default" {
        if let Some(port) = compose.port {
            assessment.inferred_port = port;
            assessment.port_source = "Compose service port".to_string();
        } else if detect_dockerfile_port(&dockerfile_path).is_none() {
            assessment
                .warning("No EXPOSE or Compose service port found; defaulting app.port to 3000.");
        }
    }

    if assessment.inferred_command.is_none() {
        if let Some(command) = compose.command.clone() {
            assessment.inferred_command = Some(command);
            assessment.command_source = compose
                .primary_service
                .as_ref()
                .map(|service| format!("Compose service {service}"))
                .or_else(|| Some("Compose service command".to_string()));
        }
    }

    if compose.command_uses_shell {
        assessment.warning(
            "Compose uses shell-form entrypoint/command; review generated app.command for signal handling and quoting.",
        );
    }

    if compose.has_multiple_services {
        assessment.warning(
            "Compose defines multiple services; prepare configures the primary web container only. Move dependencies to managed services or model sidecars explicitly in enclava.toml.",
        );
    }

    if compose.has_privileged_runtime {
        assessment.action(
            "Remove Compose privileged/cap_add/devices requirements; CAP app containers run unprivileged with Linux capabilities dropped.",
        );
    }

    if compose.has_bind_mounts {
        assessment.warning(
            "Compose bind mounts do not carry into CAP; commit needed files into the image and use [storage].paths for persistent writable data.",
        );
    }

    if compose.has_external_primary_image {
        assessment.warning(
            "Primary Compose service uses an external image without build context; the generated GitHub workflow assumes this repo builds the deploy image.",
        );
    }

    if assessment.inferred_command.is_none() {
        assessment.action(
            "Set app.command manually; no Dockerfile ENTRYPOINT/CMD or Compose command could be inferred.",
        );
    }

    app_config_status(cwd, &mut assessment);
    workflow_status(cwd, &mut assessment);
    assessment
}

fn toml_for_assessment(assessment: &PrepareAssessment) -> String {
    generate_enclava_toml_with_command(
        &assessment.app_name,
        assessment.inferred_port,
        assessment.inferred_command.as_deref(),
    )
}

fn generate_enclava_toml_with_command(name: &str, port: u16, command: Option<&[String]>) -> String {
    let Some(command) = command else {
        return generate_enclava_toml(name, port);
    };

    let command_json =
        serde_json::to_string(command).unwrap_or_else(|_| "[\"/usr/local/bin/app\"]".to_string());
    format!(
        r#"[app]
name = "{name}"
port = {port}
command = {command_json}

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

fn prepare_project<F>(
    cwd: &Path,
    check: bool,
    yes: bool,
    mut confirm_update_existing: F,
) -> Result<PrepareReport, Box<dyn std::error::Error>>
where
    F: FnMut(&[PathBuf]) -> ConfirmResult,
{
    let initial_assessment = assess_project(cwd);
    let toml_path = cwd.join("enclava.toml");
    let workflow_path = cwd
        .join(".github")
        .join("workflows")
        .join("enclava-deploy.yml");
    let existing_paths: Vec<PathBuf> = [&toml_path, &workflow_path]
        .into_iter()
        .filter(|path| path.exists())
        .cloned()
        .collect();
    let update_existing = if check || existing_paths.is_empty() {
        false
    } else if yes {
        true
    } else {
        confirm_update_existing(&existing_paths)?
    };

    let mut report = PrepareReport {
        assessment: initial_assessment.clone(),
        ..PrepareReport::default()
    };

    if check {
        return Ok(report);
    }

    let toml_content = toml_for_assessment(&initial_assessment);
    let workflow_app_name = if toml_path.exists() && !update_existing {
        existing_app_name(&toml_path, &initial_assessment.app_name)
    } else {
        initial_assessment.app_name.clone()
    };
    let workflow_content = generate_github_workflow(&workflow_app_name);

    write_target(cwd, &toml_path, &toml_content, update_existing, &mut report)?;
    write_target(
        cwd,
        &workflow_path,
        &workflow_content,
        update_existing,
        &mut report,
    )?;

    report.assessment = assess_project(cwd);
    Ok(report)
}

#[cfg(test)]
pub(crate) fn prepare_project_with_confirmation<F>(
    cwd: &Path,
    confirm_update_existing: F,
) -> Result<PrepareReport, Box<dyn std::error::Error>>
where
    F: FnMut(&[PathBuf]) -> ConfirmResult,
{
    prepare_project(cwd, false, false, confirm_update_existing)
}

fn print_assessment(assessment: &PrepareAssessment) {
    println!("Repository assessment:");
    match assessment.dockerfile.as_deref() {
        Some(path) => println!("  Dockerfile: {path}"),
        None => println!("  Dockerfile: not found"),
    }
    if !assessment.compose_files.is_empty() {
        println!("  Compose:    {}", assessment.compose_files.join(", "));
    }
    println!("  App name:   {}", assessment.app_name);
    println!(
        "  Port:       {} ({})",
        assessment.inferred_port, assessment.port_source
    );
    match assessment.inferred_command.as_ref() {
        Some(command) => {
            let command_json =
                serde_json::to_string(command).unwrap_or_else(|_| format!("{command:?}"));
            println!(
                "  Command:    {} ({})",
                command_json,
                assessment
                    .command_source
                    .as_deref()
                    .unwrap_or("repository analysis")
            );
        }
        None => println!("  Command:    not inferred"),
    }
    println!();

    if assessment.findings.is_empty() {
        println!("No readiness issues found.");
        println!();
        return;
    }

    println!("Readiness findings:");
    for finding in &assessment.findings {
        println!("  [{}] {}", finding.level.label(), finding.message);
    }
    println!();
}

fn print_report(report: &PrepareReport) {
    if !report.created.is_empty() {
        println!("Created:");
        for path in &report.created {
            println!("  {path}");
        }
        println!();
    }

    if !report.updated.is_empty() {
        println!("Updated:");
        for path in &report.updated {
            println!("  {path}");
        }
        println!();
    }

    if !report.kept_existing.is_empty() {
        println!("Kept existing:");
        for path in &report.kept_existing {
            println!("  {path}");
        }
        println!();
    }

    let changed_paths = report.changed_paths();
    if changed_paths.is_empty() {
        println!("No files changed.");
        return;
    }

    println!("Next:");
    println!("  git diff");
    println!("  git add {}", changed_paths.join(" "));
    println!("  git commit -m \"Add Enclava deployment\"");
    println!("  git push");
}

pub async fn prepare(args: PrepareArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let report = prepare_project(&cwd, args.check, args.yes, |paths| {
        println!("Found existing:");
        for path in paths {
            println!("  {}", relative_display(&cwd, path));
        }
        Confirm::new()
            .with_prompt("Update existing Enclava files?")
            .default(false)
            .interact()
            .map_err(Into::into)
    })?;

    print_assessment(&report.assessment);
    print_report(&report);

    if args.check && report.assessment.has_actions() {
        return Err(
            "repository is not ready for CAP; address actions above or run `enclava prepare`"
                .into(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_creates_missing_files_without_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("Dockerfile"),
            "FROM node:24\nEXPOSE 8080\nCMD [\"node\", \"server.js\"]\n",
        )
        .unwrap();
        let mut prompted = false;

        let report = prepare_project_with_confirmation(tmp.path(), |_| {
            prompted = true;
            Ok(false)
        })
        .unwrap();

        assert!(!prompted);
        assert_eq!(
            report.created,
            vec![
                "enclava.toml".to_string(),
                ".github/workflows/enclava-deploy.yml".to_string()
            ]
        );
        assert!(report.updated.is_empty());
        assert!(report.kept_existing.is_empty());

        let toml = std::fs::read_to_string(tmp.path().join("enclava.toml")).unwrap();
        let config = AppConfig::parse(&toml).unwrap();
        assert_eq!(config.app.port, 8080);
        assert_eq!(config.app.command, vec!["node", "server.js"]);

        let workflow =
            std::fs::read_to_string(tmp.path().join(".github/workflows/enclava-deploy.yml"))
                .unwrap();
        assert!(workflow.contains("id-token: write"));
        assert!(workflow.contains("cosign sign --yes"));
        assert!(workflow.contains("org.opencontainers.image.source=https://github.com/"));
        assert!(workflow.contains("org.opencontainers.image.revision=${{ github.sha }}"));
        assert!(!workflow.contains("https://github.com/${{ github.workflow_ref }}"));
        assert!(workflow.contains("enclava deploy --image"));
        assert!(!workflow.contains("ENCLAVA_API_KEY"));
        assert!(!workflow.contains("git push"));
        assert!(!workflow.contains("git commit"));
    }

    #[test]
    fn prepare_keeps_existing_files_without_confirmation() {
        let tmp = tempfile::tempdir().unwrap();
        let workflow_dir = tmp.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflow_dir).unwrap();
        std::fs::write(tmp.path().join("enclava.toml"), "existing config").unwrap();
        std::fs::write(workflow_dir.join("enclava-deploy.yml"), "existing workflow").unwrap();

        let report = prepare_project_with_confirmation(tmp.path(), |paths| {
            assert_eq!(paths.len(), 2);
            Ok(false)
        })
        .unwrap();

        assert!(report.created.is_empty());
        assert!(report.updated.is_empty());
        assert_eq!(
            report.kept_existing,
            vec![
                "enclava.toml".to_string(),
                ".github/workflows/enclava-deploy.yml".to_string()
            ]
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("enclava.toml")).unwrap(),
            "existing config"
        );
        assert_eq!(
            std::fs::read_to_string(workflow_dir.join("enclava-deploy.yml")).unwrap(),
            "existing workflow"
        );
    }

    #[test]
    fn prepare_overwrites_existing_files_when_confirmed() {
        let tmp = tempfile::tempdir().unwrap();
        let workflow_dir = tmp.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflow_dir).unwrap();
        std::fs::write(
            tmp.path().join("Dockerfile"),
            "FROM alpine\nEXPOSE 9090/tcp\nCMD [\"/srv/app\"]\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("enclava.toml"), "existing config").unwrap();
        std::fs::write(workflow_dir.join("enclava-deploy.yml"), "existing workflow").unwrap();

        let report = prepare_project_with_confirmation(tmp.path(), |paths| {
            assert_eq!(paths.len(), 2);
            Ok(true)
        })
        .unwrap();

        assert!(report.created.is_empty());
        assert_eq!(
            report.updated,
            vec![
                "enclava.toml".to_string(),
                ".github/workflows/enclava-deploy.yml".to_string()
            ]
        );
        assert!(report.kept_existing.is_empty());

        let toml = std::fs::read_to_string(tmp.path().join("enclava.toml")).unwrap();
        let config = AppConfig::parse(&toml).unwrap();
        assert_eq!(config.app.port, 9090);
        assert_eq!(config.app.command, vec!["/srv/app"]);

        let workflow = std::fs::read_to_string(workflow_dir.join("enclava-deploy.yml")).unwrap();
        assert!(workflow.contains("name: Build signed image"));
        assert!(workflow.contains("id-token: write"));
    }

    #[test]
    fn prepare_check_does_not_write_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("Dockerfile"),
            "FROM node:24\nEXPOSE 3001\nCMD [\"node\", \"server.js\"]\n",
        )
        .unwrap();

        let report = prepare_project(tmp.path(), true, false, |_| {
            panic!("check should not prompt")
        })
        .unwrap();

        assert!(report.created.is_empty());
        assert!(!tmp.path().join("enclava.toml").exists());
        assert_eq!(report.assessment.inferred_port, 3001);
        assert_eq!(
            report.assessment.inferred_command,
            Some(vec!["node".to_string(), "server.js".to_string()])
        );
        assert!(report.assessment.has_actions());
    }

    #[test]
    fn prepare_infers_entrypoint_and_cmd() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("Dockerfile"),
            "FROM alpine\nEXPOSE 8080\nENTRYPOINT [\"/srv/server\"]\nCMD [\"--port\", \"8080\"]\n",
        )
        .unwrap();

        let report = prepare_project_with_confirmation(tmp.path(), |_| Ok(false)).unwrap();
        let toml = std::fs::read_to_string(tmp.path().join("enclava.toml")).unwrap();
        let config = AppConfig::parse(&toml).unwrap();
        assert_eq!(config.app.command, vec!["/srv/server", "--port", "8080"]);
        assert_eq!(
            report.assessment.inferred_command,
            Some(vec![
                "/srv/server".to_string(),
                "--port".to_string(),
                "8080".to_string()
            ])
        );
    }

    #[test]
    fn prepare_reports_compose_runtime_constraints() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("docker-compose.yml"),
            r#"
services:
  web:
    build: .
    ports:
      - "8080:4000"
    command: npm start
    privileged: true
    volumes:
      - .:/app
  db:
    image: postgres:16
"#,
        )
        .unwrap();

        let report = prepare_project(tmp.path(), true, false, |_| Ok(false)).unwrap();
        assert_eq!(report.assessment.inferred_port, 4000);
        assert_eq!(
            report.assessment.inferred_command,
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "npm start".to_string()
            ])
        );
        assert!(report.assessment.findings.iter().any(|finding| {
            finding.level == FindingLevel::Action
                && finding.message.contains("privileged/cap_add/devices")
        }));
        assert!(report.assessment.findings.iter().any(|finding| {
            finding.level == FindingLevel::Warning && finding.message.contains("multiple services")
        }));
        assert!(report.assessment.findings.iter().any(|finding| {
            finding.level == FindingLevel::Warning && finding.message.contains("bind mounts")
        }));
    }
}
