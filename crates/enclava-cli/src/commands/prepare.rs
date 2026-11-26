use dialoguer::Confirm;
use enclava_cli::app_config::AppConfig;
use std::path::{Path, PathBuf};

use super::init::{
    default_app_name, detect_dockerfile_port, generate_enclava_toml, generate_github_workflow,
};

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PrepareReport {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub kept_existing: Vec<String>,
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

type ConfirmResult = Result<bool, Box<dyn std::error::Error>>;

fn relative_display(cwd: &Path, path: &Path) -> String {
    path.strip_prefix(cwd)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
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

pub(crate) fn prepare_project_with_confirmation<F>(
    cwd: &Path,
    mut confirm_update_existing: F,
) -> Result<PrepareReport, Box<dyn std::error::Error>>
where
    F: FnMut(&[PathBuf]) -> ConfirmResult,
{
    let toml_path = cwd.join("enclava.toml");
    let workflow_path = cwd
        .join(".github")
        .join("workflows")
        .join("enclava-deploy.yml");
    // An existing enclava.toml is the user's configuration (storage paths,
    // resources, command), not scaffolding: it is never regenerated. Only the
    // generated workflow can be refreshed, and only after confirmation.
    let update_workflow =
        workflow_path.exists() && confirm_update_existing(std::slice::from_ref(&workflow_path))?;

    let inferred_name = default_app_name(cwd);
    let detected_port = detect_dockerfile_port(&cwd.join("Dockerfile")).unwrap_or(3000);
    let toml_content = generate_enclava_toml(&inferred_name, detected_port);

    let workflow_app_name = if toml_path.exists() {
        existing_app_name(&toml_path, &inferred_name)
    } else {
        inferred_name.clone()
    };
    let workflow_content = generate_github_workflow(&workflow_app_name);

    let mut report = PrepareReport::default();
    write_target(cwd, &toml_path, &toml_content, false, &mut report)?;
    write_target(
        cwd,
        &workflow_path,
        &workflow_content,
        update_workflow,
        &mut report,
    )?;

    Ok(report)
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

#[derive(clap::Args)]
pub struct PrepareArgs {
    /// Regenerate an existing deploy workflow without the interactive
    /// confirmation. An existing enclava.toml is always kept as is.
    #[arg(long)]
    pub yes: bool,
}

pub async fn prepare(args: PrepareArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let report = prepare_project_with_confirmation(&cwd, |paths| {
        println!("Found existing:");
        for path in paths {
            println!("  {}", relative_display(&cwd, path));
        }
        if args.yes {
            return Ok(true);
        }
        super::interactive::require_prompt(
            "pass --yes to regenerate the existing workflow without confirmation",
        )?;
        Confirm::new()
            .with_prompt("Regenerate the existing deploy workflow?")
            .default(false)
            .interact()
            .map_err(Into::into)
    })?;
    print_report(&report);
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

        let workflow =
            std::fs::read_to_string(tmp.path().join(".github/workflows/enclava-deploy.yml"))
                .unwrap();
        assert!(workflow.contains("id-token: write"));
        assert!(workflow.contains("cosign sign --yes"));
        // Pinned installer (cosign 3.x → portable DSSE); a floating tag here
        // can regress deploys to legacy .sig objects that lack portable material.
        assert!(
            workflow.contains("sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6")
        );
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
            assert_eq!(paths, [workflow_dir.join("enclava-deploy.yml")]);
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
    fn prepare_keeps_existing_config_and_updates_workflow_when_confirmed() {
        let tmp = tempfile::tempdir().unwrap();
        let workflow_dir = tmp.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflow_dir).unwrap();
        std::fs::write(
            tmp.path().join("Dockerfile"),
            "FROM alpine\nEXPOSE 9090/tcp\n",
        )
        .unwrap();
        // A stateless config: regenerating it would inject paths = ["/data"].
        let existing = generate_enclava_toml("stateless-app", 8080)
            .replace("paths = [\"/data\"]", "paths = []")
            .replace("cpu = \"1\"", "cpu = \"0.5\"")
            .replace("memory = \"1Gi\"", "memory = \"512Mi\"");
        assert!(
            AppConfig::parse(&existing)
                .unwrap()
                .storage
                .paths
                .is_empty()
        );
        std::fs::write(tmp.path().join("enclava.toml"), &existing).unwrap();
        std::fs::write(workflow_dir.join("enclava-deploy.yml"), "existing workflow").unwrap();

        let report = prepare_project_with_confirmation(tmp.path(), |paths| {
            assert_eq!(paths, [workflow_dir.join("enclava-deploy.yml")]);
            Ok(true)
        })
        .unwrap();

        assert!(report.created.is_empty());
        assert_eq!(
            report.updated,
            vec![".github/workflows/enclava-deploy.yml".to_string()]
        );
        assert_eq!(report.kept_existing, vec!["enclava.toml".to_string()]);

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("enclava.toml")).unwrap(),
            existing
        );

        let workflow = std::fs::read_to_string(workflow_dir.join("enclava-deploy.yml")).unwrap();
        assert!(workflow.contains("name: Build signed image for stateless-app"));
        assert!(workflow.contains("id-token: write"));
    }

    #[test]
    fn prepare_keeps_existing_config_without_prompt_when_workflow_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("enclava.toml"), "existing config").unwrap();

        let report = prepare_project_with_confirmation(tmp.path(), |_| {
            panic!("nothing would be overwritten, so nothing to confirm")
        })
        .unwrap();

        assert_eq!(
            report.created,
            vec![".github/workflows/enclava-deploy.yml".to_string()]
        );
        assert_eq!(report.kept_existing, vec!["enclava.toml".to_string()]);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("enclava.toml")).unwrap(),
            "existing config"
        );
    }
}
