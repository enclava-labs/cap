//! `enclava update`: check GitHub releases for a newer CLI and replace this
//! binary with it. Same source and checks as `scripts/install.sh`: the release
//! asset for this platform, its `SHA256SUMS.txt` entry, and the cosign
//! signature on the checksums when `cosign` is on PATH.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use sha2::{Digest, Sha256};

use super::interactive;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Repository whose releases this binary updates from (a fork replaces it,
/// see docs/self-hosting.md).
const REPO: &str = "enclava-labs/cap";

/// Release tag stamped by the release workflow; source builds fall back to
/// the crate version.
pub(crate) const VERSION: &str = match option_env!("ENCLAVA_RELEASE_VERSION") {
    Some(tag) => tag,
    None => env!("CARGO_PKG_VERSION"),
};

const BIN: &str = if cfg!(windows) {
    "enclava.exe"
} else {
    "enclava"
};

/// Release archives are tens of MiB; anything past this is not one.
const MAX_ASSET_BYTES: usize = 256 * 1024 * 1024;

#[derive(Args)]
pub struct UpdateArgs {
    /// Only report whether a newer version is published
    #[arg(long, conflicts_with = "yes")]
    pub check: bool,
    /// Install the new version without asking
    #[arg(long, short = 'y')]
    pub yes: bool,
}

pub async fn run(args: UpdateArgs) -> Result<()> {
    let latest = latest_tag().await?;
    if !is_newer(VERSION, &latest) {
        println!("enclava {VERSION} is up to date.");
        return Ok(());
    }
    println!("A new version of enclava is available: {latest} (installed: {VERSION}).");
    // Resolved here but only required for the install: `--check` on a
    // platform without release builds still reports the new version.
    let asset = release_asset(std::env::consts::OS, std::env::consts::ARCH);
    if args.check {
        match asset {
            Ok(_) => println!("Run `enclava update` to install it."),
            Err(e) => println!("{e}"),
        }
        return Ok(());
    }
    let asset = asset?;
    if option_env!("ENCLAVA_RELEASE_VERSION").is_none() {
        println!("This binary was built from source; updating replaces it with the release build.");
    }
    if !args.yes {
        interactive::require_prompt("pass --yes to install the update")?;
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!("Install enclava {latest}?"))
            .default(true)
            .interact()?;
        if !confirm {
            println!("Update cancelled.");
            return Ok(());
        }
    }

    let base = format!("https://github.com/{REPO}/releases/download/{latest}");
    let client = http_client(reqwest::redirect::Policy::default())?;

    println!("Downloading {asset}...");
    let sums = download(&client, &format!("{base}/SHA256SUMS.txt")).await?;
    let expected = checksum_for(&String::from_utf8_lossy(&sums), &asset).ok_or_else(|| {
        format!(
            "release {latest} has no build for this platform ({asset}); \
             see https://github.com/{REPO}/releases"
        )
    })?;
    let archive = download(&client, &format!("{base}/{asset}")).await?;
    let actual = hex::encode(Sha256::digest(&archive));
    if actual != expected {
        return Err(
            format!("checksum mismatch for {asset} (got {actual}, want {expected})").into(),
        );
    }
    verify_signature(&client, &base, &sums).await?;

    let exe = replace_exe(&extract_binary(&archive)?)?;
    println!("Updated enclava {VERSION} -> {latest} ({})", exe.display());
    Ok(())
}

fn http_client(redirect: reqwest::redirect::Policy) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(format!("enclava-cli/{}", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .redirect(redirect)
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
        .build()?)
}

/// Release archive for this platform. Releases cover Linux, macOS and
/// Windows only; any other OS must not be handed one of those binaries.
fn release_asset(os: &str, arch: &str) -> Result<String> {
    match os {
        "linux" | "macos" | "windows" => Ok(format!("enclava-{os}-{arch}.tar.gz")),
        _ => Err(format!(
            "no release builds are published for {os}; update with \
             `cargo install --locked --git https://github.com/{REPO} enclava-cli`"
        )
        .into()),
    }
}

/// `releases/latest` redirects to `releases/tag/<tag>`; reading the redirect
/// avoids the rate-limited GitHub API (as `scripts/install.sh` does).
async fn latest_tag() -> Result<String> {
    let url = format!("https://github.com/{REPO}/releases/latest");
    let resp = http_client(reqwest::redirect::Policy::none())?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("could not check for updates: {e}"))?;
    resp.headers()
        .get(reqwest::header::LOCATION)
        .and_then(|location| location.to_str().ok())
        .and_then(|location| location.rsplit_once("/releases/tag/"))
        .map(|(_, tag)| tag.to_string())
        .filter(|tag| !tag.is_empty())
        .ok_or_else(|| {
            format!(
                "could not check for updates: {url} did not name a release (HTTP {})",
                resp.status()
            )
            .into()
        })
}

/// Tags are `vX.Y.Z[-suffix]`. Anything that does not parse is compared by
/// name, so an unexpected tag still offers the published release.
fn is_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| semver::Version::parse(v.trim_start_matches('v')).ok();
    match (parse(current), parse(latest)) {
        (Some(current), Some(latest)) => latest > current,
        _ => current != latest,
    }
}

fn checksum_for(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, name) = line.split_once(char::is_whitespace)?;
        (name.trim().trim_start_matches('*') == asset).then(|| hash.to_ascii_lowercase())
    })
}

async fn download(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("download failed for {url}: {e}"))?;
    Ok(enclava_cli::api_client::read_bounded_body(resp, MAX_ASSET_BYTES).await?)
}

/// Verify the keyless signature on the checksums when cosign is installed;
/// without it the update is checksum-verified only, like the installer.
async fn verify_signature(client: &reqwest::Client, base: &str, sums: &[u8]) -> Result<()> {
    let probe = std::process::Command::new("cosign")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if probe.is_err() {
        println!(
            "note: cosign not found; verified checksum only. \
             Install cosign for signature verification."
        );
        return Ok(());
    }
    let bundle = download(client, &format!("{base}/SHA256SUMS.txt.sigstore.json")).await?;
    let dir = tempfile::tempdir()?;
    let sums_path = dir.path().join("SHA256SUMS.txt");
    let bundle_path = dir.path().join("SHA256SUMS.txt.sigstore.json");
    std::fs::write(&sums_path, sums)?;
    std::fs::write(&bundle_path, bundle)?;
    let output = std::process::Command::new("cosign")
        .arg("verify-blob")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--certificate-identity-regexp")
        .arg(format!("^https://github.com/{REPO}/"))
        .arg("--certificate-oidc-issuer")
        .arg("https://token.actions.githubusercontent.com")
        .arg(&sums_path)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cosign signature verification failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    println!("Signature verified with cosign.");
    Ok(())
}

fn extract_binary(archive: &[u8]) -> Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_file()
            && entry.path()?.file_name() == Some(std::ffi::OsStr::new(BIN))
        {
            let mut binary = Vec::new();
            entry.read_to_end(&mut binary)?;
            return Ok(binary);
        }
    }
    Err(format!("release archive does not contain {BIN}").into())
}

/// Swap the running executable for `binary`: written next to it, then renamed
/// over it, so an interrupted update never leaves a partial binary.
fn replace_exe(binary: &[u8]) -> Result<PathBuf> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let dir = exe.parent().unwrap_or(Path::new("."));
    let mut staged = tempfile::Builder::new()
        .prefix(".enclava-update-")
        .tempfile_in(dir)
        .map_err(|e| {
            format!(
                "cannot write to {} ({e}); re-run with permission to modify that directory",
                dir.display()
            )
        })?;
    staged.write_all(binary)?;
    staged.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(staged.path(), std::fs::Permissions::from_mode(0o755))?;
    }
    // Windows cannot overwrite a running executable but can rename it; the
    // parked copy is removed by the next update.
    #[cfg(windows)]
    let parked = {
        let parked = exe.with_extension("exe.old");
        let _ = std::fs::remove_file(&parked);
        std::fs::rename(&exe, &parked)?;
        parked
    };
    if let Err(e) = staged.persist(&exe) {
        #[cfg(windows)]
        let _ = std::fs::rename(&parked, &exe);
        return Err(format!("could not replace {}: {}", exe.display(), e.error).into());
    }
    Ok(exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offers_only_newer_releases() {
        assert!(is_newer("v0.1.21", "v0.1.22"));
        assert!(is_newer("0.1.1", "v0.1.22"));
        assert!(is_newer("v0.1.18-prepare-20261116", "v0.1.18"));
        assert!(!is_newer("v0.1.22", "v0.1.22"));
        assert!(!is_newer("v0.2.0", "v0.1.22"));
        assert!(is_newer("v0.1.22", "nightly"));
    }

    #[test]
    fn only_published_platforms_get_a_release_asset() {
        assert_eq!(
            release_asset("linux", "x86_64").unwrap(),
            "enclava-linux-x86_64.tar.gz"
        );
        let refused = release_asset("freebsd", "x86_64").unwrap_err().to_string();
        assert!(refused.contains("cargo install"), "{refused}");
    }

    #[test]
    fn checksum_lookup_matches_the_exact_asset() {
        let sums = "AA11  enclava-linux-x86_64.tar.gz\nbb22  enclava-verifier-web.tar.gz\n";
        assert_eq!(
            checksum_for(sums, "enclava-linux-x86_64.tar.gz").as_deref(),
            Some("aa11")
        );
        assert_eq!(checksum_for(sums, "enclava-windows-aarch64.tar.gz"), None);
    }
}
