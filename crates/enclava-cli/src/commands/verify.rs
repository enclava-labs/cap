use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use clap::Args;
use enclava_verifier::{
    MAX_PROOF_BUNDLE_BYTES, PROOF_BUNDLE_MEDIA_TYPE, Verdict, VerificationContext,
    parse_proof_bundle, tls_leaf_spki_sha256, verify,
};
use futures::StreamExt;
use rand::{RngCore, rngs::OsRng};

#[derive(Args)]
pub struct VerifyArgs {
    /// HTTPS origin to verify directly
    #[arg(value_name = "HTTPS_ORIGIN", conflicts_with = "bundle")]
    origin: Option<String>,
    /// Appraisal policy obtained independently of the target
    #[arg(long, value_name = "PATH")]
    policy: PathBuf,
    /// Verify a previously saved proof bundle (historical evidence)
    #[arg(long, value_name = "PATH", conflicts_with = "origin")]
    bundle: Option<PathBuf>,
    /// Save the exact live proof-bundle bytes
    #[arg(long, value_name = "PATH", requires = "origin")]
    save_bundle: Option<PathBuf>,
    /// Emit the canonical result schema as compact JSON
    #[arg(long)]
    json: bool,
}

pub async fn run(args: VerifyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let policy = tokio::fs::read(&args.policy).await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (bundle, context, historical) = match (args.origin.as_deref(), args.bundle.as_ref()) {
        (Some(origin), None) => {
            let origin = normalize_origin(origin)?;
            let mut nonce = [0; 32];
            OsRng.fill_bytes(&mut nonce);
            let (bundle, channel_spki) = fetch_bundle(&origin, &nonce).await?;
            if let Some(path) = &args.save_bundle {
                tokio::fs::write(path, &bundle).await?;
            }
            (
                bundle,
                VerificationContext {
                    challenge_nonce: nonce,
                    expected_target_origin: origin,
                    now_unix_seconds: now,
                    observed_channel_spki_sha256: Some(channel_spki),
                },
                false,
            )
        }
        (None, Some(path)) => {
            let bundle = tokio::fs::read(path).await?;
            let parsed = parse_proof_bundle(&bundle)?;
            let challenge_nonce = parsed.challenge_nonce;
            let expected_target_origin = parsed.target_origin.to_owned();
            (
                bundle,
                VerificationContext {
                    challenge_nonce,
                    expected_target_origin,
                    now_unix_seconds: now,
                    observed_channel_spki_sha256: None,
                },
                true,
            )
        }
        _ => return Err("provide either HTTPS_ORIGIN or --bundle PATH".into()),
    };
    let result = verify(&bundle, &policy, context);
    if args.json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
        if historical {
            eprintln!("Historical appraisal: this saved bundle does not prove current liveness.");
        }
    }
    if result.verdict != Verdict::Pass {
        return Err(format!("verification result: {:?}", result.verdict).into());
    }
    Ok(())
}

fn normalize_origin(input: &str) -> Result<String, Box<dyn std::error::Error>> {
    let url = reqwest::Url::parse(input)?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "target must be an HTTPS origin without credentials, path, query, or fragment".into(),
        );
    }
    Ok(url.origin().ascii_serialization())
}

async fn fetch_bundle(
    origin: &str,
    nonce: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), Box<dyn std::error::Error>> {
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let url = format!("{origin}/.well-known/confidential/proof-bundle?nonce={nonce}");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .tls_info(true)
        .build()?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, PROOF_BUNDLE_MEDIA_TYPE)
        .send()
        .await?;
    if !response.status().is_success()
        || response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(PROOF_BUNDLE_MEDIA_TYPE)
        || response
            .content_length()
            .is_some_and(|length| length > MAX_PROOF_BUNDLE_BYTES as u64)
    {
        return Err(format!(
            "proof endpoint returned {} or an invalid response",
            response.status()
        )
        .into());
    }
    let leaf = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .ok_or("TLS peer certificate unavailable")?
        .to_vec();
    let channel_spki = tls_leaf_spki_sha256(&leaf)?;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > MAX_PROOF_BUNDLE_BYTES {
            return Err("proof bundle exceeds the v1 size limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, channel_spki))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_bare_https_origins() {
        assert_eq!(
            normalize_origin("https://Example.com/").unwrap(),
            "https://example.com"
        );
        for invalid in [
            "http://example.com",
            "https://example.com/path",
            "https://user@example.com",
        ] {
            assert!(normalize_origin(invalid).is_err());
        }
    }
}
