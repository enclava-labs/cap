use std::collections::BTreeSet;

fn main() {
    println!("cargo:rerun-if-changed=platform-release-profiles.json");
    if std::env::var_os("CARGO_FEATURE_RELEASE_PROFILES").is_none()
        || std::env::var_os("CARGO_FEATURE_PROD_STRICT").is_none()
    {
        return;
    }
    let raw = std::fs::read_to_string("platform-release-profiles.json")
        .expect("prod-strict requires the approved common platform-release-profiles.json bundle");
    let value: serde_json::Value =
        serde_json::from_str(&raw).expect("prod-strict requires a valid common profile bundle");
    let profiles = value.as_object().expect("profile bundle must be an object");
    assert_eq!(
        profiles.len(),
        3,
        "profile bundle must contain exactly dev, preprod and production"
    );
    let mut origins = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for name in ["dev", "preprod", "production"] {
        let profile = profiles
            .get(name)
            .expect("all three release profiles are required");
        let root = profile["root_pubkey_hex"]
            .as_str()
            .expect("profile root is required");
        assert!(
            root.len() == 64 && root.bytes().all(|b| b.is_ascii_hexdigit()),
            "profile root must be 32-byte hex"
        );
        assert!(
            !root.eq_ignore_ascii_case(
                "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd"
            ),
            "prod-strict must not trust the committed fixture root"
        );
        let profile_origins = profile["api_origins"]
            .as_array()
            .expect("profile API origins are required");
        assert!(
            !profile_origins.is_empty(),
            "profile API origins must not be empty"
        );
        for origin in profile_origins {
            let origin = origin.as_str().expect("API origin must be a string");
            assert!(
                origin.starts_with("https://"),
                "strict API origins must use HTTPS"
            );
            assert!(origins.insert(origin), "API origins must not be ambiguous");
        }
        let baseline = &profile["baseline"];
        let signing_root = baseline["signing_pubkey"]
            .as_str()
            .expect("signed baseline is required");
        assert!(
            root.eq_ignore_ascii_case(signing_root),
            "baseline signer must match its pinned profile root"
        );
        let identity = &baseline["payload"];
        let signing_key = identity["signing_service_pubkey_hex"]
            .as_str()
            .expect("signing-service identity is required");
        let ca = identity["trustee_kbs_ca_cert_pem"]
            .as_str()
            .expect("Trustee CA identity is required");
        assert!(
            signing_key.len() == 64
                && signing_key.bytes().all(|b| b.is_ascii_hexdigit())
                && !ca.trim().is_empty(),
            "installation identity must be complete"
        );
        assert!(
            identities.insert((
                root.to_ascii_lowercase(),
                signing_key.to_ascii_lowercase(),
                ca
            )),
            "profiles sharing a root must have distinct installation identities"
        );
    }
}
