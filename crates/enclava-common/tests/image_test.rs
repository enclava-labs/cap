use enclava_common::image::ImageRef;

#[test]
fn parse_digest_ref() {
    let img = ImageRef::parse(
        "ghcr.io/user/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    )
    .unwrap();
    assert_eq!(img.registry(), "ghcr.io");
    assert_eq!(img.repository(), "user/app");
    assert_eq!(
        img.digest(),
        "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    );
    assert!(img.tag().is_none());
    assert!(img.has_digest());
}

#[test]
fn parse_tag_ref() {
    let img = ImageRef::parse("ghcr.io/user/app:latest").unwrap();
    assert_eq!(img.tag(), Some("latest"));
    assert!(!img.has_digest());
}

#[test]
fn parse_bare_image() {
    let img = ImageRef::parse("ubuntu:latest").unwrap();
    assert_eq!(img.registry(), "docker.io");
    assert_eq!(img.repository(), "library/ubuntu");
    assert_eq!(img.tag(), Some("latest"));
}

#[test]
fn digest_ref_string() {
    let img = ImageRef::parse(
        "ghcr.io/user/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    )
    .unwrap();
    assert_eq!(
        img.digest_ref(),
        "ghcr.io/user/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    );
}

#[test]
fn require_digest_rejects_tag_only() {
    let img = ImageRef::parse("ghcr.io/user/app:latest").unwrap();
    let err = img.require_digest().unwrap_err();
    assert!(err.to_string().contains("digest"));
}

#[test]
fn require_digest_accepts_pinned() {
    let img = ImageRef::parse(
        "ghcr.io/user/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    )
    .unwrap();
    img.require_digest().unwrap(); // should not panic
}

#[test]
fn parse_rejects_non_sha256_digest() {
    let err = ImageRef::parse("ghcr.io/user/app@not-a-sha256-digest").unwrap_err();
    assert!(err.to_string().contains("sha256"));
}

#[test]
fn parse_rejects_short_sha256_digest() {
    let err = ImageRef::parse("ghcr.io/user/app@sha256:abc").unwrap_err();
    assert!(err.to_string().contains("64"));
}

#[test]
fn parse_tag_and_digest_ref_keeps_tag_out_of_repository() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let img = ImageRef::parse(&format!("ghcr.io/acme/app:v1@{digest}")).unwrap();
    assert_eq!(img.registry(), "ghcr.io");
    assert_eq!(img.repository(), "acme/app");
    assert_eq!(img.tag(), Some("v1"));
    assert_eq!(img.digest(), digest);
    assert_eq!(img.digest_ref(), format!("ghcr.io/acme/app@{digest}"));

    let bare = ImageRef::parse(&format!("nginx:1.27@{digest}")).unwrap();
    assert_eq!(bare.registry(), "docker.io");
    assert_eq!(bare.repository(), "library/nginx");
    assert_eq!(bare.tag(), Some("1.27"));

    let with_port =
        ImageRef::parse(&format!("registry.example.com:5000/acme/app:v1@{digest}")).unwrap();
    assert_eq!(with_port.registry(), "registry.example.com:5000");
    assert_eq!(with_port.repository(), "acme/app");
    assert_eq!(with_port.tag(), Some("v1"));
}

#[test]
fn parse_tag_and_digest_ref_rejects_invalid_tag() {
    let digest = format!("sha256:{}", "a".repeat(64));
    assert!(ImageRef::parse(&format!("ghcr.io/acme/app:v$1@{digest}")).is_err());
}

#[test]
fn parse_rejects_extra_colon_in_repository() {
    let digest = format!("sha256:{}", "a".repeat(64));
    assert!(ImageRef::parse(&format!("ghcr.io/acme/app:tag:extra@{digest}")).is_err());
    assert!(ImageRef::parse("ghcr.io/acme/app:tag:extra").is_err());
}
