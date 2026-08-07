//! Retired two-hostname migration entry point.
//!
//! The legacy implementation issued Cloudflare, HAProxy, and Kubernetes
//! mutations without the durable app/resource generation protocol used by the
//! API and worker. An accepted request could outlive this process and race a
//! later rerun, so an exclusive-maintenance flag was not a sufficient fence.
//! Existing installations must use the normal deployment reconciliation path
//! (or a purpose-built migration that claims the same durable resources) rather
//! than this unsafe one-shot tool.

fn main() -> anyhow::Result<()> {
    anyhow::bail!(
        "migrate-two-hostnames is retired because its provider writes are not durably fenced; use the normal deployment reconciliation path"
    )
}
