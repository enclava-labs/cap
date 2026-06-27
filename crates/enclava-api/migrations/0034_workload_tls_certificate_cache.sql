-- Public certificate-chain cache for workload-attested DNS-01 issuance.
-- Tenant private keys remain workload-owned inside the confidential runtime;
-- CAP stores only public certificate chains keyed by the CSR public key.
CREATE TABLE workload_tls_certificate_cache (
    acme_directory_url          text NOT NULL,
    hostnames_key               text NOT NULL,
    csr_sha256                  bytea NOT NULL,
    certificate_chain_pem       text NOT NULL,
    last_descriptor_core_hash   bytea NOT NULL,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (acme_directory_url, hostnames_key, csr_sha256),
    CONSTRAINT workload_tls_certificate_cache_pem_check
        CHECK (position('-----BEGIN CERTIFICATE-----' in certificate_chain_pem) > 0)
);

CREATE INDEX idx_workload_tls_certificate_cache_updated
    ON workload_tls_certificate_cache(updated_at);
