ALTER TABLE deployments
    ADD COLUMN sigstore_material BYTEA,
    ADD COLUMN provenance_oci_material BYTEA;
