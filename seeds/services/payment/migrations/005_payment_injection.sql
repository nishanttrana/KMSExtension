CREATE TABLE IF NOT EXISTS payment_injection_terminals (
    tenant_id                    TEXT NOT NULL,
    id                           TEXT NOT NULL,
    terminal_id                  TEXT NOT NULL,
    name                         TEXT NOT NULL,
    status                       TEXT NOT NULL DEFAULT 'pending',
    transport                    TEXT NOT NULL DEFAULT 'jwt',
    key_algorithm                TEXT NOT NULL DEFAULT 'rsa-oaep-sha256',
    public_key_pem               TEXT NOT NULL,
    public_key_fingerprint       TEXT NOT NULL,
    registration_nonce           TEXT,
    registration_nonce_expires_at TIMESTAMP,
    verified_at                  TIMESTAMP,
    auth_token_hash              TEXT,
    auth_token_issued_at         TIMESTAMP,
    last_seen_at                 TIMESTAMP,
    metadata_json                TEXT NOT NULL DEFAULT '{}',
    created_at                   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, terminal_id)
);

CREATE TABLE IF NOT EXISTS payment_injection_jobs (
    tenant_id                TEXT NOT NULL,
    id                       TEXT NOT NULL,
    terminal_id              TEXT NOT NULL,
    payment_key_id           TEXT NOT NULL,
    key_id                   TEXT NOT NULL,
    tr31_version             TEXT NOT NULL,
    tr31_usage_code          TEXT NOT NULL,
    tr31_key_block           TEXT NOT NULL,
    tr31_kcv                 TEXT NOT NULL,
    payload_ciphertext_b64   TEXT NOT NULL,
    payload_iv_b64           TEXT NOT NULL,
    wrapped_dek_b64          TEXT NOT NULL,
    dek_wrap_alg             TEXT NOT NULL,
    status                   TEXT NOT NULL DEFAULT 'queued',
    delivered_at             TIMESTAMP,
    acked_at                 TIMESTAMP,
    ack_detail               TEXT,
    created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_payment_injection_terminals_tenant_status
    ON payment_injection_terminals (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_payment_injection_jobs_tenant_terminal
    ON payment_injection_jobs (tenant_id, terminal_id, status, created_at DESC);
