-- 003: Slave SAE registry and key distribution tracking

CREATE TABLE IF NOT EXISTS qkd_slave_sae (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    endpoint        TEXT NOT NULL DEFAULT '',
    auth_token      TEXT NOT NULL DEFAULT '',
    protocol        TEXT NOT NULL DEFAULT 'ETSI GS QKD 014',
    role            TEXT NOT NULL DEFAULT 'consumer',
    mode            TEXT NOT NULL DEFAULT 'etsi',
    status          TEXT NOT NULL DEFAULT 'active',
    last_sync_at    TIMESTAMP,
    keys_distributed BIGINT NOT NULL DEFAULT 0,
    keys_available   BIGINT NOT NULL DEFAULT 0,
    max_key_rate     DOUBLE PRECISION NOT NULL DEFAULT 0,
    qber_threshold   DOUBLE PRECISION NOT NULL DEFAULT 0.11,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS qkd_distributions (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    slave_sae_id    TEXT NOT NULL,
    key_count       INTEGER NOT NULL DEFAULT 0,
    key_size_bits   INTEGER NOT NULL DEFAULT 256,
    status          TEXT NOT NULL DEFAULT 'completed',
    error_message   TEXT NOT NULL DEFAULT '',
    distributed_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_qkd_slave_sae_tenant
    ON qkd_slave_sae (tenant_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_qkd_distributions_tenant
    ON qkd_distributions (tenant_id, slave_sae_id, distributed_at DESC);
