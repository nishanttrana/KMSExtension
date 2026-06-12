CREATE TABLE IF NOT EXISTS qkd_config (
    tenant_id           TEXT PRIMARY KEY,
    qber_threshold      DOUBLE PRECISION NOT NULL DEFAULT 0.11,
    pool_low_threshold  INTEGER NOT NULL DEFAULT 10,
    auto_inject         BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS qkd_devices (
    id            TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'peer',
    slave_sae_id  TEXT NOT NULL,
    link_status   TEXT NOT NULL DEFAULT 'up',
    key_rate      DOUBLE PRECISION NOT NULL DEFAULT 0,
    qber_avg      DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_seen_at  TIMESTAMP,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS qkd_keys (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    slave_sae_id    TEXT NOT NULL,
    external_key_id TEXT NOT NULL DEFAULT '',
    key_size_bits   INTEGER NOT NULL,
    qber            DOUBLE PRECISION NOT NULL DEFAULT 0,
    status          TEXT NOT NULL,
    keycore_key_id  TEXT NOT NULL DEFAULT '',
    wrapped_dek     BYTEA NOT NULL,
    wrapped_dek_iv  BYTEA NOT NULL,
    ciphertext      BYTEA NOT NULL,
    data_iv         BYTEA NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    injected_at     TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS qkd_sessions (
    id            TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    slave_sae_id  TEXT NOT NULL,
    app_id        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open',
    opened_at     TIMESTAMP NOT NULL,
    last_used_at  TIMESTAMP,
    closed_at     TIMESTAMP,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_qkd_devices_tenant_slave
    ON qkd_devices (tenant_id, slave_sae_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_qkd_keys_pool
    ON qkd_keys (tenant_id, slave_sae_id, status, created_at);

CREATE INDEX IF NOT EXISTS idx_qkd_keys_device
    ON qkd_keys (tenant_id, device_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_qkd_sessions_tenant
    ON qkd_sessions (tenant_id, status, opened_at DESC);
