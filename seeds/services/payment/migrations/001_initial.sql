CREATE TABLE IF NOT EXISTS payment_keys (
    id                TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    key_id            TEXT NOT NULL,
    payment_type      TEXT NOT NULL,
    usage_code        TEXT NOT NULL,
    mode_of_use       TEXT NOT NULL,
    key_version_num   TEXT NOT NULL DEFAULT '00',
    exportability     TEXT NOT NULL DEFAULT 'E',
    tr31_header       TEXT,
    kcv               BYTEA,
    iso20022_party_id TEXT,
    iso20022_msg_types TEXT NOT NULL DEFAULT '[]',
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS tr31_translations (
    id            TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    source_key_id TEXT NOT NULL DEFAULT '',
    source_format TEXT NOT NULL,
    target_format TEXT NOT NULL,
    kek_key_id    TEXT NOT NULL DEFAULT '',
    result_block  TEXT,
    status        TEXT NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS pin_operations_log (
    id            TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    operation     TEXT NOT NULL,
    source_format TEXT,
    target_format TEXT,
    zpk_key_id    TEXT,
    result        TEXT NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_payment_keys_tenant_created
    ON payment_keys (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_payment_keys_tenant_key
    ON payment_keys (tenant_id, key_id);

CREATE INDEX IF NOT EXISTS idx_tr31_translations_tenant_created
    ON tr31_translations (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_pin_ops_tenant_created
    ON pin_operations_log (tenant_id, created_at DESC);
