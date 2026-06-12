-- 001: QRNG source registry, entropy pool, and health monitoring

CREATE TABLE IF NOT EXISTS qrng_sources (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    vendor          TEXT NOT NULL DEFAULT 'custom',
    endpoint        TEXT NOT NULL DEFAULT '',
    auth_token      TEXT NOT NULL DEFAULT '',
    mode            TEXT NOT NULL DEFAULT 'push',
    status          TEXT NOT NULL DEFAULT 'active',
    min_entropy_bpb DOUBLE PRECISION NOT NULL DEFAULT 7.0,
    pull_interval_s INTEGER NOT NULL DEFAULT 60,
    last_seen_at    TIMESTAMP,
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_qrng_sources_tenant
    ON qrng_sources (tenant_id, status);

CREATE TABLE IF NOT EXISTS qrng_pool (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    sample_hash     TEXT NOT NULL,
    byte_count      INTEGER NOT NULL DEFAULT 0,
    entropy_bpb     DOUBLE PRECISION NOT NULL DEFAULT 0,
    bias_score      DOUBLE PRECISION NOT NULL DEFAULT 0,
    passed_health   BOOLEAN NOT NULL DEFAULT TRUE,
    consumed        BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at     TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_qrng_pool_available
    ON qrng_pool (tenant_id, consumed, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_qrng_pool_source
    ON qrng_pool (tenant_id, source_id);

CREATE TABLE IF NOT EXISTS qrng_health_log (
    id          TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    source_id   TEXT NOT NULL DEFAULT '',
    check_type  TEXT NOT NULL DEFAULT '',
    result      TEXT NOT NULL DEFAULT 'pass',
    entropy_bpb DOUBLE PRECISION NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT '{}',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_qrng_health_tenant
    ON qrng_health_log (tenant_id, created_at DESC);
