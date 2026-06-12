-- Edge device registry
CREATE TABLE IF NOT EXISTS edge_devices (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    device_type     TEXT NOT NULL DEFAULT 'iot', -- "iot", "edge-gateway", "embedded", "mobile"
    platform        TEXT NOT NULL DEFAULT '',
    hw_fingerprint  TEXT NOT NULL DEFAULT '',
    assigned_keys   JSONB NOT NULL DEFAULT '[]',
    last_seen_at    TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'registered', -- "registered", "active", "revoked"
    offline_bundle  BYTEA,
    bundle_expires  TIMESTAMPTZ,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_edge_devices_tenant ON edge_devices(tenant_id);

