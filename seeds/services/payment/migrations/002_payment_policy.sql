CREATE TABLE IF NOT EXISTS payment_policy (
    tenant_id TEXT PRIMARY KEY,
    allowed_tr31_versions_json TEXT NOT NULL DEFAULT '["B","C","D"]',
    require_kbpk_for_tr31 BOOLEAN NOT NULL DEFAULT FALSE,
    allow_inline_key_material BOOLEAN NOT NULL DEFAULT TRUE,
    max_iso20022_payload_bytes INTEGER NOT NULL DEFAULT 1048576,
    require_iso20022_lau_context BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
