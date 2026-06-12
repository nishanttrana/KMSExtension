CREATE TABLE IF NOT EXISTS ai_protect_policies (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    patterns_json TEXT NOT NULL DEFAULT '[]',
    action TEXT NOT NULL DEFAULT 'redact',
    scope TEXT NOT NULL DEFAULT 'both',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ai_protect_policies_tenant
    ON ai_protect_policies (tenant_id);

CREATE TABLE IF NOT EXISTS ai_protect_audit (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    finding_count INTEGER NOT NULL DEFAULT 0,
    patterns_json TEXT NOT NULL DEFAULT '[]',
    context TEXT NOT NULL DEFAULT '',
    policy_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ai_protect_audit_tenant_created_at
    ON ai_protect_audit (tenant_id, created_at DESC);
