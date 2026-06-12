CREATE TABLE IF NOT EXISTS ai_configs (
    tenant_id TEXT PRIMARY KEY,
    backend TEXT NOT NULL DEFAULT 'claude',
    endpoint TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT 'claude-sonnet-4-20250514',
    api_key_secret TEXT NOT NULL DEFAULT 'ai-api-key',
    auth_json TEXT NOT NULL DEFAULT '{}',
    mcp_json TEXT NOT NULL DEFAULT '{}',
    max_context_tokens INTEGER NOT NULL DEFAULT 100000,
    temperature DOUBLE PRECISION NOT NULL DEFAULT 0.1,
    context_sources_json TEXT NOT NULL DEFAULT '{}',
    redaction_fields_json TEXT NOT NULL DEFAULT '[]',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_interactions (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    action TEXT NOT NULL,
    request_json TEXT NOT NULL DEFAULT '{}',
    context_summary_json TEXT NOT NULL DEFAULT '{}',
    response_json TEXT NOT NULL DEFAULT '{}',
    redaction_count INTEGER NOT NULL DEFAULT 0,
    backend TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ai_interactions_tenant_created_at
    ON ai_interactions (tenant_id, created_at DESC);
