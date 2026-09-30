-- AI Gateway: initial schema
-- All tables use tenant_id for strict tenant isolation.

CREATE TABLE IF NOT EXISTS ai_gateway_providers (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    provider    TEXT NOT NULL,  -- openai, anthropic, azure_openai, bedrock, vertex, ollama
    api_key     TEXT NOT NULL,  -- encrypted at rest
    base_url    TEXT NOT NULL,
    model_id    TEXT NOT NULL,
    region      TEXT NOT NULL DEFAULT '',
    max_tokens  INTEGER NOT NULL DEFAULT 4096,
    cost_per_1k_input  REAL NOT NULL DEFAULT 0,
    cost_per_1k_output REAL NOT NULL DEFAULT 0,
    priority    INTEGER NOT NULL DEFAULT 0,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_rpm INTEGER NOT NULL DEFAULT 60,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gw_providers_tenant ON ai_gateway_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gw_providers_provider ON ai_gateway_providers(provider);

CREATE TABLE IF NOT EXISTS ai_gateway_policies (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT 'warn',  -- allow, redact, block, warn
    patterns    JSONB NOT NULL DEFAULT '[]',   -- list of regex/type patterns to detect
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    priority    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gw_policies_tenant ON ai_gateway_policies(tenant_id);

CREATE TABLE IF NOT EXISTS ai_gateway_access_rules (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    model_ids   JSONB NOT NULL DEFAULT '[]',
    user_roles  JSONB NOT NULL DEFAULT '[]',
    user_ids    JSONB NOT NULL DEFAULT '[]',
    max_tokens_per_request INTEGER NOT NULL DEFAULT 4096,
    require_approval BOOLEAN NOT NULL DEFAULT FALSE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gw_access_rules_tenant ON ai_gateway_access_rules(tenant_id);

CREATE TABLE IF NOT EXISTS ai_gateway_token_budgets (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,  -- tenant, user, team
    scope_id    TEXT NOT NULL,
    max_tokens  BIGINT NOT NULL DEFAULT 0,
    max_cost_usd REAL NOT NULL DEFAULT 0,
    period      TEXT NOT NULL DEFAULT 'monthly',  -- daily, weekly, monthly
    alert_at_pct REAL NOT NULL DEFAULT 0.8,
    hard_cap    BOOLEAN NOT NULL DEFAULT FALSE,
    used_tokens BIGINT NOT NULL DEFAULT 0,
    cost_used_usd REAL NOT NULL DEFAULT 0,
    reset_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gw_budgets_tenant ON ai_gateway_token_budgets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gw_budgets_scope ON ai_gateway_token_budgets(scope, scope_id);

CREATE TABLE IF NOT EXISTS ai_gateway_guardrails (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    action      TEXT NOT NULL DEFAULT 'block',  -- block, warn, log
    topics      JSONB NOT NULL DEFAULT '[]',
    keywords    JSONB NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gw_guardrails_tenant ON ai_gateway_guardrails(tenant_id);

CREATE TABLE IF NOT EXISTS ai_gateway_audit (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    user_id          TEXT NOT NULL DEFAULT '',
    request_id       TEXT NOT NULL,
    model            TEXT NOT NULL DEFAULT '',
    provider         TEXT NOT NULL DEFAULT '',
    action           TEXT NOT NULL,  -- allow, redact, block, warn
    prompt_tokens    INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd         REAL NOT NULL DEFAULT 0,
    dlp_findings     INTEGER NOT NULL DEFAULT 0,
    injection_score  REAL NOT NULL DEFAULT 0,
    toxicity_score   REAL NOT NULL DEFAULT 0,
    guardrail_hits   JSONB NOT NULL DEFAULT '[]',
    latency_ms       INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'success',  -- success, blocked, error
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gw_audit_tenant ON ai_gateway_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gw_audit_created ON ai_gateway_audit(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gw_audit_request ON ai_gateway_audit(request_id);
CREATE INDEX IF NOT EXISTS idx_gw_audit_status ON ai_gateway_audit(status);
