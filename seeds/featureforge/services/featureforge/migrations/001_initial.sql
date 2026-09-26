-- featureforge schema. Mirrors the migration convention used across vecta-kms
-- services (services/<svc>/migrations/00N_*.sql).

CREATE TABLE IF NOT EXISTS ff_intents (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    actor        TEXT NOT NULL,
    raw_text     TEXT NOT NULL,
    mode         TEXT NOT NULL,              -- 'config' | 'scaffold'
    stage        TEXT NOT NULL,             -- pipeline stage
    action       TEXT,                       -- resolved catalog action (config mode)
    params       JSONB NOT NULL DEFAULT '{}',
    confidence   DOUBLE PRECISION NOT NULL DEFAULT 0,
    reasons      JSONB NOT NULL DEFAULT '[]',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ff_intents_tenant_idx ON ff_intents (tenant_id);
CREATE INDEX IF NOT EXISTS ff_intents_stage_idx  ON ff_intents (stage);

-- Per-intent guardrail decisions, for inspectability and post-hoc review.
CREATE TABLE IF NOT EXISTS ff_guardrail_results (
    id         BIGSERIAL PRIMARY KEY,
    intent_id  TEXT NOT NULL REFERENCES ff_intents (id) ON DELETE CASCADE,
    layer      TEXT NOT NULL,               -- classify|validate|policy|sandbox|governance
    passed     BOOLEAN NOT NULL,
    detail     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ff_guardrail_intent_idx ON ff_guardrail_results (intent_id);

-- Linkage to governance approvals for prod promotion.
CREATE TABLE IF NOT EXISTS ff_prod_approvals (
    intent_id   TEXT NOT NULL REFERENCES ff_intents (id) ON DELETE CASCADE,
    approval_id TEXT NOT NULL,              -- governance service approval id
    granted     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (intent_id, approval_id)
);
