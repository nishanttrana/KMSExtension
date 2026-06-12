-- MPC Enterprise Enhancement: participants, policies, key lifecycle

CREATE TABLE IF NOT EXISTS mpc_participants (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    last_seen_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_mpc_participants_tenant_status
    ON mpc_participants (tenant_id, status);

CREATE TABLE IF NOT EXISTS mpc_policies (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    key_ids TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_mpc_policies_tenant_enabled
    ON mpc_policies (tenant_id, enabled);

CREATE TABLE IF NOT EXISTS mpc_policy_rules (
    id TEXT NOT NULL PRIMARY KEY,
    policy_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mpc_policy_rules_policy
    ON mpc_policy_rules (tenant_id, policy_id);

-- Key lifecycle columns
ALTER TABLE mpc_keys ADD COLUMN IF NOT EXISTS key_group TEXT NOT NULL DEFAULT '';
ALTER TABLE mpc_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
ALTER TABLE mpc_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;
ALTER TABLE mpc_keys ADD COLUMN IF NOT EXISTS revocation_reason TEXT NOT NULL DEFAULT '';
