CREATE TABLE IF NOT EXISTS mpc_keys (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT 'mpc-key',
    algorithm TEXT NOT NULL,
    threshold INTEGER NOT NULL,
    participant_count INTEGER NOT NULL,
    participants_json TEXT NOT NULL DEFAULT '[]',
    keycore_key_id TEXT NOT NULL DEFAULT '',
    public_commitments_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending_dkg',
    share_version INTEGER NOT NULL DEFAULT 1,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_rotated_at TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_mpc_keys_tenant_created_at
    ON mpc_keys (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS mpc_shares (
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    share_x INTEGER NOT NULL,
    share_y_value TEXT NOT NULL,
    share_y_hash TEXT NOT NULL,
    share_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    refreshed_at TIMESTAMP,
    last_backup_at TIMESTAMP,
    backup_artifact TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, key_id, id)
);

CREATE INDEX IF NOT EXISTS idx_mpc_shares_tenant_key_node
    ON mpc_shares (tenant_id, key_id, node_id, share_version DESC);

CREATE TABLE IF NOT EXISTS mpc_ceremonies (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    type TEXT NOT NULL,
    key_id TEXT NOT NULL DEFAULT '',
    algorithm TEXT NOT NULL DEFAULT '',
    threshold INTEGER NOT NULL DEFAULT 2,
    participant_count INTEGER NOT NULL DEFAULT 0,
    participants_json TEXT NOT NULL DEFAULT '[]',
    message_hash TEXT NOT NULL DEFAULT '',
    ciphertext TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    result_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT '',
    required_contributors INTEGER NOT NULL DEFAULT 2,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_mpc_ceremonies_tenant_type_created_at
    ON mpc_ceremonies (tenant_id, type, created_at DESC);

CREATE TABLE IF NOT EXISTS mpc_contributions (
    tenant_id TEXT NOT NULL,
    ceremony_id TEXT NOT NULL,
    party_id TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, ceremony_id, party_id)
);

CREATE INDEX IF NOT EXISTS idx_mpc_contributions_tenant_ceremony
    ON mpc_contributions (tenant_id, ceremony_id, submitted_at ASC);
