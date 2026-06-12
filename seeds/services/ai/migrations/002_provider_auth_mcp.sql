-- 002_provider_auth_mcp.sql
-- Adds auth_json and mcp_json columns if the table exists and the columns are absent.
-- Safe to run whether 001 has been applied or not (columns may already exist in 001).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'ai_configs'
    ) THEN
        ALTER TABLE ai_configs ADD COLUMN IF NOT EXISTS auth_json TEXT NOT NULL DEFAULT '{}';
        ALTER TABLE ai_configs ADD COLUMN IF NOT EXISTS mcp_json  TEXT NOT NULL DEFAULT '{}';
    END IF;
END$$;
