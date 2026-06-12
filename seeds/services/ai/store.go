package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	GetConfig(ctx context.Context, tenantID string) (AIConfig, error)
	UpsertConfig(ctx context.Context, item AIConfig) error
	CreateInteraction(ctx context.Context, item AIInteraction) error
	ListRecentInteractions(ctx context.Context, tenantID string, limit int) ([]AIInteraction, error)

	ListAIProtectPolicies(ctx context.Context, tenantID string) ([]AIProtectPolicy, error)
	CreateAIProtectPolicy(ctx context.Context, p AIProtectPolicy) (AIProtectPolicy, error)
	DeleteAIProtectPolicy(ctx context.Context, tenantID, id string) error
	InsertAIProtectAuditEntry(ctx context.Context, e AIProtectAuditEntry) error
	ListAIProtectAuditEntries(ctx context.Context, tenantID string, limit int) ([]AIProtectAuditEntry, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) GetConfig(ctx context.Context, tenantID string) (AIConfig, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, backend, endpoint, model, api_key_secret, auth_json, mcp_json, max_context_tokens, temperature, context_sources_json, redaction_fields_json, updated_at
FROM ai_configs
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))
	item, err := scanAIConfig(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AIConfig{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertConfig(ctx context.Context, item AIConfig) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ai_configs (
	tenant_id, backend, endpoint, model, api_key_secret, auth_json, mcp_json, max_context_tokens, temperature, context_sources_json, redaction_fields_json, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
	backend = EXCLUDED.backend,
	endpoint = EXCLUDED.endpoint,
	model = EXCLUDED.model,
	api_key_secret = EXCLUDED.api_key_secret,
	auth_json = EXCLUDED.auth_json,
	mcp_json = EXCLUDED.mcp_json,
	max_context_tokens = EXCLUDED.max_context_tokens,
	temperature = EXCLUDED.temperature,
	context_sources_json = EXCLUDED.context_sources_json,
	redaction_fields_json = EXCLUDED.redaction_fields_json,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, item.Backend, item.Endpoint, item.Model, item.APIKeySecret, mustJSON(item.ProviderAuth, "{}"), mustJSON(item.MCP, "{}"), item.MaxContextTokens, item.Temperature, mustJSON(item.ContextSources, "{}"), mustJSON(item.RedactionFields, "[]"))
	return err
}

func (s *SQLStore) CreateInteraction(ctx context.Context, item AIInteraction) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ai_interactions (
	tenant_id, id, action, request_json, context_summary_json, response_json, redaction_count, backend, model, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Action, mustJSON(item.Request, "{}"), mustJSON(item.ContextSummary, "{}"), mustJSON(item.Response, "{}"), item.RedactionCount, item.Backend, item.Model)
	return err
}

func (s *SQLStore) ListRecentInteractions(ctx context.Context, tenantID string, limit int) ([]AIInteraction, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, action, request_json, context_summary_json, response_json, redaction_count, backend, model, created_at
FROM ai_interactions
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2
`, strings.TrimSpace(tenantID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]AIInteraction, 0)
	for rows.Next() {
		item, err := scanAIInteraction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanAIConfig(scanner interface {
	Scan(dest ...interface{}) error
}) (AIConfig, error) {
	var (
		item             AIConfig
		authJS           string
		mcpJS            string
		contextSourcesJS string
		redactionJS      string
		updatedRaw       interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.Backend,
		&item.Endpoint,
		&item.Model,
		&item.APIKeySecret,
		&authJS,
		&mcpJS,
		&item.MaxContextTokens,
		&item.Temperature,
		&contextSourcesJS,
		&redactionJS,
		&updatedRaw,
	); err != nil {
		return AIConfig{}, err
	}
	if strings.TrimSpace(authJS) != "" {
		_ = json.Unmarshal([]byte(authJS), &item.ProviderAuth)
	}
	if strings.TrimSpace(mcpJS) != "" {
		_ = json.Unmarshal([]byte(mcpJS), &item.MCP)
	}
	if strings.TrimSpace(contextSourcesJS) != "" {
		_ = json.Unmarshal([]byte(contextSourcesJS), &item.ContextSources)
	}
	item.RedactionFields = parseJSONArrayString(redactionJS)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanAIInteraction(scanner interface {
	Scan(dest ...interface{}) error
}) (AIInteraction, error) {
	var (
		item             AIInteraction
		requestJS        string
		contextSummaryJS string
		responseJS       string
		createdRaw       interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.ID,
		&item.Action,
		&requestJS,
		&contextSummaryJS,
		&responseJS,
		&item.RedactionCount,
		&item.Backend,
		&item.Model,
		&createdRaw,
	); err != nil {
		return AIInteraction{}, err
	}
	item.Request = parseJSONObject(requestJS)
	item.ContextSummary = parseJSONObject(contextSummaryJS)
	item.Response = parseJSONObject(responseJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func defaultAIConfig(tenantID string) AIConfig {
	return AIConfig{
		TenantID:     strings.TrimSpace(tenantID),
		Backend:      "claude",
		Endpoint:     "",
		Model:        "claude-sonnet-4-20250514",
		APIKeySecret: "ai-api-key",
		ProviderAuth: ProviderAuthConfig{
			Required: true,
			Type:     "api_key",
		},
		MCP: MCPConfig{
			Enabled:  false,
			Endpoint: "",
		},
		MaxContextTokens: 100000,
		Temperature:      0.1,
		ContextSources: ContextSources{
			Keys: ContextKeysConfig{
				Enabled: true,
				Limit:   1000,
				Fields:  []string{"id", "name", "algorithm", "status", "compliance", "last_rotated"},
			},
			Policies: ContextPoliciesConfig{
				Enabled: true,
				All:     true,
				Limit:   500,
			},
			Audit: ContextAuditConfig{
				Enabled:   true,
				LastHours: 24,
				Limit:     500,
			},
			Posture: ContextPostureConfig{
				Enabled: true,
				Current: true,
			},
			Alerts: ContextAlertsConfig{
				Enabled:    true,
				Unresolved: true,
				Limit:      250,
			},
		},
		RedactionFields: []string{"encrypted_material", "wrapped_dek", "pwd_hash"},
		UpdatedAt:       time.Now().UTC(),
	}
}
