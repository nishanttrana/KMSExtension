package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Store defines the persistence interface for the AI Gateway.
type Store interface {
	// Providers
	CreateProvider(ctx context.Context, p *LLMProviderConfig) error
	ListProviders(ctx context.Context, tenantID string) ([]LLMProviderConfig, error)
	GetProvider(ctx context.Context, tenantID, id string) (*LLMProviderConfig, error)
	UpdateProvider(ctx context.Context, p *LLMProviderConfig) error
	DeleteProvider(ctx context.Context, tenantID, id string) error
	UpsertProviderConfig(ctx context.Context, cfg LLMProviderConfig) error
	DeleteProviderConfig(ctx context.Context, id string) error

	// DLP Policies
	CreatePolicy(ctx context.Context, p *DLPPolicy) error
	ListPolicies(ctx context.Context, tenantID string) ([]DLPPolicy, error)
	GetPolicy(ctx context.Context, tenantID, id string) (*DLPPolicy, error)
	UpdatePolicy(ctx context.Context, p *DLPPolicy) error
	DeletePolicy(ctx context.Context, tenantID, id string) error

	// Access Rules
	CreateAccessRule(ctx context.Context, r *ModelAccessRule) error
	ListAccessRules(ctx context.Context, tenantID string) ([]ModelAccessRule, error)
	DeleteAccessRule(ctx context.Context, tenantID, id string) error

	// Token Budgets
	CreateBudget(ctx context.Context, b *TokenBudget) error
	ListBudgets(ctx context.Context, tenantID string) ([]TokenBudget, error)
	UpdateBudget(ctx context.Context, b *TokenBudget) error
	IncrementBudgetUsage(ctx context.Context, tenantID, budgetID string, tokens int64, cost float64) error

	// Guardrails
	CreateGuardrail(ctx context.Context, g *TopicGuardrail) error
	ListGuardrails(ctx context.Context, tenantID string) ([]TopicGuardrail, error)
	DeleteGuardrail(ctx context.Context, tenantID, id string) error

	// Audit
	InsertAudit(ctx context.Context, e *GatewayAuditEvent) error
	ListAudit(ctx context.Context, tenantID string, limit, offset int) ([]GatewayAuditEvent, int, error)
	GetAudit(ctx context.Context, tenantID, id string) (*GatewayAuditEvent, error)
	GetAuditStats(ctx context.Context, tenantID string) (*AuditStats, error)
}

// ── SQL Implementation ─────────────────────────────────────────────

type SQLStore struct {
	db *pkgdb.DB
}

// Ping is a database round trip for the health check.
func (s *SQLStore) Ping(ctx context.Context) error {
	return s.db.SQL().PingContext(ctx)
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

// ── Providers ──────────────────────────────────────────────────────

func (s *SQLStore) CreateProvider(ctx context.Context, p *LLMProviderConfig) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO ai_gateway_providers
		 (id, tenant_id, name, provider, api_key, base_url, model_id, region,
		  max_tokens, cost_per_1k_input, cost_per_1k_output, priority, enabled, rate_limit_rpm, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		p.ID, p.TenantID, p.Name, p.Provider, p.APIKey, p.BaseURL, p.ModelID, p.Region,
		p.MaxTokens, p.CostPer1KInput, p.CostPer1KOutput, p.Priority, p.Enabled, p.RateLimit, p.Status,
	)
	return err
}

func (s *SQLStore) ListProviders(ctx context.Context, tenantID string) ([]LLMProviderConfig, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT id, tenant_id, name, provider, api_key, base_url, model_id, region,
		        max_tokens, cost_per_1k_input, cost_per_1k_output, priority, enabled, rate_limit_rpm, status
		 FROM ai_gateway_providers WHERE tenant_id = $1 ORDER BY priority`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LLMProviderConfig
	for rows.Next() {
		var p LLMProviderConfig
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Provider, &p.APIKey, &p.BaseURL,
			&p.ModelID, &p.Region, &p.MaxTokens, &p.CostPer1KInput, &p.CostPer1KOutput,
			&p.Priority, &p.Enabled, &p.RateLimit, &p.Status); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetProvider(ctx context.Context, tenantID, id string) (*LLMProviderConfig, error) {
	var p LLMProviderConfig
	err := s.db.SQL().QueryRowContext(ctx,
		`SELECT id, tenant_id, name, provider, api_key, base_url, model_id, region,
		        max_tokens, cost_per_1k_input, cost_per_1k_output, priority, enabled, rate_limit_rpm, status
		 FROM ai_gateway_providers WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&p.ID, &p.TenantID, &p.Name, &p.Provider, &p.APIKey, &p.BaseURL,
			&p.ModelID, &p.Region, &p.MaxTokens, &p.CostPer1KInput, &p.CostPer1KOutput,
			&p.Priority, &p.Enabled, &p.RateLimit, &p.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("provider not found")
	}
	return &p, err
}

func (s *SQLStore) UpdateProvider(ctx context.Context, p *LLMProviderConfig) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`UPDATE ai_gateway_providers SET
		 name=$3, provider=$4, api_key=$5, base_url=$6, model_id=$7, region=$8,
		 max_tokens=$9, cost_per_1k_input=$10, cost_per_1k_output=$11, priority=$12,
		 enabled=$13, rate_limit_rpm=$14, status=$15, updated_at=NOW()
		 WHERE tenant_id=$1 AND id=$2`,
		p.TenantID, p.ID, p.Name, p.Provider, p.APIKey, p.BaseURL, p.ModelID, p.Region,
		p.MaxTokens, p.CostPer1KInput, p.CostPer1KOutput, p.Priority, p.Enabled, p.RateLimit, p.Status,
	)
	return err
}

func (s *SQLStore) DeleteProvider(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM ai_gateway_providers WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// UpsertProviderConfig is used by the LLMRouter to persist provider config.
func (s *SQLStore) UpsertProviderConfig(ctx context.Context, cfg LLMProviderConfig) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO ai_gateway_providers
		 (id, tenant_id, name, provider, api_key, base_url, model_id, region,
		  max_tokens, cost_per_1k_input, cost_per_1k_output, priority, enabled, rate_limit_rpm, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		 ON CONFLICT (id) DO UPDATE SET
		  name=$3, provider=$4, api_key=$5, base_url=$6, model_id=$7, region=$8,
		  max_tokens=$9, cost_per_1k_input=$10, cost_per_1k_output=$11, priority=$12,
		  enabled=$13, rate_limit_rpm=$14, status=$15, updated_at=NOW()`,
		cfg.ID, cfg.TenantID, cfg.Name, cfg.Provider, cfg.APIKey, cfg.BaseURL, cfg.ModelID, cfg.Region,
		cfg.MaxTokens, cfg.CostPer1KInput, cfg.CostPer1KOutput, cfg.Priority, cfg.Enabled, cfg.RateLimit, cfg.Status,
	)
	return err
}

// DeleteProviderConfig removes a provider by ID (any tenant).
func (s *SQLStore) DeleteProviderConfig(ctx context.Context, id string) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM ai_gateway_providers WHERE id = $1`, id)
	return err
}

// ── DLP Policies ───────────────────────────────────────────────────

func (s *SQLStore) CreatePolicy(ctx context.Context, p *DLPPolicy) error {
	patternsJSON, _ := json.Marshal(p.Patterns)
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO ai_gateway_policies (id, tenant_id, name, description, action, patterns, enabled, priority)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		p.ID, p.TenantID, p.Name, p.Description, p.Action, patternsJSON, p.Enabled, p.Priority,
	)
	return err
}

func (s *SQLStore) ListPolicies(ctx context.Context, tenantID string) ([]DLPPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT id, tenant_id, name, description, action, patterns, enabled, priority
		 FROM ai_gateway_policies WHERE tenant_id = $1 ORDER BY priority`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DLPPolicy
	for rows.Next() {
		var p DLPPolicy
		var patternsJSON []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Action,
			&patternsJSON, &p.Enabled, &p.Priority); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(patternsJSON, &p.Patterns)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetPolicy(ctx context.Context, tenantID, id string) (*DLPPolicy, error) {
	var p DLPPolicy
	var patternsJSON []byte
	err := s.db.SQL().QueryRowContext(ctx,
		`SELECT id, tenant_id, name, description, action, patterns, enabled, priority
		 FROM ai_gateway_policies WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Action, &patternsJSON, &p.Enabled, &p.Priority)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("policy not found")
	}
	_ = json.Unmarshal(patternsJSON, &p.Patterns)
	return &p, err
}

func (s *SQLStore) UpdatePolicy(ctx context.Context, p *DLPPolicy) error {
	patternsJSON, _ := json.Marshal(p.Patterns)
	_, err := s.db.SQL().ExecContext(ctx,
		`UPDATE ai_gateway_policies SET
		 name=$3, description=$4, action=$5, patterns=$6, enabled=$7, priority=$8, updated_at=NOW()
		 WHERE tenant_id=$1 AND id=$2`,
		p.TenantID, p.ID, p.Name, p.Description, p.Action, patternsJSON, p.Enabled, p.Priority,
	)
	return err
}

func (s *SQLStore) DeletePolicy(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM ai_gateway_policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// ── Access Rules ───────────────────────────────────────────────────

func (s *SQLStore) CreateAccessRule(ctx context.Context, r *ModelAccessRule) error {
	modelJSON, _ := json.Marshal(r.ModelIDs)
	rolesJSON, _ := json.Marshal(r.UserRoles)
	usersJSON, _ := json.Marshal(r.UserIDs)
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO ai_gateway_access_rules
		 (id, tenant_id, model_ids, user_roles, user_ids, max_tokens_per_request, require_approval, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		r.ID, r.TenantID, modelJSON, rolesJSON, usersJSON, r.MaxTokensPerRequest, r.RequireApproval, r.Enabled,
	)
	return err
}

func (s *SQLStore) ListAccessRules(ctx context.Context, tenantID string) ([]ModelAccessRule, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT id, tenant_id, model_ids, user_roles, user_ids, max_tokens_per_request, require_approval, enabled
		 FROM ai_gateway_access_rules WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ModelAccessRule
	for rows.Next() {
		var r ModelAccessRule
		var modelJSON, rolesJSON, usersJSON []byte
		if err := rows.Scan(&r.ID, &r.TenantID, &modelJSON, &rolesJSON, &usersJSON,
			&r.MaxTokensPerRequest, &r.RequireApproval, &r.Enabled); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(modelJSON, &r.ModelIDs)
		_ = json.Unmarshal(rolesJSON, &r.UserRoles)
		_ = json.Unmarshal(usersJSON, &r.UserIDs)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteAccessRule(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM ai_gateway_access_rules WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// ── Token Budgets ──────────────────────────────────────────────────

func (s *SQLStore) CreateBudget(ctx context.Context, b *TokenBudget) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO ai_gateway_token_budgets
		 (id, tenant_id, scope, scope_id, max_tokens, max_cost_usd, period, alert_at_pct, hard_cap, reset_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		b.ID, b.TenantID, b.Scope, b.ScopeID, b.MaxTokens, b.MaxCostUSD,
		b.Period, b.AlertAt, b.HardCap, b.ResetAt,
	)
	return err
}

func (s *SQLStore) ListBudgets(ctx context.Context, tenantID string) ([]TokenBudget, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT id, tenant_id, scope, scope_id, max_tokens, max_cost_usd, period,
		        alert_at_pct, hard_cap, used_tokens, cost_used_usd, reset_at
		 FROM ai_gateway_token_budgets WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TokenBudget
	for rows.Next() {
		var b TokenBudget
		if err := rows.Scan(&b.ID, &b.TenantID, &b.Scope, &b.ScopeID, &b.MaxTokens,
			&b.MaxCostUSD, &b.Period, &b.AlertAt, &b.HardCap, &b.Used, &b.CostUsed, &b.ResetAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateBudget(ctx context.Context, b *TokenBudget) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`UPDATE ai_gateway_token_budgets SET
		 max_tokens=$3, max_cost_usd=$4, period=$5, alert_at_pct=$6, hard_cap=$7, updated_at=NOW()
		 WHERE tenant_id=$1 AND id=$2`,
		b.TenantID, b.ID, b.MaxTokens, b.MaxCostUSD, b.Period, b.AlertAt, b.HardCap,
	)
	return err
}

func (s *SQLStore) IncrementBudgetUsage(ctx context.Context, tenantID, budgetID string, tokens int64, cost float64) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`UPDATE ai_gateway_token_budgets SET
		 used_tokens = used_tokens + $3, cost_used_usd = cost_used_usd + $4, updated_at=NOW()
		 WHERE tenant_id=$1 AND id=$2`,
		tenantID, budgetID, tokens, cost,
	)
	return err
}

// ── Guardrails ─────────────────────────────────────────────────────

func (s *SQLStore) CreateGuardrail(ctx context.Context, g *TopicGuardrail) error {
	topicsJSON, _ := json.Marshal(g.Topics)
	keywordsJSON, _ := json.Marshal(g.Keywords)
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO ai_gateway_guardrails (id, tenant_id, name, action, topics, keywords, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		g.ID, g.TenantID, g.Name, g.Action, topicsJSON, keywordsJSON, g.Enabled,
	)
	return err
}

func (s *SQLStore) ListGuardrails(ctx context.Context, tenantID string) ([]TopicGuardrail, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT id, tenant_id, name, action, topics, keywords, enabled
		 FROM ai_gateway_guardrails WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TopicGuardrail
	for rows.Next() {
		var g TopicGuardrail
		var topicsJSON, keywordsJSON []byte
		if err := rows.Scan(&g.ID, &g.TenantID, &g.Name, &g.Action,
			&topicsJSON, &keywordsJSON, &g.Enabled); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(topicsJSON, &g.Topics)
		_ = json.Unmarshal(keywordsJSON, &g.Keywords)
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteGuardrail(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM ai_gateway_guardrails WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// ── Audit ──────────────────────────────────────────────────────────

func (s *SQLStore) InsertAudit(ctx context.Context, e *GatewayAuditEvent) error {
	hitsJSON, _ := json.Marshal(e.GuardrailHits)
	_, err := s.db.SQL().ExecContext(ctx,
		`INSERT INTO ai_gateway_audit
		 (id, tenant_id, user_id, request_id, model, provider, action,
		  prompt_tokens, completion_tokens, cost_usd, dlp_findings,
		  injection_score, toxicity_score, guardrail_hits, latency_ms, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		e.ID, e.TenantID, e.UserID, e.RequestID, e.Model, e.Provider, e.Action,
		e.PromptTokens, e.CompletionTokens, e.CostUSD, e.DLPFindings,
		e.InjectionScore, e.ToxicityScore, hitsJSON, e.Latency.Milliseconds(), e.Status,
	)
	return err
}

func (s *SQLStore) ListAudit(ctx context.Context, tenantID string, limit, offset int) ([]GatewayAuditEvent, int, error) {
	var total int
	err := s.db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ai_gateway_audit WHERE tenant_id = $1`, tenantID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT id, tenant_id, user_id, request_id, model, provider, action,
		        prompt_tokens, completion_tokens, cost_usd, dlp_findings,
		        injection_score, toxicity_score, guardrail_hits, latency_ms, status, created_at
		 FROM ai_gateway_audit WHERE tenant_id = $1
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []GatewayAuditEvent
	for rows.Next() {
		var e GatewayAuditEvent
		var hitsJSON []byte
		var latencyMs int64
		if err := rows.Scan(&e.ID, &e.TenantID, &e.UserID, &e.RequestID, &e.Model, &e.Provider,
			&e.Action, &e.PromptTokens, &e.CompletionTokens, &e.CostUSD, &e.DLPFindings,
			&e.InjectionScore, &e.ToxicityScore, &hitsJSON, &latencyMs, &e.Status, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		e.Latency = time.Duration(latencyMs) * time.Millisecond
		_ = json.Unmarshal(hitsJSON, &e.GuardrailHits)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func (s *SQLStore) GetAudit(ctx context.Context, tenantID, id string) (*GatewayAuditEvent, error) {
	var e GatewayAuditEvent
	var hitsJSON []byte
	var latencyMs int64
	err := s.db.SQL().QueryRowContext(ctx,
		`SELECT id, tenant_id, user_id, request_id, model, provider, action,
		        prompt_tokens, completion_tokens, cost_usd, dlp_findings,
		        injection_score, toxicity_score, guardrail_hits, latency_ms, status, created_at
		 FROM ai_gateway_audit WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&e.ID, &e.TenantID, &e.UserID, &e.RequestID, &e.Model, &e.Provider,
			&e.Action, &e.PromptTokens, &e.CompletionTokens, &e.CostUSD, &e.DLPFindings,
			&e.InjectionScore, &e.ToxicityScore, &hitsJSON, &latencyMs, &e.Status, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("audit event not found")
	}
	e.Latency = time.Duration(latencyMs) * time.Millisecond
	_ = json.Unmarshal(hitsJSON, &e.GuardrailHits)
	return &e, err
}

func (s *SQLStore) GetAuditStats(ctx context.Context, tenantID string) (*AuditStats, error) {
	var stats AuditStats
	err := s.db.SQL().QueryRowContext(ctx,
		`SELECT
		   COUNT(*),
		   COALESCE(SUM(CASE WHEN action='block' THEN 1 ELSE 0 END), 0),
		   COALESCE(SUM(CASE WHEN action='redact' THEN 1 ELSE 0 END), 0),
		   COALESCE(SUM(prompt_tokens + completion_tokens), 0),
		   COALESCE(SUM(cost_usd), 0),
		   COALESCE(AVG(latency_ms), 0),
		   COALESCE(SUM(dlp_findings), 0)
		 FROM ai_gateway_audit WHERE tenant_id = $1`, tenantID).
		Scan(&stats.TotalRequests, &stats.TotalBlocked, &stats.TotalRedacted,
			&stats.TotalTokens, &stats.TotalCostUSD, &stats.AvgLatencyMs, &stats.DLPFindings)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT model, COUNT(*) AS cnt, SUM(prompt_tokens + completion_tokens) AS tokens
		 FROM ai_gateway_audit WHERE tenant_id = $1 AND model != ''
		 GROUP BY model ORDER BY cnt DESC LIMIT 10`, tenantID)
	if err != nil {
		return &stats, nil
	}
	defer rows.Close()
	for rows.Next() {
		var ms ModelStat
		if err := rows.Scan(&ms.Model, &ms.Requests, &ms.Tokens); err == nil {
			stats.TopModels = append(stats.TopModels, ms)
		}
	}
	return &stats, nil
}
