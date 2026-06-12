package main

import (
	"context"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type KeyCoreClient interface {
	ListKeys(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type PolicyClient interface {
	ListPolicies(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type AuditClient interface {
	ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type ComplianceClient interface {
	GetPosture(ctx context.Context, tenantID string) (map[string]interface{}, error)
}

type ReportingClient interface {
	ListAlerts(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type SecretsClient interface {
	GetSecretValue(ctx context.Context, tenantID string, id string) (string, error)
}

type LLMBackend interface {
	Generate(ctx context.Context, cfg AIConfig, prompt string, apiKey string) (LLMResult, error)
}

type ContextKeysConfig struct {
	Enabled bool     `json:"enabled"`
	Limit   int      `json:"limit"`
	Fields  []string `json:"fields"`
}

type ContextPoliciesConfig struct {
	Enabled bool `json:"enabled"`
	All     bool `json:"all"`
	Limit   int  `json:"limit"`
}

type ContextAuditConfig struct {
	Enabled   bool `json:"enabled"`
	LastHours int  `json:"last_hours"`
	Limit     int  `json:"limit"`
}

type ContextPostureConfig struct {
	Enabled bool `json:"enabled"`
	Current bool `json:"current"`
}

type ContextAlertsConfig struct {
	Enabled    bool `json:"enabled"`
	Unresolved bool `json:"unresolved"`
	Limit      int  `json:"limit"`
}

type ContextSources struct {
	Keys     ContextKeysConfig     `json:"keys"`
	Policies ContextPoliciesConfig `json:"policies"`
	Audit    ContextAuditConfig    `json:"audit"`
	Posture  ContextPostureConfig  `json:"posture"`
	Alerts   ContextAlertsConfig   `json:"alerts"`
}

type ProviderAuthConfig struct {
	Required bool   `json:"required"`
	Type     string `json:"type"`
}

type MCPConfig struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
}

type AIConfig struct {
	TenantID         string             `json:"tenant_id"`
	Backend          string             `json:"backend"`
	Endpoint         string             `json:"endpoint"`
	Model            string             `json:"model"`
	APIKeySecret     string             `json:"api_key_secret"`
	ProviderAuth     ProviderAuthConfig `json:"provider_auth"`
	MCP              MCPConfig          `json:"mcp"`
	MaxContextTokens int                `json:"max_context_tokens"`
	Temperature      float64            `json:"temperature"`
	ContextSources   ContextSources     `json:"context_sources"`
	RedactionFields  []string           `json:"redaction_fields"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

type AIConfigUpdate struct {
	Backend          string              `json:"backend"`
	Endpoint         string              `json:"endpoint"`
	Model            string              `json:"model"`
	APIKeySecret     string              `json:"api_key_secret"`
	ProviderAuth     *ProviderAuthConfig `json:"provider_auth"`
	MCP              *MCPConfig          `json:"mcp"`
	MaxContextTokens int                 `json:"max_context_tokens"`
	Temperature      float64             `json:"temperature"`
	ContextSources   ContextSources      `json:"context_sources"`
	RedactionFields  []string            `json:"redaction_fields"`
}

type QueryRequest struct {
	TenantID       string `json:"tenant_id"`
	Query          string `json:"query"`
	IncludeContext bool   `json:"include_context"`
}

type IncidentAnalysisRequest struct {
	TenantID    string                 `json:"tenant_id"`
	IncidentID  string                 `json:"incident_id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
}

type PostureRecommendationRequest struct {
	TenantID string `json:"tenant_id"`
	Focus    string `json:"focus"`
}

type PolicyExplainRequest struct {
	TenantID string                 `json:"tenant_id"`
	PolicyID string                 `json:"policy_id"`
	Policy   map[string]interface{} `json:"policy"`
}

type AIResponse struct {
	Action            string                 `json:"action"`
	TenantID          string                 `json:"tenant_id"`
	Answer            string                 `json:"answer"`
	Backend           string                 `json:"backend"`
	Model             string                 `json:"model"`
	RedactionsApplied int                    `json:"redactions_applied"`
	ContextSummary    map[string]interface{} `json:"context_summary"`
	Context           map[string]interface{} `json:"context,omitempty"`
	Warnings          []string               `json:"warnings,omitempty"`
	GeneratedAt       time.Time              `json:"generated_at"`
}

type LLMResult struct {
	Text             string                 `json:"text"`
	PromptTokens     int                    `json:"prompt_tokens"`
	CompletionTokens int                    `json:"completion_tokens"`
	Raw              map[string]interface{} `json:"raw"`
}

type AIInteraction struct {
	ID             string                 `json:"id"`
	TenantID       string                 `json:"tenant_id"`
	Action         string                 `json:"action"`
	Request        map[string]interface{} `json:"request"`
	ContextSummary map[string]interface{} `json:"context_summary"`
	Response       map[string]interface{} `json:"response"`
	RedactionCount int                    `json:"redaction_count"`
	Backend        string                 `json:"backend"`
	Model          string                 `json:"model"`
	CreatedAt      time.Time              `json:"created_at"`
}

type assembledContext struct {
	Raw            map[string]interface{}
	Redacted       map[string]interface{}
	SourceWarnings []string
	RedactionCount int
}
