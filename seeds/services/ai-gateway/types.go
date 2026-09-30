package main

import "time"

// ── Chat Completion (OpenAI-compatible) ────────────────────────────

type ChatCompletionRequest struct {
	Model       string            `json:"model"`
	Messages    []ChatMessage     `json:"messages"`
	Temperature float64           `json:"temperature,omitempty"`
	MaxTokens   int               `json:"max_tokens,omitempty"`
	Stream      bool              `json:"stream,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"` // vecta-specific: tenant, user, purpose
}

type ChatMessage struct {
	Role    string `json:"role"` // system, user, assistant
	Content string `json:"content"`
}

type ChatCompletionResponse struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Model   string        `json:"model"`
	Choices []ChatChoice  `json:"choices"`
	Usage   TokenUsage    `json:"usage"`
	Vecta   VectaMetadata `json:"vecta"`
}

type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type VectaMetadata struct {
	RequestID      string   `json:"request_id"`
	PolicyID       string   `json:"policy_id,omitempty"`
	DLPAction      string   `json:"dlp_action"`
	FindingsCount  int      `json:"findings_count"`
	FindingTypes   []string `json:"finding_types,omitempty"`
	GuardrailHits  []string `json:"guardrail_hits,omitempty"`
	InjectionScore float64  `json:"injection_score"`
	ToxicityScore  float64  `json:"toxicity_score"`
	TokenCost      float64  `json:"token_cost_usd"`
	ProviderUsed   string   `json:"provider_used"`
	Latency        string   `json:"latency"`
}

// ── Legacy Completions ─────────────────────────────────────────────

type CompletionRequest struct {
	Model       string  `json:"model"`
	Prompt      string  `json:"prompt"`
	Temperature float64 `json:"temperature,omitempty"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
}

type CompletionResponse struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Model   string        `json:"model"`
	Choices []CompChoice  `json:"choices"`
	Usage   TokenUsage    `json:"usage"`
	Vecta   VectaMetadata `json:"vecta"`
}

type CompChoice struct {
	Index        int    `json:"index"`
	Text         string `json:"text"`
	FinishReason string `json:"finish_reason"`
}

// ── Embeddings ─────────────────────────────────────────────────────

type EmbeddingRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type EmbeddingResponse struct {
	Object string          `json:"object"`
	Model  string          `json:"model"`
	Data   []EmbeddingData `json:"data"`
	Usage  TokenUsage      `json:"usage"`
	Vecta  VectaMetadata   `json:"vecta"`
}

type EmbeddingData struct {
	Index     int       `json:"index"`
	Object    string    `json:"object"`
	Embedding []float64 `json:"embedding"`
}

// ── DLP/Scan ───────────────────────────────────────────────────────

type ScanRequest struct {
	Text     string `json:"text"`
	PolicyID string `json:"policy_id,omitempty"`
}

type ScanResponse struct {
	Findings []DLPFinding `json:"findings"`
	Action   string       `json:"action"` // allow, redact, block, warn
}

type DLPFinding struct {
	Type       string  `json:"type"` // email, ssn, credit_card, api_key, etc.
	Value      string  `json:"value"`
	Redacted   string  `json:"redacted"`
	Offset     int     `json:"offset"`
	Length     int     `json:"length"`
	Confidence float64 `json:"confidence"`
}

type RedactRequest struct {
	Text     string `json:"text"`
	PolicyID string `json:"policy_id,omitempty"`
}

type RedactResponse struct {
	Original  string       `json:"original"`
	Redacted  string       `json:"redacted"`
	Findings  []DLPFinding `json:"findings"`
	Action    string       `json:"action"`
}

type EvaluateRequest struct {
	Text     string `json:"text"`
	UserID   string `json:"user_id,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
}

type EvaluateResponse struct {
	Allowed        bool         `json:"allowed"`
	Action         string       `json:"action"`
	DLPFindings    []DLPFinding `json:"dlp_findings"`
	InjectionScore float64      `json:"injection_score"`
	ToxicityScore  float64      `json:"toxicity_score"`
	GuardrailHits  []string     `json:"guardrail_hits"`
	Reasons        []string     `json:"reasons"`
}

// ── Model Registration ─────────────────────────────────────────────

type LLMProviderConfig struct {
	ID             string  `json:"id"`
	TenantID       string  `json:"tenant_id"`
	Name           string  `json:"name"`
	Provider       string  `json:"provider"` // openai, anthropic, azure_openai, bedrock, vertex, ollama
	Type           string  `json:"type"`     // alias for Provider, used by LLMRouter
	APIKey         string  `json:"api_key"`
	BaseURL        string  `json:"base_url"`
	ModelID        string  `json:"model_id"`
	Region         string  `json:"region,omitempty"`
	MaxTokens      int     `json:"max_tokens"`
	CostPer1KInput  float64 `json:"cost_per_1k_input"`
	CostPer1KOutput float64 `json:"cost_per_1k_output"`
	Priority       int     `json:"priority"`
	Enabled        bool    `json:"enabled"`
	RateLimit      int     `json:"rate_limit_rpm"`
	Status         string  `json:"status"`
}

// ── DLP Policy ─────────────────────────────────────────────────────

type DLPPolicy struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Action      string   `json:"action"` // allow, redact, block, warn
	Patterns    []string `json:"patterns"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
}

// ── Access Governance ──────────────────────────────────────────────

type ModelAccessRule struct {
	ID                 string   `json:"id"`
	TenantID           string   `json:"tenant_id"`
	ModelIDs           []string `json:"model_ids"`
	UserRoles          []string `json:"user_roles"`
	UserIDs            []string `json:"user_ids"`
	MaxTokensPerRequest int     `json:"max_tokens_per_request"`
	RequireApproval    bool     `json:"require_approval"`
	Enabled            bool     `json:"enabled"`
}

// ── Token Budget ───────────────────────────────────────────────────

type TokenBudget struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Scope      string    `json:"scope"`    // tenant, user, team
	ScopeID    string    `json:"scope_id"`
	MaxTokens  int64     `json:"max_tokens"`
	MaxCostUSD float64   `json:"max_cost_usd"`
	Period     string    `json:"period"` // daily, weekly, monthly
	AlertAt    float64   `json:"alert_at_pct"`
	HardCap    bool      `json:"hard_cap"`
	Used       int64     `json:"used_tokens"`
	CostUsed   float64   `json:"cost_used_usd"`
	ResetAt    time.Time `json:"reset_at"`
}

// ── Topic Guardrail ────────────────────────────────────────────────

type TopicGuardrail struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id"`
	Name     string   `json:"name"`
	Action   string   `json:"action"` // block, warn, log
	Topics   []string `json:"topics"` // weapon, self_harm, competitor, legal, source_code, internal_docs
	Keywords []string `json:"keywords"`
	Enabled  bool     `json:"enabled"`
}

// ── Audit Event ────────────────────────────────────────────────────

type GatewayAuditEvent struct {
	ID               string        `json:"id"`
	TenantID         string        `json:"tenant_id"`
	UserID           string        `json:"user_id"`
	RequestID        string        `json:"request_id"`
	Model            string        `json:"model"`
	Provider         string        `json:"provider"`
	Action           string        `json:"action"`
	PromptTokens     int           `json:"prompt_tokens"`
	CompletionTokens int           `json:"completion_tokens"`
	CostUSD          float64       `json:"cost_usd"`
	DLPFindings      int           `json:"dlp_findings"`
	InjectionScore   float64       `json:"injection_score"`
	ToxicityScore    float64       `json:"toxicity_score"`
	GuardrailHits    []string      `json:"guardrail_hits"`
	Latency          time.Duration `json:"latency_ms"`
	Status           string        `json:"status"` // success, blocked, error
	CreatedAt        time.Time     `json:"created_at"`
}

// ── Audit Stats ────────────────────────────────────────────────────

type AuditStats struct {
	TotalRequests  int64   `json:"total_requests"`
	TotalBlocked   int64   `json:"total_blocked"`
	TotalRedacted  int64   `json:"total_redacted"`
	TotalTokens    int64   `json:"total_tokens"`
	TotalCostUSD   float64 `json:"total_cost_usd"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	DLPFindings    int64   `json:"dlp_findings"`
	TopModels      []ModelStat `json:"top_models"`
}

type ModelStat struct {
	Model    string `json:"model"`
	Requests int64  `json:"requests"`
	Tokens   int64  `json:"tokens"`
}

// ── Usage Summary ──────────────────────────────────────────────────

type UsageSummary struct {
	Budgets []TokenBudget `json:"budgets"`
}

// ── Generic list / error responses ─────────────────────────────────

type ListResponse struct {
	Items interface{} `json:"items"`
	Total int         `json:"total"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

type HealthResponse struct {
	Status    string            `json:"status"`
	Service   string            `json:"service"`
	Version   string            `json:"version,omitempty"`
	Checks    map[string]string `json:"checks"`
	Timestamp time.Time         `json:"timestamp"`
}

type TestModelResponse struct {
	OK      bool   `json:"ok"`
	Latency string `json:"latency"`
	Error   string `json:"error,omitempty"`
}
