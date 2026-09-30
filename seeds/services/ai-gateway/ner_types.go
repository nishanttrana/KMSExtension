package main

import "context"

// CloudNERProvider is the interface for cloud-based NER/PII detection services.
type CloudNERProvider interface {
	DetectPII(ctx context.Context, text string) ([]NERFinding, error)
	Name() string
}

// NERFinding represents a single entity detected by a cloud NER provider or the local engine.
type NERFinding struct {
	EntityType string  `json:"entity_type"`
	Text       string  `json:"text"`
	Offset     int     `json:"offset"`
	Length     int     `json:"length"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"` // "local", "aws_comprehend", "google_dlp", "azure_language"
}

// ProviderHealth reports the health status of a registered LLM provider.
type ProviderHealth struct {
	ID          string  `json:"id"`
	Healthy     bool    `json:"healthy"`
	LatencyMs   int64   `json:"latency_ms"`
	ErrorRate   float64 `json:"error_rate"`
	LastChecked int64   `json:"last_checked"`
	Message     string  `json:"message,omitempty"`
}

// ProviderStatus combines config and live health for listing.
type ProviderStatus struct {
	Config LLMProviderConfig `json:"config"`
	Health ProviderHealth    `json:"health"`
}

// RouterResponse is the unified response returned by the LLM router.
type RouterResponse struct {
	ID               string `json:"id"`
	Content          string `json:"content"`
	Model            string `json:"model"`
	Provider         string `json:"provider"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	LatencyMs        int64  `json:"latency_ms"`
}
