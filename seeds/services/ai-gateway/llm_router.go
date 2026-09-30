package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// buildChatResponse constructs a ChatCompletionResponse from provider call results.
func buildChatResponse(id, content, model string, promptTokens, completionTokens int) *ChatCompletionResponse {
	return &ChatCompletionResponse{
		ID:     id,
		Object: "chat.completion",
		Model:  model,
		Choices: []ChatChoice{
			{
				Index:        0,
				Message:      ChatMessage{Role: "assistant", Content: content},
				FinishReason: "stop",
			},
		},
		Usage: TokenUsage{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
		},
	}
}

// ProviderClient wraps an HTTP client with provider-specific calling logic.
type ProviderClient struct {
	Config     LLMProviderConfig
	httpClient *http.Client
	health     ProviderHealth
	mu         sync.Mutex

	// Token-bucket rate limiting
	rateMu     sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// LLMRouter manages multiple LLM providers and routes requests with failover.
type LLMRouter struct {
	providers map[string]*ProviderClient
	store     Store
	mu        sync.RWMutex
	logger    *log.Logger
}

// NewLLMRouter creates a new router with the given store and logger.
func NewLLMRouter(store Store, logger *log.Logger) *LLMRouter {
	if logger == nil {
		logger = log.Default()
	}
	return &LLMRouter{
		providers: make(map[string]*ProviderClient),
		store:     store,
		logger:    logger,
	}
}

func newProviderClient(cfg LLMProviderConfig) *ProviderClient {
	rateLimit := cfg.RateLimit
	if rateLimit <= 0 {
		rateLimit = 60
	}
	refillRate := float64(rateLimit) / 60.0

	return &ProviderClient{
		Config: cfg,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		health: ProviderHealth{
			ID:      cfg.ID,
			Healthy: true,
		},
		tokens:     float64(rateLimit),
		maxTokens:  float64(rateLimit),
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (pc *ProviderClient) recordSuccess(latencyMs int64) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.health.Healthy = true
	pc.health.LatencyMs = latencyMs
	pc.health.ErrorRate = pc.health.ErrorRate * 0.9
	pc.health.LastChecked = time.Now().Unix()
}

func (pc *ProviderClient) recordFailure(msg string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.health.ErrorRate = pc.health.ErrorRate*0.9 + 0.1
	if pc.health.ErrorRate > 0.5 {
		pc.health.Healthy = false
	}
	pc.health.Message = msg
	pc.health.LastChecked = time.Now().Unix()
}

func (pc *ProviderClient) getHealth() ProviderHealth {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.health
}

func (pc *ProviderClient) acquireToken(ctx context.Context) error {
	pc.rateMu.Lock()
	defer pc.rateMu.Unlock()

	now := time.Now()
	elapsed := now.Sub(pc.lastRefill).Seconds()
	pc.tokens += elapsed * pc.refillRate
	if pc.tokens > pc.maxTokens {
		pc.tokens = pc.maxTokens
	}
	pc.lastRefill = now

	if pc.tokens >= 1 {
		pc.tokens--
		return nil
	}
	return fmt.Errorf("rate limit exceeded for provider %s", pc.Config.ID)
}

// RegisterProvider adds or updates a provider in the router.
func (r *LLMRouter) RegisterProvider(cfg LLMProviderConfig) error {
	if cfg.ID == "" {
		return errors.New("provider id is required")
	}
	if cfg.Type == "" && cfg.Provider == "" {
		return errors.New("provider type is required")
	}
	if cfg.Type == "" {
		cfg.Type = cfg.Provider
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.providers[cfg.ID] = newProviderClient(cfg)
	r.logger.Printf("[llm-router] registered provider %s (type=%s, priority=%d)", cfg.ID, cfg.Type, cfg.Priority)

	if r.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.store.UpsertProviderConfig(ctx, cfg); err != nil {
			r.logger.Printf("[llm-router] warning: failed to persist provider config %s: %v", cfg.ID, err)
		}
	}
	return nil
}

// RemoveProvider unregisters a provider.
func (r *LLMRouter) RemoveProvider(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, id)

	if r.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.store.DeleteProviderConfig(ctx, id); err != nil {
			r.logger.Printf("[llm-router] warning: failed to delete provider config %s: %v", id, err)
		}
	}
	return nil
}

// TestProvider runs a connectivity test against a specific provider.
func (r *LLMRouter) TestProvider(ctx context.Context, id string) (*ProviderHealth, error) {
	r.mu.RLock()
	pc, ok := r.providers[id]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("provider %s not found", id)
	}

	testReq := ChatCompletionRequest{
		Model: pc.Config.ModelID,
		Messages: []ChatMessage{
			{Role: "user", Content: "Say hello in one word."},
		},
		Temperature: 0.0,
		MaxTokens:   5,
	}

	start := time.Now()
	_, err := callProvider(ctx, pc, testReq)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		pc.recordFailure(err.Error())
		h := pc.getHealth()
		h.LatencyMs = latency
		return &h, fmt.Errorf("provider test failed: %w", err)
	}

	pc.recordSuccess(latency)
	h := pc.getHealth()
	return &h, nil
}

// ListProviders returns status of all registered providers.
func (r *LLMRouter) ListProviders() []ProviderStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]ProviderStatus, 0, len(r.providers))
	for _, pc := range r.providers {
		out = append(out, ProviderStatus{
			Config: pc.Config,
			Health: pc.getHealth(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Config.Priority < out[j].Config.Priority
	})
	return out
}

// Route selects the best provider and executes the request with failover.
func (r *LLMRouter) Route(ctx context.Context, req ChatCompletionRequest, tenantID string) (*ChatCompletionResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	candidates := r.findProviders(req.Model)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no provider found for model %q", req.Model)
	}

	var lastErr error
	for _, pc := range candidates {
		if !pc.getHealth().Healthy {
			continue
		}
		if err := pc.acquireToken(ctx); err != nil {
			lastErr = err
			continue
		}

		start := time.Now()
		resp, err := callProvider(ctx, pc, req)
		latency := time.Since(start).Milliseconds()

		if err != nil {
			pc.recordFailure(err.Error())
			lastErr = err
			r.logger.Printf("[llm-router] provider %s failed: %v, trying next", pc.Config.ID, err)
			continue
		}

		pc.recordSuccess(latency)
		resp.Vecta.ProviderUsed = pc.Config.ID
		resp.Vecta.Latency = fmt.Sprintf("%dms", latency)
		return resp, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}
	return nil, errors.New("no enabled and healthy provider found")
}

func (r *LLMRouter) findProviders(model string) []*ProviderClient {
	var exact, prefix, fallback []*ProviderClient

	for _, pc := range r.providers {
		if pc.Config.ModelID == model || pc.Config.Name == model {
			exact = append(exact, pc)
			continue
		}
		if pc.Config.ModelID != "" && strings.HasPrefix(model, pc.Config.ModelID) {
			prefix = append(prefix, pc)
		}
		if pc.Config.Enabled {
			fallback = append(fallback, pc)
		}
	}

	sortByPriority := func(s []*ProviderClient) {
		sort.Slice(s, func(i, j int) bool {
			return s[i].Config.Priority < s[j].Config.Priority
		})
	}

	if len(exact) > 0 {
		sortByPriority(exact)
		return exact
	}
	if len(prefix) > 0 {
		sortByPriority(prefix)
		return prefix
	}
	sortByPriority(fallback)
	return fallback
}

// ── Provider call dispatcher ───────────────────────────────────────

func callProvider(ctx context.Context, pc *ProviderClient, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	providerType := pc.Config.Type
	if providerType == "" {
		providerType = pc.Config.Provider
	}

	switch providerType {
	case "openai":
		return callOpenAI(ctx, pc, req)
	case "anthropic":
		return callAnthropic(ctx, pc, req)
	case "azure_openai":
		return callAzureOpenAI(ctx, pc, req)
	case "bedrock":
		return callBedrock(ctx, pc, req)
	case "vertex":
		return callVertex(ctx, pc, req)
	case "ollama":
		return callOllama(ctx, pc, req)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}
}

// ── OpenAI ─────────────────────────────────────────────────────────

func callOpenAI(ctx context.Context, pc *ProviderClient, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	model := req.Model
	if model == "" {
		model = pc.Config.ModelID
	}

	type openAIMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	msgs := make([]openAIMsg, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = openAIMsg{Role: m.Role, Content: m.Content}
	}

	body := map[string]interface{}{
		"model":    model,
		"messages": msgs,
	}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}

	data, _ := json.Marshal(body)
	baseURL := strings.TrimRight(pc.Config.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+pc.Config.APIKey)

	resp, err := pc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("openai response parse failed: %w", err)
	}

	content := extractOpenAIContent(result)
	promptTokens, completionTokens := extractOpenAIUsage(result)
	respID, _ := result["id"].(string)

	return buildChatResponse(respID, strings.TrimSpace(content), model, promptTokens, completionTokens), nil
}

// ── Anthropic ──────────────────────────────────────────────────────

func callAnthropic(ctx context.Context, pc *ProviderClient, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	model := req.Model
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	var systemMsg string
	var msgs []map[string]string
	for _, m := range req.Messages {
		if m.Role == "system" {
			systemMsg = m.Content
			continue
		}
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	body := map[string]interface{}{
		"model":      model,
		"max_tokens": maxTokens,
		"messages":   msgs,
	}
	if systemMsg != "" {
		body["system"] = systemMsg
	}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}

	data, _ := json.Marshal(body)
	baseURL := strings.TrimRight(pc.Config.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", pc.Config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := pc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("anthropic response parse failed: %w", err)
	}

	content := ""
	if contentArr, ok := result["content"].([]interface{}); ok && len(contentArr) > 0 {
		if block, ok := contentArr[0].(map[string]interface{}); ok {
			content, _ = block["text"].(string)
		}
	}

	inputTokens, outputTokens := 0, 0
	if usage, ok := result["usage"].(map[string]interface{}); ok {
		inputTokens = toInt(usage["input_tokens"])
		outputTokens = toInt(usage["output_tokens"])
	}

	respID, _ := result["id"].(string)
	return buildChatResponse(respID, strings.TrimSpace(content), model, inputTokens, outputTokens), nil
}

// ── Azure OpenAI ───────────────────────────────────────────────────

func callAzureOpenAI(ctx context.Context, pc *ProviderClient, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	model := req.Model
	if model == "" {
		model = pc.Config.ModelID
	}

	type openAIMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	msgs := make([]openAIMsg, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = openAIMsg{Role: m.Role, Content: m.Content}
	}

	body := map[string]interface{}{"messages": msgs}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}

	data, _ := json.Marshal(body)
	baseURL := strings.TrimRight(pc.Config.BaseURL, "/")
	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=2024-02-01", baseURL, model)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("api-key", pc.Config.APIKey)

	resp, err := pc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("azure openai request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure openai returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("azure openai response parse failed: %w", err)
	}

	content := extractOpenAIContent(result)
	promptTokens, completionTokens := extractOpenAIUsage(result)
	respID, _ := result["id"].(string)

	return buildChatResponse(respID, strings.TrimSpace(content), model, promptTokens, completionTokens), nil
}

// ── AWS Bedrock ────────────────────────────────────────────────────

func callBedrock(ctx context.Context, pc *ProviderClient, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	modelID := pc.Config.ModelID
	if modelID == "" {
		modelID = "anthropic.claude-3-sonnet-20240229-v1:0"
	}
	region := pc.Config.Region
	if region == "" {
		region = "us-east-1"
	}

	var msgs []map[string]string
	for _, m := range req.Messages {
		if m.Role != "system" {
			msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
		}
	}

	body := map[string]interface{}{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        req.MaxTokens,
		"messages":          msgs,
	}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}

	data, _ := json.Marshal(body)
	baseURL := pc.Config.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", region)
	}
	url := fmt.Sprintf("%s/model/%s/invoke", strings.TrimRight(baseURL, "/"), modelID)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if pc.Config.APIKey != "" {
		parts := strings.SplitN(pc.Config.APIKey, ":", 2)
		if len(parts) == 2 {
			signAWSRequest(httpReq, data, parts[0], parts[1], region, "bedrock")
		}
	}

	resp, err := pc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("bedrock request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bedrock returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("bedrock response parse failed: %w", err)
	}

	content := ""
	if contentArr, ok := result["content"].([]interface{}); ok && len(contentArr) > 0 {
		if block, ok := contentArr[0].(map[string]interface{}); ok {
			content, _ = block["text"].(string)
		}
	}
	inputTokens, outputTokens := 0, 0
	if usage, ok := result["usage"].(map[string]interface{}); ok {
		inputTokens = toInt(usage["input_tokens"])
		outputTokens = toInt(usage["output_tokens"])
	}

	return buildChatResponse(fmt.Sprintf("bedrock-%d", time.Now().UnixNano()), strings.TrimSpace(content), modelID, inputTokens, outputTokens), nil
}

// ── Google Vertex AI ───────────────────────────────────────────────

func callVertex(ctx context.Context, pc *ProviderClient, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	model := pc.Config.ModelID
	if model == "" {
		model = "gemini-1.5-pro"
	}
	region := pc.Config.Region
	if region == "" {
		region = "us-central1"
	}

	var parts []map[string]string
	for _, m := range req.Messages {
		parts = append(parts, map[string]string{"text": m.Content})
	}

	body := map[string]interface{}{
		"contents": []map[string]interface{}{{"parts": parts}},
	}
	if req.MaxTokens > 0 {
		body["generationConfig"] = map[string]interface{}{
			"maxOutputTokens": req.MaxTokens,
			"temperature":     req.Temperature,
		}
	}

	data, _ := json.Marshal(body)
	baseURL := pc.Config.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://%s-aiplatform.googleapis.com", region)
	}
	url := fmt.Sprintf("%s/v1/projects/-/locations/%s/publishers/google/models/%s:generateContent",
		strings.TrimRight(baseURL, "/"), region, model)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if pc.Config.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+pc.Config.APIKey)
	}

	resp, err := pc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("vertex request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vertex returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("vertex response parse failed: %w", err)
	}

	content := ""
	if candidates, ok := result["candidates"].([]interface{}); ok && len(candidates) > 0 {
		if candidate, ok := candidates[0].(map[string]interface{}); ok {
			if cContent, ok := candidate["content"].(map[string]interface{}); ok {
				if cParts, ok := cContent["parts"].([]interface{}); ok && len(cParts) > 0 {
					if part, ok := cParts[0].(map[string]interface{}); ok {
						content, _ = part["text"].(string)
					}
				}
			}
		}
	}

	promptTokens, completionTokens := 0, 0
	if usageMeta, ok := result["usageMetadata"].(map[string]interface{}); ok {
		promptTokens = toInt(usageMeta["promptTokenCount"])
		completionTokens = toInt(usageMeta["candidatesTokenCount"])
	}

	return buildChatResponse(fmt.Sprintf("vertex-%d", time.Now().UnixNano()), strings.TrimSpace(content), model, promptTokens, completionTokens), nil
}

// ── Ollama (local) ─────────────────────────────────────────────────

func callOllama(ctx context.Context, pc *ProviderClient, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	model := req.Model
	if model == "" {
		model = pc.Config.ModelID
	}

	type ollamaMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	msgs := make([]ollamaMsg, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = ollamaMsg{Role: m.Role, Content: m.Content}
	}

	body := map[string]interface{}{
		"model":    model,
		"messages": msgs,
		"stream":   false,
	}
	if req.Temperature > 0 {
		body["options"] = map[string]interface{}{"temperature": req.Temperature}
	}

	data, _ := json.Marshal(body)
	baseURL := strings.TrimRight(pc.Config.BaseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/chat", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := pc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("ollama response parse failed: %w", err)
	}

	content := ""
	if msg, ok := result["message"].(map[string]interface{}); ok {
		content, _ = msg["content"].(string)
	}

	promptTokens, completionTokens := 0, 0
	if evalCount, ok := result["eval_count"].(float64); ok {
		completionTokens = int(evalCount)
	}
	if promptEvalCount, ok := result["prompt_eval_count"].(float64); ok {
		promptTokens = int(promptEvalCount)
	}

	return buildChatResponse(fmt.Sprintf("ollama-%d", time.Now().UnixNano()), strings.TrimSpace(content), model, promptTokens, completionTokens), nil
}

// ── Helpers ────────────────────────────────────────────────────────

func extractOpenAIContent(result map[string]interface{}) string {
	if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if msg, ok := choice["message"].(map[string]interface{}); ok {
				content, _ := msg["content"].(string)
				return content
			}
		}
	}
	return ""
}

func extractOpenAIUsage(result map[string]interface{}) (int, int) {
	if usage, ok := result["usage"].(map[string]interface{}); ok {
		return toInt(usage["prompt_tokens"]), toInt(usage["completion_tokens"])
	}
	return 0, 0
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

// signAWSv4 signs an AWS request (parameter order used by cloud_ner.go).
func signAWSv4(req *http.Request, payload []byte, region, service, accessKey, secretKey string) {
	signAWSRequest(req, payload, accessKey, secretKey, region, service)
}

func signAWSRequest(req *http.Request, payload []byte, accessKey, secretKey, region, service string) {
	now := time.Now().UTC()
	date := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", sha256Hex(payload))

	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"
	canonical := fmt.Sprintf("POST\n%s\n\ncontent-type:%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n\n%s\n%s",
		req.URL.Path, req.Header.Get("Content-Type"), req.URL.Host,
		req.Header.Get("x-amz-content-sha256"), amzDate,
		signedHeaders, sha256Hex(payload))

	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credScope, sha256Hex([]byte(canonical)))

	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func base64URLEncode(data []byte) string {
	const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	buf := make([]byte, 0, ((len(data)+2)/3)*4)
	for i := 0; i < len(data); i += 3 {
		val := uint(data[i]) << 16
		if i+1 < len(data) {
			val |= uint(data[i+1]) << 8
		}
		if i+2 < len(data) {
			val |= uint(data[i+2])
		}
		buf = append(buf, encodeURL[(val>>18)&0x3F])
		buf = append(buf, encodeURL[(val>>12)&0x3F])
		if i+1 < len(data) {
			buf = append(buf, encodeURL[(val>>6)&0x3F])
		}
		if i+2 < len(data) {
			buf = append(buf, encodeURL[val&0x3F])
		}
	}
	return string(buf)
}
