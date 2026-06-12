package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPLLMBackend struct {
	client *http.Client
}

func NewHTTPLLMBackend(timeout time.Duration) *HTTPLLMBackend {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPLLMBackend{
		client: &http.Client{Timeout: timeout},
	}
}

func (b *HTTPLLMBackend) Generate(ctx context.Context, cfg AIConfig, prompt string, apiKey string) (LLMResult, error) {
	backend := normalizeBackend(cfg.Backend)
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return LLMResult{}, errors.New("llm endpoint is empty")
	}

	switch backend {
	case "claude":
		return b.callClaude(ctx, endpoint, cfg, prompt, apiKey)
	case "openai", "azure-openai", "copilot", "self-hosted", "vllm", "llamacpp":
		return b.callOpenAICompatible(ctx, endpoint, cfg, prompt, apiKey, backend == "azure-openai")
	case "ollama":
		return b.callOllama(ctx, endpoint, cfg, prompt)
	default:
		return LLMResult{}, errors.New("unsupported backend: " + backend)
	}
}

func (b *HTTPLLMBackend) callClaude(ctx context.Context, endpoint string, cfg AIConfig, prompt string, apiKey string) (LLMResult, error) {
	reqBody := map[string]interface{}{
		"model":       cfg.Model,
		"max_tokens":  2048,
		"temperature": cfg.Temperature,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}
	headers := map[string]string{
		"anthropic-version": "2023-06-01",
	}
	mergeAuthHeaders(headers, cfg, apiKey, "x-api-key")
	out, err := b.doJSON(ctx, endpoint, reqBody, headers)
	if err != nil {
		return LLMResult{}, err
	}

	text := ""
	content, _ := out["content"].([]interface{})
	for _, item := range content {
		part, _ := item.(map[string]interface{})
		if strings.EqualFold(firstString(part["type"]), "text") {
			text = firstString(part["text"])
			break
		}
	}
	usage, _ := out["usage"].(map[string]interface{})
	return LLMResult{
		Text:             strings.TrimSpace(text),
		PromptTokens:     extractInt(usage["input_tokens"]),
		CompletionTokens: extractInt(usage["output_tokens"]),
		Raw:              out,
	}, nil
}

func (b *HTTPLLMBackend) callOpenAICompatible(ctx context.Context, endpoint string, cfg AIConfig, prompt string, apiKey string, azure bool) (LLMResult, error) {
	_ = azure
	reqBody := map[string]interface{}{
		"model":       cfg.Model,
		"temperature": cfg.Temperature,
		"messages": []map[string]interface{}{
			{"role": "system", "content": "You are a KMS security assistant. Use only provided context."},
			{"role": "user", "content": prompt},
		},
	}
	headers := map[string]string{}
	mergeAuthHeaders(headers, cfg, apiKey, "api-key")
	out, err := b.doJSON(ctx, endpoint, reqBody, headers)
	if err != nil {
		return LLMResult{}, err
	}
	choices, _ := out["choices"].([]interface{})
	msg := map[string]interface{}{}
	if len(choices) > 0 {
		first, _ := choices[0].(map[string]interface{})
		msg, _ = first["message"].(map[string]interface{})
	}
	usage, _ := out["usage"].(map[string]interface{})
	return LLMResult{
		Text:             strings.TrimSpace(firstString(msg["content"], out["text"], out["response"])),
		PromptTokens:     extractInt(usage["prompt_tokens"]),
		CompletionTokens: extractInt(usage["completion_tokens"]),
		Raw:              out,
	}, nil
}

func mergeAuthHeaders(headers map[string]string, cfg AIConfig, apiKey string, apiKeyHeader string) {
	cred := strings.TrimSpace(apiKey)
	if cred == "" {
		return
	}
	authType := normalizeAuthType(cfg.ProviderAuth.Type)
	if authType == "" {
		authType = defaultAuthTypeForBackend(cfg.Backend)
	}
	switch authType {
	case "api_key":
		header := strings.TrimSpace(apiKeyHeader)
		if header == "" {
			header = "x-api-key"
		}
		headers[header] = cred
	case "bearer":
		headers["Authorization"] = "Bearer " + cred
	case "none":
		return
	default:
		headers["Authorization"] = "Bearer " + cred
	}
}

func (b *HTTPLLMBackend) callOllama(ctx context.Context, endpoint string, cfg AIConfig, prompt string) (LLMResult, error) {
	reqBody := map[string]interface{}{
		"model":       cfg.Model,
		"prompt":      prompt,
		"stream":      false,
		"temperature": cfg.Temperature,
	}
	out, err := b.doJSON(ctx, endpoint, reqBody, nil)
	if err != nil {
		return LLMResult{}, err
	}
	return LLMResult{
		Text: strings.TrimSpace(firstString(out["response"], out["text"])),
		Raw:  out,
	}, nil
}

func (b *HTTPLLMBackend) doJSON(ctx context.Context, endpoint string, payload interface{}, headers map[string]string) (map[string]interface{}, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		if strings.TrimSpace(v) == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(firstString(out["error"], out["message"]))
		if msg == "" {
			msg = "llm request failed"
		}
		return nil, errors.New(msg)
	}
	return out, nil
}
