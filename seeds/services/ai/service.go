package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

type Service struct {
	store      Store
	keycore    KeyCoreClient
	policy     PolicyClient
	audit      AuditClient
	compliance ComplianceClient
	reporting  ReportingClient
	secrets    SecretsClient
	llm        LLMBackend
	events     EventPublisher
	dlpEngine  *DLPEngine
	dlpProxy   *DLPProxy
	now        func() time.Time
}

func NewService(store Store, keycore KeyCoreClient, policy PolicyClient, audit AuditClient, compliance ComplianceClient, reporting ReportingClient, secrets SecretsClient, llm LLMBackend, events EventPublisher) *Service {
	if llm == nil {
		llm = NewHTTPLLMBackend(30 * time.Second)
	}
	dlpEngine := NewDLPEngine(store, logger)
	dlpProxy := NewDLPProxy(dlpEngine, store, events, logger)
	return &Service{
		store:      store,
		keycore:    keycore,
		policy:     policy,
		audit:      audit,
		compliance: compliance,
		reporting:  reporting,
		secrets:    secrets,
		llm:        llm,
		events:     events,
		dlpEngine:  dlpEngine,
		dlpProxy:   dlpProxy,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) GetConfig(ctx context.Context, tenantID string) (AIConfig, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return AIConfig{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetConfig(ctx, tenantID)
	if err == nil {
		return normalizeConfig(item), nil
	}
	if !errors.Is(err, errNotFound) {
		return AIConfig{}, err
	}
	item = defaultAIConfig(tenantID)
	if err := s.store.UpsertConfig(ctx, item); err != nil {
		return AIConfig{}, err
	}
	return item, nil
}

func (s *Service) UpdateConfig(ctx context.Context, tenantID string, in AIConfigUpdate) (AIConfig, error) {
	item, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return AIConfig{}, err
	}
	backendChanged := false
	if strings.TrimSpace(in.Backend) != "" {
		item.Backend = strings.TrimSpace(in.Backend)
		backendChanged = true
	}
	if in.Endpoint != "" {
		item.Endpoint = strings.TrimSpace(in.Endpoint)
	}
	if strings.TrimSpace(in.Model) != "" {
		item.Model = strings.TrimSpace(in.Model)
	}
	if in.APIKeySecret != "" {
		item.APIKeySecret = strings.TrimSpace(in.APIKeySecret)
	}
	if in.ProviderAuth != nil {
		item.ProviderAuth = ProviderAuthConfig{
			Required: in.ProviderAuth.Required,
			Type:     strings.TrimSpace(in.ProviderAuth.Type),
		}
	} else if backendChanged {
		item.ProviderAuth = ProviderAuthConfig{
			Required: backendRequiresAuth(item.Backend),
			Type:     defaultAuthTypeForBackend(item.Backend),
		}
	}
	if in.MCP != nil {
		item.MCP = MCPConfig{
			Enabled:  in.MCP.Enabled,
			Endpoint: strings.TrimSpace(in.MCP.Endpoint),
		}
	}
	if in.MaxContextTokens > 0 {
		item.MaxContextTokens = in.MaxContextTokens
	}
	if in.Temperature >= 0 && in.Temperature <= 2 {
		item.Temperature = in.Temperature
	}
	if hasContextSources(in.ContextSources) {
		item.ContextSources = in.ContextSources
	}
	if len(in.RedactionFields) > 0 {
		item.RedactionFields = in.RedactionFields
	}
	item = normalizeConfig(item)
	if err := validateConfig(item); err != nil {
		return AIConfig{}, err
	}
	if err := s.store.UpsertConfig(ctx, item); err != nil {
		return AIConfig{}, err
	}
	_ = s.publishAudit(ctx, "audit.ai.config_updated", tenantID, map[string]interface{}{
		"backend": item.Backend,
		"model":   item.Model,
	})
	return s.GetConfig(ctx, tenantID)
}

func (s *Service) Query(ctx context.Context, req QueryRequest) (AIResponse, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" || strings.TrimSpace(req.Query) == "" {
		return AIResponse{}, newServiceError(400, "bad_request", "tenant_id and query are required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return AIResponse{}, err
	}
	_ = s.publishAudit(ctx, "audit.ai.query", tenantID, map[string]interface{}{
		"query": truncateString(req.Query, 256),
	})
	assembled := s.assembleContext(ctx, tenantID, cfg)
	_ = s.publishAudit(ctx, "audit.ai.context_accessed", tenantID, assembled.Redacted["summary"].(map[string]interface{}))
	prompt := s.promptForQuery(req.Query, assembled.Redacted)
	out := s.runPrompt(ctx, tenantID, "query", req.Query, prompt, cfg, assembled, req.IncludeContext)
	_ = s.publishAudit(ctx, "audit.ai.query_completed", tenantID, map[string]interface{}{
		"backend":  out.Backend,
		"model":    out.Model,
		"warnings": len(out.Warnings),
	})
	return out, nil
}

func (s *Service) AnalyzeIncident(ctx context.Context, req IncidentAnalysisRequest) (AIResponse, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return AIResponse{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return AIResponse{}, err
	}
	assembled := s.assembleContext(ctx, tenantID, cfg)
	incident := map[string]interface{}{
		"incident_id":  strings.TrimSpace(req.IncidentID),
		"title":        strings.TrimSpace(req.Title),
		"description":  strings.TrimSpace(req.Description),
		"input_detail": req.Details,
	}
	prompt := s.promptForIncident(incident, assembled.Redacted)
	out := s.runPrompt(ctx, tenantID, "incident_analysis", req.IncidentID, prompt, cfg, assembled, false)
	return out, nil
}

func (s *Service) RecommendPosture(ctx context.Context, req PostureRecommendationRequest) (AIResponse, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return AIResponse{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return AIResponse{}, err
	}
	assembled := s.assembleContext(ctx, tenantID, cfg)
	prompt := s.promptForPosture(req.Focus, assembled.Redacted)
	return s.runPrompt(ctx, tenantID, "posture_recommendation", req.Focus, prompt, cfg, assembled, false), nil
}

func (s *Service) ExplainPolicy(ctx context.Context, req PolicyExplainRequest) (AIResponse, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return AIResponse{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return AIResponse{}, err
	}
	assembled := s.assembleContext(ctx, tenantID, cfg)
	policy := cloneMap(req.Policy)
	if len(policy) == 0 && strings.TrimSpace(req.PolicyID) != "" {
		rawPolicies, _ := assembled.Redacted["policies"].([]interface{})
		for _, it := range rawPolicies {
			m, _ := it.(map[string]interface{})
			if strings.EqualFold(firstString(m["id"]), strings.TrimSpace(req.PolicyID)) {
				policy = m
				break
			}
		}
	}
	prompt := s.promptForPolicy(req.PolicyID, policy, assembled.Redacted)
	return s.runPrompt(ctx, tenantID, "policy_explanation", req.PolicyID, prompt, cfg, assembled, false), nil
}

func (s *Service) runPrompt(ctx context.Context, tenantID string, action string, userInput string, prompt string, cfg AIConfig, assembled assembledContext, includeContext bool) AIResponse {
	// DLP: Intercept outbound prompt before sending to LLM
	var dlpWarnings []string
	if s.dlpProxy != nil {
		intercepted, err := s.dlpProxy.InterceptRequest(ctx, tenantID, prompt)
		if err != nil {
			dlpWarnings = append(dlpWarnings, "dlp request intercept error: "+err.Error())
		} else if !intercepted.Allowed {
			// Policy blocked the request entirely
			return AIResponse{
				Action:            action,
				TenantID:          tenantID,
				Answer:            fmt.Sprintf("Request blocked by DLP policy %s: sensitive data detected (%d findings)", intercepted.PolicyID, len(intercepted.Findings)),
				Backend:           "dlp_blocked",
				Model:             cfg.Model,
				RedactionsApplied: len(intercepted.Findings),
				ContextSummary:    cloneMap(assembled.Redacted["summary"].(map[string]interface{})),
				Warnings:          []string{"DLP policy blocked this request"},
				GeneratedAt:       s.now(),
			}
		} else {
			prompt = intercepted.ProcessedText
			if len(intercepted.Findings) > 0 && intercepted.Action == "warn" {
				dlpWarnings = append(dlpWarnings, fmt.Sprintf("DLP warning: %d sensitive data findings in prompt", len(intercepted.Findings)))
			}
		}
	}

	out, backend, warnings := s.callLLM(ctx, cfg, applyMCPPromptContract(prompt, cfg), action, assembled.Redacted)

	// DLP: Intercept inbound LLM response
	if s.dlpProxy != nil {
		intercepted, err := s.dlpProxy.InterceptResponse(ctx, tenantID, out)
		if err != nil {
			dlpWarnings = append(dlpWarnings, "dlp response intercept error: "+err.Error())
		} else {
			out = intercepted.ProcessedText
			if len(intercepted.Findings) > 0 {
				dlpWarnings = append(dlpWarnings, fmt.Sprintf("DLP: %d sensitive items redacted from LLM response", len(intercepted.Findings)))
			}
		}
	}
	warnings = append(warnings, dlpWarnings...)

	// Enforce response-side redaction so sensitive markers cannot leak back to clients.
	out, textRedactions := redactText(out)
	totalRedactions := assembled.RedactionCount + textRedactions
	if totalRedactions > 0 {
		_ = s.publishAudit(ctx, "audit.ai.redaction_applied", tenantID, map[string]interface{}{
			"count":  totalRedactions,
			"action": action,
		})
	}

	response := AIResponse{
		Action:            action,
		TenantID:          tenantID,
		Answer:            strings.TrimSpace(out),
		Backend:           backend,
		Model:             cfg.Model,
		RedactionsApplied: totalRedactions,
		ContextSummary:    cloneMap(assembled.Redacted["summary"].(map[string]interface{})),
		Warnings:          append([]string{}, warnings...),
		GeneratedAt:       s.now(),
	}
	if includeContext {
		response.Context = cloneMap(assembled.Redacted)
	}
	_ = s.store.CreateInteraction(ctx, AIInteraction{
		ID:             newID("aii"),
		TenantID:       tenantID,
		Action:         action,
		Request:        map[string]interface{}{"input": userInput},
		ContextSummary: cloneMap(response.ContextSummary),
		Response: map[string]interface{}{
			"answer":   response.Answer,
			"warnings": response.Warnings,
		},
		RedactionCount: response.RedactionsApplied,
		Backend:        response.Backend,
		Model:          response.Model,
	})
	return response
}

func (s *Service) callLLM(ctx context.Context, cfg AIConfig, prompt string, action string, redactedContext map[string]interface{}) (string, string, []string) {
	warnings := []string{}
	if s.llm == nil {
		return s.fallbackAnswer(action, prompt, redactedContext), "fallback", warnings
	}
	apiKey := strings.TrimSpace(os.Getenv("AI_API_KEY"))
	if strings.TrimSpace(cfg.APIKeySecret) != "" && s.secrets != nil {
		if sec, err := s.secrets.GetSecretValue(ctx, redactedContext["tenant_id"].(string), cfg.APIKeySecret); err == nil && strings.TrimSpace(sec) != "" {
			apiKey = sec
		} else if err != nil {
			warnings = append(warnings, "secret lookup failed: "+err.Error())
		}
	}
	if cfg.ProviderAuth.Required && strings.TrimSpace(apiKey) == "" {
		warnings = append(warnings, "provider authentication required but no credential is configured")
		return s.fallbackAnswer(action, prompt, redactedContext), "fallback", warnings
	}
	// Best-effort zeroization for transient API key buffers after outbound LLM call.
	defer pkgcrypto.Zeroize([]byte(apiKey))
	llmOut, err := s.llm.Generate(ctx, cfg, prompt, apiKey)
	if err != nil || strings.TrimSpace(llmOut.Text) == "" {
		if err != nil {
			warnings = append(warnings, "llm backend unavailable: "+err.Error())
		} else {
			warnings = append(warnings, "llm returned empty response")
		}
		return s.fallbackAnswer(action, prompt, redactedContext), "fallback", warnings
	}
	return llmOut.Text, normalizeBackend(cfg.Backend), warnings
}

func (s *Service) fallbackAnswer(action string, prompt string, redactedContext map[string]interface{}) string {
	summary, _ := redactedContext["summary"].(map[string]interface{})
	switch action {
	case "query":
		return fmt.Sprintf("LLM backend unavailable. Context captured for query analysis. Keys=%d Policies=%d Events=%d Alerts=%d.",
			extractInt(summary["keys_count"]),
			extractInt(summary["policies_count"]),
			extractInt(summary["audit_events_count"]),
			extractInt(summary["alerts_count"]),
		)
	case "incident_analysis":
		return "Incident analysis fallback: review high/critical unresolved alerts, correlate with recent audit events, and verify policy violations."
	case "posture_recommendation":
		return "Posture recommendation fallback: rotate stale keys, remove deprecated algorithms, enforce MFA, and remediate open compliance gaps."
	case "policy_explanation":
		return "Policy explanation fallback: this policy constrains key operations by tenant, role, action, and approval requirements."
	default:
		return "LLM backend unavailable; generated fallback response."
	}
}

func (s *Service) assembleContext(ctx context.Context, tenantID string, cfg AIConfig) assembledContext {
	raw := map[string]interface{}{
		"tenant_id":    tenantID,
		"generated_at": s.now().Format(time.RFC3339),
		"keys":         []interface{}{},
		"policies":     []interface{}{},
		"audit_events": []interface{}{},
		"posture":      map[string]interface{}{},
		"alerts":       []interface{}{},
		"summary":      map[string]interface{}{},
	}
	warnings := []string{}
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}

	if cfg.ContextSources.Keys.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys, err := s.fetchKeys(ctx, tenantID, cfg.ContextSources.Keys.Limit, cfg.ContextSources.Keys.Fields)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, "keycore: "+err.Error())
				return
			}
			raw["keys"] = keys
		}()
	}
	if cfg.ContextSources.Policies.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			policies, err := s.fetchPolicies(ctx, tenantID, cfg.ContextSources.Policies.Limit)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, "policy: "+err.Error())
				return
			}
			raw["policies"] = policies
		}()
	}
	if cfg.ContextSources.Audit.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			events, err := s.fetchAuditEvents(ctx, tenantID, cfg.ContextSources.Audit.LastHours, cfg.ContextSources.Audit.Limit)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, "audit: "+err.Error())
				return
			}
			raw["audit_events"] = events
		}()
	}
	if cfg.ContextSources.Posture.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			posture, err := s.fetchPosture(ctx, tenantID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, "compliance: "+err.Error())
				return
			}
			raw["posture"] = posture
		}()
	}
	if cfg.ContextSources.Alerts.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			alerts, err := s.fetchAlerts(ctx, tenantID, cfg.ContextSources.Alerts.Limit, cfg.ContextSources.Alerts.Unresolved)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, "reporting: "+err.Error())
				return
			}
			raw["alerts"] = alerts
		}()
	}
	wg.Wait()

	keys, _ := raw["keys"].([]interface{})
	policies, _ := raw["policies"].([]interface{})
	events, _ := raw["audit_events"].([]interface{})
	alerts, _ := raw["alerts"].([]interface{})
	posture, _ := raw["posture"].(map[string]interface{})
	raw["summary"] = map[string]interface{}{
		"keys_count":         len(keys),
		"policies_count":     len(policies),
		"audit_events_count": len(events),
		"alerts_count":       len(alerts),
		"posture_score":      extractInt(posture["overall_score"]),
	}

	// Redact high-risk fields before prompt assembly; LLM never sees protected fields.
	redacted, n := redactMapFields(raw, cfg.RedactionFields)
	if len(warnings) > 0 {
		redacted["warnings"] = uniqueStrings(warnings)
	}
	return assembledContext{
		Raw:            raw,
		Redacted:       redacted,
		SourceWarnings: uniqueStrings(warnings),
		RedactionCount: n,
	}
}

func (s *Service) fetchKeys(ctx context.Context, tenantID string, limit int, fields []string) ([]interface{}, error) {
	if s.keycore == nil {
		return []interface{}{}, nil
	}
	items, err := s.keycore.ListKeys(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		out = append(out, includeFields(item, fields))
	}
	return out, nil
}

func (s *Service) fetchPolicies(ctx context.Context, tenantID string, limit int) ([]interface{}, error) {
	if s.policy == nil {
		return []interface{}{}, nil
	}
	items, err := s.policy.ListPolicies(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		out = append(out, cloneMap(item))
	}
	return out, nil
}

func (s *Service) fetchAuditEvents(ctx context.Context, tenantID string, lastHours int, limit int) ([]interface{}, error) {
	if s.audit == nil {
		return []interface{}{}, nil
	}
	if lastHours <= 0 {
		lastHours = 24
	}
	items, err := s.audit.ListEvents(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	cutoff := s.now().Add(-time.Duration(lastHours) * time.Hour)
	filtered := make([]interface{}, 0, len(items))
	for _, item := range items {
		ts := parseTimeString(firstString(item["timestamp"], item["created_at"]))
		if !ts.IsZero() && ts.Before(cutoff) {
			continue
		}
		filtered = append(filtered, cloneMap(item))
	}
	return filtered, nil
}

func (s *Service) fetchPosture(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	if s.compliance == nil {
		return map[string]interface{}{}, nil
	}
	return s.compliance.GetPosture(ctx, tenantID)
}

func (s *Service) fetchAlerts(ctx context.Context, tenantID string, limit int, unresolvedOnly bool) ([]interface{}, error) {
	if s.reporting == nil {
		return []interface{}{}, nil
	}
	items, err := s.reporting.ListAlerts(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		status := strings.ToLower(strings.TrimSpace(firstString(item["status"])))
		if unresolvedOnly && (status == "resolved" || status == "false_positive" || status == "closed") {
			continue
		}
		out = append(out, cloneMap(item))
	}
	return out, nil
}

func (s *Service) promptForQuery(query string, contextWindow map[string]interface{}) string {
	return s.renderPrompt("Natural language query", query, contextWindow, "Answer clearly with relevant evidence from context.")
}

func (s *Service) promptForIncident(incident map[string]interface{}, contextWindow map[string]interface{}) string {
	return s.renderPrompt("Incident analysis", mustJSON(incident, "{}"), contextWindow, "Summarize incident timeline, likely root cause, impact, and next containment actions.")
}

func (s *Service) promptForPosture(focus string, contextWindow map[string]interface{}) string {
	if strings.TrimSpace(focus) == "" {
		focus = "overall posture"
	}
	return s.renderPrompt("Posture recommendations", focus, contextWindow, "Return the top 5 prioritized improvements with expected impact.")
}

func (s *Service) promptForPolicy(policyID string, policy map[string]interface{}, contextWindow map[string]interface{}) string {
	payload := map[string]interface{}{
		"policy_id": policyID,
		"policy":    policy,
	}
	return s.renderPrompt("Policy explanation", mustJSON(payload, "{}"), contextWindow, "Explain in plain English: purpose, enforcement behavior, exceptions, and risk tradeoffs.")
}

func (s *Service) renderPrompt(kind string, userInput string, contextWindow map[string]interface{}, instruction string) string {
	rawContext := mustJSON(contextWindow, "{}")
	maxLen := 200000
	if len(rawContext) > maxLen {
		rawContext = rawContext[:maxLen]
	}
	return strings.Join([]string{
		"You are Vecta KMS AI Context Engine.",
		"Task: " + kind,
		"User input:",
		userInput,
		"Use only this redacted context:",
		rawContext,
		"Output requirements:",
		"- Be concise and actionable",
		"- If context is insufficient, say what is missing",
		"- Never fabricate IDs or counts",
		instruction,
	}, "\n")
}

func applyMCPPromptContract(prompt string, cfg AIConfig) string {
	if !cfg.MCP.Enabled {
		return prompt
	}
	target := strings.TrimSpace(cfg.MCP.Endpoint)
	if target == "" {
		target = "configured MCP client"
	}
	return strings.Join([]string{
		prompt,
		"MCP compatibility mode is enabled.",
		"Return strict JSON with keys: summary, actions, evidence, risk_level.",
		"Do not include markdown wrappers or extra text outside JSON.",
		"Ensure response is safe for machine consumption by " + target + ".",
	}, "\n")
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "ai",
		"action":    subject,
		"timestamp": s.now().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func normalizeConfig(item AIConfig) AIConfig {
	item.Backend = normalizeBackend(item.Backend)
	if item.Backend == "" {
		item.Backend = "claude"
	}
	item.Endpoint = strings.TrimSpace(item.Endpoint)
	if strings.TrimSpace(item.Model) == "" {
		item.Model = "claude-sonnet-4-20250514"
	}
	item.ProviderAuth.Type = normalizeAuthType(item.ProviderAuth.Type)
	if item.ProviderAuth.Type == "" {
		item.ProviderAuth.Type = defaultAuthTypeForBackend(item.Backend)
	}
	if backendRequiresAuth(item.Backend) {
		item.ProviderAuth.Required = true
	}
	item.MCP.Endpoint = strings.TrimSpace(item.MCP.Endpoint)
	if item.MaxContextTokens <= 0 {
		item.MaxContextTokens = 100000
	}
	if item.Temperature < 0 || item.Temperature > 2 {
		item.Temperature = 0.1
	}
	item.RedactionFields = uniqueStrings(item.RedactionFields)
	if len(item.RedactionFields) == 0 {
		item.RedactionFields = []string{"encrypted_material", "wrapped_dek", "pwd_hash"}
	}
	normalized := defaultAIConfig(item.TenantID)
	normalized.Backend = item.Backend
	normalized.Endpoint = item.Endpoint
	normalized.Model = item.Model
	normalized.APIKeySecret = item.APIKeySecret
	normalized.ProviderAuth = item.ProviderAuth
	normalized.MCP = item.MCP
	normalized.MaxContextTokens = item.MaxContextTokens
	normalized.Temperature = item.Temperature
	if hasContextSources(item.ContextSources) {
		normalized.ContextSources = item.ContextSources
	}
	normalized.RedactionFields = item.RedactionFields
	normalized.UpdatedAt = item.UpdatedAt
	return normalized
}

func validateConfig(item AIConfig) error {
	allowed := map[string]struct{}{
		"claude":       {},
		"openai":       {},
		"azure-openai": {},
		"copilot":      {},
		"self-hosted":  {},
		"ollama":       {},
		"vllm":         {},
		"llamacpp":     {},
	}
	backend := normalizeBackend(item.Backend)
	if _, ok := allowed[backend]; !ok {
		keys := make([]string, 0, len(allowed))
		for k := range allowed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return newServiceError(400, "bad_request", "unsupported backend; allowed="+strings.Join(keys, ","))
	}
	allowedAuth := map[string]struct{}{
		"none":    {},
		"api_key": {},
		"bearer":  {},
	}
	authType := normalizeAuthType(item.ProviderAuth.Type)
	if _, ok := allowedAuth[authType]; !ok {
		return newServiceError(400, "bad_request", "unsupported provider_auth.type; allowed=api_key,bearer,none")
	}
	if backendRequiresAuth(backend) && !item.ProviderAuth.Required {
		return newServiceError(400, "bad_request", "provider_auth.required must be true for "+backend)
	}
	if item.ProviderAuth.Required && authType == "none" {
		return newServiceError(400, "bad_request", "provider_auth.type cannot be none when authentication is required")
	}
	if item.ProviderAuth.Required && strings.TrimSpace(item.APIKeySecret) == "" {
		return newServiceError(400, "bad_request", "api_key_secret is required when provider authentication is enabled")
	}
	if strings.TrimSpace(item.Endpoint) == "" {
		return newServiceError(400, "bad_request", "endpoint is required for AI provider integration")
	}
	if item.MCP.Enabled && strings.TrimSpace(item.MCP.Endpoint) == "" {
		return newServiceError(400, "bad_request", "mcp.endpoint is required when mcp.enabled is true")
	}
	if item.MaxContextTokens < 256 {
		return newServiceError(400, "bad_request", "max_context_tokens must be >= 256")
	}
	if item.Temperature < 0 || item.Temperature > 2 {
		return newServiceError(400, "bad_request", "temperature must be between 0 and 2")
	}
	return nil
}

func truncateString(v string, max int) string {
	v = strings.TrimSpace(v)
	if max <= 0 || len(v) <= max {
		return v
	}
	return v[:max]
}

func hasContextSources(v ContextSources) bool {
	return v.Keys.Enabled ||
		v.Keys.Limit != 0 ||
		len(v.Keys.Fields) > 0 ||
		v.Policies.Enabled ||
		v.Policies.All ||
		v.Policies.Limit != 0 ||
		v.Audit.Enabled ||
		v.Audit.LastHours != 0 ||
		v.Audit.Limit != 0 ||
		v.Posture.Enabled ||
		v.Posture.Current ||
		v.Alerts.Enabled ||
		v.Alerts.Unresolved ||
		v.Alerts.Limit != 0
}
