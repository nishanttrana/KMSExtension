package main

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"
)

// InterceptResult captures the outcome of a DLP interception.
type InterceptResult struct {
	Allowed       bool      `json:"allowed"`
	Action        string    `json:"action"` // "allow", "redact", "block", "warn"
	OriginalText  string    `json:"-"`
	ProcessedText string    `json:"processed_text"`
	Findings      []Finding `json:"findings"`
	PolicyID      string    `json:"policy_id,omitempty"`
	AuditID       string    `json:"audit_id"`
}

// DLPProxy intercepts LLM requests and responses, enforcing tenant DLP policies.
type DLPProxy struct {
	engine *DLPEngine
	store  Store
	events EventPublisher
	logger *log.Logger

	// Cached policies per tenant with TTL
	policyCache map[string]*policyCacheEntry
	cacheMu     sync.RWMutex
}

type policyCacheEntry struct {
	policy    *DLPPolicy
	fetchedAt time.Time
}

const policyCacheTTL = 60 * time.Second

// NewDLPProxy creates a proxy that enforces DLP policies on LLM traffic.
func NewDLPProxy(engine *DLPEngine, store Store, events EventPublisher, logger *log.Logger) *DLPProxy {
	return &DLPProxy{
		engine:      engine,
		store:       store,
		events:      events,
		logger:      logger,
		policyCache: make(map[string]*policyCacheEntry),
	}
}

// InterceptRequest scans and enforces DLP policy on outbound LLM prompts.
func (p *DLPProxy) InterceptRequest(ctx context.Context, tenantID string, prompt string) (*InterceptResult, error) {
	return p.intercept(ctx, tenantID, prompt, "input")
}

// InterceptResponse scans and enforces DLP policy on inbound LLM completions.
func (p *DLPProxy) InterceptResponse(ctx context.Context, tenantID string, completion string) (*InterceptResult, error) {
	return p.intercept(ctx, tenantID, completion, "output")
}

func (p *DLPProxy) intercept(ctx context.Context, tenantID string, text string, direction string) (*InterceptResult, error) {
	policy := p.getActivePolicy(ctx, tenantID)

	// If no policy is active, scan but allow everything through
	if policy == nil {
		findings := p.engine.Scan(text)
		auditID := newID("dlpa")
		p.logAudit(ctx, tenantID, "allow", direction, len(findings), findingTypes(findings), "", auditID)
		return &InterceptResult{
			Allowed:       true,
			Action:        "allow",
			OriginalText:  text,
			ProcessedText: text,
			Findings:      findings,
			AuditID:       auditID,
		}, nil
	}

	// Check scope: does this policy apply to the current direction?
	if !policyAppliesToDirection(policy, direction) {
		return &InterceptResult{
			Allowed:       true,
			Action:        "allow",
			OriginalText:  text,
			ProcessedText: text,
			AuditID:       newID("dlpa"),
		}, nil
	}

	// Run detectors with policy filtering
	findings := p.engine.ScanWithPolicy(text, policy)
	auditID := newID("dlpa")

	action := policy.Action
	if action == "" {
		action = "redact"
	}

	result := &InterceptResult{
		Allowed:       true,
		Action:        action,
		OriginalText:  text,
		ProcessedText: text,
		Findings:      findings,
		PolicyID:      policy.ID,
		AuditID:       auditID,
	}

	// No findings means allow regardless
	if len(findings) == 0 {
		result.Action = "allow"
		p.logAudit(ctx, tenantID, "allow", direction, 0, nil, policy.ID, auditID)
		return result, nil
	}

	switch action {
	case "block":
		result.Allowed = false
		result.ProcessedText = ""
		p.logAudit(ctx, tenantID, "block", direction, len(findings), findingTypes(findings), policy.ID, auditID)
		p.publishDLPEvent(ctx, "audit.ai.dlp_blocked", tenantID, policy.ID, len(findings), direction)

	case "redact":
		result.ProcessedText = p.engine.Redact(text, findings)
		p.logAudit(ctx, tenantID, "redact", direction, len(findings), findingTypes(findings), policy.ID, auditID)
		p.publishDLPEvent(ctx, "audit.ai.dlp_redacted", tenantID, policy.ID, len(findings), direction)

	case "warn":
		// Allow through but flag findings
		result.Allowed = true
		p.logAudit(ctx, tenantID, "warn", direction, len(findings), findingTypes(findings), policy.ID, auditID)
		p.publishDLPEvent(ctx, "audit.ai.dlp_warning", tenantID, policy.ID, len(findings), direction)

	default: // "allow"
		p.logAudit(ctx, tenantID, "allow", direction, len(findings), findingTypes(findings), policy.ID, auditID)
	}

	return result, nil
}

// getActivePolicy returns the first enabled DLPPolicy for the tenant (cached 60s).
func (p *DLPProxy) getActivePolicy(ctx context.Context, tenantID string) *DLPPolicy {
	p.cacheMu.RLock()
	entry, ok := p.policyCache[tenantID]
	p.cacheMu.RUnlock()

	if ok && time.Since(entry.fetchedAt) < policyCacheTTL {
		return entry.policy
	}

	// Fetch from store
	policies, err := p.store.ListAIProtectPolicies(ctx, tenantID)
	if err != nil {
		if p.logger != nil {
			p.logger.Printf("dlp: failed to fetch policies for tenant %s: %v", tenantID, err)
		}
		// Return cached if available, even if stale
		if ok {
			return entry.policy
		}
		return nil
	}

	var active *DLPPolicy
	for _, pol := range policies {
		if pol.Enabled {
			active = &DLPPolicy{
				AIProtectPolicy: pol,
				MinConfidence:   0.7, // default
			}
			break
		}
	}

	p.cacheMu.Lock()
	p.policyCache[tenantID] = &policyCacheEntry{
		policy:    active,
		fetchedAt: time.Now(),
	}
	p.cacheMu.Unlock()

	return active
}

// InvalidatePolicyCache removes the cached policy for a tenant (call after policy CRUD).
func (p *DLPProxy) InvalidatePolicyCache(tenantID string) {
	p.cacheMu.Lock()
	delete(p.policyCache, tenantID)
	p.cacheMu.Unlock()
}

func policyAppliesToDirection(policy *DLPPolicy, direction string) bool {
	if policy.Scope == "both" || policy.Scope == "" {
		return true
	}
	return policy.Scope == direction
}

func findingTypes(findings []Finding) []string {
	seen := make(map[string]bool, len(findings))
	var types []string
	for _, f := range findings {
		if !seen[f.Type] {
			seen[f.Type] = true
			types = append(types, f.Type)
		}
	}
	return types
}

func (p *DLPProxy) logAudit(ctx context.Context, tenantID, action, direction string, findingCount int, patterns []string, policyID, auditID string) {
	if patterns == nil {
		patterns = []string{}
	}
	entry := AIProtectAuditEntry{
		ID:           auditID,
		TenantID:     tenantID,
		Action:       action,
		FindingCount: findingCount,
		Patterns:     patterns,
		Context:      direction,
		PolicyID:     policyID,
		CreatedAt:    time.Now().UTC(),
	}
	if err := p.store.InsertAIProtectAuditEntry(ctx, entry); err != nil && p.logger != nil {
		p.logger.Printf("dlp: audit insert failed: %v", err)
	}
}

func (p *DLPProxy) publishDLPEvent(ctx context.Context, subject, tenantID, policyID string, findingCount int, direction string) {
	if p.events == nil {
		return
	}
	data := map[string]interface{}{
		"policy_id":     policyID,
		"finding_count": findingCount,
		"direction":     direction,
	}
	raw, _ := mustJSONBytes(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "ai",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	_ = p.events.Publish(ctx, subject, raw)
}

func mustJSONBytes(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
