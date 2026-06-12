package main

import (
	"net/http"
	"strings"
	"time"
)

// AIProtectPolicy represents a tenant-scoped data protection policy.
type AIProtectPolicy struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	// Patterns to scan for: email, ssn, credit_card, credential, phone, name, address, health, financial, government_id
	Patterns       []string  `json:"patterns"`
	// Action on match: "redact", "block", "warn", "allow"
	Action         string    `json:"action"`
	Scope          string    `json:"scope"` // "input", "output", "both"
	Enabled        bool      `json:"enabled"`
	MinConfidence  float64   `json:"min_confidence,omitempty"`
	CustomPatterns []CustomPattern `json:"custom_patterns,omitempty"`
	Exemptions     []string  `json:"exemptions,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AIProtectScanRequest is the request body for scan, redact, and block-check endpoints.
type AIProtectScanRequest struct {
	TenantID string   `json:"tenant_id"`
	Text     string   `json:"text"`
	Patterns []string `json:"patterns"` // if empty uses all detectors
	PolicyID string   `json:"policy_id,omitempty"`
	Context  string   `json:"context"` // "input" or "output"
}

// AIProtectFinding is a single match found during a scan (API-facing).
type AIProtectFinding struct {
	Pattern    string  `json:"pattern"`
	Category   string  `json:"category"`
	Match      string  `json:"match"`
	Offset     int     `json:"offset"`
	EndOffset  int     `json:"end_offset"`
	Count      int     `json:"count"`
	Confidence float64 `json:"confidence"`
}

// AIProtectScanResult is the result of a scan or redact operation.
type AIProtectScanResult struct {
	RequestID    string               `json:"request_id"`
	TenantID     string               `json:"tenant_id"`
	Safe         bool                 `json:"safe"`
	FindingCount int                  `json:"finding_count"`
	Findings     []AIProtectFinding   `json:"findings"`
	RedactedText string               `json:"redacted_text"`
	Action       string               `json:"action"`
	PolicyID     string               `json:"policy_id,omitempty"`
	ScannedAt    time.Time            `json:"scanned_at"`
}

// AIProtectAuditEntry records an audit log entry for a protect operation.
type AIProtectAuditEntry struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Action       string    `json:"action"` // "scan", "redact", "block", "warn", "allow"
	FindingCount int       `json:"finding_count"`
	Patterns     []string  `json:"patterns_matched"`
	Context      string    `json:"context"`
	PolicyID     string    `json:"policy_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// resolveDLPPolicy loads a DLPPolicy when a policy_id is given, otherwise returns nil.
func (h *Handler) resolveDLPPolicy(r *http.Request, tenantID, policyID string) *DLPPolicy {
	if strings.TrimSpace(policyID) == "" {
		return nil
	}
	policies, err := h.svc.store.ListAIProtectPolicies(r.Context(), tenantID)
	if err != nil {
		return nil
	}
	for _, p := range policies {
		if p.ID == policyID && p.Enabled {
			return &DLPPolicy{
				AIProtectPolicy: p,
				MinConfidence:   p.MinConfidence,
				CustomPatterns:  p.CustomPatterns,
				Exemptions:      p.Exemptions,
			}
		}
	}
	return nil
}

// convertFindings converts internal DLP findings to the API-facing format.
func convertFindings(findings []Finding) []AIProtectFinding {
	// Aggregate by type
	type agg struct {
		pattern    string
		category   string
		firstMatch string
		firstStart int
		firstEnd   int
		count      int
		maxConf    float64
	}
	aggMap := make(map[string]*agg)
	for _, f := range findings {
		key := f.Type
		if a, ok := aggMap[key]; ok {
			a.count++
			if f.Confidence > a.maxConf {
				a.maxConf = f.Confidence
			}
		} else {
			aggMap[key] = &agg{
				pattern:    f.Type,
				category:   f.Category,
				firstMatch: f.RedactedVal,
				firstStart: f.StartPos,
				firstEnd:   f.EndPos,
				count:      1,
				maxConf:    f.Confidence,
			}
		}
	}

	out := make([]AIProtectFinding, 0, len(aggMap))
	for _, a := range aggMap {
		out = append(out, AIProtectFinding{
			Pattern:    a.pattern,
			Category:   a.category,
			Match:      a.firstMatch,
			Offset:     a.firstStart,
			EndOffset:  a.firstEnd,
			Count:      a.count,
			Confidence: a.maxConf,
		})
	}
	return out
}

// handleAIProtectScan handles POST /ai/protect/scan.
// Uses the DLPEngine for detection. Optionally applies a policy_id for filtering.
func (h *Handler) handleAIProtectScan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AIProtectScanRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (body or X-Tenant-ID)", reqID, "")
		return
	}

	var findings []Finding
	policy := h.resolveDLPPolicy(r, req.TenantID, req.PolicyID)
	if policy != nil {
		findings = h.svc.dlpEngine.ScanWithPolicy(req.Text, policy)
	} else {
		findings = h.svc.dlpEngine.Scan(req.Text)
		// Filter by requested patterns if provided (no policy)
		if len(req.Patterns) > 0 {
			patSet := make(map[string]bool, len(req.Patterns))
			for _, p := range req.Patterns {
				patSet[strings.ToLower(strings.TrimSpace(p))] = true
			}
			var filtered []Finding
			for _, f := range findings {
				if patSet[strings.ToLower(f.Type)] || patSet[strings.ToLower(f.Category)] || patSet[strings.ToLower(f.DetectorName)] {
					filtered = append(filtered, f)
				}
			}
			findings = filtered
		}
	}

	apiFindings := convertFindings(findings)
	matchedNames := findingTypes(findings)

	policyID := ""
	if policy != nil {
		policyID = policy.ID
	}

	result := AIProtectScanResult{
		RequestID:    reqID,
		TenantID:     req.TenantID,
		Safe:         len(findings) == 0,
		FindingCount: len(findings),
		Findings:     apiFindings,
		RedactedText: req.Text,
		Action:       "scan",
		PolicyID:     policyID,
		ScannedAt:    time.Now().UTC(),
	}

	entry := AIProtectAuditEntry{
		ID:           newID("aipa"),
		TenantID:     req.TenantID,
		Action:       "scan",
		FindingCount: len(findings),
		Patterns:     matchedNames,
		Context:      req.Context,
		PolicyID:     policyID,
	}
	_ = h.svc.store.InsertAIProtectAuditEntry(r.Context(), entry)

	if len(findings) > 0 {
		_ = h.svc.publishAudit(r.Context(), "audit.ai.pii_found", req.TenantID, map[string]interface{}{
			"action":        "scan",
			"finding_count": len(findings),
			"patterns":      matchedNames,
			"context":       req.Context,
			"policy_id":     policyID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}

// handleAIProtectRedact handles POST /ai/protect/redact.
// Uses the DLPEngine for detection and type-specific redaction.
func (h *Handler) handleAIProtectRedact(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AIProtectScanRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (body or X-Tenant-ID)", reqID, "")
		return
	}

	var findings []Finding
	policy := h.resolveDLPPolicy(r, req.TenantID, req.PolicyID)
	if policy != nil {
		findings = h.svc.dlpEngine.ScanWithPolicy(req.Text, policy)
	} else {
		findings = h.svc.dlpEngine.Scan(req.Text)
		if len(req.Patterns) > 0 {
			patSet := make(map[string]bool, len(req.Patterns))
			for _, p := range req.Patterns {
				patSet[strings.ToLower(strings.TrimSpace(p))] = true
			}
			var filtered []Finding
			for _, f := range findings {
				if patSet[strings.ToLower(f.Type)] || patSet[strings.ToLower(f.Category)] || patSet[strings.ToLower(f.DetectorName)] {
					filtered = append(filtered, f)
				}
			}
			findings = filtered
		}
	}

	redactedText := h.svc.dlpEngine.Redact(req.Text, findings)
	apiFindings := convertFindings(findings)
	matchedNames := findingTypes(findings)

	policyID := ""
	if policy != nil {
		policyID = policy.ID
	}

	result := AIProtectScanResult{
		RequestID:    reqID,
		TenantID:     req.TenantID,
		Safe:         len(findings) == 0,
		FindingCount: len(findings),
		Findings:     apiFindings,
		RedactedText: redactedText,
		Action:       "redact",
		PolicyID:     policyID,
		ScannedAt:    time.Now().UTC(),
	}

	entry := AIProtectAuditEntry{
		ID:           newID("aipa"),
		TenantID:     req.TenantID,
		Action:       "redact",
		FindingCount: len(findings),
		Patterns:     matchedNames,
		Context:      req.Context,
		PolicyID:     policyID,
	}
	_ = h.svc.store.InsertAIProtectAuditEntry(r.Context(), entry)

	if len(findings) > 0 {
		_ = h.svc.publishAudit(r.Context(), "audit.ai.pii_found", req.TenantID, map[string]interface{}{
			"action":        "redact",
			"finding_count": len(findings),
			"patterns":      matchedNames,
			"context":       req.Context,
			"policy_id":     policyID,
		})
		_ = h.svc.publishAudit(r.Context(), "audit.ai.redaction_applied", req.TenantID, map[string]interface{}{
			"finding_count": len(findings),
			"patterns":      matchedNames,
			"context":       req.Context,
			"policy_id":     policyID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}

// handleAIProtectBlock handles POST /ai/protect/block.
// Tests if a text would be blocked by the tenant's active DLP policy.
func (h *Handler) handleAIProtectBlock(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AIProtectScanRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (body or X-Tenant-ID)", reqID, "")
		return
	}

	direction := req.Context
	if direction == "" {
		direction = "input"
	}

	intercepted, err := h.svc.dlpProxy.InterceptRequest(r.Context(), req.TenantID, req.Text)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}

	apiFindings := convertFindings(intercepted.Findings)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id": reqID,
		"result": map[string]interface{}{
			"would_block":  !intercepted.Allowed,
			"action":       intercepted.Action,
			"policy_id":    intercepted.PolicyID,
			"finding_count": len(intercepted.Findings),
			"findings":     apiFindings,
			"audit_id":     intercepted.AuditID,
		},
	})
}

// handleListAIProtectPolicies handles GET /ai/protect/policies.
func (h *Handler) handleListAIProtectPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return
	}
	policies, err := h.svc.store.ListAIProtectPolicies(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policies": policies, "request_id": reqID})
}

// handleCreateAIProtectPolicy handles POST /ai/protect/policies.
func (h *Handler) handleCreateAIProtectPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)

	var req AIProtectPolicy
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantID)
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (body or X-Tenant-ID)", reqID, "")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, req.TenantID)
		return
	}

	// Apply defaults.
	req.ID = newID("aipp")
	if strings.TrimSpace(req.Action) == "" {
		req.Action = "redact"
	}
	if strings.TrimSpace(req.Scope) == "" {
		req.Scope = "both"
	}
	if !req.Enabled {
		req.Enabled = true
	}
	if req.Patterns == nil {
		req.Patterns = []string{}
	}
	if req.MinConfidence <= 0 {
		req.MinConfidence = 0.7
	}

	policy, err := h.svc.store.CreateAIProtectPolicy(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}

	// Invalidate the proxy cache so the new policy takes effect immediately
	h.svc.dlpProxy.InvalidatePolicyCache(req.TenantID)

	_ = h.svc.publishAudit(r.Context(), "audit.ai.policy_created", policy.TenantID, map[string]interface{}{
		"policy_id":      policy.ID,
		"name":           policy.Name,
		"action":         policy.Action,
		"scope":          policy.Scope,
		"enabled":        policy.Enabled,
		"min_confidence": req.MinConfidence,
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"policy": policy, "request_id": reqID})
}

// handleDeleteAIProtectPolicy handles DELETE /ai/protect/policies/{id}.
func (h *Handler) handleDeleteAIProtectPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}

	if err := h.svc.store.DeleteAIProtectPolicy(r.Context(), tenantID, id); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	// Invalidate the proxy cache so deletion takes effect immediately
	h.svc.dlpProxy.InvalidatePolicyCache(tenantID)

	_ = h.svc.publishAudit(r.Context(), "audit.ai.policy_deleted", tenantID, map[string]interface{}{
		"policy_id": id,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleListAIProtectAudit handles GET /ai/protect/audit.
func (h *Handler) handleListAIProtectAudit(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return
	}
	entries, err := h.svc.store.ListAIProtectAuditEntries(r.Context(), tenantID, 200)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries, "request_id": reqID})
}
