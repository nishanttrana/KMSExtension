package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/tenantcheck"
)

// Handler is the HTTP handler for the TFE service.
type Handler struct {
	store     Store
	publisher EventPublisher
	mux       *http.ServeMux
}

// NewHandler creates a new Handler.
func NewHandler(store Store, publisher EventPublisher) *Handler {
	h := &Handler{store: store, publisher: publisher}
	h.mux = h.routes()
	return h
}

// publishAudit publishes an audit event to NATS. Errors are silently dropped.
func (h *Handler) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) {
	if h.publisher == nil {
		return
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "tfe",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return
	}
	_ = h.publisher.Publish(ctx, subject, raw)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)

	// Agents
	mux.HandleFunc("POST /tfe/agents", h.handleRegisterAgent)
	mux.HandleFunc("GET /tfe/agents", h.handleListAgents)
	mux.HandleFunc("GET /tfe/agents/{id}", h.handleGetAgent)
	mux.HandleFunc("PUT /tfe/agents/{id}/heartbeat", h.handleHeartbeat)
	mux.HandleFunc("DELETE /tfe/agents/{id}", h.handleDeleteAgent)

	// Policies
	mux.HandleFunc("POST /tfe/policies", h.handleCreatePolicy)
	mux.HandleFunc("GET /tfe/policies", h.handleListPolicies)
	mux.HandleFunc("GET /tfe/policies/{id}", h.handleGetPolicy)
	mux.HandleFunc("PUT /tfe/policies/{id}", h.handleUpdatePolicy)
	mux.HandleFunc("DELETE /tfe/policies/{id}", h.handleDeletePolicy)

	// Summary
	mux.HandleFunc("GET /tfe/summary", h.handleGetSummary)

	// File Encryption TDE agent download and audit
	mux.HandleFunc("GET /tfe/file-encrypt/download", h.handleFileEncryptDownload)
	mux.HandleFunc("POST /tfe/file-encrypt/audit", h.handleFileEncryptAudit)

	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
}

// --- Agent handlers ---

func (h *Handler) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterAgentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if strings.TrimSpace(req.Hostname) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "hostname is required", reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.OS) == "" {
		req.OS = "linux"
	}
	if strings.TrimSpace(req.AgentVersion) == "" {
		req.AgentVersion = "1.0"
	}

	now := time.Now().UTC()
	agent := TFEAgent{
		ID:           newTFEID("agt"),
		TenantID:     strings.TrimSpace(req.TenantID),
		Hostname:     strings.TrimSpace(req.Hostname),
		OS:           strings.TrimSpace(req.OS),
		AgentVersion: strings.TrimSpace(req.AgentVersion),
		Status:       "registered",
		LastSeen:     now,
		PolicyCount:  0,
		CreatedAt:    now,
	}

	saved, err := h.store.CreateAgent(r.Context(), agent)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_agent_failed", err.Error(), reqID, req.TenantID)
		return
	}
	h.publishAudit(r.Context(), "audit.tfe.agent_registered", saved.TenantID, map[string]interface{}{
		"agent_id": saved.ID,
		"hostname": saved.Hostname,
		"os":       saved.OS,
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"agent": saved, "request_id": reqID})
}

func (h *Handler) handleListAgents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant_id"), tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return
	}
	items, err := h.store.ListAgents(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_agents_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	agent, err := h.store.GetAgent(r.Context(), tenantID, id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "get_agent_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"agent": agent, "request_id": reqID})
}

func (h *Handler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	var req HeartbeatRequest
	_ = decodeJSON(r, &req)
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "active"
	}
	if err := h.store.UpdateAgentHeartbeat(r.Context(), tenantID, id, status, time.Now().UTC()); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "heartbeat_failed", err.Error(), reqID, tenantID)
		return
	}
	h.publishAudit(r.Context(), "audit.tfe.agent_heartbeat", tenantID, map[string]interface{}{
		"agent_id": id,
		"status":   status,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	if err := h.store.DeleteAgent(r.Context(), tenantID, id); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_agent_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

// --- Policy handlers ---

func (h *Handler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateTFEPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if strings.TrimSpace(req.AgentID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "agent_id is required", reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "path is required", reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.Algorithm) == "" {
		req.Algorithm = "AES-256-XTS"
	}
	if req.IncludeGlobs == nil {
		req.IncludeGlobs = []string{}
	}
	if req.ExcludeGlobs == nil {
		req.ExcludeGlobs = []string{}
	}

	now := time.Now().UTC()
	policy := TFEPolicy{
		ID:           newTFEID("pol"),
		TenantID:     strings.TrimSpace(req.TenantID),
		AgentID:      strings.TrimSpace(req.AgentID),
		Name:         strings.TrimSpace(req.Name),
		Path:         strings.TrimSpace(req.Path),
		Recursive:    req.Recursive,
		KeyID:        strings.TrimSpace(req.KeyID),
		Algorithm:    strings.TrimSpace(req.Algorithm),
		IncludeGlobs: req.IncludeGlobs,
		ExcludeGlobs: req.ExcludeGlobs,
		Status:       "active",
		LastActivity: now,
		CreatedAt:    now,
	}

	saved, err := h.store.CreatePolicy(r.Context(), policy)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_policy_failed", err.Error(), reqID, req.TenantID)
		return
	}
	h.publishAudit(r.Context(), "audit.tfe.policy_created", saved.TenantID, map[string]interface{}{
		"policy_id": saved.ID,
		"agent_id":  saved.AgentID,
		"name":      saved.Name,
		"path":      saved.Path,
		"key_id":    saved.KeyID,
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"policy": saved, "request_id": reqID})
}

func (h *Handler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant_id"), tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return
	}
	agentID := r.URL.Query().Get("agent_id")
	items, err := h.store.ListPolicies(r.Context(), tenantID, agentID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_policies_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	policy, err := h.store.GetPolicy(r.Context(), tenantID, id)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "get_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": policy, "request_id": reqID})
}

func (h *Handler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	var req UpdateTFEPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	updated, err := h.store.UpdatePolicy(r.Context(), tenantID, id, req)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "update_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	h.publishAudit(r.Context(), "audit.tfe.policy_updated", tenantID, map[string]interface{}{
		"policy_id": updated.ID,
		"agent_id":  updated.AgentID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": updated, "request_id": reqID})
}

func (h *Handler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	if err := h.store.DeletePolicy(r.Context(), tenantID, id); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	h.publishAudit(r.Context(), "audit.tfe.policy_deleted", tenantID, map[string]interface{}{
		"policy_id": id,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

// --- Summary handler ---

func (h *Handler) handleGetSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant_id"), tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return
	}
	summary, err := h.store.GetSummary(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_summary_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": summary, "request_id": reqID})
}

// --- shared HTTP helpers ---

func requestID(r *http.Request) string {
	id := r.Header.Get("X-Request-ID")
	if strings.TrimSpace(id) == "" {
		id = newTFEID("req")
	}
	return id
}

func tenantFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
}

func mustTenant(r *http.Request, w http.ResponseWriter, reqID string) string {
	tenantID := firstNonEmpty(tenantFromRequest(r), strings.TrimSpace(r.URL.Query().Get("tenant_id")))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return ""
	}
	// A01 fix: verify the request tenant matches the authenticated JWT tenant
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return ""
	}
	return tenantID
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code, message, requestID, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error":      code,
		"message":    message,
		"request_id": requestID,
		"tenant_id":  tenantID,
	})
}

func decodeJSON(r *http.Request, out interface{}) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return err
	}
	return json.NewDecoder(bytes.NewReader(body)).Decode(out)
}

func intParamTFE(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func (h *Handler) handleFileEncryptDownload(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant_id"), tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "tenant_id is required", reqID, "")
		return
	}
	q := r.URL.Query()
	req := FileEncryptDownloadRequest{
		TenantID:     tenantID,
		TargetOS:     strings.TrimSpace(q.Get("os")),
		Distro:       strings.TrimSpace(q.Get("distro")),
		KeyID:        strings.TrimSpace(q.Get("key_id")),
		WatchDirs:    strings.TrimSpace(q.Get("watch_dirs")),
		FilePatterns: strings.TrimSpace(q.Get("file_patterns")),
		RotationDays: intParamTFE(q.Get("rotation_days"), 90),
		APIBaseURL:   strings.TrimSpace(q.Get("api_base_url")),
	}
	pkg, err := buildTFEAgentPackage(req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build_package_failed", err.Error(), reqID, tenantID)
		return
	}
	h.publishAudit(r.Context(), "audit.tfe.agent_package_downloaded", tenantID, map[string]interface{}{
		"target_os": pkg.TargetOS,
		"distro":    pkg.Distro,
		"key_id":    pkg.KeyID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"package": pkg, "request_id": reqID})
}

func (h *Handler) handleFileEncryptAudit(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FileEncryptAuditRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := firstNonEmpty(req.TenantID, tenantFromRequest(r))
	h.publishAudit(r.Context(), "audit.tfe.file_encrypt_agent_run", tenantID, map[string]interface{}{
		"key_id":          req.KeyID,
		"operation":       req.Operation,
		"files_processed": req.FilesProcessed,
		"hostname":        req.Hostname,
		"agent_version":   req.AgentVersion,
		"timestamp":       req.Timestamp,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}
