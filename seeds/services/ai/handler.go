package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type Handler struct {
	svc *Service
	mux *http.ServeMux
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ai/query", h.handleQuery)
	mux.HandleFunc("POST /ai/analyze/incident", h.handleAnalyzeIncident)
	mux.HandleFunc("POST /ai/recommend/posture", h.handleRecommendPosture)
	mux.HandleFunc("POST /ai/explain/policy", h.handleExplainPolicy)
	mux.HandleFunc("GET /ai/config", h.handleGetConfig)
	mux.HandleFunc("PUT /ai/config", h.handleUpdateConfig)
	mux.HandleFunc("POST /ai/protect/scan", h.handleAIProtectScan)
	mux.HandleFunc("POST /ai/protect/redact", h.handleAIProtectRedact)
	mux.HandleFunc("POST /ai/protect/block", h.handleAIProtectBlock)
	mux.HandleFunc("GET /ai/protect/policies", h.handleListAIProtectPolicies)
	mux.HandleFunc("POST /ai/protect/policies", h.handleCreateAIProtectPolicy)
	mux.HandleFunc("DELETE /ai/protect/policies/{id}", h.handleDeleteAIProtectPolicy)
	mux.HandleFunc("GET /ai/protect/audit", h.handleListAIProtectAudit)
	return mux
}

func (h *Handler) handleQuery(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req QueryRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.Query(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAnalyzeIncident(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req IncidentAnalysisRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.AnalyzeIncident(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleRecommendPosture(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req PostureRecommendationRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.RecommendPosture(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleExplainPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req PolicyExplainRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.ExplainPolicy(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return
	}
	item, err := h.svc.GetConfig(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": item, "request_id": reqID})
}

func (h *Handler) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return
	}
	var req AIConfigUpdate
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	item, err := h.svc.UpdateConfig(r.Context(), tenantID, req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": item, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	// A05: avoid leaking internal error details for 5xx responses
	status := httpStatusForErr(err)
	msg := err.Error()
	if status >= 500 {
		msg = "internal server error"
	}
	writeErr(w, status, "internal_error", msg, reqID, tenantID)
}

func decodeJSONAllowEmpty(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func tenantFromRequest(r *http.Request) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID != "" {
		return tenantID
	}
	return strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
}

func firstTenant(values ...string) string {
	for _, v := range values {
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

func writeErr(w http.ResponseWriter, status int, code string, message string, requestID string, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       code,
			"message":    message,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}
