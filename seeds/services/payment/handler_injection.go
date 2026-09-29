package main

import (
	"net/http"
	"strings"
)

func (h *Handler) handleRegisterInjectionTerminal(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterInjectionTerminalRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.RegisterInjectionTerminal(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"item":       item,
		"request_id": reqID,
	})
}

func (h *Handler) handleListInjectionTerminals(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	items, err := h.svc.ListInjectionTerminals(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleIssueInjectionChallenge(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	terminalID := strings.TrimSpace(r.PathValue("id"))
	if tenantID == "" || terminalID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and terminal id are required"), reqID, tenantID)
		return
	}
	nonce, expiresAt, err := h.svc.IssueInjectionChallenge(r.Context(), tenantID, terminalID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge": map[string]interface{}{
			"nonce":      nonce,
			"expires_at": expiresAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
		},
		"request_id": reqID,
	})
}

func (h *Handler) handleVerifyInjectionChallenge(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	terminalID := strings.TrimSpace(r.PathValue("id"))
	var req VerifyInjectionChallengeRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantID)
	if req.TenantID == "" || terminalID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and terminal id are required"), reqID, tenantID)
		return
	}
	out, err := h.svc.VerifyInjectionChallenge(r.Context(), terminalID, req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"result":     out,
		"request_id": reqID,
	})
}

func (h *Handler) handleCreateInjectionJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	var req CreateInjectionJobRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantID)
	if req.TenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	item, err := h.svc.CreateInjectionJob(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"item":       item,
		"request_id": reqID,
	})
}

func (h *Handler) handleListInjectionJobs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	terminalID := strings.TrimSpace(r.URL.Query().Get("terminal_id"))
	items, err := h.svc.ListInjectionJobs(r.Context(), tenantID, terminalID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handlePullNextInjectionJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	terminalID := strings.TrimSpace(r.PathValue("id"))
	token := terminalTokenFromRequest(r)
	if tenantID == "" || terminalID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and terminal id are required"), reqID, tenantID)
		return
	}
	item, err := h.svc.PullNextInjectionJob(r.Context(), tenantID, terminalID, token)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"item":       item,
		"request_id": reqID,
	})
}

func (h *Handler) handleAckInjectionJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	jobID := strings.TrimSpace(r.PathValue("id"))
	token := terminalTokenFromRequest(r)
	var req AckInjectionJobRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantID)
	if req.TenantID == "" || jobID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and job id are required"), reqID, req.TenantID)
		return
	}
	item, err := h.svc.AckInjectionJob(r.Context(), jobID, req, token)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"item":       item,
		"request_id": reqID,
	})
}

func terminalTokenFromRequest(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get("X-Terminal-Token")); token != "" {
		return token
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}
