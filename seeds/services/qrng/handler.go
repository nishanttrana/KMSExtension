package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"vecta-kms/pkg/tenantcheck"
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
	// Source management
	mux.HandleFunc("POST /qrng/v1/sources", h.handleRegisterSource)
	mux.HandleFunc("GET /qrng/v1/sources", h.handleListSources)
	mux.HandleFunc("GET /qrng/v1/sources/{id}", h.handleGetSource)
	mux.HandleFunc("PUT /qrng/v1/sources/{id}", h.handleUpdateSource)
	mux.HandleFunc("DELETE /qrng/v1/sources/{id}", h.handleDeleteSource)

	// Entropy operations
	mux.HandleFunc("POST /qrng/v1/ingest", h.handleIngest)
	mux.HandleFunc("POST /qrng/v1/draw", h.handleDraw)

	// Monitoring
	mux.HandleFunc("GET /qrng/v1/pool/status", h.handlePoolStatus)
	mux.HandleFunc("GET /qrng/v1/health", h.handleListHealth)
	mux.HandleFunc("GET /qrng/v1/overview", h.handleOverview)
	return mux
}

// ── Source handlers ──────────────────────────────────────────

func (h *Handler) handleRegisterSource(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterSourceRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	}
	out, err := h.svc.RegisterSource(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"source": out, "request_id": reqID})
}

func (h *Handler) handleListSources(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListSources(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetSource(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetSource(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"source": out, "request_id": reqID})
}

func (h *Handler) handleUpdateSource(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterSourceRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID := firstNonEmpty(req.TenantID, strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	out, err := h.svc.UpdateSource(r.Context(), tenantID, r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"source": out, "request_id": reqID})
}

func (h *Handler) handleDeleteSource(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteSource(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "request_id": reqID})
}

// ── Entropy handlers ─────────────────────────────────────────

func (h *Handler) handleIngest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req IngestRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	}
	out, err := h.svc.IngestEntropy(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleDraw(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DrawRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	}
	out, err := h.svc.DrawEntropy(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

// ── Monitoring handlers ──────────────────────────────────────

func (h *Handler) handlePoolStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetPoolStatus(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"pool": out, "request_id": reqID})
}

func (h *Handler) handleListHealth(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := parseIntWithDefault(strings.TrimSpace(r.URL.Query().Get("limit")), 100)
	items, err := h.svc.ListHealthEvents(r.Context(), tenantID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleOverview(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetOverview(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"overview": out, "request_id": reqID})
}

// ── JSON helpers ─────────────────────────────────────────────

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

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
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

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	// A01 fix: verify the request tenant matches the authenticated JWT tenant
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return ""
	}
	return tenantID
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parseIntWithDefault(raw string, def int) int {
	if strings.TrimSpace(raw) == "" {
		return def
	}
	n := 0
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

func writeJSON(w http.ResponseWriter, code int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, code int, errCode string, msg string, requestID string, tenantID string) {
	writeJSON(w, code, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       errCode,
			"message":    msg,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}
