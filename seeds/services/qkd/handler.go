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
	mux.HandleFunc("GET /api/v1/keys/{slave}/status", h.handleETSIStatus)
	mux.HandleFunc("POST /api/v1/keys/{slave}/enc_keys", h.handleETSIEncKeys)
	mux.HandleFunc("POST /api/v1/keys/{slave}/dec_keys", h.handleETSIDecKeys)

	mux.HandleFunc("POST /qkd/v1/open_connect", h.handleOpenConnect)
	mux.HandleFunc("POST /qkd/v1/get_key", h.handleGetKey)
	mux.HandleFunc("POST /qkd/v1/close", h.handleCloseConnect)

	mux.HandleFunc("GET /qkd/v1/devices", h.handleListDevices)
	mux.HandleFunc("GET /qkd/v1/devices/{id}/status", h.handleDeviceStatus)
	mux.HandleFunc("GET /qkd/v1/overview", h.handleOverview)
	mux.HandleFunc("GET /qkd/v1/keys", h.handleListKeys)
	mux.HandleFunc("GET /qkd/v1/logs", h.handleListLogs)
	mux.HandleFunc("POST /qkd/v1/keys/{id}/inject", h.handleInjectKey)
	mux.HandleFunc("POST /qkd/v1/test/generate", h.handleTestGenerate)

	mux.HandleFunc("GET /qkd/v1/config", h.handleGetConfig)
	mux.HandleFunc("PUT /qkd/v1/config", h.handleUpdateConfig)

	mux.HandleFunc("POST /qkd/v1/sae", h.handleRegisterSAE)
	mux.HandleFunc("GET /qkd/v1/sae", h.handleListSAEs)
	mux.HandleFunc("GET /qkd/v1/sae/{id}", h.handleGetSAE)
	mux.HandleFunc("PUT /qkd/v1/sae/{id}", h.handleUpdateSAE)
	mux.HandleFunc("DELETE /qkd/v1/sae/{id}", h.handleDeleteSAE)
	mux.HandleFunc("POST /qkd/v1/sae/{id}/distribute", h.handleDistributeKeys)
	mux.HandleFunc("GET /qkd/v1/distributions", h.handleListDistributions)
	return mux
}

func (h *Handler) handleETSIStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetSlaveStatus(r.Context(), tenantID, r.PathValue("slave"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": out, "request_id": reqID})
}

func (h *Handler) handleETSIEncKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ReceiveKeysRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID := firstNonEmpty(req.TenantID, strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	out, err := h.svc.ReceiveEncKeys(r.Context(), tenantID, r.PathValue("slave"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleETSIDecKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RetrieveKeysRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID := firstNonEmpty(req.TenantID, strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	out, err := h.svc.RetrieveDecKeys(r.Context(), tenantID, r.PathValue("slave"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleOpenConnect(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req OpenConnectRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	out, err := h.svc.OpenConnect(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"session": out, "request_id": reqID})
}

func (h *Handler) handleGetKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req GetKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	out, err := h.svc.GetKey(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleCloseConnect(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CloseConnectRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	out, err := h.svc.CloseConnect(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"session": out, "request_id": reqID})
}

func (h *Handler) handleListDevices(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListDevices(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleDeviceStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.DeviceStatus(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": out, "request_id": reqID})
}

func (h *Handler) handleOverview(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	slaveSAEID := strings.TrimSpace(r.URL.Query().Get("slave_sae_id"))
	out, err := h.svc.Overview(r.Context(), tenantID, slaveSAEID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"overview": out, "request_id": reqID})
}

func (h *Handler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	slaveSAEID := strings.TrimSpace(r.URL.Query().Get("slave_sae_id"))
	if slaveSAEID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "slave_sae_id is required"), reqID, tenantID)
		return
	}
	limit := parseIntWithDefault(strings.TrimSpace(r.URL.Query().Get("limit")), 100)
	if limit <= 0 {
		limit = 100
	}
	statuses := splitCSV(strings.TrimSpace(r.URL.Query().Get("status")))
	items, err := h.svc.ListKeys(r.Context(), tenantID, slaveSAEID, statuses, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleListLogs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := parseIntWithDefault(strings.TrimSpace(r.URL.Query().Get("limit")), 100)
	if limit <= 0 {
		limit = 100
	}
	items, err := h.svc.ListLogs(r.Context(), tenantID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleInjectKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req InjectRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	out, err := h.svc.InjectKey(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleTestGenerate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req TestGenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	out, err := h.svc.GenerateTestKeys(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"result":     out,
		"request_id": reqID,
	})
}

func (h *Handler) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetConfig(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": out, "request_id": reqID})
}

func (h *Handler) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req QKDConfig
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	out, err := h.svc.UpdateConfig(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": out, "request_id": reqID})
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

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
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

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseIntWithDefault(raw string, def int) int {
	if strings.TrimSpace(raw) == "" {
		return def
	}
	n := 0
	sign := 1
	start := 0
	if strings.HasPrefix(raw, "-") {
		sign = -1
		start = 1
	}
	for i := start; i < len(raw); i++ {
		ch := raw[i]
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	return sign * n
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
