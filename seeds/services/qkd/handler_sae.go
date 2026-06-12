package main

import (
	"net/http"
	"strings"
)

func (h *Handler) handleRegisterSAE(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterSAERequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	}
	out, err := h.svc.RegisterSlaveSAE(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"sae": out, "request_id": reqID})
}

func (h *Handler) handleListSAEs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListSlaveSAEs(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetSAE(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetSlaveSAE(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sae": out, "request_id": reqID})
}

func (h *Handler) handleUpdateSAE(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterSAERequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID := firstNonEmpty(req.TenantID, strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	out, err := h.svc.UpdateSlaveSAE(r.Context(), tenantID, r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sae": out, "request_id": reqID})
}

func (h *Handler) handleDeleteSAE(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteSlaveSAE(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "request_id": reqID})
}

func (h *Handler) handleDistributeKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DistributeKeysRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	}
	req.SlaveSAEID = r.PathValue("id")
	out, err := h.svc.DistributeKeys(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleListDistributions(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	slaveSAEID := strings.TrimSpace(r.URL.Query().Get("slave_sae_id"))
	limit := parseIntWithDefault(strings.TrimSpace(r.URL.Query().Get("limit")), 50)
	items, err := h.svc.ListDistributions(r.Context(), tenantID, slaveSAEID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}
