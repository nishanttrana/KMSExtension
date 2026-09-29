package main

import "net/http"

func (h *Handler) handleGetPaymentAP2Profile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	item, err := h.svc.GetPaymentAP2Profile(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"profile": item, "request_id": reqID})
}

func (h *Handler) handleSetPaymentAP2Profile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	var req PaymentAP2Profile
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantID)
	if req.TenantID != tenantID {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context"), reqID, tenantID)
		return
	}
	item, err := h.svc.UpdatePaymentAP2Profile(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"profile": item, "request_id": reqID})
}

func (h *Handler) handleEvaluatePaymentAP2(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	var req PaymentAP2EvaluateRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantID)
	if req.TenantID != tenantID {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context"), reqID, tenantID)
		return
	}
	result, err := h.svc.EvaluatePaymentAP2(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}
