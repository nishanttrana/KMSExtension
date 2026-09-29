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
	h.mux.ServeHTTP(w, r.WithContext(withPaymentChannel(r.Context(), paymentChannelREST)))
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /payment/keys", h.handleRegisterPaymentKey)
	mux.HandleFunc("GET /payment/keys", h.handleListPaymentKeys)
	mux.HandleFunc("GET /payment/keys/{id}", h.handleGetPaymentKey)
	mux.HandleFunc("PUT /payment/keys/{id}", h.handleUpdatePaymentKey)
	mux.HandleFunc("POST /payment/keys/{id}/rotate", h.handleRotatePaymentKey)
	mux.HandleFunc("GET /payment/policy", h.handleGetPaymentPolicy)
	mux.HandleFunc("PUT /payment/policy", h.handleSetPaymentPolicy)
	mux.HandleFunc("GET /payment/ap2/profile", h.handleGetPaymentAP2Profile)
	mux.HandleFunc("PUT /payment/ap2/profile", h.handleSetPaymentAP2Profile)
	mux.HandleFunc("POST /payment/ap2/evaluate", h.handleEvaluatePaymentAP2)
	mux.HandleFunc("GET /payment/crypto/operations", h.handleListPaymentCryptoOperations)
	mux.HandleFunc("POST /payment/crypto", h.handlePaymentCryptoDispatch)

	mux.HandleFunc("POST /payment/tr31/create", h.handleTR31Create)
	mux.HandleFunc("POST /payment/tr31/parse", h.handleTR31Parse)
	mux.HandleFunc("POST /payment/tr31/translate", h.handleTR31Translate)
	mux.HandleFunc("POST /payment/tr31/validate", h.handleTR31Validate)
	mux.HandleFunc("GET /payment/tr31/key-usages", h.handleTR31KeyUsages)

	mux.HandleFunc("POST /payment/pin/translate", h.handlePINTranslate)
	mux.HandleFunc("POST /payment/pin/pvv/generate", h.handlePVVGenerate)
	mux.HandleFunc("POST /payment/pin/pvv/verify", h.handlePVVVerify)
	mux.HandleFunc("POST /payment/pin/offset/generate", h.handleOffsetGenerate)
	mux.HandleFunc("POST /payment/pin/offset/verify", h.handleOffsetVerify)
	mux.HandleFunc("POST /payment/pin/cvv/compute", h.handleCVVCompute)
	mux.HandleFunc("POST /payment/pin/cvv/verify", h.handleCVVVerify)

	mux.HandleFunc("POST /payment/mac/retail", h.handleMACRetail)
	mux.HandleFunc("POST /payment/mac/iso9797", h.handleMACISO9797)
	mux.HandleFunc("POST /payment/mac/cmac", h.handleMACCMAC)
	mux.HandleFunc("POST /payment/mac/verify", h.handleMACVerify)

	mux.HandleFunc("POST /payment/iso20022/sign", h.handleISO20022Sign)
	mux.HandleFunc("POST /payment/iso20022/verify", h.handleISO20022Verify)
	mux.HandleFunc("POST /payment/iso20022/encrypt", h.handleISO20022Encrypt)
	mux.HandleFunc("POST /payment/iso20022/decrypt", h.handleISO20022Decrypt)
	mux.HandleFunc("POST /payment/iso20022/lau/generate", h.handleLAUGenerate)
	mux.HandleFunc("POST /payment/iso20022/lau/verify", h.handleLAUVerify)

	mux.HandleFunc("POST /payment/injection/terminals", h.handleRegisterInjectionTerminal)
	mux.HandleFunc("GET /payment/injection/terminals", h.handleListInjectionTerminals)
	mux.HandleFunc("POST /payment/injection/terminals/{id}/challenge", h.handleIssueInjectionChallenge)
	mux.HandleFunc("POST /payment/injection/terminals/{id}/verify", h.handleVerifyInjectionChallenge)
	mux.HandleFunc("POST /payment/injection/jobs", h.handleCreateInjectionJob)
	mux.HandleFunc("GET /payment/injection/jobs", h.handleListInjectionJobs)
	mux.HandleFunc("GET /payment/injection/terminals/{id}/jobs/next", h.handlePullNextInjectionJob)
	mux.HandleFunc("POST /payment/injection/jobs/{id}/ack", h.handleAckInjectionJob)

	return mux
}

func (h *Handler) handleRegisterPaymentKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterPaymentKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.RegisterPaymentKey(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleListPaymentKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	items, err := h.svc.ListPaymentKeys(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetPaymentKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	item, err := h.svc.GetPaymentKey(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleUpdatePaymentKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req UpdatePaymentKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.UpdatePaymentKey(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleRotatePaymentKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RotatePaymentKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		if !strings.Contains(err.Error(), "request body is required") {
			h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
			return
		}
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.RotatePaymentKey(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleGetPaymentPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	item, err := h.svc.GetPaymentPolicy(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
}

func (h *Handler) handleSetPaymentPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	var req PaymentPolicy
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantID)
	if req.TenantID != tenantID {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context"), reqID, tenantID)
		return
	}
	item, err := h.svc.UpdatePaymentPolicy(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
}

func (h *Handler) handleListPaymentCryptoOperations(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id":  tenantID,
		"operations": h.svc.SupportedPaymentCryptoOperations(),
		"request_id": reqID,
	})
}

func (h *Handler) handlePaymentCryptoDispatch(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required"), reqID, "")
		return
	}
	var req PaymentCryptoDispatchRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantID)
	if !strings.EqualFold(req.TenantID, tenantID) {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context"), reqID, tenantID)
		return
	}
	result, err := h.svc.DispatchPaymentCrypto(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"operation":  strings.ToLower(strings.TrimSpace(req.Operation)),
		"result":     result,
		"request_id": reqID,
	})
}

func (h *Handler) handleTR31Create(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateTR31Request
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.CreateTR31(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleTR31Parse(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ParseTR31Request
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.ParseTR31(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleTR31Translate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req TranslateTR31Request
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.TranslateTR31(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleTR31Validate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ValidateTR31Request
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.ValidateTR31(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleTR31KeyUsages(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id":  tenantID,
		"key_usages": h.svc.SupportedTR31KeyUsages(),
		"request_id": reqID,
	})
}

func (h *Handler) handlePINTranslate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req TranslatePINRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	block, err := h.svc.TranslatePIN(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"pin_block": block, "request_id": reqID})
}

func (h *Handler) handlePVVGenerate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req PVVGenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	pvv, err := h.svc.GeneratePVV(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"pvv": pvv, "request_id": reqID})
}

func (h *Handler) handlePVVVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req PVVVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	ok, err := h.svc.VerifyPVV(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"verified": ok, "request_id": reqID})
}

func (h *Handler) handleOffsetGenerate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req OffsetGenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	offset, err := h.svc.GenerateOffset(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"offset": offset, "request_id": reqID})
}

func (h *Handler) handleOffsetVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req OffsetVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	ok, err := h.svc.VerifyOffset(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"verified": ok, "request_id": reqID})
}

func (h *Handler) handleCVVCompute(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CVVComputeRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	cvv, err := h.svc.ComputeCVV(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"cvv": cvv, "request_id": reqID})
}

func (h *Handler) handleCVVVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CVVVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	ok, err := h.svc.VerifyCVV(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"verified": ok, "request_id": reqID})
}

func (h *Handler) handleMACRetail(w http.ResponseWriter, r *http.Request) {
	h.handleMACWithDefaults(w, r, MACRequest{Type: "retail"})
}

func (h *Handler) handleMACISO9797(w http.ResponseWriter, r *http.Request) {
	h.handleMACWithDefaults(w, r, MACRequest{Type: "iso9797", Algorithm: 3})
}

func (h *Handler) handleMACCMAC(w http.ResponseWriter, r *http.Request) {
	h.handleMACWithDefaults(w, r, MACRequest{Type: "cmac"})
}

func (h *Handler) handleMACWithDefaults(w http.ResponseWriter, r *http.Request, defaults MACRequest) {
	reqID := requestID(r)
	var req MACRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	if strings.TrimSpace(req.Type) == "" {
		req.Type = defaults.Type
	}
	if req.Algorithm == 0 && defaults.Algorithm != 0 {
		req.Algorithm = defaults.Algorithm
	}
	macB64, err := h.svc.ComputeMAC(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"mac_b64": macB64, "request_id": reqID})
}

func (h *Handler) handleMACVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req VerifyMACRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	ok, err := h.svc.VerifyMAC(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"verified": ok, "request_id": reqID})
}

func (h *Handler) handleISO20022Sign(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ISO20022SignRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.ISO20022Sign(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleISO20022Verify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ISO20022VerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	ok, err := h.svc.ISO20022Verify(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"verified": ok, "request_id": reqID})
}

func (h *Handler) handleISO20022Encrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ISO20022EncryptRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.ISO20022Encrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleISO20022Decrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ISO20022DecryptRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	xml, err := h.svc.ISO20022Decrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"xml": xml, "request_id": reqID})
}

func (h *Handler) handleLAUGenerate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req LAUGenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	lau, err := h.svc.GenerateLAU(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"lau_b64": lau, "request_id": reqID})
}

func (h *Handler) handleLAUVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req LAUVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	ok, err := h.svc.VerifyLAU(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"verified": ok, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, requestID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, requestID, tenantID)
		return
	}
	// A05: avoid leaking internal error details for 5xx responses
	status := httpStatusForErr(err)
	msg := err.Error()
	if status >= 500 {
		msg = "internal server error"
	}
	writeErr(w, status, "internal_error", msg, requestID, tenantID)
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

func tenantFromRequest(r *http.Request) string {
	return firstNonEmpty(
		strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		strings.TrimSpace(r.Header.Get("X-Tenant-ID")),
	)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
