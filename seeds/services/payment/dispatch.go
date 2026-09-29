package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

var supportedPaymentCryptoOperations = []string{
	"tr31.create",
	"tr31.parse",
	"tr31.translate",
	"tr31.validate",
	"tr31.key-usages",
	"pin.translate",
	"pin.pvv.generate",
	"pin.pvv.verify",
	"pin.offset.generate",
	"pin.offset.verify",
	"pin.cvv.compute",
	"pin.cvv.verify",
	"mac.retail",
	"mac.iso9797",
	"mac.cmac",
	"mac.verify",
	"iso20022.sign",
	"iso20022.verify",
	"iso20022.encrypt",
	"iso20022.decrypt",
	"iso20022.lau.generate",
	"iso20022.lau.verify",
}

func (s *Service) SupportedPaymentCryptoOperations() []string {
	out := make([]string, len(supportedPaymentCryptoOperations))
	copy(out, supportedPaymentCryptoOperations)
	return out
}

func (s *Service) DispatchPaymentCrypto(ctx context.Context, req PaymentCryptoDispatchRequest) (interface{}, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	op := strings.ToLower(strings.TrimSpace(req.Operation))
	if op == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "operation is required")
	}

	switch op {
	case "tr31.create":
		var in CreateTR31Request
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		return s.CreateTR31(ctx, in)
	case "tr31.parse":
		var in ParseTR31Request
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		return s.ParseTR31(ctx, in)
	case "tr31.translate":
		var in TranslateTR31Request
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		return s.TranslateTR31(ctx, in)
	case "tr31.validate":
		var in ValidateTR31Request
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		return s.ValidateTR31(ctx, in)
	case "tr31.key-usages":
		return map[string]interface{}{"key_usages": s.SupportedTR31KeyUsages()}, nil
	case "pin.translate":
		var in TranslatePINRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		block, err := s.TranslatePIN(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"pin_block": block}, nil
	case "pin.pvv.generate":
		var in PVVGenerateRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		pvv, err := s.GeneratePVV(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"pvv": pvv}, nil
	case "pin.pvv.verify":
		var in PVVVerifyRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		ok, err := s.VerifyPVV(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"verified": ok}, nil
	case "pin.offset.generate":
		var in OffsetGenerateRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		offset, err := s.GenerateOffset(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"offset": offset}, nil
	case "pin.offset.verify":
		var in OffsetVerifyRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		ok, err := s.VerifyOffset(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"verified": ok}, nil
	case "pin.cvv.compute":
		var in CVVComputeRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		cvv, err := s.ComputeCVV(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"cvv": cvv}, nil
	case "pin.cvv.verify":
		var in CVVVerifyRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		ok, err := s.VerifyCVV(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"verified": ok}, nil
	case "mac.retail", "mac.iso9797", "mac.cmac":
		var in MACRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		if strings.TrimSpace(in.Type) == "" {
			in.Type = strings.TrimPrefix(op, "mac.")
		}
		if strings.EqualFold(op, "mac.iso9797") && in.Algorithm == 0 {
			in.Algorithm = 3
		}
		macB64, err := s.ComputeMAC(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"mac_b64": macB64}, nil
	case "mac.verify":
		var in VerifyMACRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		ok, err := s.VerifyMAC(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"verified": ok}, nil
	case "iso20022.sign":
		var in ISO20022SignRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		return s.ISO20022Sign(ctx, in)
	case "iso20022.verify":
		var in ISO20022VerifyRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		ok, err := s.ISO20022Verify(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"verified": ok}, nil
	case "iso20022.encrypt":
		var in ISO20022EncryptRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		return s.ISO20022Encrypt(ctx, in)
	case "iso20022.decrypt":
		var in ISO20022DecryptRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		xml, err := s.ISO20022Decrypt(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"xml": xml}, nil
	case "iso20022.lau.generate":
		var in LAUGenerateRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		lau, err := s.GenerateLAU(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"lau_b64": lau}, nil
	case "iso20022.lau.verify":
		var in LAUVerifyRequest
		if err := decodeDispatchPayload(req.Payload, &in); err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := enforceDispatchTenant(tenantID, &in.TenantID); err != nil {
			return nil, err
		}
		ok, err := s.VerifyLAU(ctx, in)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"verified": ok}, nil
	default:
		return nil, newServiceError(http.StatusNotImplemented, "operation_not_supported", "unsupported payment crypto operation")
	}
}

func decodeDispatchPayload(raw json.RawMessage, out interface{}) error {
	payload := bytes.TrimSpace(raw)
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func enforceDispatchTenant(dispatchTenant string, payloadTenant *string) error {
	if payloadTenant == nil {
		return nil
	}
	current := strings.TrimSpace(*payloadTenant)
	if current == "" {
		*payloadTenant = dispatchTenant
		return nil
	}
	if !strings.EqualFold(current, dispatchTenant) {
		return newServiceError(http.StatusBadRequest, "bad_request", "tenant mismatch between dispatch request and payload")
	}
	*payloadTenant = dispatchTenant
	return nil
}
