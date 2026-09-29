package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

var supportedAP2ProtocolBindings = []string{"a2a", "mcp", "x402"}
var supportedAP2TransactionModes = []string{"human_present", "human_not_present"}
var supportedAP2PaymentRails = []string{"card", "ach", "rtp", "wire", "stablecoin"}

func defaultPaymentAP2Profile(tenantID string) PaymentAP2Profile {
	return PaymentAP2Profile{
		TenantID:                      strings.TrimSpace(tenantID),
		Enabled:                       false,
		AllowedProtocolBindings:       []string{"a2a", "mcp"},
		AllowedTransactionModes:       append([]string{}, supportedAP2TransactionModes...),
		AllowedPaymentRails:           []string{"card", "ach", "rtp"},
		AllowedCurrencies:             []string{"USD"},
		DefaultCurrency:               "USD",
		RequireIntentMandate:          true,
		RequireCartMandate:            true,
		RequirePaymentMandate:         true,
		RequireMerchantSignature:      true,
		RequireVerifiableCredential:   true,
		RequireWalletAttestation:      false,
		RequireRiskSignals:            true,
		RequireTokenizedInstrument:    true,
		AllowX402Extension:            false,
		MaxHumanPresentAmountMinor:    1000000,
		MaxHumanNotPresentAmountMinor: 250000,
		TrustedCredentialIssuers:      []string{},
	}
}

func normalizeAP2ProtocolBinding(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "a2a":
		return "a2a"
	case "mcp":
		return "mcp"
	case "x402":
		return "x402"
	default:
		return ""
	}
}

func normalizeAP2TransactionMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "human_present", "human-present", "present":
		return "human_present"
	case "human_not_present", "human-not-present", "delegated", "agentic":
		return "human_not_present"
	default:
		return ""
	}
}

func normalizeAP2Rail(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "card", "cards":
		return "card"
	case "ach":
		return "ach"
	case "rtp":
		return "rtp"
	case "wire":
		return "wire"
	case "stablecoin", "token":
		return "stablecoin"
	default:
		return ""
	}
}

func normalizeCurrencyCode(v string) string {
	code := strings.ToUpper(strings.TrimSpace(v))
	if len(code) != 3 {
		return ""
	}
	for _, c := range code {
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	return code
}

func normalizeCurrencyList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, item := range uniqueStrings(values) {
		if code := normalizeCurrencyCode(item); code != "" {
			out = append(out, code)
		}
	}
	return out
}

func normalizeAP2StringList(values []string, normalize func(string) string, fallback []string) []string {
	out := make([]string, 0, len(values))
	for _, item := range uniqueStrings(values) {
		if normalized := normalize(item); normalized != "" && !containsString(out, normalized) {
			out = append(out, normalized)
		}
	}
	if len(out) == 0 && len(fallback) > 0 {
		return append([]string{}, fallback...)
	}
	return out
}

func normalizeTrustedIssuers(values []string) []string {
	out := make([]string, 0, len(values))
	for _, item := range uniqueStrings(values) {
		issuer := strings.TrimSpace(item)
		if issuer == "" {
			continue
		}
		out = append(out, issuer)
	}
	return out
}

func normalizePaymentAP2Profile(in PaymentAP2Profile) PaymentAP2Profile {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.AllowedProtocolBindings = normalizeAP2StringList(in.AllowedProtocolBindings, normalizeAP2ProtocolBinding, []string{"a2a", "mcp"})
	in.AllowedTransactionModes = normalizeAP2StringList(in.AllowedTransactionModes, normalizeAP2TransactionMode, supportedAP2TransactionModes)
	in.AllowedPaymentRails = normalizeAP2StringList(in.AllowedPaymentRails, normalizeAP2Rail, []string{"card", "ach", "rtp"})
	in.AllowedCurrencies = normalizeCurrencyList(in.AllowedCurrencies)
	in.DefaultCurrency = normalizeCurrencyCode(in.DefaultCurrency)
	if in.DefaultCurrency == "" {
		if len(in.AllowedCurrencies) > 0 {
			in.DefaultCurrency = in.AllowedCurrencies[0]
		} else {
			in.DefaultCurrency = "USD"
		}
	}
	if len(in.AllowedCurrencies) == 0 {
		in.AllowedCurrencies = []string{in.DefaultCurrency}
	} else if !containsString(in.AllowedCurrencies, in.DefaultCurrency) {
		in.AllowedCurrencies = append([]string{in.DefaultCurrency}, in.AllowedCurrencies...)
	}
	if in.MaxHumanPresentAmountMinor <= 0 {
		in.MaxHumanPresentAmountMinor = 1000000
	}
	if in.MaxHumanNotPresentAmountMinor <= 0 {
		in.MaxHumanNotPresentAmountMinor = 250000
	}
	if in.MaxHumanPresentAmountMinor > 1000000000 {
		in.MaxHumanPresentAmountMinor = 1000000000
	}
	if in.MaxHumanNotPresentAmountMinor > 1000000000 {
		in.MaxHumanNotPresentAmountMinor = 1000000000
	}
	in.TrustedCredentialIssuers = normalizeTrustedIssuers(in.TrustedCredentialIssuers)
	in.UpdatedBy = strings.TrimSpace(in.UpdatedBy)
	return in
}

func normalizePaymentAP2EvaluateRequest(in PaymentAP2EvaluateRequest) PaymentAP2EvaluateRequest {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.AgentID = strings.TrimSpace(in.AgentID)
	in.MerchantID = strings.TrimSpace(in.MerchantID)
	in.Operation = strings.ToLower(strings.TrimSpace(in.Operation))
	in.ProtocolBinding = normalizeAP2ProtocolBinding(in.ProtocolBinding)
	in.TransactionMode = normalizeAP2TransactionMode(in.TransactionMode)
	in.PaymentRail = normalizeAP2Rail(in.PaymentRail)
	in.Currency = normalizeCurrencyCode(in.Currency)
	in.CredentialIssuer = strings.TrimSpace(in.CredentialIssuer)
	return in
}

func containsFold(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, item := range values {
		if strings.EqualFold(strings.TrimSpace(item), needle) {
			return true
		}
	}
	return false
}

func requiredAP2Mandates(profile PaymentAP2Profile) []string {
	required := make([]string, 0, 6)
	if profile.RequireIntentMandate {
		required = append(required, "intent_mandate")
	}
	if profile.RequireCartMandate {
		required = append(required, "cart_mandate")
	}
	if profile.RequirePaymentMandate {
		required = append(required, "payment_mandate")
	}
	if profile.RequireMerchantSignature {
		required = append(required, "merchant_signature")
	}
	if profile.RequireVerifiableCredential {
		required = append(required, "verifiable_credential")
	}
	if profile.RequireWalletAttestation {
		required = append(required, "wallet_attestation")
	}
	if profile.RequireRiskSignals {
		required = append(required, "risk_signals")
	}
	if profile.RequireTokenizedInstrument {
		required = append(required, "tokenized_instrument")
	}
	return uniqueStrings(required)
}

func amountLimitForMode(profile PaymentAP2Profile, mode string) int64 {
	if normalizeAP2TransactionMode(mode) == "human_not_present" {
		return profile.MaxHumanNotPresentAmountMinor
	}
	return profile.MaxHumanPresentAmountMinor
}

func (s *Service) GetPaymentAP2Profile(ctx context.Context, tenantID string) (PaymentAP2Profile, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PaymentAP2Profile{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetPaymentAP2Profile(ctx, tenantID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return defaultPaymentAP2Profile(tenantID), nil
		}
		return PaymentAP2Profile{}, err
	}
	return normalizePaymentAP2Profile(item), nil
}

func (s *Service) UpdatePaymentAP2Profile(ctx context.Context, in PaymentAP2Profile) (PaymentAP2Profile, error) {
	in = normalizePaymentAP2Profile(in)
	if in.TenantID == "" {
		return PaymentAP2Profile{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.UpsertPaymentAP2Profile(ctx, in)
	if err != nil {
		return PaymentAP2Profile{}, err
	}
	item = normalizePaymentAP2Profile(item)
	_ = s.publishAudit(ctx, "audit.payment.ap2_profile_updated", item.TenantID, map[string]interface{}{
		"enabled":                            item.Enabled,
		"allowed_protocol_bindings":          item.AllowedProtocolBindings,
		"allowed_transaction_modes":          item.AllowedTransactionModes,
		"allowed_payment_rails":              item.AllowedPaymentRails,
		"allowed_currencies":                 item.AllowedCurrencies,
		"default_currency":                   item.DefaultCurrency,
		"require_intent_mandate":             item.RequireIntentMandate,
		"require_cart_mandate":               item.RequireCartMandate,
		"require_payment_mandate":            item.RequirePaymentMandate,
		"require_merchant_signature":         item.RequireMerchantSignature,
		"require_verifiable_credential":      item.RequireVerifiableCredential,
		"require_wallet_attestation":         item.RequireWalletAttestation,
		"require_risk_signals":               item.RequireRiskSignals,
		"require_tokenized_instrument":       item.RequireTokenizedInstrument,
		"allow_x402_extension":               item.AllowX402Extension,
		"max_human_present_amount_minor":     item.MaxHumanPresentAmountMinor,
		"max_human_not_present_amount_minor": item.MaxHumanNotPresentAmountMinor,
		"trusted_credential_issuers":         item.TrustedCredentialIssuers,
	})
	return item, nil
}

func (s *Service) EvaluatePaymentAP2(ctx context.Context, in PaymentAP2EvaluateRequest) (PaymentAP2EvaluateResponse, error) {
	in = normalizePaymentAP2EvaluateRequest(in)
	if in.TenantID == "" {
		return PaymentAP2EvaluateResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if in.AmountMinor < 0 {
		return PaymentAP2EvaluateResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "amount_minor cannot be negative")
	}
	profile, err := s.GetPaymentAP2Profile(ctx, in.TenantID)
	if err != nil {
		return PaymentAP2EvaluateResponse{}, err
	}

	fingerprintPayload := map[string]interface{}{
		"agent_id":                     in.AgentID,
		"merchant_id":                  in.MerchantID,
		"operation":                    in.Operation,
		"protocol_binding":             in.ProtocolBinding,
		"transaction_mode":             in.TransactionMode,
		"payment_rail":                 in.PaymentRail,
		"currency":                     in.Currency,
		"amount_minor":                 in.AmountMinor,
		"has_intent_mandate":           in.HasIntentMandate,
		"has_cart_mandate":             in.HasCartMandate,
		"has_payment_mandate":          in.HasPaymentMandate,
		"has_merchant_signature":       in.HasMerchantSignature,
		"has_verifiable_credential":    in.HasVerifiableCredential,
		"has_wallet_attestation":       in.HasWalletAttestation,
		"has_risk_signals":             in.HasRiskSignals,
		"payment_instrument_tokenized": in.PaymentInstrumentTokenized,
		"credential_issuer":            in.CredentialIssuer,
	}
	rawFingerprint, _ := json.Marshal(fingerprintPayload)
	sum := sha256.Sum256(rawFingerprint)

	resp := PaymentAP2EvaluateResponse{
		Decision:                "deny",
		Allowed:                 false,
		RequiredMandates:        requiredAP2Mandates(profile),
		MissingArtifacts:        []string{},
		Reasons:                 []string{},
		AppliedControls:         []string{},
		RecommendedNextSteps:    []string{},
		MaxPermittedAmountMinor: amountLimitForMode(profile, in.TransactionMode),
		RequestFingerprint:      hex.EncodeToString(sum[:]),
		Profile:                 profile,
	}

	denyReasons := make([]string, 0, 8)
	reviewReasons := make([]string, 0, 8)
	missing := make([]string, 0, 8)
	controls := make([]string, 0, 8)
	next := make([]string, 0, 8)

	if !profile.Enabled {
		denyReasons = append(denyReasons, "AP2 policy is disabled for this tenant")
		next = append(next, "Enable the AP2 profile before routing agentic payments")
	}
	if in.ProtocolBinding == "" || !containsString(profile.AllowedProtocolBindings, in.ProtocolBinding) {
		denyReasons = append(denyReasons, "protocol binding is not allowed by AP2 policy")
		next = append(next, "Use one of the allowed protocol bindings for this tenant")
	}
	if in.ProtocolBinding == "x402" && !profile.AllowX402Extension {
		denyReasons = append(denyReasons, "x402 extension is disabled in the AP2 profile")
		next = append(next, "Enable x402 support in the AP2 profile or use A2A/MCP")
	}
	if in.TransactionMode == "" || !containsString(profile.AllowedTransactionModes, in.TransactionMode) {
		denyReasons = append(denyReasons, "transaction mode is not allowed by AP2 policy")
	}
	if in.PaymentRail == "" || !containsString(profile.AllowedPaymentRails, in.PaymentRail) {
		denyReasons = append(denyReasons, "payment rail is not allowed by AP2 policy")
	}
	if in.Currency == "" || !containsString(profile.AllowedCurrencies, in.Currency) {
		denyReasons = append(denyReasons, "currency is not allowed by AP2 policy")
	}

	if profile.RequireIntentMandate && !in.HasIntentMandate {
		missing = append(missing, "intent_mandate")
	}
	if profile.RequireCartMandate && !in.HasCartMandate {
		missing = append(missing, "cart_mandate")
	}
	if profile.RequirePaymentMandate && !in.HasPaymentMandate {
		missing = append(missing, "payment_mandate")
	}
	if profile.RequireMerchantSignature && !in.HasMerchantSignature {
		missing = append(missing, "merchant_signature")
	}
	if profile.RequireVerifiableCredential && !in.HasVerifiableCredential {
		missing = append(missing, "verifiable_credential")
	}
	if profile.RequireWalletAttestation && !in.HasWalletAttestation {
		missing = append(missing, "wallet_attestation")
	}
	if profile.RequireRiskSignals && !in.HasRiskSignals {
		missing = append(missing, "risk_signals")
	}
	if profile.RequireTokenizedInstrument && !in.PaymentInstrumentTokenized {
		missing = append(missing, "tokenized_instrument")
	}
	if len(missing) > 0 {
		denyReasons = append(denyReasons, "request is missing AP2-required mandates or trust artifacts")
		next = append(next, "Collect and bind the missing AP2 artifacts before authorization")
	}

	if limit := amountLimitForMode(profile, in.TransactionMode); limit > 0 && in.AmountMinor > limit {
		reviewReasons = append(reviewReasons, "payment amount exceeds the automatic AP2 approval threshold")
		controls = append(controls, "step_up_approval")
		next = append(next, "Route the payment to explicit user approval or stronger issuer step-up")
		resp.MaxPermittedAmountMinor = limit
	}
	if len(profile.TrustedCredentialIssuers) > 0 && in.CredentialIssuer != "" && !containsFold(profile.TrustedCredentialIssuers, in.CredentialIssuer) {
		reviewReasons = append(reviewReasons, "credential issuer is outside the tenant trust set")
		controls = append(controls, "issuer_trust_review")
		next = append(next, "Use a trusted issuer or update the AP2 trust list")
	}

	if in.TransactionMode == "human_not_present" {
		controls = append(controls, "delegated_agent_payment")
	}
	if in.HasIntentMandate {
		controls = append(controls, "intent_bound_scope")
	}
	if in.HasCartMandate {
		controls = append(controls, "cart_bound_scope")
	}
	if in.HasPaymentMandate {
		controls = append(controls, "payment_mandate_bound")
	}
	if in.HasVerifiableCredential {
		controls = append(controls, "verifiable_credential_present")
	}
	if in.HasWalletAttestation {
		controls = append(controls, "wallet_attestation_present")
	}
	if in.PaymentInstrumentTokenized {
		controls = append(controls, "tokenized_instrument")
	}
	if in.ProtocolBinding == "a2a" {
		controls = append(controls, "a2a_agent_binding")
	}
	if in.ProtocolBinding == "mcp" {
		controls = append(controls, "mcp_tool_binding")
	}
	if in.ProtocolBinding == "x402" && profile.AllowX402Extension {
		controls = append(controls, "x402_receipt_binding")
	}

	resp.MissingArtifacts = uniqueStrings(missing)
	resp.AppliedControls = uniqueStrings(controls)
	resp.RecommendedNextSteps = uniqueStrings(next)

	switch {
	case len(denyReasons) > 0:
		resp.Decision = "deny"
		resp.Allowed = false
		resp.Reasons = uniqueStrings(append(denyReasons, reviewReasons...))
	case len(reviewReasons) > 0:
		resp.Decision = "review"
		resp.Allowed = false
		resp.Reasons = uniqueStrings(reviewReasons)
	default:
		resp.Decision = "allow"
		resp.Allowed = true
		resp.Reasons = []string{"request satisfies the active AP2 profile"}
		resp.RecommendedNextSteps = uniqueStrings(append(resp.RecommendedNextSteps, "Proceed with issuer or network authorization using the bound AP2 artifacts"))
	}

	_ = s.publishAudit(ctx, "audit.payment.ap2_evaluated", in.TenantID, map[string]interface{}{
		"decision":            resp.Decision,
		"allowed":             resp.Allowed,
		"protocol_binding":    in.ProtocolBinding,
		"transaction_mode":    in.TransactionMode,
		"payment_rail":        in.PaymentRail,
		"currency":            in.Currency,
		"amount_minor":        in.AmountMinor,
		"missing_artifacts":   resp.MissingArtifacts,
		"applied_controls":    resp.AppliedControls,
		"request_fingerprint": resp.RequestFingerprint,
	})
	return resp, nil
}
