package main

import (
	"context"
	"net/http"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
)

type paymentChannelContextKey struct{}
type paymentPolicyContextKey struct{}
type paymentJWTClaimsContextKey struct{}

const (
	paymentChannelREST = "rest"
	paymentChannelTCP  = "tcp"
)

func withPaymentChannel(ctx context.Context, channel string) context.Context {
	channel = strings.ToLower(strings.TrimSpace(channel))
	if channel == "" {
		channel = paymentChannelREST
	}
	return context.WithValue(ctx, paymentChannelContextKey{}, channel)
}

func paymentChannelFromContext(ctx context.Context) string {
	raw, _ := ctx.Value(paymentChannelContextKey{}).(string)
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return paymentChannelREST
	}
	return raw
}

func withPaymentPolicy(ctx context.Context, policy PaymentPolicy) context.Context {
	return context.WithValue(ctx, paymentPolicyContextKey{}, policy)
}

func paymentPolicyFromContext(ctx context.Context) (PaymentPolicy, bool) {
	policy, ok := ctx.Value(paymentPolicyContextKey{}).(PaymentPolicy)
	return policy, ok
}

func withPaymentJWTClaims(ctx context.Context, claims *pkgauth.Claims) context.Context {
	if claims == nil {
		return ctx
	}
	return context.WithValue(ctx, paymentJWTClaimsContextKey{}, claims)
}

func paymentJWTClaimsFromContext(ctx context.Context) (*pkgauth.Claims, bool) {
	claims, ok := ctx.Value(paymentJWTClaimsContextKey{}).(*pkgauth.Claims)
	return claims, ok
}

func (s *Service) policyFromContextOrStore(ctx context.Context, tenantID string) (PaymentPolicy, error) {
	if policy, ok := paymentPolicyFromContext(ctx); ok && strings.EqualFold(strings.TrimSpace(policy.TenantID), strings.TrimSpace(tenantID)) {
		return normalizePaymentPolicy(policy), nil
	}
	policy, err := s.mustPaymentPolicy(ctx, tenantID)
	if err != nil {
		return PaymentPolicy{}, err
	}
	return normalizePaymentPolicy(policy), nil
}

func (s *Service) enforceOperationPolicy(ctx context.Context, tenantID string, operation string) (PaymentPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PaymentPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	policy, err := s.policyFromContextOrStore(ctx, tenantID)
	if err != nil {
		return PaymentPolicy{}, err
	}
	channel := paymentChannelFromContext(ctx)
	if channel == paymentChannelTCP {
		if !policy.AllowTCPInterface {
			return PaymentPolicy{}, newServiceError(http.StatusForbidden, "policy_violation", "payment tcp interface is disabled by payment policy")
		}
		op := strings.ToLower(strings.TrimSpace(operation))
		if op != "" && len(policy.AllowedTCPOperations) > 0 && !containsString(policy.AllowedTCPOperations, op) {
			return PaymentPolicy{}, newServiceError(http.StatusForbidden, "policy_violation", "requested operation is blocked on payment tcp interface")
		}
	}
	return policy, nil
}

func enforceInlineKeyMaterialPolicy(policy PaymentPolicy, keyID string, material string, materialField string, keyField string) error {
	hasInline := strings.TrimSpace(material) != ""
	hasKeyID := strings.TrimSpace(keyID) != ""
	if hasInline {
		if policy.RequireKeyIDForOperations || !policy.AllowInlineKeyMaterial {
			return newServiceError(http.StatusForbidden, "policy_violation", "inline key material is blocked by payment policy")
		}
	}
	if policy.RequireKeyIDForOperations && !hasKeyID {
		msg := "key_id is required by payment policy"
		if strings.TrimSpace(keyField) != "" {
			msg = keyField + " is required by payment policy"
		}
		return newServiceError(http.StatusForbidden, "policy_violation", msg)
	}
	if !hasInline && !hasKeyID {
		if strings.TrimSpace(materialField) != "" && strings.TrimSpace(keyField) != "" {
			return newServiceError(http.StatusBadRequest, "bad_request", materialField+" or "+keyField+" is required")
		}
	}
	return nil
}

func isPINFormatAllowed(policy PaymentPolicy, format string) bool {
	normalized := normalizePINFormat(format)
	if normalized == "" {
		return false
	}
	allowed := policy.AllowedPINBlockFormats
	if len(allowed) == 0 {
		allowed = supportedPINBlockFormats
	}
	for _, item := range allowed {
		if normalizePINFormat(item) == normalized {
			return true
		}
	}
	return false
}

func validatePANPolicy(policy PaymentPolicy, pan string) error {
	pan = strings.TrimSpace(pan)
	if pan == "" {
		return nil
	}
	if policy.BlockWildcardPAN {
		for _, r := range pan {
			if r < '0' || r > '9' {
				return newServiceError(http.StatusForbidden, "policy_violation", "PAN must contain digits only by payment policy")
			}
		}
	}
	return nil
}
