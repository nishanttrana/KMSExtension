package main

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

func TestPaymentPolicyStrictModeDoesNotAutoOverrideControls(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	out, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:                  "tenant-strict",
		StrictPCIDSS40:            true,
		RequireKBPKForTR31:        false,
		AllowInlineKeyMaterial:    true,
		RequireISO20022LAUContext: false,
		RequireKeyIDForOperations: false,
		RequireJWTOnTCP:           false,
		BlockWildcardPAN:          false,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if !out.StrictPCIDSS40 {
		t.Fatalf("expected strict_pci_dss_4_0=true")
	}
	if out.RequireKBPKForTR31 {
		t.Fatalf("strict flag must not auto-force require_kbpk_for_tr31")
	}
	if !out.AllowInlineKeyMaterial {
		t.Fatalf("strict flag must not auto-disable inline key material")
	}
	if out.RequireISO20022LAUContext {
		t.Fatalf("strict flag must not auto-force require_iso20022_lau_context")
	}
	if out.RequireKeyIDForOperations {
		t.Fatalf("strict flag must not auto-force require_key_id_for_operations")
	}
	if out.RequireJWTOnTCP {
		t.Fatalf("strict flag must not auto-force require_jwt_on_tcp")
	}
	if out.BlockWildcardPAN {
		t.Fatalf("strict flag must not auto-force block_wildcard_pan")
	}
}

func TestPaymentPolicyBlocksInlineKeyMaterialWhenKeyIDRequired(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:                  "tenant-inline",
		RequireKeyIDForOperations: true,
		AllowInlineKeyMaterial:    false,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	rawKey := []byte("123456789012345678901234")
	rawKeyB64 := base64.StdEncoding.EncodeToString(rawKey)
	_, err = svc.TranslatePIN(ctx, TranslatePINRequest{
		TenantID:        "tenant-inline",
		SourceFormat:    "ISO-0",
		TargetFormat:    "ISO-1",
		PINBlock:        "0000000000000000",
		PAN:             "4111111111111111",
		SourceZPKKeyB64: rawKeyB64,
		TargetZPKKeyB64: rawKeyB64,
		SourceZPKKeyID:  "",
		TargetZPKKeyID:  "",
	})
	if err == nil {
		t.Fatalf("expected policy_violation for inline key material")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError, got: %v", err)
	}
	if svcErr.Code != "policy_violation" {
		t.Fatalf("expected policy_violation, got: %s (%s)", svcErr.Code, svcErr.Message)
	}
}

func TestPaymentPolicyBlocksDisallowedPINFormat(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:               "tenant-pin-format",
		AllowedPINBlockFormats: []string{"ISO-0"},
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	_, err = svc.TranslatePIN(ctx, TranslatePINRequest{
		TenantID:       "tenant-pin-format",
		SourceFormat:   "ISO-0",
		TargetFormat:   "ISO-1",
		PINBlock:       "0000000000000000",
		PAN:            "4111111111111111",
		SourceZPKKeyID: "zpk-src",
		TargetZPKKeyID: "zpk-tgt",
	})
	if err == nil {
		t.Fatalf("expected policy_violation for disallowed pin format")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError, got: %v", err)
	}
	if svcErr.Code != "policy_violation" {
		t.Fatalf("expected policy_violation, got: %s (%s)", svcErr.Code, svcErr.Message)
	}
}

func TestPaymentPolicyDisableISO0RemovesISO0AtRuntime(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	out, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:               "tenant-disable-iso0",
		DisableISO0PINBlock:    true,
		AllowedPINBlockFormats: []string{"ISO-0", "ISO-1", "ISO-3"},
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if containsString(out.AllowedPINBlockFormats, "ISO-0") {
		t.Fatalf("ISO-0 must be removed when disable_iso0_pin_block=true")
	}

	_, err = svc.TranslatePIN(ctx, TranslatePINRequest{
		TenantID:       "tenant-disable-iso0",
		SourceFormat:   "ISO-0",
		TargetFormat:   "ISO-1",
		PINBlock:       "0000000000000000",
		PAN:            "4111111111111111",
		SourceZPKKeyID: "zpk-src",
		TargetZPKKeyID: "zpk-tgt",
	})
	if err == nil {
		t.Fatalf("expected policy_violation for disabled ISO-0")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError, got: %v", err)
	}
	if svcErr.Code != "policy_violation" {
		t.Fatalf("expected policy_violation, got: %s (%s)", svcErr.Code, svcErr.Message)
	}
}

func TestPaymentPolicyRejectsInvalidDecimalizationTable(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:            "tenant-decimalization-invalid",
		DecimalizationTable: "0123ABCDEF",
	})
	if err == nil {
		t.Fatalf("expected validation error for invalid decimalization table")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError, got: %v", err)
	}
	if svcErr.Code != "bad_request" {
		t.Fatalf("expected bad_request, got: %s (%s)", svcErr.Code, svcErr.Message)
	}
}

func TestPaymentPolicyDecimalizationTableAffectsPVV(t *testing.T) {
	fipstest.SkipIfStrict(t, "TDES PVV")
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:               "tenant-decimalization-runtime",
		DecimalizationTable:    "9999999999999999",
		AllowInlineKeyMaterial: true,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	pvv, err := svc.GeneratePVV(ctx, PVVGenerateRequest{
		TenantID:  "tenant-decimalization-runtime",
		PVKKeyB64: base64.StdEncoding.EncodeToString([]byte("1234567890ABCDEF")),
		PIN:       "1234",
		PAN:       "4111111111111111",
		PVKI:      "1",
	})
	if err != nil {
		t.Fatalf("generate pvv: %v", err)
	}
	if pvv != "9999" {
		t.Fatalf("expected pvv=9999 with all-9 decimalization table, got=%s", pvv)
	}
}

func TestPaymentPolicyBlocksTCPWhenDisabled(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:             "tenant-tcp",
		AllowTCPInterface:    false,
		AllowedTCPOperations: []string{"pin.translate"},
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	tcpCtx := withPaymentChannel(ctx, paymentChannelTCP)
	_, err = svc.enforceOperationPolicy(tcpCtx, "tenant-tcp", "pin.translate")
	if err == nil {
		t.Fatalf("expected policy_violation for disabled tcp")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError, got: %v", err)
	}
	if svcErr.Code != "policy_violation" {
		t.Fatalf("expected policy_violation, got: %s (%s)", svcErr.Code, svcErr.Message)
	}
}
