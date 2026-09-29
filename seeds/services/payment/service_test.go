package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

func TestServicePaymentKeyLifecycle(t *testing.T) {
	svc, _, _, pub := newPaymentService(t)
	ctx := context.Background()

	created, err := svc.RegisterPaymentKey(ctx, RegisterPaymentKeyRequest{
		TenantID:      "tenant-a",
		KeyID:         "kc-1",
		PaymentType:   "ZMK",
		UsageCode:     "K0",
		ModeOfUse:     "B",
		Exportability: "E",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.KCVHex == "" {
		t.Fatalf("unexpected created key: %+v", created)
	}

	got, err := svc.GetPaymentKey(ctx, "tenant-a", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != "kc-1" {
		t.Fatalf("unexpected key: %+v", got)
	}

	updated, err := svc.UpdatePaymentKey(ctx, created.ID, UpdatePaymentKeyRequest{
		TenantID:      "tenant-a",
		PaymentType:   "TPK",
		UsageCode:     "P0",
		ModeOfUse:     "E",
		Exportability: "N",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.PaymentType != "TPK" || updated.ModeOfUse != "E" {
		t.Fatalf("unexpected updated key: %+v", updated)
	}

	rot, err := svc.RotatePaymentKey(ctx, created.ID, RotatePaymentKeyRequest{
		TenantID: "tenant-a",
		Reason:   "test-rotation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rot.VersionID == "" {
		t.Fatalf("missing version id: %+v", rot)
	}
	if pub.Count("audit.payment.key_rotated") == 0 {
		t.Fatal("expected rotation audit event")
	}
}

func TestServiceTR31PINAndMACFlows(t *testing.T) {
	fipstest.SkipIfStrict(t, "TDES (TR-31 / PIN / MAC)")
	svc, _, keycore, _ := newPaymentService(t)
	ctx := context.Background()

	keycore.materials["tenant-b:kc-2"] = []byte("1234567890ABCDEF")
	kbpkB64 := base64.StdEncoding.EncodeToString([]byte("0123456789ABCDEF0123456789ABCDEF"))
	createResp, err := svc.CreateTR31(ctx, CreateTR31Request{
		TenantID:    "tenant-b",
		KeyID:       "kc-2",
		TR31Version: "D",
		Algorithm:   "AES",
		UsageCode:   "D0",
		KBPKKeyB64:  kbpkB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if createResp.KeyBlock == "" || !strings.HasPrefix(createResp.KeyBlock, "D") || strings.Contains(createResp.KeyBlock, "|") {
		t.Fatalf("unexpected tr31 create response: %+v", createResp)
	}

	validateResp, err := svc.ValidateTR31(ctx, ValidateTR31Request{
		TenantID:   "tenant-b",
		KeyBlock:   createResp.KeyBlock,
		KBPKKeyB64: kbpkB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !validateResp.Valid {
		t.Fatalf("expected valid tr31 block: %+v", validateResp)
	}

	parseResp, err := svc.ParseTR31(ctx, ParseTR31Request{
		TenantID:    "tenant-b",
		KeyBlock:    createResp.KeyBlock,
		KBPKKeyB64:  kbpkB64,
		ImportToKMS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parseResp.ImportedKeyID == "" {
		t.Fatalf("expected imported key id: %+v", parseResp)
	}

	translated, err := svc.TranslateTR31(ctx, TranslateTR31Request{
		TenantID:         "tenant-b",
		SourceFormat:     TR31FormatD,
		TargetFormat:     TR31FormatAESKWP,
		SourceBlock:      createResp.KeyBlock,
		SourceKBPKKeyB64: kbpkB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(translated.ResultBlock, "AESKWP|") {
		t.Fatalf("unexpected translation block: %+v", translated)
	}

	sourcePINKey := []byte("1234567890ABCDEF")
	targetPINKey := []byte("FEDCBA0987654321")
	keycore.materials["tenant-b:zpk-src"] = append([]byte{}, sourcePINKey...)
	keycore.materials["tenant-b:zpk-dst"] = append([]byte{}, targetPINKey...)
	pan := "4111111111111111"
	clearISO0, err := buildPINClearBlock("ISO-0", "1234", pan)
	if err != nil {
		t.Fatal(err)
	}
	sourceTDES, err := normalizeTDESKey(sourcePINKey)
	if err != nil {
		t.Fatal(err)
	}
	sourcePINBlock, err := tdesECBEncrypt(sourceTDES, clearISO0)
	if err != nil {
		t.Fatal(err)
	}
	pinTranslated, err := svc.TranslatePIN(ctx, TranslatePINRequest{
		TenantID:       "tenant-b",
		SourceFormat:   "ISO-0",
		TargetFormat:   "ISO-1",
		PINBlock:       strings.ToUpper(hex.EncodeToString(sourcePINBlock)),
		PAN:            pan,
		SourceZPKKeyID: "zpk-src",
		TargetZPKKeyID: "zpk-dst",
	})
	if err != nil {
		t.Fatal(err)
	}
	targetTDES, err := normalizeTDESKey(targetPINKey)
	if err != nil {
		t.Fatal(err)
	}
	targetBlockRaw, err := hex.DecodeString(pinTranslated)
	if err != nil {
		t.Fatal(err)
	}
	targetClear, err := tdesECBDecrypt(targetTDES, targetBlockRaw)
	if err != nil {
		t.Fatal(err)
	}
	decodedPIN, err := decodePINFromClearBlock("ISO-1", targetClear, pan)
	if err != nil {
		t.Fatal(err)
	}
	if decodedPIN != "1234" {
		t.Fatalf("translated pin mismatch got=%s", decodedPIN)
	}

	pvv, err := svc.GeneratePVV(ctx, PVVGenerateRequest{
		TenantID:  "tenant-b",
		PVKKeyB64: base64.StdEncoding.EncodeToString([]byte("1234567890ABCDEF")),
		PIN:       "1234",
		PAN:       "4111111111111111",
		PVKI:      "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pvv) != 4 {
		t.Fatalf("unexpected pvv: %s", pvv)
	}

	ok, err := svc.VerifyPVV(ctx, PVVVerifyRequest{
		TenantID:  "tenant-b",
		PVKKeyB64: base64.StdEncoding.EncodeToString([]byte("1234567890ABCDEF")),
		PIN:       "1234",
		PAN:       "4111111111111111",
		PVKI:      "1",
		PVV:       pvv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected pvv verification true")
	}

	macB64, err := svc.ComputeMAC(ctx, MACRequest{
		TenantID: "tenant-b",
		KeyB64:   base64.StdEncoding.EncodeToString([]byte("12345678ABCDEFGH")),
		DataB64:  base64.StdEncoding.EncodeToString([]byte("hello-payment")),
		Type:     "retail",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyMAC, err := svc.VerifyMAC(ctx, VerifyMACRequest{
		TenantID: "tenant-b",
		KeyB64:   base64.StdEncoding.EncodeToString([]byte("12345678ABCDEFGH")),
		DataB64:  base64.StdEncoding.EncodeToString([]byte("hello-payment")),
		MACB64:   macB64,
		Type:     "retail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyMAC {
		t.Fatal("expected mac verification true")
	}
}

func TestServiceISOAndLAUFlows(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()
	xml := "<Document><Msg>ok</Msg></Document>"

	signed, err := svc.ISO20022Sign(ctx, ISO20022SignRequest{
		TenantID: "tenant-c",
		KeyID:    "iso-key-1",
		XML:      xml,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(signed["signature_b64"]) == "" {
		t.Fatalf("missing signature response: %+v", signed)
	}

	verified, err := svc.ISO20022Verify(ctx, ISO20022VerifyRequest{
		TenantID:     "tenant-c",
		KeyID:        "iso-key-1",
		XML:          xml,
		SignatureB64: signed["signature_b64"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("expected xml verification true")
	}

	enc, err := svc.ISO20022Encrypt(ctx, ISO20022EncryptRequest{
		TenantID: "tenant-c",
		KeyID:    "iso-key-1",
		XML:      xml,
	})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := svc.ISO20022Decrypt(ctx, ISO20022DecryptRequest{
		TenantID:      "tenant-c",
		KeyID:         "iso-key-1",
		CiphertextB64: enc["ciphertext"],
		IVB64:         enc["iv"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec != xml {
		t.Fatalf("decrypt mismatch got=%s want=%s", dec, xml)
	}

	lau, err := svc.GenerateLAU(ctx, LAUGenerateRequest{
		TenantID:  "tenant-c",
		LAUKeyB64: base64.StdEncoding.EncodeToString([]byte("lau-secret-123456")),
		Message:   "pacs.008 payload",
		Context:   "swift",
	})
	if err != nil {
		t.Fatal(err)
	}
	lauOK, err := svc.VerifyLAU(ctx, LAUVerifyRequest{
		TenantID:  "tenant-c",
		LAUKeyB64: base64.StdEncoding.EncodeToString([]byte("lau-secret-123456")),
		Message:   "pacs.008 payload",
		Context:   "swift",
		LAUB64:    lau,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !lauOK {
		t.Fatal("expected lau verification true")
	}
}

func TestServicePaymentAP2ProfileDefaultsAndUpdate(t *testing.T) {
	svc, _, _, pub := newPaymentService(t)
	ctx := context.Background()

	defaultProfile, err := svc.GetPaymentAP2Profile(ctx, "tenant-ap2")
	if err != nil {
		t.Fatal(err)
	}
	if defaultProfile.Enabled {
		t.Fatal("expected AP2 default profile disabled")
	}
	if !strings.EqualFold(defaultProfile.DefaultCurrency, "USD") {
		t.Fatalf("unexpected default currency: %+v", defaultProfile)
	}

	updated, err := svc.UpdatePaymentAP2Profile(ctx, PaymentAP2Profile{
		TenantID:                      "tenant-ap2",
		Enabled:                       true,
		AllowedProtocolBindings:       []string{"a2a", "mcp", "x402"},
		AllowedTransactionModes:       []string{"human_present", "human_not_present"},
		AllowedPaymentRails:           []string{"card", "ach"},
		AllowedCurrencies:             []string{"usd", "eur"},
		DefaultCurrency:               "eur",
		RequireIntentMandate:          true,
		RequireCartMandate:            true,
		RequirePaymentMandate:         true,
		RequireMerchantSignature:      true,
		RequireVerifiableCredential:   true,
		RequireWalletAttestation:      true,
		RequireRiskSignals:            true,
		RequireTokenizedInstrument:    true,
		AllowX402Extension:            true,
		MaxHumanPresentAmountMinor:    500000,
		MaxHumanNotPresentAmountMinor: 120000,
		TrustedCredentialIssuers:      []string{"issuer.example"},
		UpdatedBy:                     "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Enabled || !containsString(updated.AllowedProtocolBindings, "x402") {
		t.Fatalf("unexpected updated AP2 profile: %+v", updated)
	}
	if pub.Count("audit.payment.ap2_profile_updated") == 0 {
		t.Fatal("expected AP2 profile audit event")
	}
}

func TestServiceEvaluatePaymentAP2(t *testing.T) {
	svc, _, _, pub := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentAP2Profile(ctx, PaymentAP2Profile{
		TenantID:                      "tenant-eval",
		Enabled:                       true,
		AllowedProtocolBindings:       []string{"a2a", "mcp"},
		AllowedTransactionModes:       []string{"human_present", "human_not_present"},
		AllowedPaymentRails:           []string{"card", "ach"},
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
		MaxHumanPresentAmountMinor:    900000,
		MaxHumanNotPresentAmountMinor: 200000,
		TrustedCredentialIssuers:      []string{"issuer.example"},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowResp, err := svc.EvaluatePaymentAP2(ctx, PaymentAP2EvaluateRequest{
		TenantID:                   "tenant-eval",
		AgentID:                    "agent-1",
		MerchantID:                 "merchant-1",
		Operation:                  "authorize",
		ProtocolBinding:            "a2a",
		TransactionMode:            "human_not_present",
		PaymentRail:                "card",
		Currency:                   "USD",
		AmountMinor:                150000,
		HasIntentMandate:           true,
		HasCartMandate:             true,
		HasPaymentMandate:          true,
		HasMerchantSignature:       true,
		HasVerifiableCredential:    true,
		HasWalletAttestation:       false,
		HasRiskSignals:             true,
		PaymentInstrumentTokenized: true,
		CredentialIssuer:           "issuer.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !allowResp.Allowed || allowResp.Decision != "allow" || strings.TrimSpace(allowResp.RequestFingerprint) == "" {
		t.Fatalf("unexpected allow response: %+v", allowResp)
	}

	reviewResp, err := svc.EvaluatePaymentAP2(ctx, PaymentAP2EvaluateRequest{
		TenantID:                   "tenant-eval",
		AgentID:                    "agent-2",
		MerchantID:                 "merchant-1",
		Operation:                  "authorize",
		ProtocolBinding:            "mcp",
		TransactionMode:            "human_not_present",
		PaymentRail:                "card",
		Currency:                   "USD",
		AmountMinor:                350000,
		HasIntentMandate:           true,
		HasCartMandate:             true,
		HasPaymentMandate:          true,
		HasMerchantSignature:       true,
		HasVerifiableCredential:    true,
		HasRiskSignals:             true,
		PaymentInstrumentTokenized: true,
		CredentialIssuer:           "untrusted.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if reviewResp.Decision != "review" || reviewResp.Allowed {
		t.Fatalf("expected review response: %+v", reviewResp)
	}
	if !containsString(reviewResp.AppliedControls, "step_up_approval") {
		t.Fatalf("expected step-up control: %+v", reviewResp)
	}

	denyResp, err := svc.EvaluatePaymentAP2(ctx, PaymentAP2EvaluateRequest{
		TenantID:                   "tenant-eval",
		AgentID:                    "agent-3",
		MerchantID:                 "merchant-1",
		Operation:                  "authorize",
		ProtocolBinding:            "x402",
		TransactionMode:            "human_not_present",
		PaymentRail:                "stablecoin",
		Currency:                   "USD",
		AmountMinor:                120000,
		HasIntentMandate:           false,
		HasCartMandate:             false,
		HasPaymentMandate:          false,
		HasMerchantSignature:       false,
		HasVerifiableCredential:    false,
		HasRiskSignals:             false,
		PaymentInstrumentTokenized: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if denyResp.Decision != "deny" || denyResp.Allowed {
		t.Fatalf("expected deny response: %+v", denyResp)
	}
	if !containsString(denyResp.MissingArtifacts, "intent_mandate") {
		t.Fatalf("expected missing intent mandate: %+v", denyResp)
	}
	if pub.Count("audit.payment.ap2_evaluated") == 0 {
		t.Fatal("expected AP2 evaluation audit event")
	}
}
