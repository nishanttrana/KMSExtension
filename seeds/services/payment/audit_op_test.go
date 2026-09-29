package main

import (
	"context"
	"encoding/base64"
	"testing"
)

func meteredEvent(t *testing.T, ev map[string]interface{}, op, result string) {
	t.Helper()
	d, _ := ev["data"].(map[string]interface{})
	if ev == nil || ev["result"] != result || d["metered_op"] != op {
		t.Fatalf("event not metered as %s/%s: %+v", op, result, ev)
	}
	if _, ok := d["duration_ms"].(float64); !ok {
		t.Fatalf("no duration_ms: %+v", ev)
	}
}

// Every payment operation emits one event when it returns: its success
// event, or <op>_failed / <op>_refused, with the result at top level. Local
// cryptography is metered; ISO 20022 (run by keycore) is audited but not
// metered, so one request is never counted twice.
func TestPaymentOperationsAuditedAndMetered(t *testing.T) {
	svc, _, _, pub := newPaymentService(t)
	ctx := context.Background()
	pvk := base64.StdEncoding.EncodeToString([]byte("1234567890ABCDEF"))

	// Holds in every FIPS mode: strict mode may refuse TDES, which must
	// then be the metered outcome.
	if _, err := svc.GeneratePVV(ctx, PVVGenerateRequest{TenantID: "tenant-b", PVKKeyB64: pvk, PIN: "1234", PAN: "4111111111111111", PVKI: "1"}); err == nil {
		meteredEvent(t, pub.Event("audit.payment.pvv_generated"), "pvv_generate", "success")
	} else if ev := pub.Event("audit.payment.pvv_generate_refused"); ev != nil {
		meteredEvent(t, ev, "pvv_generate", "refused")
	} else {
		meteredEvent(t, pub.Event("audit.payment.pvv_generate_failed"), "pvv_generate", "failure")
	}

	if _, err := svc.ComputeMAC(ctx, MACRequest{TenantID: "tenant-b"}); err == nil {
		t.Fatal("MAC without key or data accepted")
	}
	if pub.Event("audit.payment.mac_compute_failed") == nil && pub.Event("audit.payment.mac_compute_refused") == nil {
		t.Fatal("failed MAC not audited")
	}

	if _, err := svc.ISO20022Sign(ctx, ISO20022SignRequest{TenantID: "tenant-b"}); err == nil {
		t.Fatal("ISO 20022 sign without key accepted")
	}
	ev := pub.Event("audit.payment.iso20022_sign_failed")
	if ev == nil {
		ev = pub.Event("audit.payment.iso20022_sign_refused")
	}
	if d, _ := ev["data"].(map[string]interface{}); ev == nil || d["metered_op"] != nil {
		t.Fatalf("ISO 20022 sign failure: want audited, not metered: %+v", ev)
	}
}
