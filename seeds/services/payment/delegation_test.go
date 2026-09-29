package main

import (
	"context"
	"testing"
)

// PIN translation exports the source ZPK as translate-decrypt and the target
// as translate-encrypt, so keycore checks those grants of the user.
func TestTranslatePINNamesItsUsages(t *testing.T) {
	svc, _, fake, _ := newPaymentService(t)
	_, _ = svc.TranslatePIN(context.Background(), TranslatePINRequest{
		TenantID: "tenant-u", SourceFormat: "ISO-0", TargetFormat: "ISO-1",
		PINBlock: "0000000000000000", PAN: "4111111111111111",
		SourceZPKKeyID: "zpk-src", TargetZPKKeyID: "zpk-dst",
	})
	if fake.usages["zpk-src"] != "translate-decrypt" || fake.usages["zpk-dst"] != "translate-encrypt" {
		t.Fatalf("usages sent to keycore: %v", fake.usages)
	}
}
