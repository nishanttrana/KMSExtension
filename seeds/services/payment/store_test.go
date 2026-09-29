package main

import (
	"context"
	"testing"
)

func TestStorePaymentKeyCRUD(t *testing.T) {
	_, store, _, _ := newPaymentService(t)
	ctx := context.Background()

	key := PaymentKey{
		ID:               "pk1",
		TenantID:         "tenant-1",
		KeyID:            "kc-1",
		PaymentType:      "ZMK",
		UsageCode:        "K0",
		ModeOfUse:        "B",
		KeyVersionNum:    "00",
		Exportability:    "E",
		TR31Header:       "00K0AES",
		KCV:              []byte{0xAA, 0xBB, 0xCC},
		ISO20022PartyID:  "party-1",
		ISO20022MsgTypes: `["pacs.008"]`,
	}
	if err := store.CreatePaymentKey(ctx, key); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetPaymentKey(ctx, "tenant-1", "pk1")
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != "kc-1" || got.KCVHex != "AABBCC" {
		t.Fatalf("unexpected key: %+v", got)
	}

	key.PaymentType = "TPK"
	key.ModeOfUse = "E"
	key.ISO20022MsgTypes = `["pain.001"]`
	if err := store.UpdatePaymentKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdatePaymentKeyVersion(ctx, "tenant-1", "pk1", "01"); err != nil {
		t.Fatal(err)
	}

	got, err = store.GetPaymentKey(ctx, "tenant-1", "pk1")
	if err != nil {
		t.Fatal(err)
	}
	if got.PaymentType != "TPK" || got.KeyVersionNum != "01" {
		t.Fatalf("unexpected updated key: %+v", got)
	}

	items, err := store.ListPaymentKeys(ctx, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one key, got %d", len(items))
	}
}

func TestStoreTranslationAndPINLogs(t *testing.T) {
	_, store, _, _ := newPaymentService(t)
	ctx := context.Background()

	if err := store.CreateTR31Translation(ctx, TR31Translation{
		ID:           "tx1",
		TenantID:     "tenant-2",
		SourceKeyID:  "key1",
		SourceFormat: TR31FormatVariant,
		TargetFormat: TR31FormatD,
		KEKKeyID:     "kek-1",
		ResultBlock:  "D|AES|D0|AA==|A1B2C3",
		Status:       "success",
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.CreatePINOperationLog(ctx, PINOperationLog{
		ID:           "pin1",
		TenantID:     "tenant-2",
		Operation:    "translate",
		SourceFormat: "ISO-0",
		TargetFormat: "ISO-4",
		ZPKKeyID:     "zpk-1",
		Result:       "success",
	}); err != nil {
		t.Fatal(err)
	}
}
