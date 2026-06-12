package main

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestServiceReceiveRetrieveAndInject(t *testing.T) {
	svc, store, keycore, pub := newQKDService(t)
	ctx := context.Background()
	if _, err := svc.UpdateConfig(ctx, QKDConfig{
		TenantID:         "tenant-a",
		QBERThreshold:    0.10,
		PoolLowThreshold: 1,
		AutoInject:       false,
	}); err != nil {
		t.Fatal(err)
	}

	keyA := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	keyB := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxzy123456"))
	resp, err := svc.ReceiveEncKeys(ctx, "tenant-a", "slave-1", ReceiveKeysRequest{
		DeviceID:   "alice-1",
		DeviceName: "Alice Node",
		Role:       "alice",
		LinkStatus: "up",
		Keys: []ReceivedKey{
			{KeyID: "qk-ok", MaterialB64: keyA, QBER: 0.03},
			{KeyID: "qk-bad", MaterialB64: keyB, QBER: 0.50},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AcceptedCount != 1 || resp.DiscardedCount != 1 {
		t.Fatalf("unexpected receive response %+v", resp)
	}
	if pub.Count("audit.qkd.key_received") == 0 || pub.Count("audit.qkd.key_discarded") == 0 {
		t.Fatalf("expected key_received and key_discarded events")
	}

	status, err := svc.GetSlaveStatus(ctx, "tenant-a", "slave-1")
	if err != nil {
		t.Fatal(err)
	}
	if status["available_key_count"].(int) != 1 {
		t.Fatalf("unexpected slave status %+v", status)
	}

	decResp, err := svc.RetrieveDecKeys(ctx, "tenant-a", "slave-1", RetrieveKeysRequest{
		TenantID: "tenant-a",
		Count:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(decResp.Keys) != 1 || decResp.Keys[0].KeyID != "qk-ok" {
		t.Fatalf("unexpected dec keys response %+v", decResp)
	}

	// Reset status for injection test.
	if err := store.UpdateKeysStatus(ctx, "tenant-a", []string{"qk-ok"}, []string{KeyStatusConsumed}, KeyStatusAvailable); err != nil {
		t.Fatal(err)
	}
	injectResp, err := svc.InjectKey(ctx, "qk-ok", InjectRequest{
		TenantID: "tenant-a",
		Name:     "qkd-imported",
		Purpose:  "encrypt",
		Consume:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if injectResp.KeyCoreKeyID == "" {
		t.Fatalf("expected keycore key id %+v", injectResp)
	}
	if len(keycore.keys) == 0 {
		t.Fatalf("expected fake keycore import")
	}
	if pub.Count("audit.qkd.key_injected") == 0 {
		t.Fatalf("expected key_injected event")
	}
}

func TestServiceSessionFlow(t *testing.T) {
	svc, _, _, _ := newQKDService(t)
	ctx := context.Background()
	keyA := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	if _, err := svc.ReceiveEncKeys(ctx, "tenant-b", "slave-2", ReceiveKeysRequest{
		DeviceID:   "alice-2",
		DeviceName: "Alice2",
		Role:       "alice",
		LinkStatus: "up",
		Keys: []ReceivedKey{
			{KeyID: "qk-sess-1", MaterialB64: keyA, QBER: 0.01},
		},
	}); err != nil {
		t.Fatal(err)
	}
	openResp, err := svc.OpenConnect(ctx, OpenConnectRequest{
		TenantID:   "tenant-b",
		DeviceID:   "consumer-1",
		SlaveSAEID: "slave-2",
		AppID:      "app-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if openResp.SessionID == "" {
		t.Fatalf("missing session id")
	}
	getResp, err := svc.GetKey(ctx, GetKeyRequest{
		TenantID:  "tenant-b",
		SessionID: openResp.SessionID,
		Count:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(getResp.Keys) != 1 {
		t.Fatalf("expected one session key %+v", getResp)
	}
	closeResp, err := svc.CloseConnect(ctx, CloseConnectRequest{
		TenantID:  "tenant-b",
		SessionID: openResp.SessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if closeResp.Status != "closed" {
		t.Fatalf("unexpected close response %+v", closeResp)
	}
}
