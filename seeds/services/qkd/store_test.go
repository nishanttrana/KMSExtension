package main

import (
	"context"
	"testing"
	"time"
)

func TestStoreConfigDeviceAndSession(t *testing.T) {
	_, store, _, _ := newQKDService(t)
	ctx := context.Background()
	cfg := QKDConfig{
		TenantID:         "tenant-1",
		QBERThreshold:    0.09,
		PoolLowThreshold: 5,
		AutoInject:       true,
		UpdatedAt:        time.Now().UTC(),
	}
	if err := store.UpsertConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	gotCfg, err := store.GetConfig(ctx, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotCfg.PoolLowThreshold != 5 || !gotCfg.AutoInject {
		t.Fatalf("unexpected config %+v", gotCfg)
	}

	device := QKDDevice{
		ID:         "dev-1",
		TenantID:   "tenant-1",
		Name:       "Alice Device",
		Role:       "alice",
		SlaveSAEID: "slave-A",
		LinkStatus: LinkStatusUp,
		KeyRate:    12.5,
		QBERAvg:    0.03,
		LastSeenAt: time.Now().UTC(),
	}
	if err := store.UpsertDevice(ctx, device); err != nil {
		t.Fatal(err)
	}
	gotDevice, err := store.GetDevice(ctx, "tenant-1", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotDevice.SlaveSAEID != "slave-A" {
		t.Fatalf("unexpected device %+v", gotDevice)
	}

	sess := QKDSession{
		ID:         "sess-1",
		TenantID:   "tenant-1",
		DeviceID:   "dev-1",
		SlaveSAEID: "slave-A",
		AppID:      "app-1",
		Status:     "open",
		OpenedAt:   time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchSession(ctx, "tenant-1", "sess-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(ctx, "tenant-1", "sess-1"); err != nil {
		t.Fatal(err)
	}
	gotSess, err := store.GetSession(ctx, "tenant-1", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotSess.Status != "closed" {
		t.Fatalf("unexpected session %+v", gotSess)
	}
}

func TestStoreQKDKeyPoolAndInjection(t *testing.T) {
	_, store, _, _ := newQKDService(t)
	ctx := context.Background()
	key := QKDKey{
		ID:            "qk-1",
		TenantID:      "tenant-2",
		DeviceID:      "dev-2",
		SlaveSAEID:    "slave-B",
		ExternalKeyID: "ext-1",
		KeySizeBits:   256,
		QBER:          0.02,
		Status:        KeyStatusAvailable,
		WrappedDEK:    []byte("wd"),
		WrappedDEKIV:  []byte("wdiv"),
		Ciphertext:    []byte("cipher"),
		DataIV:        []byte("iv"),
	}
	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	n, err := store.CountAvailableKeys(ctx, "tenant-2", "slave-B")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected available=1 got %d", n)
	}
	keys, err := store.ListAvailableKeysBySlave(ctx, "tenant-2", "slave-B", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != "qk-1" {
		t.Fatalf("unexpected keys %+v", keys)
	}
	if err := store.UpdateKeysStatus(ctx, "tenant-2", []string{"qk-1"}, []string{KeyStatusAvailable}, KeyStatusConsumed); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetKey(ctx, "tenant-2", "qk-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != KeyStatusConsumed {
		t.Fatalf("expected consumed status got %s", got.Status)
	}
	if err := store.SetKeyInjected(ctx, "tenant-2", "qk-1", "keycore-1", KeyStatusInjected); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetKey(ctx, "tenant-2", "qk-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != KeyStatusInjected || got.KeyCoreKeyID != "keycore-1" {
		t.Fatalf("unexpected injected key %+v", got)
	}
}
