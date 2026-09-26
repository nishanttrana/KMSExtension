package main

import (
	"context"
	"testing"
)

func testProviderConfig(name string) ProviderConfig {
	return ProviderConfig{
		ProviderName:        name,
		Passphrase:          "test-passphrase",
		HardwareFingerprint: "test-host",
		MlockRequired:       false,
		ArgonMemoryKB:       8 * 1024,
		ArgonIterations:     1,
		ArgonParallel:       1,
		Thales: ThalesConfig{
			Endpoint:  "thales.local",
			Partition: "partition-a",
			SlotLabel: "slot-a",
		},
		Vecta: VectaConfig{
			Endpoint:  "vecta.local",
			ProjectID: "project-a",
			KeyDomain: "domain-a",
		},
	}
}

func TestSoftwareProviderWrapUnwrapSignRandom(t *testing.T) {
	p, err := NewProvider(testProviderConfig(ProviderSoftware))
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	defer p.Close() //nolint:errcheck

	plain := []byte("my-dek")
	wrapped, iv, err := p.WrapKey(context.Background(), plain)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	out, err := p.UnwrapKey(context.Background(), wrapped, iv)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(out) != string(plain) {
		t.Fatalf("unwrap mismatch: got=%q want=%q", string(out), string(plain))
	}

	sigA, err := p.Sign(context.Background(), []byte("data"), "label1")
	if err != nil {
		t.Fatalf("sign A: %v", err)
	}
	sigB, err := p.Sign(context.Background(), []byte("data"), "label1")
	if err != nil {
		t.Fatalf("sign B: %v", err)
	}
	if string(sigA) != string(sigB) {
		t.Fatalf("expected deterministic signature")
	}

	rnd, err := p.GenerateRandom(context.Background(), 48)
	if err != nil {
		t.Fatalf("random: %v", err)
	}
	if len(rnd) != 48 {
		t.Fatalf("unexpected random length: %d", len(rnd))
	}
}

func TestEmbeddedProvidersThalesAndVecta(t *testing.T) {
	for _, name := range []string{ProviderThales, ProviderVecta} {
		p, err := NewProvider(testProviderConfig(name))
		if err != nil {
			t.Fatalf("new provider %s: %v", name, err)
		}

		if p.Name() != name {
			t.Fatalf("provider name mismatch: got=%s want=%s", p.Name(), name)
		}
		info, err := p.GetKeyInfo(context.Background(), "key1")
		if err != nil {
			t.Fatalf("get key info %s: %v", name, err)
		}
		if info["integration_mode"] != "embedded_adapter" {
			t.Fatalf("expected embedded_adapter mode for %s", name)
		}
		_ = p.Close()
	}
}

func TestProviderCloseZeroizesMEK(t *testing.T) {
	cfg := testProviderConfig(ProviderSoftware)
	p, err := newSoftwareProvider(cfg)
	if err != nil {
		t.Fatalf("new software provider: %v", err)
	}
	if len(p.mek) == 0 {
		t.Fatalf("mek should not be empty")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for i, b := range p.mek {
		if b != 0 {
			t.Fatalf("mek not zeroized at index %d", i)
		}
	}
}
