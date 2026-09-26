package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"

	"golang.org/x/crypto/argon2"
)

const (
	ProviderSoftware = "software"
	ProviderThales   = "thales"
	ProviderVecta    = "vecta"
)

func NewProvider(cfg ProviderConfig) (Provider, error) {
	name := strings.ToLower(strings.TrimSpace(cfg.ProviderName))
	if name == "" {
		name = ProviderSoftware
	}
	switch name {
	case ProviderSoftware:
		cfg.ProviderName = ProviderSoftware
		return newSoftwareProvider(cfg)
	case ProviderThales:
		return newThalesProvider(cfg)
	case ProviderVecta:
		return newVectaProvider(cfg)
	default:
		return nil, newServiceError(http.StatusBadRequest, "bad_provider", "unsupported provider: "+name)
	}
}

type softwareProvider struct {
	name      string
	mek       []byte
	mlocked   bool
	metadata  map[string]string
	createdAt time.Time
	mu        sync.RWMutex
	closed    bool
}

func newSoftwareProvider(cfg ProviderConfig) (*softwareProvider, error) {
	passphrase := strings.TrimSpace(cfg.Passphrase)
	if passphrase == "" {
		return nil, newServiceError(http.StatusBadRequest, "config_error", "SOFTWARE_VAULT_PASSPHRASE is required")
	}
	memoryKB := cfg.ArgonMemoryKB
	if memoryKB == 0 {
		memoryKB = 128 * 1024
	}
	iterations := cfg.ArgonIterations
	if iterations == 0 {
		iterations = 4
	}
	parallel := cfg.ArgonParallel
	if parallel == 0 {
		parallel = 4
	}
	fingerprint := hostFingerprint(cfg.HardwareFingerprint)
	salt := sha256.Sum256([]byte("vecta-software-vault|" + cfg.ProviderName + "|" + fingerprint))
	pw := []byte(passphrase)
	mek := argon2.IDKey(pw, salt[:], iterations, memoryKB, parallel, 32)
	zeroizeAll(pw)

	p := &softwareProvider{
		name:      defaultProviderName(cfg.ProviderName),
		mek:       mek,
		metadata:  map[string]string{},
		createdAt: time.Now().UTC(),
	}
	p.metadata["kdf"] = "argon2id"
	p.metadata["kdf_memory_kb"] = fmt.Sprintf("%d", memoryKB)
	p.metadata["kdf_iterations"] = fmt.Sprintf("%d", iterations)
	p.metadata["kdf_parallelism"] = fmt.Sprintf("%d", parallel)
	p.metadata["fingerprint_hash"] = shortHash(fingerprint)

	if err := pkgcrypto.Mlock(p.mek); err != nil {
		if cfg.MlockRequired {
			zeroizeAll(p.mek)
			return nil, fmt.Errorf("mlock failed: %w", err)
		}
		p.metadata["mlock_status"] = "best_effort_failed"
		return p, nil
	}
	p.mlocked = true
	p.metadata["mlock_status"] = "locked"
	return p, nil
}

func (p *softwareProvider) Name() string {
	return p.name
}

func (p *softwareProvider) WrapKey(_ context.Context, plaintextDEK []byte) ([]byte, []byte, error) {
	if len(plaintextDEK) == 0 {
		return nil, nil, newServiceError(http.StatusBadRequest, "bad_request", "plaintext_dek is required")
	}
	mek, err := p.snapshotMEK()
	if err != nil {
		return nil, nil, err
	}
	defer zeroizeAll(mek)
	ciphertext, iv, err := aesGCMEncrypt(mek, plaintextDEK)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, iv, nil
}

func (p *softwareProvider) UnwrapKey(_ context.Context, wrappedDEK []byte, iv []byte) ([]byte, error) {
	if len(wrappedDEK) == 0 || len(iv) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "wrapped_dek and iv are required")
	}
	mek, err := p.snapshotMEK()
	if err != nil {
		return nil, err
	}
	defer zeroizeAll(mek)
	return aesGCMDecrypt(mek, wrappedDEK, iv)
}

func (p *softwareProvider) Sign(_ context.Context, data []byte, keyLabel string) ([]byte, error) {
	if len(data) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "data is required")
	}
	mek, err := p.snapshotMEK()
	if err != nil {
		return nil, err
	}
	defer zeroizeAll(mek)
	derived := deriveSigningKey(mek, keyLabel)
	defer zeroizeAll(derived)
	sig := hmacSign(derived, data)
	return sig, nil
}

func (p *softwareProvider) GenerateRandom(_ context.Context, length int) ([]byte, error) {
	if length <= 0 || length > 65536 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "length must be between 1 and 65536")
	}
	out := make([]byte, length)
	if _, err := pkgcrypto.Reader.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *softwareProvider) GetKeyInfo(_ context.Context, label string) (map[string]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, newServiceError(http.StatusServiceUnavailable, "provider_closed", "provider is closed")
	}
	out := map[string]string{
		"provider":     p.name,
		"key_label":    strings.TrimSpace(label),
		"created_at":   ts(p.createdAt),
		"mechanism":    "AES-256-GCM + HMAC-SHA256",
		"mlock_status": p.metadata["mlock_status"],
	}
	for k, v := range p.metadata {
		out[k] = v
	}
	return out, nil
}

func (p *softwareProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if p.mlocked {
		_ = pkgcrypto.Munlock(p.mek)
	}
	zeroizeAll(p.mek)
	p.closed = true
	return nil
}

func (p *softwareProvider) snapshotMEK() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, newServiceError(http.StatusServiceUnavailable, "provider_closed", "provider is closed")
	}
	out := make([]byte, len(p.mek))
	copy(out, p.mek)
	return out, nil
}

type embeddedProvider struct {
	name  string
	core  *softwareProvider
	extra map[string]string
}

func (p *embeddedProvider) Name() string {
	return p.name
}

func (p *embeddedProvider) WrapKey(ctx context.Context, plaintextDEK []byte) ([]byte, []byte, error) {
	return p.core.WrapKey(ctx, plaintextDEK)
}

func (p *embeddedProvider) UnwrapKey(ctx context.Context, wrappedDEK []byte, iv []byte) ([]byte, error) {
	return p.core.UnwrapKey(ctx, wrappedDEK, iv)
}

func (p *embeddedProvider) Sign(ctx context.Context, data []byte, keyLabel string) ([]byte, error) {
	return p.core.Sign(ctx, data, keyLabel)
}

func (p *embeddedProvider) GenerateRandom(ctx context.Context, length int) ([]byte, error) {
	return p.core.GenerateRandom(ctx, length)
}

func (p *embeddedProvider) GetKeyInfo(ctx context.Context, label string) (map[string]string, error) {
	info, err := p.core.GetKeyInfo(ctx, label)
	if err != nil {
		return nil, err
	}
	info["provider"] = p.name
	info["integration_mode"] = "embedded_adapter"
	for k, v := range p.extra {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		info[k] = v
	}
	return info, nil
}

func (p *embeddedProvider) Close() error {
	return p.core.Close()
}

func newThalesProvider(cfg ProviderConfig) (Provider, error) {
	seedParts := []string{
		cfg.Passphrase,
		cfg.Thales.Endpoint,
		cfg.Thales.Partition,
		cfg.Thales.SlotLabel,
		ProviderThales,
	}
	coreCfg := cfg
	coreCfg.ProviderName = ProviderThales
	coreCfg.Passphrase = strings.Join(seedParts, "|")
	core, err := newSoftwareProvider(coreCfg)
	if err != nil {
		return nil, err
	}
	extra := trimMap(map[string]string{
		"thales_endpoint":   cfg.Thales.Endpoint,
		"thales_partition":  cfg.Thales.Partition,
		"thales_slot_label": cfg.Thales.SlotLabel,
	})
	return &embeddedProvider{name: ProviderThales, core: core, extra: extra}, nil
}

func newVectaProvider(cfg ProviderConfig) (Provider, error) {
	seedParts := []string{
		cfg.Passphrase,
		cfg.Vecta.Endpoint,
		cfg.Vecta.ProjectID,
		cfg.Vecta.KeyDomain,
		ProviderVecta,
	}
	coreCfg := cfg
	coreCfg.ProviderName = ProviderVecta
	coreCfg.Passphrase = strings.Join(seedParts, "|")
	core, err := newSoftwareProvider(coreCfg)
	if err != nil {
		return nil, err
	}
	extra := trimMap(map[string]string{
		"vecta_endpoint":   cfg.Vecta.Endpoint,
		"vecta_project_id": cfg.Vecta.ProjectID,
		"vecta_key_domain": cfg.Vecta.KeyDomain,
	})
	return &embeddedProvider{name: ProviderVecta, core: core, extra: extra}, nil
}

func shortHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("%x", sum[:8])
}

func defaultProviderName(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ProviderSoftware
	}
	return v
}

func supportedProviders() []string {
	items := []string{ProviderSoftware, ProviderThales, ProviderVecta}
	sort.Strings(items)
	return items
}
