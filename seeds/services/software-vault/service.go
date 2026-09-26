package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

func NewService(provider Provider) *SoftwareVaultService {
	return &SoftwareVaultService{
		provider: provider,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *SoftwareVaultService) WrapKey(ctx context.Context, plaintextDEK []byte) ([]byte, []byte, error) {
	if s.provider == nil {
		return nil, nil, newServiceError(http.StatusServiceUnavailable, "provider_missing", "provider not configured")
	}
	return s.provider.WrapKey(ctx, plaintextDEK)
}

func (s *SoftwareVaultService) UnwrapKey(ctx context.Context, wrappedDEK []byte, iv []byte) ([]byte, error) {
	if s.provider == nil {
		return nil, newServiceError(http.StatusServiceUnavailable, "provider_missing", "provider not configured")
	}
	return s.provider.UnwrapKey(ctx, wrappedDEK, iv)
}

func (s *SoftwareVaultService) Sign(ctx context.Context, data []byte, keyLabel string) ([]byte, error) {
	if s.provider == nil {
		return nil, newServiceError(http.StatusServiceUnavailable, "provider_missing", "provider not configured")
	}
	return s.provider.Sign(ctx, data, strings.TrimSpace(keyLabel))
}

func (s *SoftwareVaultService) GenerateRandom(ctx context.Context, length int) ([]byte, error) {
	if s.provider == nil {
		return nil, newServiceError(http.StatusServiceUnavailable, "provider_missing", "provider not configured")
	}
	return s.provider.GenerateRandom(ctx, length)
}

func (s *SoftwareVaultService) GetKeyInfo(ctx context.Context, label string) (map[string]string, error) {
	if s.provider == nil {
		return nil, newServiceError(http.StatusServiceUnavailable, "provider_missing", "provider not configured")
	}
	return s.provider.GetKeyInfo(ctx, strings.TrimSpace(label))
}

func (s *SoftwareVaultService) Close() error {
	if s.provider == nil {
		return nil
	}
	return s.provider.Close()
}
