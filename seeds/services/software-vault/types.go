package main

import (
	"context"
	"time"
)

type Provider interface {
	Name() string
	WrapKey(ctx context.Context, plaintextDEK []byte) (wrappedDEK []byte, iv []byte, err error)
	UnwrapKey(ctx context.Context, wrappedDEK []byte, iv []byte) ([]byte, error)
	Sign(ctx context.Context, data []byte, keyLabel string) ([]byte, error)
	GenerateRandom(ctx context.Context, length int) ([]byte, error)
	GetKeyInfo(ctx context.Context, label string) (map[string]string, error)
	Close() error
}

type ProviderConfig struct {
	ProviderName        string
	Passphrase          string
	HardwareFingerprint string
	MlockRequired       bool

	ArgonMemoryKB   uint32
	ArgonIterations uint32
	ArgonParallel   uint8

	Thales ThalesConfig
	Vecta  VectaConfig
}

type ThalesConfig struct {
	Endpoint  string
	Partition string
	SlotLabel string
}

type VectaConfig struct {
	Endpoint  string
	ProjectID string
	KeyDomain string
}

type SoftwareVaultService struct {
	provider Provider
	now      func() time.Time
}

type serviceError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e serviceError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Message
}

func newServiceError(status int, code string, message string) serviceError {
	return serviceError{Code: code, Message: message, HTTPStatus: status}
}
