package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

type serviceError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e serviceError) Error() string {
	if strings.TrimSpace(e.Message) == "" {
		return e.Code
	}
	return e.Message
}

func newServiceError(status int, code string, message string) serviceError {
	return serviceError{
		Code:       strings.TrimSpace(code),
		Message:    strings.TrimSpace(message),
		HTTPStatus: status,
	}
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = pkgcrypto.Reader.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func normalizeLinkStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", LinkStatusUp:
		return LinkStatusUp
	case LinkStatusDown:
		return LinkStatusDown
	default:
		return ""
	}
}

func normalizeKeyStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case KeyStatusAvailable:
		return KeyStatusAvailable
	case KeyStatusReserved:
		return KeyStatusReserved
	case KeyStatusConsumed:
		return KeyStatusConsumed
	case KeyStatusDiscarded:
		return KeyStatusDiscarded
	case KeyStatusInjected:
		return KeyStatusInjected
	default:
		return ""
	}
}

func validJSONOr(v string, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	if json.Valid([]byte(v)) {
		return v
	}
	return fallback
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func normalizeRole(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "alice", "bob", "peer", "provider", "consumer":
		return v
	default:
		return "peer"
	}
}

func normalizeQKDConfig(cfg QKDConfig) QKDConfig {
	cfg.TenantID = strings.TrimSpace(cfg.TenantID)
	if cfg.QBERThreshold <= 0 || cfg.QBERThreshold > 1 {
		cfg.QBERThreshold = 0.11
	}
	if cfg.PoolLowThreshold <= 0 {
		cfg.PoolLowThreshold = 10
	}
	if cfg.PoolCapacity <= 0 {
		cfg.PoolCapacity = 1250000
	}
	if cfg.PoolCapacity < cfg.PoolLowThreshold {
		cfg.PoolCapacity = cfg.PoolLowThreshold
	}
	if strings.TrimSpace(cfg.Protocol) == "" {
		cfg.Protocol = "ETSI GS QKD 014"
	}
	if cfg.DistanceKM <= 0 {
		cfg.DistanceKM = 47
	}
	if !cfg.ServiceEnabled && !cfg.ETSIAPIEnabled && cfg.UpdatedAt.IsZero() {
		// Default runtime behavior is enabled unless explicitly disabled in stored config.
		cfg.ServiceEnabled = true
		cfg.ETSIAPIEnabled = true
	}
	if cfg.UpdatedAt.IsZero() {
		cfg.UpdatedAt = time.Now().UTC()
	}
	return cfg
}

func hashToAES256(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func decodeB64Key(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("key material is required")
	}
	out, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("key must be base64")
	}
	if len(out) == 0 {
		return nil, errors.New("decoded key is empty")
	}
	return out, nil
}

func httpStatusForErr(err error) int {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		return svcErr.HTTPStatus
	}
	return http.StatusInternalServerError
}
