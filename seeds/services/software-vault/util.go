package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

func envOr(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envUint32(key string, fallback uint32) uint32 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return fallback
	}
	return uint32(n)
}

func envUint8(key string, fallback uint8) uint8 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil {
		return fallback
	}
	return uint8(n)
}

func hostFingerprint(override string) string {
	if strings.TrimSpace(override) != "" {
		return strings.TrimSpace(override)
	}
	host, _ := os.Hostname()
	parts := []string{host, runtime.GOOS, runtime.GOARCH}
	for _, file := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if raw, err := os.ReadFile(file); err == nil {
			value := strings.TrimSpace(string(raw))
			if value != "" {
				parts = append(parts, value)
				break
			}
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func b64(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(v)
}

func b64d(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("base64 value is required")
	}
	out, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	return out, nil
}

func parseBytesField(m map[string]interface{}, keys ...string) ([]byte, error) {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if out, err := b64d(s); err == nil {
			return out, nil
		}
		return []byte(s), nil
	}
	return nil, errors.New("required bytes field missing")
}

func parseStringField(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok {
			continue
		}
		if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func parseIntField(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok {
			continue
		}
		switch x := raw.(type) {
		case float64:
			return int(x)
		case int:
			return x
		case int64:
			return int(x)
		case string:
			n, _ := strconv.Atoi(strings.TrimSpace(x))
			if n > 0 {
				return n
			}
		}
	}
	return 0
}

func zeroizeAll(items ...[]byte) {
	for _, item := range items {
		for i := range item {
			item[i] = 0
		}
	}
}

func deriveSigningKey(mek []byte, label string) []byte {
	h := hmac.New(sha256.New, mek)
	_, _ = h.Write([]byte("software-vault-signing|" + strings.TrimSpace(label)))
	return h.Sum(nil)
}

func hmacSign(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// AES-GCM goes through pkg/crypto so the IV is generated inside the FIPS
// module and the provider works in every FIPS runtime mode.
func aesGCMEncrypt(key []byte, plaintext []byte) ([]byte, []byte, error) {
	iv, ciphertext, err := pkgcrypto.SealDetached(key, plaintext, nil)
	return ciphertext, iv, err
}

func aesGCMDecrypt(key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	return pkgcrypto.OpenDetached(key, iv, ciphertext, nil)
}

func trimMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
