package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgmpc "vecta-kms/pkg/mpc"
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

func httpStatusForErr(err error) int {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		return svcErr.HTTPStatus
	}
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = pkgcrypto.Reader.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
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
		"2006-01-02",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
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

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func parseJSONArrayString(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return []string{}
	}
	var raw []interface{}
	_ = json.Unmarshal([]byte(v), &raw)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s := strings.TrimSpace(firstString(item))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseJSONObject(v string) map[string]interface{} {
	v = strings.TrimSpace(v)
	if v == "" {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	_ = json.Unmarshal([]byte(v), &out)
	if out == nil {
		return map[string]interface{}{}
	}
	return out
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		switch x := v.(type) {
		case string:
			if strings.TrimSpace(x) != "" {
				return strings.TrimSpace(x)
			}
		case []byte:
			s := strings.TrimSpace(string(x))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func extractInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func containsString(items []string, needle string) bool {
	needle = strings.TrimSpace(strings.ToLower(needle))
	for _, s := range items {
		if strings.ToLower(strings.TrimSpace(s)) == needle {
			return true
		}
	}
	return false
}

func sha256Hex(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func decodeFlexibleBinary(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return []byte{}, nil
	}
	if raw, err := hex.DecodeString(v); err == nil {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(v); err == nil {
		return raw, nil
	}
	return []byte(v), nil
}

func encodeBinaryB64(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}

func xorDecryptWithSecret(secret *big.Int, ciphertext []byte) []byte {
	return pkgmpc.XORDecryptWithSecret(secret, ciphertext)
}

func normalizeAlgorithm(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "ECDSA_SECP256K1"
	}
	return v
}

func normalizeCeremonyType(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "dkg", "sign", "decrypt":
		return v
	default:
		return "dkg"
	}
}

func atoi(v string) int {
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return n
		}
		n = n*10 + int(v[i]-'0')
	}
	return n
}
