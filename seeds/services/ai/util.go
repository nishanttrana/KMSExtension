package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
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

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func extractInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float32:
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

func extractFloat(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case string:
		n, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return n
	default:
		return 0
	}
}

func extractBool(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func parseJSONArray(v string) []interface{} {
	v = strings.TrimSpace(v)
	if v == "" {
		return []interface{}{}
	}
	var out []interface{}
	_ = json.Unmarshal([]byte(v), &out)
	if out == nil {
		return []interface{}{}
	}
	return out
}

func parseJSONArrayString(v string) []string {
	raw := parseJSONArray(v)
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

func normalizeBackend(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "chatgpt", "gpt", "openai-chatgpt":
		return "openai"
	case "github-copilot", "copilot-chat":
		return "copilot"
	case "self-hosted-openai", "self_hosted", "own-hosted":
		return "self-hosted"
	default:
		return s
	}
}

func normalizeAuthType(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "apikey", "api-key", "x-api-key":
		return "api_key"
	case "authorization":
		return "bearer"
	default:
		return s
	}
}

func backendRequiresAuth(backend string) bool {
	switch normalizeBackend(backend) {
	case "claude", "openai", "azure-openai", "copilot":
		return true
	default:
		return false
	}
}

func defaultAuthTypeForBackend(backend string) string {
	switch normalizeBackend(backend) {
	case "claude":
		return "api_key"
	case "openai", "azure-openai", "copilot", "self-hosted", "vllm", "llamacpp":
		return "bearer"
	case "ollama":
		return "none"
	default:
		return "bearer"
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

func round2(v float64) float64 {
	n, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 2, 64), 64)
	return n
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

func includeFields(in map[string]interface{}, fields []string) map[string]interface{} {
	if len(fields) == 0 {
		return cloneMap(in)
	}
	allowed := map[string]struct{}{}
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "" {
			allowed[f] = struct{}{}
		}
	}
	out := map[string]interface{}{}
	for k, v := range in {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(k))]; ok {
			out[k] = v
		}
	}
	return out
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	for k, v := range in {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		return cloneMap(x)
	case []interface{}:
		out := make([]interface{}, 0, len(x))
		for _, it := range x {
			out = append(out, cloneValue(it))
		}
		return out
	case []map[string]interface{}:
		out := make([]interface{}, 0, len(x))
		for _, it := range x {
			out = append(out, cloneMap(it))
		}
		return out
	default:
		return x
	}
}

func redactMapFields(in map[string]interface{}, fields []string) (map[string]interface{}, int) {
	fieldSet := map[string]struct{}{}
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "" {
			fieldSet[f] = struct{}{}
		}
	}
	out, n := redactValue(in, fieldSet)
	obj, _ := out.(map[string]interface{})
	if obj == nil {
		return map[string]interface{}{}, n
	}
	return obj, n
}

func redactValue(v interface{}, fields map[string]struct{}) (interface{}, int) {
	switch x := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		total := 0
		for k, val := range x {
			key := strings.ToLower(strings.TrimSpace(k))
			if _, ok := fields[key]; ok {
				out[k] = "[REDACTED]"
				total++
				continue
			}
			next, n := redactValue(val, fields)
			out[k] = next
			total += n
		}
		return out, total
	case []interface{}:
		out := make([]interface{}, 0, len(x))
		total := 0
		for _, item := range x {
			next, n := redactValue(item, fields)
			out = append(out, next)
			total += n
		}
		return out, total
	case []map[string]interface{}:
		out := make([]interface{}, 0, len(x))
		total := 0
		for _, item := range x {
			next, n := redactValue(item, fields)
			out = append(out, next)
			total += n
		}
		return out, total
	default:
		return x, 0
	}
}

var (
	reNamedSecret = regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*([A-Za-z0-9_\-]{6,})`)
	reOpenAIKey   = regexp.MustCompile(`\bsk-[A-Za-z0-9]{16,}\b`)
	reLongHex     = regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`)
)

func redactText(text string) (string, int) {
	total := 0
	text = reNamedSecret.ReplaceAllStringFunc(text, func(s string) string {
		total++
		idx := strings.IndexAny(s, ":=")
		if idx < 0 {
			return "[REDACTED]"
		}
		return s[:idx+1] + " [REDACTED]"
	})
	text = reOpenAIKey.ReplaceAllStringFunc(text, func(_ string) string {
		total++
		return "[REDACTED_API_KEY]"
	})
	text = reLongHex.ReplaceAllStringFunc(text, func(_ string) string {
		total++
		return "[REDACTED_HEX]"
	})
	return text, total
}

func sanitizeErrorMessage(v map[string]interface{}) string {
	errAny, ok := v["error"]
	if !ok {
		return "request failed"
	}
	errMap, ok := errAny.(map[string]interface{})
	if !ok {
		return "request failed"
	}
	msg, _ := errMap["message"].(string)
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "request failed"
	}
	return msg
}
