package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
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

func httpStatusForErr(err error) int {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		return svcErr.HTTPStatus
	}
	return http.StatusInternalServerError
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
		time.RFC3339Nano, time.RFC3339,
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

func boolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case []byte:
		return string(x) == "true" || string(x) == "1"
	case string:
		return x == "true" || x == "1"
	default:
		return false
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

// ── NIST SP 800-90B entropy quality tests ────────────────────

// shannonEntropyBPB computes bits-per-byte Shannon entropy.
// Returns value in [0.0, 8.0]. High-quality random data scores > 7.9.
func shannonEntropyBPB(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// biasScore returns proportion of bits that deviate from 50% expectation.
// Returns 0.0 (perfectly unbiased) to 1.0 (all-0 or all-1).
func biasScore(data []byte) float64 {
	if len(data) == 0 {
		return 1.0
	}
	ones := 0
	total := len(data) * 8
	for _, b := range data {
		for i := 0; i < 8; i++ {
			if (b>>uint(i))&1 == 1 {
				ones++
			}
		}
	}
	p := float64(ones) / float64(total)
	return math.Abs(p-0.5) * 2
}

// adaptiveProportionTest implements NIST SP 800-90B section 4.4.1.
// Returns true if no single byte value appears excessively often.
func adaptiveProportionTest(data []byte) bool {
	if len(data) < 64 {
		return true
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	// Conservative cutoff for high-entropy sources
	cutoff := len(data) / 16
	if cutoff < 8 {
		cutoff = 8
	}
	for _, c := range freq {
		if c > cutoff {
			return false
		}
	}
	return true
}

// repetitionCountTest implements NIST SP 800-90B section 4.4.2.
// Returns true if no byte value repeats consecutively more than cutoff times.
func repetitionCountTest(data []byte, cutoff int) bool {
	if cutoff <= 0 {
		cutoff = 10
	}
	if len(data) < 2 {
		return true
	}
	run := 1
	for i := 1; i < len(data); i++ {
		if data[i] == data[i-1] {
			run++
			if run > cutoff {
				return false
			}
		} else {
			run = 1
		}
	}
	return true
}

type qualityResult struct {
	EntropyOK  bool    `json:"entropy_ok"`
	AdaptiveOK bool    `json:"adaptive_ok"`
	RepeatOK   bool    `json:"repeat_ok"`
	BiasOK     bool    `json:"bias_ok"`
	Measured   float64 `json:"measured_bpb"`
	Bias       float64 `json:"bias_score"`
}

func (q qualityResult) AllPassed() bool {
	return q.EntropyOK && q.AdaptiveOK && q.RepeatOK && q.BiasOK
}

func validateQuality(raw []byte, minEntropyBPB float64) (qualityResult, error) {
	if len(raw) < MinIngestBytes {
		return qualityResult{}, errors.New("sample too small (min 32 bytes)")
	}
	measured := shannonEntropyBPB(raw)
	bias := biasScore(raw)
	return qualityResult{
		Measured:   measured,
		Bias:       bias,
		EntropyOK:  measured >= minEntropyBPB,
		AdaptiveOK: adaptiveProportionTest(raw),
		RepeatOK:   repetitionCountTest(raw, 10),
		BiasOK:     bias < MaxBiasScore,
	}, nil
}

func normalizeVendor(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "id-quantique-quantis", "idq", "quantis":
		return "id-quantique-quantis"
	case "quintessencelabs-qstream", "quintessencelabs", "qstream":
		return "quintessencelabs-qstream"
	case "toshiba":
		return "toshiba"
	case "cloud-aws", "aws":
		return "cloud-aws"
	case "cloud-azure", "azure":
		return "cloud-azure"
	default:
		return "custom"
	}
}

func normalizeSourceMode(v string) string {
	if strings.ToLower(strings.TrimSpace(v)) == SourceModePull {
		return SourceModePull
	}
	return SourceModePush
}

func normalizeSourceStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case SourceStatusActive:
		return SourceStatusActive
	case SourceStatusPaused:
		return SourceStatusPaused
	case SourceStatusError:
		return SourceStatusError
	case SourceStatusRemoved:
		return SourceStatusRemoved
	default:
		return SourceStatusActive
	}
}
