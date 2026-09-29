package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgpayment "vecta-kms/pkg/payment"
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
	b, err := pkgcrypto.RandomBytes(8)
	if err != nil {
		panic("payment: system randomness unavailable: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func normalizeTR31Version(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "B":
		return "B"
	case "C":
		return "C"
	case "D":
		return "D"
	case "A":
		return "A"
	default:
		return ""
	}
}

func normalizeTR31Format(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", TR31FormatVariant:
		return TR31FormatVariant
	case TR31FormatB:
		return TR31FormatB
	case TR31FormatC:
		return TR31FormatC
	case TR31FormatD:
		return TR31FormatD
	case TR31FormatAESKWP:
		return TR31FormatAESKWP
	default:
		return ""
	}
}

func normalizePINFormat(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "0", "ISO0", "ISO-0":
		return "ISO-0"
	case "1", "ISO1", "ISO-1":
		return "ISO-1"
	case "3", "ISO3", "ISO-3":
		return "ISO-3"
	case "4", "ISO4", "ISO-4":
		return "ISO-4"
	default:
		return ""
	}
}

func normalizeModeOfUse(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "B":
		return "B"
	case "E":
		return "E"
	case "D":
		return "D"
	case "N":
		return "N"
	default:
		return ""
	}
}

func normalizeExportability(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "E":
		return "E"
	case "N":
		return "N"
	case "S":
		return "S"
	default:
		return ""
	}
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
	default:
		return 0
	}
}

func decodeB64(input string, field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", field+" must be base64")
	}
	if len(raw) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", field+" cannot be empty")
	}
	return raw, nil
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func decimalize(sum []byte, digits int) string {
	if digits <= 0 {
		digits = 4
	}
	out := make([]byte, 0, digits)
	for _, b := range sum {
		hi := (b >> 4) & 0x0F
		lo := b & 0x0F
		if hi <= 9 {
			out = append(out, byte('0'+hi))
		}
		if len(out) == digits {
			break
		}
		if lo <= 9 {
			out = append(out, byte('0'+lo))
		}
		if len(out) == digits {
			break
		}
	}
	for len(out) < digits {
		out = append(out, '0')
	}
	return string(out)
}

func generatePVV(key []byte, pin string, pan string, pvki string, decimalizationTable string) (string, error) {
	return computePVVWithTDES(key, pin, pan, pvki, decimalizationTable)
}

func buildTR31Block(version string, algorithm string, usageCode string, key []byte, kcv string) (string, string, error) {
	version = normalizeTR31Version(version)
	if version == "" {
		return "", "", errors.New("unsupported tr31_version")
	}
	if version != "A" && version != "B" && version != "C" && version != "D" {
		return "", "", errors.New("unsupported tr31_version")
	}
	if strings.TrimSpace(kcv) == "" {
		var err error
		kcv, err = computePaymentKCV(key, algorithm)
		if err != nil {
			return "", "", err
		}
	}
	payload := base64.StdEncoding.EncodeToString(key)
	block := version + "|" + strings.ToUpper(defaultString(algorithm, "AES")) + "|" + strings.ToUpper(defaultString(usageCode, "D0")) + "|" + payload + "|" + strings.ToUpper(strings.TrimSpace(kcv))
	header := version + strings.ToUpper(defaultString(usageCode, "D0")) + defaultString(strings.ToUpper(algorithm), "AES")
	return block, header, nil
}

func normalizeISOXML(v string) string {
	return strings.TrimSpace(strings.ReplaceAll(v, "\r\n", "\n"))
}

func parseKCVHex(v string) []byte {
	raw, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil
	}
	return raw
}

func formatKCVHex(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(v))
}

func parseJSONArrayString(raw string) []string {
	items := parseStringListJSON(raw)
	return uniqueStrings(items)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		key := strings.ToUpper(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func containsString(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), needle) {
			return true
		}
	}
	return false
}

func mustJSON(v interface{}) string {
	raw, _ := json.Marshal(v)
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func boolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []byte:
		s := strings.TrimSpace(string(x))
		return s == "1" || strings.EqualFold(s, "true")
	case string:
		s := strings.TrimSpace(x)
		return s == "1" || strings.EqualFold(s, "true")
	default:
		return false
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

// The payment-industry primitives below live in pkg/payment (the single
// sanctioned implementation); these wrappers keep historical call sites.

func normalizeTDESKey(raw []byte) ([]byte, error) { return pkgpayment.NormalizeTDESKey(raw) }

func tdesECBEncrypt(key24 []byte, block8 []byte) ([]byte, error) {
	return pkgpayment.TDESECBEncrypt(key24, block8)
}

func tdesECBDecrypt(key24 []byte, block8 []byte) ([]byte, error) {
	return pkgpayment.TDESECBDecrypt(key24, block8)
}

func sanitizeDigits(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errors.New("value is required")
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return "", errors.New("value must be numeric")
		}
	}
	return v, nil
}

func extractPAN12(pan string) (string, error) {
	pan, err := sanitizeDigits(pan)
	if err != nil {
		return "", errors.New("pan is required and must be numeric")
	}
	if len(pan) < 13 {
		return "", errors.New("pan must be at least 13 digits")
	}
	noCheck := pan[:len(pan)-1]
	if len(noCheck) < 12 {
		return "", errors.New("pan must contain at least 12 digits excluding check digit")
	}
	return noCheck[len(noCheck)-12:], nil
}

func xorHexString(a string, b string) (string, error) { return pkgpayment.XORHex(a, b) }

func buildPINClearBlock(format string, pin string, pan string) ([]byte, error) {
	return pkgpayment.BuildPINClearBlock(normalizePINFormat(format), pin, pan)
}

func decodePINFromClearBlock(format string, clear []byte, pan string) (string, error) {
	return pkgpayment.DecodePINFromClearBlock(normalizePINFormat(format), clear, pan)
}

func computePVVWithTDES(key []byte, pin string, pan string, pvki string, decimalizationTable string) (string, error) {
	return pkgpayment.ComputePVVTDES(key, pin, pan, defaultString(pvki, "1"), decimalizationTable)
}

func computeCVVWithTDES(cvk []byte, pan string, expiryYYMM string, serviceCode string) (string, error) {
	return pkgpayment.ComputeCVVTDES(cvk, pan, expiryYYMM, serviceCode)
}

func generatePINOffset(pin string, referencePIN string) (string, error) {
	return pkgpayment.GeneratePINOffset(pin, referencePIN)
}

func verifyPINOffset(pin string, referencePIN string, offset string) bool {
	return pkgpayment.VerifyPINOffset(pin, referencePIN, offset)
}

func iso9797Alg1MAC(key []byte, msg []byte) ([]byte, error) {
	return pkgpayment.ISO9797Alg1MAC(key, msg)
}

func iso9797Method2Pad(data []byte, blockSize int) []byte {
	return pkgpayment.ISO9797Method2Pad(data, blockSize)
}

func aesCMAC(key []byte, msg []byte) ([]byte, error) { return pkgpayment.AESCMAC(key, msg) }

func computePaymentKCV(key []byte, algorithmHint string) (string, error) {
	return pkgpayment.ComputeKCV(key, algorithmHint)
}
