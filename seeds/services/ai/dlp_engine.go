package main

import (
	"fmt"
	"log"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

// DLPPolicy extends AIProtectPolicy with confidence-aware enforcement.
type DLPPolicy struct {
	AIProtectPolicy
	MinConfidence  float64         `json:"min_confidence"`
	CustomPatterns []CustomPattern `json:"custom_patterns,omitempty"`
	Exemptions     []string        `json:"exemptions,omitempty"`
}

// CustomPattern allows tenants to define their own regex-based detectors.
type CustomPattern struct {
	Name       string  `json:"name"`
	Pattern    string  `json:"pattern"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
}

// Finding represents a single piece of sensitive data detected in text.
type Finding struct {
	DetectorName string  `json:"detector_name"`
	Category     string  `json:"category"`
	Type         string  `json:"type"`
	Value        string  `json:"-"`
	RedactedVal  string  `json:"redacted_value"`
	StartPos     int     `json:"start_pos"`
	EndPos       int     `json:"end_pos"`
	Confidence   float64 `json:"confidence"`
	Context      string  `json:"context,omitempty"`
}

// Detector is the interface every DLP detector must implement.
type Detector interface {
	Name() string
	Detect(text string) []Finding
}

// DLPEngine orchestrates all detectors and applies tenant-scoped policies.
type DLPEngine struct {
	detectors []Detector
	policies  map[string]*DLPPolicy // tenant_id -> active policy
	store     Store
	mu        sync.RWMutex
	logger    *log.Logger
}

// NewDLPEngine creates an engine with all built-in detectors.
func NewDLPEngine(store Store, logger *log.Logger) *DLPEngine {
	return &DLPEngine{
		detectors: []Detector{
			&CreditCardDetector{},
			&SSNDetector{},
			&EmailDetector{},
			&PhoneDetector{},
			&NameDetector{},
			&AddressDetector{},
			&HealthDataDetector{},
			&FinancialDetector{},
			&CredentialDetector{},
			&GovernmentIDDetector{},
		},
		policies: make(map[string]*DLPPolicy),
		store:    store,
		logger:   logger,
	}
}

// Scan runs every detector against text and returns all findings.
func (e *DLPEngine) Scan(text string) []Finding {
	var all []Finding
	for _, d := range e.detectors {
		all = append(all, d.Detect(text)...)
	}
	// Sort by position for stable output
	sort.Slice(all, func(i, j int) bool { return all[i].StartPos < all[j].StartPos })
	return all
}

// ScanWithPolicy runs detectors then filters by the given policy.
func (e *DLPEngine) ScanWithPolicy(text string, policy *DLPPolicy) []Finding {
	all := e.Scan(text)
	if policy == nil {
		return all
	}

	// Build exemption set
	exemptions := make(map[string]bool, len(policy.Exemptions))
	for _, ex := range policy.Exemptions {
		exemptions[strings.ToLower(strings.TrimSpace(ex))] = true
	}

	// Build enabled pattern set; empty means all
	enabledPatterns := make(map[string]bool, len(policy.Patterns))
	for _, p := range policy.Patterns {
		enabledPatterns[strings.ToLower(strings.TrimSpace(p))] = true
	}

	minConf := policy.MinConfidence
	if minConf <= 0 {
		minConf = 0.7
	}

	var filtered []Finding
	for _, f := range all {
		if f.Confidence < minConf {
			continue
		}
		typ := strings.ToLower(f.Type)
		cat := strings.ToLower(f.Category)
		if exemptions[typ] || exemptions[cat] || exemptions[f.DetectorName] {
			continue
		}
		if len(enabledPatterns) > 0 {
			if !enabledPatterns[typ] && !enabledPatterns[cat] && !enabledPatterns[f.DetectorName] {
				continue
			}
		}
		filtered = append(filtered, f)
	}

	// Append custom pattern matches
	for _, cp := range policy.CustomPatterns {
		re, err := regexp.Compile(cp.Pattern)
		if err != nil {
			continue
		}
		locs := re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			val := text[loc[0]:loc[1]]
			conf := cp.Confidence
			if conf <= 0 {
				conf = 0.8
			}
			if conf < minConf {
				continue
			}
			filtered = append(filtered, Finding{
				DetectorName: "custom:" + cp.Name,
				Category:     cp.Category,
				Type:         cp.Name,
				Value:        val,
				RedactedVal:  "[CUSTOM REDACTED]",
				StartPos:     loc[0],
				EndPos:       loc[1],
				Confidence:   conf,
				Context:      extractContext(text, loc[0], loc[1]),
			})
		}
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].StartPos < filtered[j].StartPos })
	return filtered
}

// Redact replaces findings in text with type-specific masks.
func (e *DLPEngine) Redact(text string, findings []Finding) string {
	if len(findings) == 0 {
		return text
	}
	// Process in reverse order to preserve positions
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].StartPos > sorted[j].StartPos })

	result := text
	for _, f := range sorted {
		if f.StartPos < 0 || f.EndPos > len(result) || f.StartPos >= f.EndPos {
			continue
		}
		mask := redactByType(f)
		result = result[:f.StartPos] + mask + result[f.EndPos:]
	}
	return result
}

// redactByType returns a type-appropriate mask for a finding.
func redactByType(f Finding) string {
	val := f.Value
	switch f.Type {
	case "ssn":
		if len(val) >= 4 {
			return "***-**-" + val[len(val)-4:]
		}
		return "***-**-****"
	case "credit_card":
		digits := extractDigits(val)
		if len(digits) >= 4 {
			return "****-****-****-" + digits[len(digits)-4:]
		}
		return "****-****-****-****"
	case "email":
		parts := strings.SplitN(val, "@", 2)
		if len(parts) == 2 {
			local := parts[0]
			prefix := local
			if len(local) > 2 {
				prefix = local[:2]
			}
			return prefix + "***@" + parts[1]
		}
		return "[EMAIL REDACTED]"
	case "phone":
		digits := extractDigits(val)
		if len(digits) >= 4 {
			return "(***) ***-" + digits[len(digits)-4:]
		}
		return "(***) ***-****"
	case "name":
		return "[NAME REDACTED]"
	case "address", "uk_postcode":
		return "[ADDRESS REDACTED]"
	case "aws_key", "gcp_key", "azure_connection", "github_pat", "gitlab_pat",
		"slack_token", "private_key", "jwt", "password", "connection_string",
		"high_entropy":
		return "[CREDENTIAL REDACTED]"
	case "mrn", "icd_code", "drug_name", "health_dob":
		return "[HEALTH DATA REDACTED]"
	case "bank_account", "routing_number", "iban", "swift_bic":
		return "[FINANCIAL REDACTED]"
	case "us_passport", "uk_ni", "canadian_sin", "aadhaar":
		return "[GOV ID REDACTED]"
	default:
		return "[REDACTED]"
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func extractDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func extractContext(text string, start, end int) string {
	ctxStart := start - 20
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := end + 20
	if ctxEnd > len(text) {
		ctxEnd = len(text)
	}
	return text[ctxStart:ctxEnd]
}

// luhnCheck validates a number string using the Luhn algorithm.
func luhnCheck(number string) bool {
	digits := extractDigits(number)
	if len(digits) < 2 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// abaChecksum validates a 9-digit ABA routing number.
// Formula: (d1*3 + d2*7 + d3*1 + d4*3 + d5*7 + d6*1 + d7*3 + d8*7 + d9*1) % 10 == 0
func abaChecksum(digits string) bool {
	if len(digits) != 9 {
		return false
	}
	weights := []int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0
	for i := 0; i < 9; i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
		sum += int(digits[i]-'0') * weights[i]
	}
	return sum%10 == 0
}

// ibanValidate checks IBAN using ISO 7064 mod-97 algorithm.
func ibanValidate(iban string) bool {
	cleaned := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(iban)), " ", "")
	if len(cleaned) < 5 || len(cleaned) > 34 {
		return false
	}
	// Move first 4 chars to end
	rearranged := cleaned[4:] + cleaned[:4]
	// Convert letters to numbers (A=10, B=11, ... Z=35)
	var numStr strings.Builder
	for _, ch := range rearranged {
		if ch >= '0' && ch <= '9' {
			numStr.WriteRune(ch)
		} else if ch >= 'A' && ch <= 'Z' {
			numStr.WriteString(fmt.Sprintf("%d", int(ch-'A'+10)))
		} else {
			return false
		}
	}
	// mod-97 on the large number
	n := new(big.Int)
	n.SetString(numStr.String(), 10)
	mod := new(big.Int)
	mod.Mod(n, big.NewInt(97))
	return mod.Int64() == 1
}

// verhoeffCheck validates using the Verhoeff algorithm (used for Aadhaar).
func verhoeffCheck(number string) bool {
	digits := extractDigits(number)
	if len(digits) == 0 {
		return false
	}

	d := [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	inv := [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}
	p := [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	_ = inv // used in validation

	c := 0
	for i := len(digits) - 1; i >= 0; i-- {
		pos := (len(digits) - 1 - i) % 8
		digit := int(digits[i] - '0')
		c = d[c][p[pos][digit]]
	}
	return c == 0
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// ---------------------------------------------------------------------------
// 1. CreditCardDetector
// ---------------------------------------------------------------------------

type CreditCardDetector struct{}

var reCreditCard = regexp.MustCompile(
	`\b(?:` +
		`4[0-9]{12}(?:[0-9]{3})?` + // Visa
		`|5[1-5][0-9]{14}` + // Mastercard 5xxx
		`|2(?:2[2-9][1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[0-1][0-9]|720)[0-9]{12}` + // Mastercard 2xxx
		`|3[47][0-9]{13}` + // Amex
		`|3(?:0[0-5]|[68][0-9])[0-9]{11}` + // Diners
		`|6(?:011|5[0-9]{2})[0-9]{12}` + // Discover
		`|(?:2131|1800|35\d{3})\d{11}` + // JCB
		`)\b`)

// Also match with common separators (dashes/spaces)
var reCreditCardFormatted = regexp.MustCompile(
	`\b(?:` +
		`4[0-9]{3}[\s\-][0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{4}` + // Visa
		`|5[1-5][0-9]{2}[\s\-][0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{4}` + // Mastercard
		`|3[47][0-9]{2}[\s\-][0-9]{6}[\s\-][0-9]{5}` + // Amex
		`)\b`)

func (d *CreditCardDetector) Name() string { return "credit_card" }

func (d *CreditCardDetector) Detect(text string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	processMatch := func(loc []int) {
		val := text[loc[0]:loc[1]]
		digits := extractDigits(val)
		if seen[digits] {
			return
		}
		seen[digits] = true

		conf := 0.4
		if luhnCheck(digits) {
			conf = 0.95
		}
		findings = append(findings, Finding{
			DetectorName: "credit_card",
			Category:     "financial",
			Type:         "credit_card",
			Value:        val,
			RedactedVal:  redactByType(Finding{Type: "credit_card", Value: val}),
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   conf,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}

	for _, loc := range reCreditCard.FindAllStringIndex(text, -1) {
		processMatch(loc)
	}
	for _, loc := range reCreditCardFormatted.FindAllStringIndex(text, -1) {
		processMatch(loc)
	}
	return findings
}

// ---------------------------------------------------------------------------
// 2. SSNDetector
// ---------------------------------------------------------------------------

type SSNDetector struct{}

var (
	reSSNDashed = regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)
	reSSNSpaced = regexp.MustCompile(`\b(\d{3})\s(\d{2})\s(\d{4})\b`)
	reSSNBare   = regexp.MustCompile(`(?i)(?:ssn|social\s*security|tax\s*id)\s*[:=#]?\s*(\d{9})\b`)
)

func (d *SSNDetector) Name() string { return "ssn" }

func (d *SSNDetector) Detect(text string) []Finding {
	var findings []Finding

	validateSSN := func(area, group, serial string) bool {
		a := atoiSimple(area)
		g := atoiSimple(group)
		s := atoiSimple(serial)
		if a == 0 || a == 666 || a >= 900 {
			return false
		}
		if g == 0 || s == 0 {
			return false
		}
		return true
	}

	// Dashed format: XXX-XX-XXXX
	for _, match := range reSSNDashed.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		area := text[match[2]:match[3]]
		group := text[match[4]:match[5]]
		serial := text[match[6]:match[7]]
		conf := 0.5
		if validateSSN(area, group, serial) {
			conf = 0.9
		}
		findings = append(findings, Finding{
			DetectorName: "ssn",
			Category:     "pii",
			Type:         "ssn",
			Value:        full,
			RedactedVal:  "***-**-" + serial,
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   conf,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// Spaced format: XXX XX XXXX
	for _, match := range reSSNSpaced.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		area := text[match[2]:match[3]]
		group := text[match[4]:match[5]]
		serial := text[match[6]:match[7]]
		conf := 0.5
		if validateSSN(area, group, serial) {
			conf = 0.85
		}
		findings = append(findings, Finding{
			DetectorName: "ssn",
			Category:     "pii",
			Type:         "ssn",
			Value:        full,
			RedactedVal:  "***-**-" + serial,
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   conf,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// Bare 9-digit near keyword
	for _, match := range reSSNBare.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		digits := text[match[2]:match[3]]
		area := digits[:3]
		group := digits[3:5]
		serial := digits[5:]
		conf := 0.4
		if validateSSN(area, group, serial) {
			conf = 0.6
		}
		findings = append(findings, Finding{
			DetectorName: "ssn",
			Category:     "pii",
			Type:         "ssn",
			Value:        full,
			RedactedVal:  "***-**-" + serial,
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   conf,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	return findings
}

func atoiSimple(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// ---------------------------------------------------------------------------
// 3. EmailDetector
// ---------------------------------------------------------------------------

type EmailDetector struct{}

// RFC 5322 compliant email regex with proper TLD validation.
var reEmail = regexp.MustCompile(`[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,63}`)

func (d *EmailDetector) Name() string { return "email" }

func (d *EmailDetector) Detect(text string) []Finding {
	var findings []Finding
	for _, loc := range reEmail.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		// Validate TLD is not numeric-only
		parts := strings.Split(val, ".")
		tld := parts[len(parts)-1]
		isNumericTLD := true
		for _, r := range tld {
			if !unicode.IsDigit(r) {
				isNumericTLD = false
				break
			}
		}
		if isNumericTLD {
			continue
		}
		if len(tld) < 2 || len(tld) > 63 {
			continue
		}
		findings = append(findings, Finding{
			DetectorName: "email",
			Category:     "pii",
			Type:         "email",
			Value:        val,
			RedactedVal:  redactByType(Finding{Type: "email", Value: val}),
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   0.95,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// 4. PhoneDetector
// ---------------------------------------------------------------------------

type PhoneDetector struct{}

var (
	rePhoneUS     = regexp.MustCompile(`(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?[2-9]\d{2}[\s.\-]?\d{4}\b`)
	rePhoneUK     = regexp.MustCompile(`\+44\s?\d{4}\s?\d{6}`)
	rePhoneIntl   = regexp.MustCompile(`\+[1-9]\d{0,2}[\s.\-]?\d[\d\s.\-]{6,13}\d`)
	rePhoneE164   = regexp.MustCompile(`\+[1-9]\d{6,14}\b`)
)

func (d *PhoneDetector) Name() string { return "phone" }

func (d *PhoneDetector) Detect(text string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	addFinding := func(loc []int, conf float64) {
		val := text[loc[0]:loc[1]]
		digits := extractDigits(val)
		if seen[digits] {
			return
		}
		if len(digits) < 7 {
			return
		}
		seen[digits] = true
		findings = append(findings, Finding{
			DetectorName: "phone",
			Category:     "pii",
			Type:         "phone",
			Value:        val,
			RedactedVal:  redactByType(Finding{Type: "phone", Value: val}),
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   conf,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}

	for _, loc := range rePhoneUS.FindAllStringIndex(text, -1) {
		addFinding(loc, 0.85)
	}
	for _, loc := range rePhoneUK.FindAllStringIndex(text, -1) {
		addFinding(loc, 0.85)
	}
	for _, loc := range rePhoneIntl.FindAllStringIndex(text, -1) {
		addFinding(loc, 0.80)
	}
	for _, loc := range rePhoneE164.FindAllStringIndex(text, -1) {
		digits := extractDigits(text[loc[0]:loc[1]])
		if len(digits) >= 10 && len(digits) <= 15 {
			addFinding(loc, 0.85)
		} else if len(digits) >= 7 {
			addFinding(loc, 0.5)
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// 5. NameDetector
// ---------------------------------------------------------------------------

type NameDetector struct{}

var (
	reNameLabel  = regexp.MustCompile(`(?i)(?:name|patient|customer|user|employee|applicant|contact|recipient|client)\s*[:]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)`)
	reNameTitle  = regexp.MustCompile(`(?:Dr|Mr|Mrs|Ms|Prof|Rev|Sir|Dame|Lord|Lady)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+`)
)

func (d *NameDetector) Name() string { return "name" }

func (d *NameDetector) Detect(text string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, match := range reNameLabel.FindAllStringSubmatchIndex(text, -1) {
		nameVal := text[match[2]:match[3]]
		if seen[nameVal] {
			continue
		}
		seen[nameVal] = true
		findings = append(findings, Finding{
			DetectorName: "name",
			Category:     "pii",
			Type:         "name",
			Value:        nameVal,
			RedactedVal:  "[NAME REDACTED]",
			StartPos:     match[2],
			EndPos:       match[3],
			Confidence:   0.7,
			Context:      extractContext(text, match[2], match[3]),
		})
	}
	for _, loc := range reNameTitle.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		if seen[val] {
			continue
		}
		seen[val] = true
		findings = append(findings, Finding{
			DetectorName: "name",
			Category:     "pii",
			Type:         "name",
			Value:        val,
			RedactedVal:  "[NAME REDACTED]",
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   0.7,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// 6. AddressDetector
// ---------------------------------------------------------------------------

type AddressDetector struct{}

var (
	reUSAddress = regexp.MustCompile(`\d+\s+[A-Z][a-z]+(?:\s+[A-Z]?[a-z]+)*\s+(?:St|Ave|Blvd|Dr|Rd|Ln|Ct|Way|Pl|Cir|Ter|Pkwy|Hwy)\.?,?\s+[A-Z][a-z]+(?:\s+[A-Z]?[a-z]+)*,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?`)
	reUKPostcode = regexp.MustCompile(`\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b`)
)

func (d *AddressDetector) Name() string { return "address" }

func (d *AddressDetector) Detect(text string) []Finding {
	var findings []Finding
	for _, loc := range reUSAddress.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		findings = append(findings, Finding{
			DetectorName: "address",
			Category:     "pii",
			Type:         "address",
			Value:        val,
			RedactedVal:  "[ADDRESS REDACTED]",
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   0.85,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}
	for _, loc := range reUKPostcode.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		findings = append(findings, Finding{
			DetectorName: "address",
			Category:     "pii",
			Type:         "uk_postcode",
			Value:        val,
			RedactedVal:  "[ADDRESS REDACTED]",
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   0.85,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// 7. HealthDataDetector
// ---------------------------------------------------------------------------

type HealthDataDetector struct{}

var (
	reMRN      = regexp.MustCompile(`(?i)(?:mrn|medical\s*record|patient\s*(?:id|number))\s*[:=#]?\s*(\d{6,10})\b`)
	reICDCode  = regexp.MustCompile(`(?i)(?:icd|diagnosis|dx)\s*[:=#]?\s*([A-Z]\d{2}(?:\.\d{1,2})?)`)
	reHealthDOB = regexp.MustCompile(`(?i)(?:dob|date\s*of\s*birth|born\s*on)\s*[:=#]?\s*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})`)
)

// Top-200 prescription drug names (partial list for detection).
var commonDrugNames = map[string]bool{
	"lisinopril": true, "atorvastatin": true, "metformin": true, "amlodipine": true,
	"metoprolol": true, "omeprazole": true, "simvastatin": true, "losartan": true,
	"albuterol": true, "gabapentin": true, "hydrochlorothiazide": true, "sertraline": true,
	"acetaminophen": true, "amoxicillin": true, "pantoprazole": true, "furosemide": true,
	"atenolol": true, "prednisone": true, "levothyroxine": true, "fluticasone": true,
	"pravastatin": true, "citalopram": true, "trazodone": true, "montelukast": true,
	"rosuvastatin": true, "carvedilol": true, "tramadol": true, "meloxicam": true,
	"escitalopram": true, "fluoxetine": true, "bupropion": true, "duloxetine": true,
	"venlafaxine": true, "alprazolam": true, "clonazepam": true, "lorazepam": true,
	"diazepam": true, "zolpidem": true, "cyclobenzaprine": true, "naproxen": true,
	"ibuprofen": true, "celecoxib": true, "pregabalin": true, "oxycodone": true,
	"hydrocodone": true, "morphine": true, "fentanyl": true, "warfarin": true,
	"clopidogrel": true, "apixaban": true, "rivaroxaban": true, "enoxaparin": true,
	"insulin": true, "glipizide": true, "pioglitazone": true, "sitagliptin": true,
	"empagliflozin": true, "dapagliflozin": true, "liraglutide": true, "semaglutide": true,
	"doxycycline": true, "azithromycin": true, "ciprofloxacin": true, "levofloxacin": true,
	"cephalexin": true, "clindamycin": true, "sulfamethoxazole": true, "trimethoprim": true,
	"metronidazole": true, "nitrofurantoin": true, "fluconazole": true, "acyclovir": true,
	"valacyclovir": true, "tamsulosin": true, "finasteride": true, "sildenafil": true,
	"tadalafil": true, "testosterone": true, "estradiol": true, "progesterone": true,
	"norethindrone": true, "spironolactone": true, "liothyronine": true, "methimazole": true,
	"propylthiouracil": true, "prochlorperazine": true, "ondansetron": true, "promethazine": true,
	"diphenhydramine": true, "hydroxyzine": true, "cetirizine": true, "loratadine": true,
	"fexofenadine": true, "ranitidine": true, "famotidine": true, "sucralfate": true,
	"docusate": true, "polyethylene": true, "lactulose": true, "bisacodyl": true,
	"loperamide": true, "lithium": true, "lamotrigine": true, "valproic": true,
	"carbamazepine": true, "topiramate": true, "levetiracetam": true, "phenytoin": true,
	"quetiapine": true, "risperidone": true, "olanzapine": true, "aripiprazole": true,
	"haloperidol": true, "clozapine": true, "methylphenidate": true, "amphetamine": true,
	"atomoxetine": true, "clonidine": true, "guanfacine": true, "sumatriptan": true,
	"rizatriptan": true, "baclofen": true, "tizanidine": true, "methocarbamol": true,
	"carisoprodol": true, "benzonatate": true, "dextromethorphan": true, "guaifenesin": true,
}

func (d *HealthDataDetector) Name() string { return "health_data" }

func (d *HealthDataDetector) Detect(text string) []Finding {
	var findings []Finding

	// MRN detection
	for _, match := range reMRN.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		findings = append(findings, Finding{
			DetectorName: "health_data",
			Category:     "health",
			Type:         "mrn",
			Value:        full,
			RedactedVal:  "[HEALTH DATA REDACTED]",
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   0.75,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// ICD code detection
	for _, match := range reICDCode.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		findings = append(findings, Finding{
			DetectorName: "health_data",
			Category:     "health",
			Type:         "icd_code",
			Value:        full,
			RedactedVal:  "[HEALTH DATA REDACTED]",
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   0.75,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// DOB near health context
	for _, match := range reHealthDOB.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		findings = append(findings, Finding{
			DetectorName: "health_data",
			Category:     "health",
			Type:         "health_dob",
			Value:        full,
			RedactedVal:  "[HEALTH DATA REDACTED]",
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   0.75,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// Drug name detection using word boundary scanning
	lower := strings.ToLower(text)
	words := regexp.MustCompile(`\b[a-z]{4,}\b`)
	for _, loc := range words.FindAllStringIndex(lower, -1) {
		word := lower[loc[0]:loc[1]]
		if commonDrugNames[word] {
			findings = append(findings, Finding{
				DetectorName: "health_data",
				Category:     "health",
				Type:         "drug_name",
				Value:        text[loc[0]:loc[1]],
				RedactedVal:  "[HEALTH DATA REDACTED]",
				StartPos:     loc[0],
				EndPos:       loc[1],
				Confidence:   0.75,
				Context:      extractContext(text, loc[0], loc[1]),
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// 8. FinancialDetector
// ---------------------------------------------------------------------------

type FinancialDetector struct{}

var (
	reBankAccount  = regexp.MustCompile(`(?i)(?:account|acct)\s*(?:number|no|#|num)?\s*[:=#]?\s*(\d{8,17})\b`)
	reRoutingNum   = regexp.MustCompile(`(?i)(?:routing|aba|transit)\s*(?:number|no|#|num)?\s*[:=#]?\s*(\d{9})\b`)
	reIBAN         = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`)
	reSWIFT        = regexp.MustCompile(`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`)
)

func (d *FinancialDetector) Name() string { return "financial" }

func (d *FinancialDetector) Detect(text string) []Finding {
	var findings []Finding

	// Bank account numbers
	for _, match := range reBankAccount.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		findings = append(findings, Finding{
			DetectorName: "financial",
			Category:     "financial",
			Type:         "bank_account",
			Value:        full,
			RedactedVal:  "[FINANCIAL REDACTED]",
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   0.85,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// Routing numbers with ABA checksum
	for _, match := range reRoutingNum.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		digits := text[match[2]:match[3]]
		conf := 0.5
		if abaChecksum(digits) {
			conf = 0.9
		}
		findings = append(findings, Finding{
			DetectorName: "financial",
			Category:     "financial",
			Type:         "routing_number",
			Value:        full,
			RedactedVal:  "[FINANCIAL REDACTED]",
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   conf,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// IBAN with mod-97 validation
	for _, loc := range reIBAN.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		// IBAN must start with two letters and two digits
		if len(val) < 5 {
			continue
		}
		if val[0] < 'A' || val[0] > 'Z' || val[1] < 'A' || val[1] > 'Z' {
			continue
		}
		if val[2] < '0' || val[2] > '9' || val[3] < '0' || val[3] > '9' {
			continue
		}
		conf := 0.5
		if ibanValidate(val) {
			conf = 0.9
		}
		findings = append(findings, Finding{
			DetectorName: "financial",
			Category:     "financial",
			Type:         "iban",
			Value:        val,
			RedactedVal:  "[FINANCIAL REDACTED]",
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   conf,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}

	// SWIFT/BIC codes - require financial context to reduce false positives
	swiftContext := regexp.MustCompile(`(?i)(?:swift|bic|bank|transfer|wire)`)
	if swiftContext.MatchString(text) {
		for _, loc := range reSWIFT.FindAllStringIndex(text, -1) {
			val := text[loc[0]:loc[1]]
			if len(val) != 8 && len(val) != 11 {
				continue
			}
			findings = append(findings, Finding{
				DetectorName: "financial",
				Category:     "financial",
				Type:         "swift_bic",
				Value:        val,
				RedactedVal:  "[FINANCIAL REDACTED]",
				StartPos:     loc[0],
				EndPos:       loc[1],
				Confidence:   0.8,
				Context:      extractContext(text, loc[0], loc[1]),
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// 9. CredentialDetector
// ---------------------------------------------------------------------------

type CredentialDetector struct{}

var (
	reAWSKey       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reAWSSecret    = regexp.MustCompile(`(?i)(?:aws_secret|secret_access_key)\s*[:=]\s*[A-Za-z0-9/+=]{40}`)
	reGCPKey       = regexp.MustCompile(`"private_key"\s*:\s*"-----BEGIN`)
	reAzureConn    = regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`)
	reGitHubPAT    = regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)
	reGitLabPAT    = regexp.MustCompile(`\bglpat-[A-Za-z0-9\-]{20,}\b`)
	reSlackToken   = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`)
	rePrivateKey   = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)
	rePrivateKeyHdr = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)
	reJWT          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	rePassword     = regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*(\S{6,})`)
	reConnString   = regexp.MustCompile(`(?:postgres|mysql|mongodb|redis|amqp|postgresql)://[^\s"']+`)
)

func (d *CredentialDetector) Name() string { return "credential" }

func (d *CredentialDetector) Detect(text string) []Finding {
	var findings []Finding

	addCred := func(loc []int, typ string, conf float64) {
		val := text[loc[0]:loc[1]]
		findings = append(findings, Finding{
			DetectorName: "credential",
			Category:     "credential",
			Type:         typ,
			Value:        val,
			RedactedVal:  "[CREDENTIAL REDACTED]",
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   conf,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}

	for _, loc := range reAWSKey.FindAllStringIndex(text, -1) {
		addCred(loc, "aws_key", 0.95)
	}
	for _, loc := range reAWSSecret.FindAllStringIndex(text, -1) {
		addCred(loc, "aws_key", 0.95)
	}
	for _, loc := range reGCPKey.FindAllStringIndex(text, -1) {
		addCred(loc, "gcp_key", 0.95)
	}
	for _, loc := range reAzureConn.FindAllStringIndex(text, -1) {
		addCred(loc, "azure_connection", 0.95)
	}
	for _, loc := range reGitHubPAT.FindAllStringIndex(text, -1) {
		addCred(loc, "github_pat", 0.95)
	}
	for _, loc := range reGitLabPAT.FindAllStringIndex(text, -1) {
		addCred(loc, "gitlab_pat", 0.95)
	}
	for _, loc := range reSlackToken.FindAllStringIndex(text, -1) {
		addCred(loc, "slack_token", 0.95)
	}

	// Full private key block detection
	for _, loc := range rePrivateKey.FindAllStringIndex(text, -1) {
		addCred(loc, "private_key", 0.95)
	}
	// Header-only fallback (if full block not found)
	if len(rePrivateKey.FindAllStringIndex(text, -1)) == 0 {
		for _, loc := range rePrivateKeyHdr.FindAllStringIndex(text, -1) {
			addCred(loc, "private_key", 0.9)
		}
	}

	// JWT validation: 3 base64url segments
	for _, loc := range reJWT.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		parts := strings.Split(val, ".")
		if len(parts) == 3 && len(parts[0]) > 2 && len(parts[1]) > 2 && len(parts[2]) > 2 {
			addCred(loc, "jwt", 0.95)
		}
	}

	// Password assignments
	for _, loc := range rePassword.FindAllStringIndex(text, -1) {
		addCred(loc, "password", 0.90)
	}

	// Connection strings
	for _, loc := range reConnString.FindAllStringIndex(text, -1) {
		addCred(loc, "connection_string", 0.95)
	}

	// High-entropy string detection (Shannon entropy > 4.5 on strings > 20 chars)
	reHighEntropy := regexp.MustCompile(`(?i)(?:key|token|secret|password|credential|auth)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?`)
	for _, match := range reHighEntropy.FindAllStringSubmatchIndex(text, -1) {
		if match[2] < 0 || match[3] < 0 {
			continue
		}
		candidate := text[match[2]:match[3]]
		entropy := shannonEntropy(candidate)
		if entropy > 4.5 {
			findings = append(findings, Finding{
				DetectorName: "credential",
				Category:     "credential",
				Type:         "high_entropy",
				Value:        text[match[0]:match[1]],
				RedactedVal:  "[CREDENTIAL REDACTED]",
				StartPos:     match[0],
				EndPos:       match[1],
				Confidence:   0.6,
				Context:      extractContext(text, match[0], match[1]),
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// 10. GovernmentIDDetector
// ---------------------------------------------------------------------------

type GovernmentIDDetector struct{}

var (
	reUSPassport   = regexp.MustCompile(`(?i)(?:passport)\s*(?:number|no|#|num)?\s*[:=#]?\s*([A-Z0-9]{9})\b`)
	reUKNI         = regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b`)
	reCanadianSIN  = regexp.MustCompile(`(?i)(?:sin|social\s*insurance)\s*[:=#]?\s*(\d{3}[\s\-]?\d{3}[\s\-]?\d{3})\b`)
	reAadhaar      = regexp.MustCompile(`(?i)(?:aadhaar|aadhar|uid)\s*[:=#]?\s*(\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b`)
)

func (d *GovernmentIDDetector) Name() string { return "government_id" }

func (d *GovernmentIDDetector) Detect(text string) []Finding {
	var findings []Finding

	// US Passport
	for _, match := range reUSPassport.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		findings = append(findings, Finding{
			DetectorName: "government_id",
			Category:     "pii",
			Type:         "us_passport",
			Value:        full,
			RedactedVal:  "[GOV ID REDACTED]",
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   0.85,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// UK National Insurance number
	for _, loc := range reUKNI.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		findings = append(findings, Finding{
			DetectorName: "government_id",
			Category:     "pii",
			Type:         "uk_ni",
			Value:        val,
			RedactedVal:  "[GOV ID REDACTED]",
			StartPos:     loc[0],
			EndPos:       loc[1],
			Confidence:   0.85,
			Context:      extractContext(text, loc[0], loc[1]),
		})
	}

	// Canadian SIN with Luhn validation
	for _, match := range reCanadianSIN.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		sinDigits := extractDigits(text[match[2]:match[3]])
		conf := 0.5
		if len(sinDigits) == 9 && luhnCheck(sinDigits) {
			conf = 0.85
		}
		findings = append(findings, Finding{
			DetectorName: "government_id",
			Category:     "pii",
			Type:         "canadian_sin",
			Value:        full,
			RedactedVal:  "[GOV ID REDACTED]",
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   conf,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	// Indian Aadhaar with Verhoeff validation
	for _, match := range reAadhaar.FindAllStringSubmatchIndex(text, -1) {
		full := text[match[0]:match[1]]
		digits := extractDigits(text[match[2]:match[3]])
		conf := 0.5
		if len(digits) == 12 && verhoeffCheck(digits) {
			conf = 0.85
		}
		findings = append(findings, Finding{
			DetectorName: "government_id",
			Category:     "pii",
			Type:         "aadhaar",
			Value:        full,
			RedactedVal:  "[GOV ID REDACTED]",
			StartPos:     match[0],
			EndPos:       match[1],
			Confidence:   conf,
			Context:      extractContext(text, match[0], match[1]),
		})
	}

	return findings
}
