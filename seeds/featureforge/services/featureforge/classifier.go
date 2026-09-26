package featureforge

import (
	"regexp"
	"strings"
)

// keywordClassifier is a deterministic stand-in for the LLM classifier.
//
// WHY DETERMINISTIC IN THE PROTOTYPE: in a KMS you want reproducible,
// testable guardrail behavior. The real implementation swaps this for an LLM
// call constrained to emit JSON matching the catalog schema (structured
// outputs / tool use), but the surrounding pipeline — validation, policy,
// dry-run, governance, audit — is identical and is what actually keeps the
// system safe. The classifier is treated as UNTRUSTED: nothing it returns is
// acted on until every downstream guardrail passes.
type keywordClassifier struct{}

// NewKeywordClassifier returns the deterministic classifier.
func NewKeywordClassifier() Classifier { return keywordClassifier{} }

var (
	reRSABits   = regexp.MustCompile(`(?i)rsa[-\s]?(\d{3,4})`)
	reMinBits   = regexp.MustCompile(`(\d{3,5})\s*(?:bit|bits)`)
	reInterface = regexp.MustCompile(`(?i)\b(rest|kmip|ekm|payment)\b`)
)

func (keywordClassifier) Classify(raw string, catalog []CatalogAction) (Mode, string, map[string]interface{}, float64, error) {
	text := strings.ToLower(strings.TrimSpace(raw))
	params := map[string]interface{}{}

	// --- Scaffold mode: explicit signals that this is a code feature. ---
	if strings.Contains(text, "endpoint") || strings.Contains(text, "service") ||
		strings.Contains(text, "api ") || strings.Contains(text, "implement ") ||
		strings.Contains(text, "build a ") || strings.Contains(text, "add support for") {
		return ModeScaffold, "", params, 0.7, nil
	}

	// --- Config mode: map to a catalog action. ---
	switch {
	case strings.Contains(text, "block") || strings.Contains(text, "disallow") || strings.Contains(text, "restrict"):
		if m := reRSABits.FindStringSubmatch(text); m != nil {
			params["algorithm"] = "RSA-" + m[1]
			return ModeConfig, "policy.restrict_algorithm", params, 0.92, nil
		}
		// generic "block X" with no recognized algorithm => low confidence.
		return ModeConfig, "policy.restrict_algorithm", params, 0.4, nil

	case strings.Contains(text, "require approval") || strings.Contains(text, "needs approval"):
		switch {
		case strings.Contains(text, "delet"):
			params["operation"] = "key.delete"
		case strings.Contains(text, "export"):
			params["operation"] = "key.export"
		}
		return ModeConfig, "policy.require_approval_for", params, 0.85, nil

	case strings.Contains(text, "minimum") || strings.Contains(text, "min key") || strings.Contains(text, "key size"):
		if strings.Contains(text, "rsa") {
			params["key_type"] = "RSA"
		} else if strings.Contains(text, "ec") || strings.Contains(text, "elliptic") {
			params["key_type"] = "EC"
		}
		if m := reMinBits.FindStringSubmatch(text); m != nil {
			params["min_bits"] = m[1]
		}
		return ModeConfig, "policy.set_min_key_size", params, 0.8, nil

	case (strings.Contains(text, "hybrid") || strings.Contains(text, "pqc") || strings.Contains(text, "post-quantum")) &&
		strings.Contains(text, "enable"):
		if m := reInterface.FindStringSubmatch(text); m != nil {
			params["interface"] = strings.ToLower(m[1])
		}
		return ModeConfig, "pqc.enable_hybrid", params, 0.83, nil
	}

	// Unrecognized: deliberately low confidence so the validation layer rejects it.
	return ModeConfig, "", params, 0.0, nil
}
