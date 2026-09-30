package main

import (
	"log"
	"regexp"
	"strings"
)

// InjectionPattern defines a single detection pattern with its category and score.
type InjectionPattern struct {
	Category string
	Name     string
	Pattern  *regexp.Regexp
	Score    float64
}

// InjectionResult holds the outcome of prompt injection analysis.
type InjectionResult struct {
	Score    float64  `json:"score"`    // 0.0-1.0 (0=safe, 1=definitely injection)
	Category string   `json:"category"` // highest-scoring category
	Details  []string `json:"details"`  // specific patterns matched
	Blocked  bool     `json:"blocked"`  // score > threshold
}

// InjectionDetector scans text for prompt injection attacks across multiple categories.
type InjectionDetector struct {
	patterns  []InjectionPattern
	threshold float64
	logger    *log.Logger
}

// NewInjectionDetector creates a detector with all built-in attack patterns.
func NewInjectionDetector(threshold float64, logger *log.Logger) *InjectionDetector {
	if threshold <= 0 {
		threshold = 0.5
	}
	if logger == nil {
		logger = log.Default()
	}

	d := &InjectionDetector{
		threshold: threshold,
		logger:    logger,
	}
	d.patterns = d.buildPatterns()
	return d
}

func (d *InjectionDetector) buildPatterns() []InjectionPattern {
	ci := "(?i)" // case-insensitive prefix

	return []InjectionPattern{
		// ── Jailbreak Attempts (0.7-0.9) ──
		{Category: "jailbreak", Name: "ignore_previous_instructions", Pattern: regexp.MustCompile(ci + `ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions`), Score: 0.85},
		{Category: "jailbreak", Name: "disregard_instructions", Pattern: regexp.MustCompile(ci + `disregard\s+(your|all|any)\s+instructions`), Score: 0.85},
		{Category: "jailbreak", Name: "DAN_mode", Pattern: regexp.MustCompile(ci + `you\s+are\s+now\s+DAN|do\s+anything\s+now`), Score: 0.9},
		{Category: "jailbreak", Name: "pretend_act_as", Pattern: regexp.MustCompile(ci + `(pretend|act\s+as\s+if)\s+you\s+are`), Score: 0.7},
		{Category: "jailbreak", Name: "from_now_on", Pattern: regexp.MustCompile(ci + `from\s+now\s+on\s+you\s+will|you\s+must\s+now`), Score: 0.7},
		{Category: "jailbreak", Name: "forget_everything", Pattern: regexp.MustCompile(ci + `forget\s+(everything|all|your\s+training|your\s+previous)`), Score: 0.8},
		{Category: "jailbreak", Name: "bypass_safety", Pattern: regexp.MustCompile(ci + `bypass\s+(your\s+)?safety|override\s+(your\s+)?restrictions`), Score: 0.85},
		{Category: "jailbreak", Name: "unrestricted_ai", Pattern: regexp.MustCompile(ci + `you\s+are\s+an?\s+unrestricted\s+(AI|model|assistant)`), Score: 0.9},
		{Category: "jailbreak", Name: "developer_mode", Pattern: regexp.MustCompile(ci + `(developer|maintenance|debug|god)\s+mode`), Score: 0.8},
		{Category: "jailbreak", Name: "roleplay_evil", Pattern: regexp.MustCompile(ci + `(pretend|act|role\s*play)\s+(as\s+)?(an?\s+)?(evil|malicious|unfiltered|uncensored)`), Score: 0.8},

		// ── System Prompt Extraction (0.8-0.95) ──
		{Category: "system_prompt_leak", Name: "repeat_system_prompt", Pattern: regexp.MustCompile(ci + `repeat\s+(your\s+)?system\s+prompt`), Score: 0.9},
		{Category: "system_prompt_leak", Name: "what_are_instructions", Pattern: regexp.MustCompile(ci + `what\s+are\s+your\s+instructions`), Score: 0.8},
		{Category: "system_prompt_leak", Name: "show_initial_prompt", Pattern: regexp.MustCompile(ci + `show\s+(me\s+)?(your\s+)?(initial|original|first)\s+prompt`), Score: 0.9},
		{Category: "system_prompt_leak", Name: "print_system_message", Pattern: regexp.MustCompile(ci + `print\s+(your\s+)?system\s+message`), Score: 0.9},
		{Category: "system_prompt_leak", Name: "output_configuration", Pattern: regexp.MustCompile(ci + `output\s+(your\s+)?configuration`), Score: 0.85},
		{Category: "system_prompt_leak", Name: "what_told_to_do", Pattern: regexp.MustCompile(ci + `what\s+were\s+you\s+told\s+to\s+do`), Score: 0.8},
		{Category: "system_prompt_leak", Name: "reveal_hidden_instructions", Pattern: regexp.MustCompile(ci + `reveal\s+(your\s+)?(hidden|secret)\s+instructions`), Score: 0.95},
		{Category: "system_prompt_leak", Name: "display_rules", Pattern: regexp.MustCompile(ci + `(display|list|enumerate)\s+(your\s+)?(rules|guidelines|constraints|system\s+prompt)`), Score: 0.85},

		// ── Indirect Injection (0.6-0.8) ──
		{Category: "indirect_injection", Name: "markdown_image_injection", Pattern: regexp.MustCompile(`!\[.*?\]\(https?://`), Score: 0.6},
		{Category: "indirect_injection", Name: "html_script_tag", Pattern: regexp.MustCompile(ci + `<script[\s>]`), Score: 0.8},
		{Category: "indirect_injection", Name: "html_img_tag", Pattern: regexp.MustCompile(ci + `<img\s+src\s*=`), Score: 0.7},
		{Category: "indirect_injection", Name: "html_iframe_tag", Pattern: regexp.MustCompile(ci + `<iframe[\s>]`), Score: 0.75},
		{Category: "indirect_injection", Name: "js_fetch", Pattern: regexp.MustCompile(ci + `fetch\s*\(`), Score: 0.7},
		{Category: "indirect_injection", Name: "js_xmlhttprequest", Pattern: regexp.MustCompile(ci + `XMLHttpRequest`), Score: 0.7},
		{Category: "indirect_injection", Name: "js_sendbeacon", Pattern: regexp.MustCompile(ci + `navigator\.sendBeacon`), Score: 0.8},
		{Category: "indirect_injection", Name: "inst_markers", Pattern: regexp.MustCompile(`\[INST\]|\[/INST\]`), Score: 0.75},
		{Category: "indirect_injection", Name: "sys_tags", Pattern: regexp.MustCompile(`<<SYS>>|<</SYS>>`), Score: 0.75},
		{Category: "indirect_injection", Name: "html_event_handler", Pattern: regexp.MustCompile(ci + `on(load|error|click|mouseover)\s*=`), Score: 0.7},

		// ── Encoding Attacks (0.7-0.9) ──
		{Category: "encoding_attack", Name: "base64_decode_instruction", Pattern: regexp.MustCompile(ci + `base64[:\s]|decode\s+this\s+(base64|string)`), Score: 0.7},
		{Category: "encoding_attack", Name: "long_base64_string", Pattern: regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`), Score: 0.3}, // low individual score, needs context
		{Category: "encoding_attack", Name: "rot13_hint", Pattern: regexp.MustCompile(ci + `rot13|rot-13|caesar\s+cipher`), Score: 0.7},
		{Category: "encoding_attack", Name: "hex_payload", Pattern: regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){4,}`), Score: 0.8},
		{Category: "encoding_attack", Name: "zero_width_chars", Pattern: regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{2060}]{2,}`), Score: 0.85},
		{Category: "encoding_attack", Name: "unicode_homoglyphs", Pattern: regexp.MustCompile(`[\x{0400}-\x{04FF}\x{0370}-\x{03FF}]`), Score: 0.3}, // combined with Latin context
		{Category: "encoding_attack", Name: "unicode_escape_sequences", Pattern: regexp.MustCompile(`(\\u[0-9a-fA-F]{4}){3,}`), Score: 0.75},

		// ── Delimiter Injection (0.6-0.8) ──
		{Category: "delimiter_injection", Name: "xml_system_close", Pattern: regexp.MustCompile(ci + `</(system|assistant|user|human|instructions)>`), Score: 0.8},
		{Category: "delimiter_injection", Name: "json_role_system", Pattern: regexp.MustCompile(`\{\s*"role"\s*:\s*"system"`), Score: 0.75},
		{Category: "delimiter_injection", Name: "separator_then_instruction", Pattern: regexp.MustCompile(`(---|===|\*\*\*)\s*\n\s*(new|actual|real|ignore|forget|system)`), Score: 0.7},
		{Category: "delimiter_injection", Name: "code_block_escape", Pattern: regexp.MustCompile("```\\s*(system|ignore|forget|new instructions)"), Score: 0.7},
		{Category: "delimiter_injection", Name: "xml_open_tags", Pattern: regexp.MustCompile(ci + `<(system|instructions|prompt|context)\s*>`), Score: 0.7},
	}
}

// Analyze checks text for prompt injection patterns and returns a scored result.
func (d *InjectionDetector) Analyze(text string) InjectionResult {
	result := InjectionResult{
		Score:   0.0,
		Details: []string{},
	}

	if strings.TrimSpace(text) == "" {
		return result
	}

	categoryScores := make(map[string]float64)

	for _, p := range d.patterns {
		matches := p.Pattern.FindAllString(text, -1)
		if len(matches) > 0 {
			// Each additional match of the same pattern adds 20% of the base score
			matchScore := p.Score + float64(len(matches)-1)*p.Score*0.2
			if matchScore > 1.0 {
				matchScore = 1.0
			}

			categoryScores[p.Category] += matchScore

			for _, m := range matches {
				detail := p.Category + ":" + p.Name + " matched \"" + truncate(m, 80) + "\""
				result.Details = append(result.Details, detail)
			}
		}
	}

	// Check for combined encoding attack: base64 string + decode instruction
	if categoryScores["encoding_attack"] > 0 {
		hasBase64String := false
		hasDecodeHint := false
		for _, p := range d.patterns {
			if p.Name == "long_base64_string" && p.Pattern.MatchString(text) {
				hasBase64String = true
			}
			if p.Name == "base64_decode_instruction" && p.Pattern.MatchString(text) {
				hasDecodeHint = true
			}
		}
		if hasBase64String && hasDecodeHint {
			categoryScores["encoding_attack"] += 0.4
			result.Details = append(result.Details, "encoding_attack:combined_base64_decode (base64 string + decode instruction)")
		}
	}

	// Check for homoglyph mixed script attack: Latin + Cyrillic/Greek in same word-like context
	if categoryScores["encoding_attack"] > 0 {
		latinRe := regexp.MustCompile(`[a-zA-Z]`)
		cyrillicGreekRe := regexp.MustCompile(`[\x{0400}-\x{04FF}\x{0370}-\x{03FF}]`)
		if latinRe.MatchString(text) && cyrillicGreekRe.MatchString(text) {
			categoryScores["encoding_attack"] += 0.4
			result.Details = append(result.Details, "encoding_attack:mixed_script_homoglyph (Latin + Cyrillic/Greek chars detected)")
		}
	}

	// Calculate final score: take the max category score, add diminishing contributions from others
	var maxCategory string
	var maxScore float64
	for cat, score := range categoryScores {
		if score > 1.0 {
			score = 1.0
			categoryScores[cat] = 1.0
		}
		if score > maxScore {
			maxScore = score
			maxCategory = cat
		}
	}

	result.Score = maxScore
	// Add 10% of each other category's score (multiple attack vectors are more suspicious)
	for cat, score := range categoryScores {
		if cat != maxCategory {
			result.Score += score * 0.1
		}
	}
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	result.Category = maxCategory
	result.Blocked = result.Score >= d.threshold

	if result.Blocked {
		d.logger.Printf("[injection_detector] BLOCKED score=%.2f category=%s details=%v", result.Score, result.Category, result.Details)
	}

	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
