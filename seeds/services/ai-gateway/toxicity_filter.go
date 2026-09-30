package main

import (
	"regexp"
	"strings"
	"unicode"
)

// ToxicityResult holds the outcome of toxicity analysis.
type ToxicityResult struct {
	Score      float64            `json:"score"`      // 0.0-1.0 overall
	Categories map[string]float64 `json:"categories"` // per-category scores
	Flagged    bool               `json:"flagged"`
	Details    []string           `json:"details"`
}

// toxicityPattern represents a keyword or phrase to detect with severity weight.
type toxicityPattern struct {
	Pattern  *regexp.Regexp
	Severity float64 // 0.0-1.0 per-match severity
	Label    string
}

// ToxicityFilter detects toxic, harmful, or inappropriate content via keyword matching.
type ToxicityFilter struct {
	threshold  float64
	categories map[string][]toxicityPattern
}

// NewToxicityFilter creates a filter with built-in keyword lists per category.
func NewToxicityFilter(threshold float64) *ToxicityFilter {
	if threshold <= 0 {
		threshold = 0.5
	}
	f := &ToxicityFilter{
		threshold:  threshold,
		categories: make(map[string][]toxicityPattern),
	}
	f.buildPatterns()
	return f
}

func (f *ToxicityFilter) buildPatterns() {
	ci := "(?i)"

	// ── Hate Speech ──
	f.categories["hate_speech"] = []toxicityPattern{
		{Pattern: regexp.MustCompile(ci + `\b(racial|ethnic)\s+slur`), Severity: 0.8, Label: "meta_slur_reference"},
		{Pattern: regexp.MustCompile(ci + `\b(white|black|asian|jewish|muslim|christian|hindu)\s+supremac`), Severity: 0.9, Label: "supremacist_ideology"},
		{Pattern: regexp.MustCompile(ci + `\b(subhuman|untermensch|mongrel|savage)\b`), Severity: 0.85, Label: "dehumanizing_language"},
		{Pattern: regexp.MustCompile(ci + `\b(race\s+war|ethnic\s+cleansing|genocide)\b`), Severity: 0.95, Label: "genocidal_language"},
		{Pattern: regexp.MustCompile(ci + `\b(go\s+back\s+to\s+(your|their)\s+(country|continent))\b`), Severity: 0.7, Label: "xenophobic_rhetoric"},
		{Pattern: regexp.MustCompile(ci + `\b(dirty|filthy|disgusting)\s+(jew|muslim|arab|mexican|immigrant|refugee)`), Severity: 0.9, Label: "slur_with_group"},
		{Pattern: regexp.MustCompile(ci + `\b(all|every)\s+(jews?|muslims?|blacks?|whites?|asians?|mexicans?)\s+(are|should)`), Severity: 0.75, Label: "group_generalization"},
		{Pattern: regexp.MustCompile(ci + `\bdeath\s+to\s+(jews?|muslims?|christians?|blacks?|whites?|americans?)`), Severity: 0.95, Label: "death_wish_group"},
		{Pattern: regexp.MustCompile(ci + `\b(neo[- ]?nazi|white\s+power|heil\s+hitler|sieg\s+heil)\b`), Severity: 0.95, Label: "nazi_reference"},
		{Pattern: regexp.MustCompile(ci + `\b(inferior\s+race|master\s+race)\b`), Severity: 0.9, Label: "racial_hierarchy"},
	}

	// ── Harassment ──
	f.categories["harassment"] = []toxicityPattern{
		{Pattern: regexp.MustCompile(ci + `\b(kill\s+yourself|kys)\b`), Severity: 0.95, Label: "suicide_encouragement"},
		{Pattern: regexp.MustCompile(ci + `\b(i('ll|m\s+going\s+to)|we('ll|\s+will))\s+(find|hunt|track)\s+(you|them|her|him)\b`), Severity: 0.85, Label: "stalking_threat"},
		{Pattern: regexp.MustCompile(ci + `\b(you('re|\s+are)\s+(worthless|pathetic|disgusting|garbage|trash|useless))\b`), Severity: 0.7, Label: "personal_attack"},
		{Pattern: regexp.MustCompile(ci + `\b(nobody\s+(loves|likes|cares\s+about)\s+you)\b`), Severity: 0.7, Label: "emotional_abuse"},
		{Pattern: regexp.MustCompile(ci + `\b(i\s+know\s+where\s+you\s+live)\b`), Severity: 0.9, Label: "doxxing_threat"},
		{Pattern: regexp.MustCompile(ci + `\b(swat(ting)?|dox(x)?(ing)?)\b`), Severity: 0.85, Label: "swatting_doxxing"},
		{Pattern: regexp.MustCompile(ci + `\b(shut\s+up|stfu|go\s+die)\b`), Severity: 0.5, Label: "hostile_dismissal"},
		{Pattern: regexp.MustCompile(ci + `\b(you\s+deserve\s+to\s+(die|suffer|be\s+(hurt|killed|raped)))\b`), Severity: 0.95, Label: "deserved_harm"},
		{Pattern: regexp.MustCompile(ci + `\b(i('ll|m\s+gonna)\s+(beat|hurt|destroy|ruin)\s+(you|your))\b`), Severity: 0.8, Label: "physical_threat"},
	}

	// ── Sexual Content ──
	f.categories["sexual_content"] = []toxicityPattern{
		{Pattern: regexp.MustCompile(ci + `\b(explicit\s+sexual|graphic\s+sex(ual)?)\b`), Severity: 0.7, Label: "explicit_sexual"},
		{Pattern: regexp.MustCompile(ci + `\b(sexual\s+(harassment|assault|abuse|violence))\b`), Severity: 0.9, Label: "sexual_violence"},
		{Pattern: regexp.MustCompile(ci + `\b(non[- ]?consensual|without\s+consent)\b`), Severity: 0.85, Label: "non_consensual"},
		{Pattern: regexp.MustCompile(ci + `\b(child\s+(porn(ography)?|sexual|exploitation|abuse))\b`), Severity: 0.99, Label: "csam"},
		{Pattern: regexp.MustCompile(ci + `\b(revenge\s+porn|intimate\s+image)\b`), Severity: 0.85, Label: "revenge_porn"},
		{Pattern: regexp.MustCompile(ci + `\b(sex(ual)?\s+with\s+(minor|child|kid|underage))\b`), Severity: 0.99, Label: "minor_sexual"},
		{Pattern: regexp.MustCompile(ci + `\b(groping|fondling|molest(ing|ation)?)\b`), Severity: 0.85, Label: "molestation"},
		{Pattern: regexp.MustCompile(ci + `\b(send\s+(me\s+)?nudes|dick\s+pic)\b`), Severity: 0.7, Label: "solicitation"},
	}

	// ── Violence ──
	f.categories["violence"] = []toxicityPattern{
		{Pattern: regexp.MustCompile(ci + `\b(i('ll|m\s+going\s+to)\s+kill\s+(you|them|him|her|everyone))\b`), Severity: 0.95, Label: "death_threat"},
		{Pattern: regexp.MustCompile(ci + `\b(mass\s+(shooting|murder|killing)|school\s+shooting)\b`), Severity: 0.95, Label: "mass_violence"},
		{Pattern: regexp.MustCompile(ci + `\b(bomb\s+threat|plant\s+a\s+bomb)\b`), Severity: 0.95, Label: "bomb_threat"},
		{Pattern: regexp.MustCompile(ci + `\b(dismember|decapitat|mutilat|disembowel|torture)\b`), Severity: 0.85, Label: "graphic_violence"},
		{Pattern: regexp.MustCompile(ci + `\b(stab|shoot|slash|bludgeon)\s+(you|them|him|her)\b`), Severity: 0.8, Label: "violence_threat"},
		{Pattern: regexp.MustCompile(ci + `\b(burn\s+(them|you|him|her)\s+alive)\b`), Severity: 0.9, Label: "extreme_violence"},
		{Pattern: regexp.MustCompile(ci + `\b(blood(y)?\s+(everywhere|all\s+over)|pool\s+of\s+blood)\b`), Severity: 0.6, Label: "graphic_description"},
		{Pattern: regexp.MustCompile(ci + `\b(hit\s+list|kill\s+list|target\s+list)\b`), Severity: 0.9, Label: "kill_list"},
		{Pattern: regexp.MustCompile(ci + `\b(terrorist|terrorism|jihad(ist)?|martyr\s+operation)\b`), Severity: 0.75, Label: "terrorism"},
	}

	// ── Discrimination ──
	f.categories["discrimination"] = []toxicityPattern{
		{Pattern: regexp.MustCompile(ci + `\b(women|females?)\s+(shouldn't|can't|don't|are\s+too\s+(weak|emotional|stupid))\b`), Severity: 0.75, Label: "gender_discrimination"},
		{Pattern: regexp.MustCompile(ci + `\b(men\s+are\s+(superior|better|smarter)\s+than\s+women)\b`), Severity: 0.8, Label: "gender_superiority"},
		{Pattern: regexp.MustCompile(ci + `\b(disabled|handicapped|crippled)\s+(people\s+)?(shouldn't|can't|are\s+(useless|burden))\b`), Severity: 0.8, Label: "disability_discrimination"},
		{Pattern: regexp.MustCompile(ci + `\b(too\s+old|boomers?\s+(are|should)|old\s+people\s+are\s+(useless|stupid))\b`), Severity: 0.65, Label: "age_discrimination"},
		{Pattern: regexp.MustCompile(ci + `\b(gay|lesbian|trans|queer|homosexual)\s+(people\s+)?(are\s+)?(sick|disgusting|abomination|mental(ly)?\s+(ill|sick)|unnatural)\b`), Severity: 0.85, Label: "lgbtq_discrimination"},
		{Pattern: regexp.MustCompile(ci + `\b(don't\s+hire|shouldn't\s+employ)\s+.*(women|blacks?|muslims?|disabled|old|gay)\b`), Severity: 0.85, Label: "employment_discrimination"},
		{Pattern: regexp.MustCompile(ci + `\b(illegals?|aliens?)\s+(don't\s+deserve|should\s+(be\s+deported|go\s+back))\b`), Severity: 0.75, Label: "immigration_discrimination"},
		{Pattern: regexp.MustCompile(ci + `\b(separate\s+but\s+equal|segregat(e|ion))\b`), Severity: 0.7, Label: "segregation"},
	}
}

// Analyze scans text for toxic content across all categories.
func (f *ToxicityFilter) Analyze(text string) ToxicityResult {
	result := ToxicityResult{
		Score:      0.0,
		Categories: make(map[string]float64),
		Flagged:    false,
		Details:    []string{},
	}

	if strings.TrimSpace(text) == "" {
		return result
	}

	// Normalize: lowercase, collapse whitespace, strip non-alphanumeric except spaces
	normalized := normalizeForToxicity(text)

	for category, patterns := range f.categories {
		catScore := 0.0
		matchCount := 0

		for _, p := range patterns {
			// Search both original and normalized text to catch obfuscation
			matches := p.Pattern.FindAllString(text, -1)
			if len(matches) == 0 {
				matches = p.Pattern.FindAllString(normalized, -1)
			}

			if len(matches) > 0 {
				matchCount += len(matches)
				// First match gets full severity, additional matches add diminishing amounts
				matchSeverity := p.Severity + float64(len(matches)-1)*p.Severity*0.1
				catScore += matchSeverity

				for _, m := range matches {
					// Check context window (5 words around match) to reduce false positives
					context := extractContext(text, m, 5)
					result.Details = append(result.Details, category+":"+p.Label+" \""+truncateStr(m, 60)+"\" ctx:\""+truncateStr(context, 80)+"\"")
				}
			}
		}

		// Normalize category score to 0-1 range
		if catScore > 1.0 {
			catScore = 1.0
		}
		if catScore > 0 {
			result.Categories[category] = catScore
		}
	}

	// Overall score: max category score + diminishing contributions from others
	var maxScore float64
	for _, score := range result.Categories {
		if score > maxScore {
			maxScore = score
		}
	}
	result.Score = maxScore
	for _, score := range result.Categories {
		if score < maxScore {
			result.Score += score * 0.1
		}
	}
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	result.Flagged = result.Score >= f.threshold
	return result
}

// normalizeForToxicity lowercases and collapses whitespace for matching.
func normalizeForToxicity(text string) string {
	lower := strings.ToLower(text)
	// Remove common obfuscation characters between letters: dots, asterisks, underscores, dashes
	var b strings.Builder
	b.Grow(len(lower))
	prevSpace := false
	for _, r := range lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevSpace = false
		} else if unicode.IsSpace(r) || r == '.' || r == '*' || r == '_' || r == '-' {
			if !prevSpace {
				b.WriteRune(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return b.String()
}

// extractContext returns up to n words before and after the match in the source text.
func extractContext(text, match string, windowWords int) string {
	idx := strings.Index(strings.ToLower(text), strings.ToLower(match))
	if idx == -1 {
		return match
	}

	// Find start: go back windowWords words
	start := idx
	wordsSeen := 0
	for start > 0 && wordsSeen < windowWords {
		start--
		if start > 0 && text[start] == ' ' {
			wordsSeen++
		}
	}

	// Find end: go forward windowWords words past the match
	end := idx + len(match)
	wordsSeen = 0
	for end < len(text) && wordsSeen < windowWords {
		if text[end] == ' ' {
			wordsSeen++
		}
		end++
	}

	return strings.TrimSpace(text[start:end])
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
