package main

import (
	"regexp"
	"strings"
	"sync"
)

// TopicGuardEngine evaluates text against configurable topic guardrails.
type TopicGuardEngine struct {
	rules            []TopicGuardrail
	builtinKeywords  map[string][]string
	builtinPhrases   map[string][]*regexp.Regexp
	codeDLP          *SourceCodeDetector
	mu               sync.RWMutex
}

// TopicCheckResult holds the evaluation outcome for a topic guardrail check.
type TopicCheckResult struct {
	Allowed       bool         `json:"allowed"`
	Action        string       `json:"action"` // allow, block, warn
	ViolatedRules []string     `json:"violated_rules"`
	MatchedTopics []TopicMatch `json:"matched_topics"`
}

// TopicMatch describes a single topic match with its keywords and score.
type TopicMatch struct {
	Topic    string   `json:"topic"`
	Keywords []string `json:"keywords"`
	Score    float64  `json:"score"`
}

// NewTopicGuardEngine creates an engine with built-in topic keyword dictionaries.
func NewTopicGuardEngine() *TopicGuardEngine {
	e := &TopicGuardEngine{
		codeDLP: NewSourceCodeDetector(),
	}
	e.builtinKeywords = e.buildKeywordLists()
	e.builtinPhrases = e.buildPhraseLists()
	return e
}

func (e *TopicGuardEngine) buildKeywordLists() map[string][]string {
	return map[string][]string{
		"weapons": {
			"how to make a bomb", "build a weapon", "explosive device", "firearm assembly",
			"3d print gun", "chemical weapon", "make explosives", "build a gun",
			"improvised explosive", "detonate", "ammunition manufacturing", "weapon blueprint",
			"pipe bomb", "molotov cocktail", "biological weapon", "nerve agent",
			"ricin", "anthrax", "dirty bomb", "nuclear device",
		},
		"self_harm": {
			"how to kill myself", "suicide methods", "self harm techniques", "ways to die",
			"end my life", "painless death", "suicide note", "kill myself",
			"want to die", "methods of suicide", "cut myself", "overdose to die",
			"hang myself", "jump off", "slit my wrists",
		},
		"illegal_activity": {
			"how to hack", "steal credit card", "bypass security", "create malware",
			"ransomware", "phishing kit", "ddos attack", "exploit vulnerability",
			"crack password", "sql injection attack", "keylogger", "trojan horse",
			"identity theft", "money laundering", "forge documents", "counterfeit",
			"drug manufacturing", "pick a lock illegally", "break into",
			"social engineering attack", "zero day exploit",
		},
		"legal_advice": {
			"am i liable", "can i sue", "legal obligation", "contract breach",
			"attorney advice", "legal counsel", "statute of limitations",
			"file a lawsuit", "legal liability", "tort claim", "class action",
			"legal representation", "court order", "injunction",
			"legal rights in", "is it illegal to",
		},
		"financial_advice": {
			"should i invest", "buy or sell", "stock recommendation", "financial planning",
			"investment advice", "portfolio allocation", "which stock", "crypto recommendation",
			"trading strategy", "guaranteed returns", "best investment", "retirement planning",
			"market prediction", "stock pick", "forex trading advice",
		},
		"medical_advice": {
			"diagnose my", "what medication should", "prescription for", "medical treatment for",
			"what disease do i have", "symptoms indicate", "should i take medicine",
			"drug dosage for", "cure for", "alternative treatment", "medical diagnosis",
			"stop taking medication", "home remedy for disease", "self medicate",
		},
	}
}

func (e *TopicGuardEngine) buildPhraseLists() map[string][]*regexp.Regexp {
	ci := "(?i)"
	return map[string][]*regexp.Regexp{
		"weapons": {
			regexp.MustCompile(ci + `how\s+to\s+(make|build|create|construct)\s+(a\s+)?(bomb|weapon|explosive|gun|firearm)`),
			regexp.MustCompile(ci + `(assemble|manufacture|produce)\s+(a\s+)?(weapon|firearm|explosive|bomb)`),
			regexp.MustCompile(ci + `(chemical|biological|nuclear)\s+weapon`),
			regexp.MustCompile(ci + `3d\s+print(ed|ing)?\s+(a\s+)?(gun|firearm|weapon)`),
		},
		"self_harm": {
			regexp.MustCompile(ci + `(how\s+to|ways?\s+to|methods?\s+(of|to|for))\s+(kill\s+myself|commit\s+suicide|end\s+my\s+life|die)`),
			regexp.MustCompile(ci + `(want|going|plan(ning)?)\s+to\s+(kill\s+myself|die|end\s+(my|it))`),
			regexp.MustCompile(ci + `(self[- ]?harm|self[- ]?injury)\s+(technique|method|way)`),
		},
		"illegal_activity": {
			regexp.MustCompile(ci + `how\s+to\s+(hack|crack|break\s+into|exploit|bypass)`),
			regexp.MustCompile(ci + `(create|build|write|develop)\s+(a\s+)?(malware|virus|trojan|ransomware|keylogger|phishing)`),
			regexp.MustCompile(ci + `(steal|forge|counterfeit|launder)\s+(credit\s+card|identity|money|document)`),
		},
		"legal_advice": {
			regexp.MustCompile(ci + `(am\s+i|are\s+we)\s+(legally\s+)?(liable|responsible|obligated)`),
			regexp.MustCompile(ci + `(can|should)\s+i\s+sue`),
			regexp.MustCompile(ci + `(legal|attorney|lawyer)\s+(advice|counsel|opinion)`),
		},
		"financial_advice": {
			regexp.MustCompile(ci + `should\s+i\s+(invest|buy|sell)\b`),
			regexp.MustCompile(ci + `(stock|crypto|investment)\s+(recommendation|advice|pick|tip)`),
			regexp.MustCompile(ci + `(guaranteed|best)\s+(return|investment|profit)`),
		},
		"medical_advice": {
			regexp.MustCompile(ci + `(diagnose|diagnosis)\s+(my|me|this)`),
			regexp.MustCompile(ci + `what\s+(medication|medicine|drug|treatment)\s+should`),
			regexp.MustCompile(ci + `(prescription|dosage|dose)\s+for\b`),
		},
	}
}

// SetRules replaces the current ruleset (thread-safe).
func (e *TopicGuardEngine) SetRules(rules []TopicGuardrail) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// AddRule appends a single rule.
func (e *TopicGuardEngine) AddRule(rule TopicGuardrail) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// Check evaluates text against all enabled rules and returns the result.
func (e *TopicGuardEngine) Check(text string) TopicCheckResult {
	e.mu.RLock()
	rules := make([]TopicGuardrail, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	result := TopicCheckResult{
		Allowed:       true,
		Action:        "allow",
		ViolatedRules: []string{},
		MatchedTopics: []TopicMatch{},
	}

	if strings.TrimSpace(text) == "" {
		return result
	}

	normalizedText := strings.ToLower(text)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		for _, topic := range rule.Topics {
			match := e.matchTopic(topic, normalizedText, text, rule.Keywords)
			if match.Score > 0 {
				result.MatchedTopics = append(result.MatchedTopics, match)
				result.ViolatedRules = append(result.ViolatedRules, rule.ID+":"+rule.Name)

				// Strictest action wins: block > warn > log > allow
				if actionPriority(rule.Action) > actionPriority(result.Action) {
					result.Action = rule.Action
				}
			}
		}
	}

	if result.Action == "block" {
		result.Allowed = false
	}

	return result
}

// matchTopic checks a single topic against the text.
func (e *TopicGuardEngine) matchTopic(topic, normalizedText, originalText string, customKeywords []string) TopicMatch {
	match := TopicMatch{
		Topic:    topic,
		Keywords: []string{},
	}

	// Check built-in keyword list
	if keywords, ok := e.builtinKeywords[topic]; ok {
		for _, kw := range keywords {
			if containsPhrase(normalizedText, kw) {
				match.Keywords = append(match.Keywords, kw)
				match.Score += 0.3
			}
		}
	}

	// Check built-in regex phrases
	if phrases, ok := e.builtinPhrases[topic]; ok {
		for _, p := range phrases {
			if found := p.FindString(originalText); found != "" {
				match.Keywords = append(match.Keywords, found)
				match.Score += 0.4
			}
		}
	}

	// Check custom keywords from the rule
	for _, kw := range customKeywords {
		lowerKw := strings.ToLower(kw)
		if containsPhrase(normalizedText, lowerKw) {
			match.Keywords = append(match.Keywords, kw)
			match.Score += 0.25
		}
	}

	// Special handling: source_code topic uses SourceCodeDLP
	if topic == "source_code" {
		findings := e.codeDLP.Detect(originalText)
		if len(findings) > 0 {
			for _, f := range findings {
				match.Keywords = append(match.Keywords, f.Category+":"+f.Language)
				match.Score += 0.2 * f.Confidence
			}
		}
	}

	// Cap score at 1.0
	if match.Score > 1.0 {
		match.Score = 1.0
	}

	return match
}

// containsPhrase does word-boundary-aware phrase matching.
func containsPhrase(text, phrase string) bool {
	idx := strings.Index(text, phrase)
	if idx == -1 {
		return false
	}

	// Check left boundary
	if idx > 0 {
		ch := text[idx-1]
		if isWordChar(ch) {
			return false
		}
	}

	// Check right boundary
	end := idx + len(phrase)
	if end < len(text) {
		ch := text[end]
		if isWordChar(ch) {
			return false
		}
	}

	return true
}

func isWordChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_'
}

func actionPriority(action string) int {
	switch action {
	case "block":
		return 3
	case "warn":
		return 2
	case "log":
		return 1
	default:
		return 0
	}
}
