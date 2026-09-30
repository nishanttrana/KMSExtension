package main

import (
	"regexp"
	"strings"
)

// CodeFinding represents a detected source code or sensitive config fragment.
type CodeFinding struct {
	Language   string  `json:"language"`
	Snippet    string  `json:"snippet"`
	StartPos   int     `json:"start_pos"`
	EndPos     int     `json:"end_pos"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"` // function_def, class_def, sql_query, api_schema, internal_url, config_block, import_stmt, shell_cmd, container_manifest
}

// codePattern defines a detection rule for source code fragments.
type codePattern struct {
	Language   string
	Category   string
	Pattern    *regexp.Regexp
	Confidence float64
}

// SourceCodeDetector identifies source code, configs, and internal URLs in text.
type SourceCodeDetector struct {
	patterns []codePattern
}

// NewSourceCodeDetector creates a detector with all built-in code patterns.
func NewSourceCodeDetector() *SourceCodeDetector {
	d := &SourceCodeDetector{}
	d.patterns = d.buildPatterns()
	return d
}

func (d *SourceCodeDetector) buildPatterns() []codePattern {
	return []codePattern{
		// ── Function Definitions ──
		{Language: "go", Category: "function_def", Pattern: regexp.MustCompile(`(?m)^func\s+(\([^)]*\)\s+)?\w+\s*\(`), Confidence: 0.9},
		{Language: "python", Category: "function_def", Pattern: regexp.MustCompile(`(?m)^[ \t]*def\s+\w+\s*\(`), Confidence: 0.9},
		{Language: "javascript", Category: "function_def", Pattern: regexp.MustCompile(`(?m)(function\s+\w+\s*\(|const\s+\w+\s*=\s*(async\s+)?\([^)]*\)\s*=>)`), Confidence: 0.85},
		{Language: "rust", Category: "function_def", Pattern: regexp.MustCompile(`(?m)^[ \t]*(pub\s+)?fn\s+\w+\s*[<(]`), Confidence: 0.9},
		{Language: "java", Category: "function_def", Pattern: regexp.MustCompile(`(?m)(public|private|protected)\s+(static\s+)?(void|int|String|boolean|long|double|float|\w+(<[^>]+>)?)\s+\w+\s*\(`), Confidence: 0.9},
		{Language: "csharp", Category: "function_def", Pattern: regexp.MustCompile(`(?m)(public|private|protected|internal)\s+(static\s+)?(async\s+)?(void|int|string|bool|Task|var|\w+)\s+\w+\s*\(`), Confidence: 0.85},

		// ── Class/Struct Definitions ──
		{Language: "python", Category: "class_def", Pattern: regexp.MustCompile(`(?m)^[ \t]*class\s+\w+[\s(:]`), Confidence: 0.9},
		{Language: "java", Category: "class_def", Pattern: regexp.MustCompile(`(?m)(public|private|abstract)?\s*class\s+\w+`), Confidence: 0.85},
		{Language: "go", Category: "class_def", Pattern: regexp.MustCompile(`(?m)^type\s+\w+\s+struct\s*\{`), Confidence: 0.95},
		{Language: "go", Category: "class_def", Pattern: regexp.MustCompile(`(?m)^type\s+\w+\s+interface\s*\{`), Confidence: 0.95},
		{Language: "typescript", Category: "class_def", Pattern: regexp.MustCompile(`(?m)(export\s+)?(class|interface)\s+\w+`), Confidence: 0.85},
		{Language: "rust", Category: "class_def", Pattern: regexp.MustCompile(`(?m)^(pub\s+)?struct\s+\w+`), Confidence: 0.9},

		// ── Import Statements ──
		{Language: "python", Category: "import_stmt", Pattern: regexp.MustCompile(`(?m)^(import\s+\w|from\s+\w+\s+import)`), Confidence: 0.85},
		{Language: "go", Category: "import_stmt", Pattern: regexp.MustCompile(`(?m)^import\s*(\(|")`), Confidence: 0.9},
		{Language: "javascript", Category: "import_stmt", Pattern: regexp.MustCompile(`(?m)(require\s*\(\s*['"]|import\s+.*\s+from\s+['"])`), Confidence: 0.85},
		{Language: "java", Category: "import_stmt", Pattern: regexp.MustCompile(`(?m)^import\s+(static\s+)?[\w.]+\.\*?\s*;`), Confidence: 0.9},
		{Language: "c", Category: "import_stmt", Pattern: regexp.MustCompile(`(?m)^#include\s*[<"]`), Confidence: 0.9},
		{Language: "rust", Category: "import_stmt", Pattern: regexp.MustCompile(`(?m)^use\s+[\w:]+`), Confidence: 0.85},

		// ── SQL Queries ──
		{Language: "sql", Category: "sql_query", Pattern: regexp.MustCompile(`(?i)SELECT\s+.+\s+FROM\s+\w+`), Confidence: 0.9},
		{Language: "sql", Category: "sql_query", Pattern: regexp.MustCompile(`(?i)INSERT\s+INTO\s+\w+`), Confidence: 0.9},
		{Language: "sql", Category: "sql_query", Pattern: regexp.MustCompile(`(?i)UPDATE\s+\w+\s+SET\s+`), Confidence: 0.9},
		{Language: "sql", Category: "sql_query", Pattern: regexp.MustCompile(`(?i)DELETE\s+FROM\s+\w+`), Confidence: 0.9},
		{Language: "sql", Category: "sql_query", Pattern: regexp.MustCompile(`(?i)CREATE\s+TABLE\s+`), Confidence: 0.9},
		{Language: "sql", Category: "sql_query", Pattern: regexp.MustCompile(`(?i)ALTER\s+TABLE\s+\w+`), Confidence: 0.9},
		{Language: "sql", Category: "sql_query", Pattern: regexp.MustCompile(`(?i)DROP\s+TABLE\s+`), Confidence: 0.85},

		// ── API Schemas ──
		{Language: "openapi", Category: "api_schema", Pattern: regexp.MustCompile(`(?i)openapi:\s*['"]?[23]`), Confidence: 0.95},
		{Language: "openapi", Category: "api_schema", Pattern: regexp.MustCompile(`(?i)swagger:\s*['"]?2`), Confidence: 0.95},
		{Language: "openapi", Category: "api_schema", Pattern: regexp.MustCompile(`(?m)paths:\s*\n\s+/`), Confidence: 0.85},
		{Language: "rest", Category: "api_schema", Pattern: regexp.MustCompile(`(?i)["']/api/v\d+/\w+`), Confidence: 0.7},
		{Language: "python", Category: "api_schema", Pattern: regexp.MustCompile(`@app\.(route|get|post|put|delete|patch)\s*\(`), Confidence: 0.9},
		{Language: "java", Category: "api_schema", Pattern: regexp.MustCompile(`@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(`), Confidence: 0.9},
		{Language: "javascript", Category: "api_schema", Pattern: regexp.MustCompile(`(router|app)\.(get|post|put|delete|patch)\s*\(\s*['"/]`), Confidence: 0.85},
		{Language: "graphql", Category: "api_schema", Pattern: regexp.MustCompile(`(?m)(type\s+Query|type\s+Mutation)\s*\{`), Confidence: 0.85},

		// ── Internal URLs (RFC 1918 + internal domains) ──
		{Language: "url", Category: "internal_url", Pattern: regexp.MustCompile(`https?://(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(:\d+)?(/\S*)?`), Confidence: 0.95},
		{Language: "url", Category: "internal_url", Pattern: regexp.MustCompile(`(?i)https?://[\w.-]+\.(internal|local|corp|intranet|private|lan)(:\d+)?(/\S*)?`), Confidence: 0.9},
		{Language: "url", Category: "internal_url", Pattern: regexp.MustCompile(`https?://localhost(:\d+)?(/\S*)?`), Confidence: 0.8},

		// ── Config Blocks ──
		{Language: "config", Category: "config_block", Pattern: regexp.MustCompile(`(?im)^[ \t]*(password|passwd|secret|api_key|apikey|api_secret|access_key|secret_key|private_key|token|auth_token)\s*[:=]\s*\S+`), Confidence: 0.95},
		{Language: "config", Category: "config_block", Pattern: regexp.MustCompile(`(?i)(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|SLACK_TOKEN|DATABASE_URL)\s*=\s*\S+`), Confidence: 0.95},
		{Language: "config", Category: "config_block", Pattern: regexp.MustCompile(`(?i)(-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----)`), Confidence: 0.99},
		{Language: "config", Category: "config_block", Pattern: regexp.MustCompile(`(?i)(connection_string|conn_str|dsn)\s*[:=]\s*["']?\w+://`), Confidence: 0.9},

		// ── Shell Commands ──
		{Language: "shell", Category: "shell_cmd", Pattern: regexp.MustCompile(`(?m)^#!/bin/(bash|sh|zsh)`), Confidence: 0.95},
		{Language: "shell", Category: "shell_cmd", Pattern: regexp.MustCompile(`(?m)(curl|wget)\s+(-[a-zA-Z]+\s+)*https?://`), Confidence: 0.7},
		{Language: "shell", Category: "shell_cmd", Pattern: regexp.MustCompile(`(?m)ssh\s+(-[a-zA-Z]+\s+)*\w+@[\w.-]+`), Confidence: 0.85},
		{Language: "shell", Category: "shell_cmd", Pattern: regexp.MustCompile(`(?m)sudo\s+\w+`), Confidence: 0.7},
		{Language: "shell", Category: "shell_cmd", Pattern: regexp.MustCompile(`(?m)(chmod|chown|iptables|systemctl|service)\s+`), Confidence: 0.75},

		// ── Docker/K8s Manifests ──
		{Language: "dockerfile", Category: "container_manifest", Pattern: regexp.MustCompile(`(?m)^FROM\s+[\w./-]+(:\S+)?`), Confidence: 0.9},
		{Language: "kubernetes", Category: "container_manifest", Pattern: regexp.MustCompile(`(?m)^apiVersion:\s+\S+`), Confidence: 0.9},
		{Language: "kubernetes", Category: "container_manifest", Pattern: regexp.MustCompile(`(?m)^kind:\s+(Deployment|Service|Pod|StatefulSet|DaemonSet|ConfigMap|Secret|Ingress)`), Confidence: 0.95},
		{Language: "kubernetes", Category: "container_manifest", Pattern: regexp.MustCompile(`(?m)^spec:\s*$`), Confidence: 0.5},
		{Language: "docker-compose", Category: "container_manifest", Pattern: regexp.MustCompile(`(?m)^services:\s*\n\s+\w+:`), Confidence: 0.85},
	}
}

// Detect scans text and returns all code/config findings.
func (d *SourceCodeDetector) Detect(text string) []CodeFinding {
	if strings.TrimSpace(text) == "" {
		return nil
	}

	var findings []CodeFinding
	seen := make(map[string]bool) // dedup by start position + category

	for _, p := range d.patterns {
		matches := p.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			key := string(rune(loc[0])) + ":" + p.Category
			if seen[key] {
				continue
			}
			seen[key] = true

			snippet := text[loc[0]:loc[1]]
			if len(snippet) > 100 {
				snippet = snippet[:100]
			}

			findings = append(findings, CodeFinding{
				Language:   p.Language,
				Snippet:    snippet,
				StartPos:   loc[0],
				EndPos:     loc[1],
				Confidence: p.Confidence,
				Category:   p.Category,
			})
		}
	}

	return findings
}

// DetectWithThreshold returns only findings at or above the given confidence.
func (d *SourceCodeDetector) DetectWithThreshold(text string, minConfidence float64) []CodeFinding {
	all := d.Detect(text)
	var filtered []CodeFinding
	for _, f := range all {
		if f.Confidence >= minConfidence {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// HasCode is a quick check returning true if any code pattern matches.
func (d *SourceCodeDetector) HasCode(text string) bool {
	for _, p := range d.patterns {
		if p.Pattern.MatchString(text) {
			return true
		}
	}
	return false
}
