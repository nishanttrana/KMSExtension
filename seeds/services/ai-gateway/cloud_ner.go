package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// AWS Comprehend PII Detection
// ---------------------------------------------------------------------------

// AWSComprehendNER detects PII using the AWS Comprehend DetectPiiEntities API.
type AWSComprehendNER struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	httpClient      *http.Client
}

// NewAWSComprehendNER creates an AWS Comprehend PII detector.
func NewAWSComprehendNER(region, accessKeyID, secretAccessKey string) *AWSComprehendNER {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSComprehendNER{
		Region:          region,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *AWSComprehendNER) Name() string { return "aws_comprehend" }

// DetectPII calls AWS Comprehend DetectPiiEntities via HTTP with SigV4 signing.
func (c *AWSComprehendNER) DetectPII(ctx context.Context, text string) ([]NERFinding, error) {
	reqBody := map[string]interface{}{
		"Text":         text,
		"LanguageCode": "en",
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal comprehend request: %w", err)
	}

	endpoint := fmt.Sprintf("https://comprehend.%s.amazonaws.com", c.Region)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create comprehend request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-amz-json-1.1")
	httpReq.Header.Set("X-Amz-Target", "Comprehend_20171127.DetectPiiEntities")

	// AWS SigV4 signing
	signAWSv4(httpReq, payload, c.Region, "comprehend", c.AccessKeyID, c.SecretAccessKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("comprehend http call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read comprehend response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("comprehend returned status %d: %s", resp.StatusCode, truncateStr(string(respBody), 500))
	}

	var result struct {
		Entities []struct {
			Type       string  `json:"Type"`
			Score      float64 `json:"Score"`
			BeginOffset int    `json:"BeginOffset"`
			EndOffset   int    `json:"EndOffset"`
		} `json:"Entities"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal comprehend response: %w", err)
	}

	findings := make([]NERFinding, 0, len(result.Entities))
	for _, entity := range result.Entities {
		entityText := ""
		if entity.BeginOffset >= 0 && entity.EndOffset <= len(text) && entity.BeginOffset < entity.EndOffset {
			entityText = text[entity.BeginOffset:entity.EndOffset]
		}
		findings = append(findings, NERFinding{
			EntityType: mapComprehendType(entity.Type),
			Text:       entityText,
			Offset:     entity.BeginOffset,
			Length:     entity.EndOffset - entity.BeginOffset,
			Confidence: entity.Score,
			Source:     "aws_comprehend",
		})
	}
	return findings, nil
}

// mapComprehendType normalizes AWS Comprehend PII entity types to a common format.
func mapComprehendType(awsType string) string {
	mapping := map[string]string{
		"NAME":                  "PERSON_NAME",
		"ADDRESS":               "ADDRESS",
		"EMAIL":                 "EMAIL_ADDRESS",
		"PHONE":                 "PHONE_NUMBER",
		"SSN":                   "US_SSN",
		"CREDIT_DEBIT_NUMBER":   "CREDIT_CARD",
		"BANK_ACCOUNT_NUMBER":   "BANK_ACCOUNT",
		"CREDIT_DEBIT_CVV":      "CVV",
		"CREDIT_DEBIT_EXPIRY":   "CREDIT_CARD_EXPIRY",
		"DATE_TIME":             "DATE",
		"DRIVER_ID":             "DRIVERS_LICENSE",
		"PASSPORT_NUMBER":       "PASSPORT",
		"IP_ADDRESS":            "IP_ADDRESS",
		"URL":                   "URL",
		"AGE":                   "AGE",
		"USERNAME":              "USERNAME",
		"PASSWORD":              "PASSWORD",
		"AWS_ACCESS_KEY":        "API_KEY",
		"AWS_SECRET_KEY":        "API_SECRET",
	}
	if mapped, ok := mapping[awsType]; ok {
		return mapped
	}
	return awsType
}

// ---------------------------------------------------------------------------
// Google Cloud DLP
// ---------------------------------------------------------------------------

// GoogleCloudDLP detects PII using the Google Cloud DLP API.
type GoogleCloudDLP struct {
	ProjectID string
	AuthJSON  string // service account key JSON
	httpClient *http.Client
}

// NewGoogleCloudDLP creates a Google Cloud DLP PII detector.
func NewGoogleCloudDLP(projectID, authJSON string) *GoogleCloudDLP {
	return &GoogleCloudDLP{
		ProjectID:  projectID,
		AuthJSON:   authJSON,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GoogleCloudDLP) Name() string { return "google_dlp" }

// DetectPII calls Google Cloud DLP content:inspect via HTTP.
func (g *GoogleCloudDLP) DetectPII(ctx context.Context, text string) ([]NERFinding, error) {
	if g.ProjectID == "" {
		return nil, fmt.Errorf("google dlp: project_id is required")
	}

	infoTypes := []map[string]string{
		{"name": "PERSON_NAME"},
		{"name": "EMAIL_ADDRESS"},
		{"name": "PHONE_NUMBER"},
		{"name": "CREDIT_CARD_NUMBER"},
		{"name": "US_SOCIAL_SECURITY_NUMBER"},
		{"name": "STREET_ADDRESS"},
		{"name": "DATE_OF_BIRTH"},
		{"name": "PASSPORT"},
		{"name": "US_DRIVERS_LICENSE_NUMBER"},
		{"name": "IP_ADDRESS"},
		{"name": "URL"},
		{"name": "IBAN_CODE"},
		{"name": "SWIFT_CODE"},
		{"name": "MEDICAL_RECORD_NUMBER"},
		{"name": "US_BANK_ROUTING_MICR"},
	}

	reqBody := map[string]interface{}{
		"item": map[string]interface{}{
			"value": text,
		},
		"inspectConfig": map[string]interface{}{
			"infoTypes":     infoTypes,
			"minLikelihood": "POSSIBLE",
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal dlp request: %w", err)
	}

	endpoint := fmt.Sprintf("https://dlp.googleapis.com/v2/projects/%s/content:inspect", g.ProjectID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create dlp request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Obtain Google access token from service account JSON
	accessToken, err := obtainGoogleAccessToken(ctx, g.AuthJSON, g.httpClient)
	if err != nil {
		return nil, fmt.Errorf("google dlp auth: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("dlp http call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read dlp response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("google dlp returned status %d: %s", resp.StatusCode, truncateStr(string(respBody), 500))
	}

	var result struct {
		Result struct {
			Findings []struct {
				InfoType struct {
					Name string `json:"name"`
				} `json:"infoType"`
				Likelihood string `json:"likelihood"`
				Location   struct {
					ByteRange struct {
						Start int `json:"start"`
						End   int `json:"end"`
					} `json:"byteRange"`
					CodepointRange struct {
						Start int `json:"start"`
						End   int `json:"end"`
					} `json:"codepointRange"`
				} `json:"location"`
				Quote string `json:"quote"`
			} `json:"findings"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal dlp response: %w", err)
	}

	findings := make([]NERFinding, 0, len(result.Result.Findings))
	for _, f := range result.Result.Findings {
		offset := f.Location.CodepointRange.Start
		length := f.Location.CodepointRange.End - f.Location.CodepointRange.Start
		if length <= 0 {
			offset = f.Location.ByteRange.Start
			length = f.Location.ByteRange.End - f.Location.ByteRange.Start
		}

		findings = append(findings, NERFinding{
			EntityType: mapGoogleDLPType(f.InfoType.Name),
			Text:       f.Quote,
			Offset:     offset,
			Length:     length,
			Confidence: googleLikelihoodToScore(f.Likelihood),
			Source:     "google_dlp",
		})
	}
	return findings, nil
}

// mapGoogleDLPType normalizes Google DLP info types to common format.
func mapGoogleDLPType(dlpType string) string {
	mapping := map[string]string{
		"PERSON_NAME":               "PERSON_NAME",
		"EMAIL_ADDRESS":             "EMAIL_ADDRESS",
		"PHONE_NUMBER":              "PHONE_NUMBER",
		"CREDIT_CARD_NUMBER":        "CREDIT_CARD",
		"US_SOCIAL_SECURITY_NUMBER": "US_SSN",
		"STREET_ADDRESS":            "ADDRESS",
		"DATE_OF_BIRTH":             "DATE_OF_BIRTH",
		"PASSPORT":                  "PASSPORT",
		"US_DRIVERS_LICENSE_NUMBER":  "DRIVERS_LICENSE",
		"IP_ADDRESS":                "IP_ADDRESS",
		"URL":                       "URL",
		"IBAN_CODE":                 "IBAN",
		"SWIFT_CODE":                "SWIFT",
		"MEDICAL_RECORD_NUMBER":     "MEDICAL_RECORD",
		"US_BANK_ROUTING_MICR":      "BANK_ROUTING",
	}
	if mapped, ok := mapping[dlpType]; ok {
		return mapped
	}
	return dlpType
}

// googleLikelihoodToScore converts Google DLP likelihood enum to a float64 score.
func googleLikelihoodToScore(likelihood string) float64 {
	switch strings.ToUpper(likelihood) {
	case "VERY_UNLIKELY":
		return 0.1
	case "UNLIKELY":
		return 0.3
	case "POSSIBLE":
		return 0.5
	case "LIKELY":
		return 0.7
	case "VERY_LIKELY":
		return 0.9
	default:
		return 0.5
	}
}

// ---------------------------------------------------------------------------
// Azure AI Language PII Detection
// ---------------------------------------------------------------------------

// AzureAILanguage detects PII using the Azure AI Language API.
type AzureAILanguage struct {
	Endpoint string // e.g. "https://my-resource.cognitiveservices.azure.com"
	APIKey   string
	httpClient *http.Client
}

// NewAzureAILanguage creates an Azure AI Language PII detector.
func NewAzureAILanguage(endpoint, apiKey string) *AzureAILanguage {
	return &AzureAILanguage{
		Endpoint:   strings.TrimRight(endpoint, "/"),
		APIKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *AzureAILanguage) Name() string { return "azure_language" }

// DetectPII calls Azure AI Language PII entity recognition via HTTP.
func (a *AzureAILanguage) DetectPII(ctx context.Context, text string) ([]NERFinding, error) {
	if a.Endpoint == "" {
		return nil, fmt.Errorf("azure language: endpoint is required")
	}
	if a.APIKey == "" {
		return nil, fmt.Errorf("azure language: api_key is required")
	}

	reqBody := map[string]interface{}{
		"kind": "PiiEntityRecognition",
		"parameters": map[string]interface{}{
			"modelVersion": "latest",
		},
		"analysisInput": map[string]interface{}{
			"documents": []map[string]interface{}{
				{
					"id":       "1",
					"text":     text,
					"language": "en",
				},
			},
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal azure language request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/language/:analyze-text?api-version=2023-04-01", a.Endpoint)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create azure language request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Ocp-Apim-Subscription-Key", a.APIKey)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("azure language http call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read azure language response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("azure language returned status %d: %s", resp.StatusCode, truncateStr(string(respBody), 500))
	}

	var result struct {
		Results struct {
			Documents []struct {
				ID       string `json:"id"`
				Entities []struct {
					Text            string  `json:"text"`
					Category        string  `json:"category"`
					Subcategory     string  `json:"subcategory"`
					ConfidenceScore float64 `json:"confidenceScore"`
					Offset          int     `json:"offset"`
					Length          int     `json:"length"`
				} `json:"entities"`
			} `json:"documents"`
			Errors []struct {
				ID    string `json:"id"`
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			} `json:"errors"`
		} `json:"results"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal azure language response: %w", err)
	}

	if len(result.Results.Errors) > 0 {
		return nil, fmt.Errorf("azure language error: %s - %s",
			result.Results.Errors[0].Error.Code, result.Results.Errors[0].Error.Message)
	}

	var findings []NERFinding
	for _, doc := range result.Results.Documents {
		for _, entity := range doc.Entities {
			findings = append(findings, NERFinding{
				EntityType: mapAzureCategory(entity.Category, entity.Subcategory),
				Text:       entity.Text,
				Offset:     entity.Offset,
				Length:     entity.Length,
				Confidence: entity.ConfidenceScore,
				Source:     "azure_language",
			})
		}
	}
	return findings, nil
}

// mapAzureCategory normalizes Azure PII entity categories to common format.
func mapAzureCategory(category, subcategory string) string {
	cat := strings.ToUpper(category)
	sub := strings.ToUpper(subcategory)

	switch cat {
	case "PERSON":
		return "PERSON_NAME"
	case "EMAIL":
		return "EMAIL_ADDRESS"
	case "PHONENUMBER":
		return "PHONE_NUMBER"
	case "ADDRESS":
		return "ADDRESS"
	case "USSOCIALSECURITYNUMBER":
		return "US_SSN"
	case "CREDITCARDNUMBER":
		return "CREDIT_CARD"
	case "DATEOFBIRTH":
		return "DATE_OF_BIRTH"
	case "IPADDRESS":
		return "IP_ADDRESS"
	case "URL":
		return "URL"
	case "ORGANIZATION":
		return "ORGANIZATION"
	case "DATETIME":
		if sub == "DATE" {
			return "DATE"
		}
		return "DATETIME"
	default:
		if subcategory != "" {
			return cat + "_" + sub
		}
		return cat
	}
}

// ---------------------------------------------------------------------------
// Hybrid Detector (Local + Cloud)
// ---------------------------------------------------------------------------

// LocalDLPDetector is the interface for the local regex-based DLP engine.
// This matches the DLPEngine from services/ai/.
type LocalDLPDetector interface {
	ScanText(text string) []LocalFinding
}

// LocalFinding mirrors the Finding type from the local DLP engine.
type LocalFinding struct {
	DetectorName string  `json:"detector_name"`
	Category     string  `json:"category"`
	Type         string  `json:"type"`
	Value        string  `json:"-"`
	RedactedVal  string  `json:"redacted_value"`
	StartPos     int     `json:"start_pos"`
	EndPos       int     `json:"end_pos"`
	Confidence   float64 `json:"confidence"`
}

// HybridDetector combines local regex detection with cloud NER for high-accuracy PII detection.
type HybridDetector struct {
	localEngine LocalDLPDetector
	cloudNER    CloudNERProvider
	useCloud    bool
	logger      *log.Logger
}

// NewHybridDetector creates a HybridDetector with local and optional cloud detection.
func NewHybridDetector(localEngine LocalDLPDetector, cloudNER CloudNERProvider, useCloud bool, logger *log.Logger) *HybridDetector {
	if logger == nil {
		logger = log.Default()
	}
	return &HybridDetector{
		localEngine: localEngine,
		cloudNER:    cloudNER,
		useCloud:    useCloud,
		logger:      logger,
	}
}

// Detect runs dual-layer PII detection: local regex first, then cloud NER if enabled.
func (h *HybridDetector) Detect(ctx context.Context, text string) ([]NERFinding, error) {
	// Layer 1: Run local regex engine (fast, no network call)
	var localFindings []NERFinding
	if h.localEngine != nil {
		rawFindings := h.localEngine.ScanText(text)
		for _, f := range rawFindings {
			localFindings = append(localFindings, NERFinding{
				EntityType: f.Category,
				Text:       f.RedactedVal,
				Offset:     f.StartPos,
				Length:     f.EndPos - f.StartPos,
				Confidence: f.Confidence,
				Source:     "local",
			})
		}
		h.logger.Printf("[hybrid-detector] local engine found %d findings", len(localFindings))
	}

	// Layer 2: Call cloud NER if enabled, provider is set, and text is substantial
	var cloudFindings []NERFinding
	if h.useCloud && h.cloudNER != nil && len(text) > 50 {
		var err error
		cloudFindings, err = h.cloudNER.DetectPII(ctx, text)
		if err != nil {
			// Cloud NER failure is non-fatal; log and continue with local results
			h.logger.Printf("[hybrid-detector] cloud NER (%s) failed: %v", h.cloudNER.Name(), err)
		} else {
			h.logger.Printf("[hybrid-detector] cloud NER (%s) found %d findings", h.cloudNER.Name(), len(cloudFindings))
			// Cloud NER findings get +0.1 confidence boost (more accurate than regex)
			for i := range cloudFindings {
				cloudFindings[i].Confidence += 0.1
				if cloudFindings[i].Confidence > 1.0 {
					cloudFindings[i].Confidence = 1.0
				}
			}
		}
	}

	// Merge and deduplicate: keep highest confidence for overlapping findings
	merged := mergeFindings(localFindings, cloudFindings)
	return merged, nil
}

// mergeFindings deduplicates overlapping findings, keeping the one with highest confidence.
func mergeFindings(local, cloud []NERFinding) []NERFinding {
	all := make([]NERFinding, 0, len(local)+len(cloud))
	all = append(all, local...)
	all = append(all, cloud...)

	if len(all) == 0 {
		return nil
	}

	// Sort by offset, then by confidence descending
	sort.Slice(all, func(i, j int) bool {
		if all[i].Offset != all[j].Offset {
			return all[i].Offset < all[j].Offset
		}
		return all[i].Confidence > all[j].Confidence
	})

	// Deduplicate overlapping ranges: keep the higher-confidence finding
	result := make([]NERFinding, 0, len(all))
	for _, f := range all {
		overlaps := false
		for i := range result {
			existing := &result[i]
			existingEnd := existing.Offset + existing.Length
			fEnd := f.Offset + f.Length

			// Check if ranges overlap
			if f.Offset < existingEnd && fEnd > existing.Offset {
				overlaps = true
				// Keep the one with higher confidence
				if f.Confidence > existing.Confidence {
					*existing = f
				}
				break
			}
		}
		if !overlaps {
			result = append(result, f)
		}
	}

	return result
}
