package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerQueryAndConfig(t *testing.T) {
	h, _, _, _ := newAIHandler(t)
	tenantID := "tenant-handler"

	getReq := httptest.NewRequest(http.MethodGet, "/ai/config?tenant_id="+tenantID, nil)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get config status=%d body=%s", getRR.Code, getRR.Body.String())
	}

	putReq := httptest.NewRequest(http.MethodPut, "/ai/config?tenant_id="+tenantID, strings.NewReader(`{
		"backend":"openai",
		"endpoint":"https://api.example.test/v1/chat/completions",
		"model":"gpt-4o-mini",
		"provider_auth":{"required":true,"type":"bearer"},
		"mcp":{"enabled":true,"endpoint":"mcp://kms-ai"},
		"temperature":0.2
	}`))
	putReq.Header.Set("Content-Type", "application/json")
	putRR := httptest.NewRecorder()
	h.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("update config status=%d body=%s", putRR.Code, putRR.Body.String())
	}

	queryReq := httptest.NewRequest(http.MethodPost, "/ai/query", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"query":"show unresolved incidents",
		"include_context":true
	}`))
	queryReq.Header.Set("Content-Type", "application/json")
	queryRR := httptest.NewRecorder()
	h.ServeHTTP(queryRR, queryReq)
	if queryRR.Code != http.StatusOK {
		t.Fatalf("query status=%d body=%s", queryRR.Code, queryRR.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(queryRR.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode query payload: %v", err)
	}
	result, _ := payload["result"].(map[string]interface{})
	if result == nil {
		t.Fatalf("missing result payload")
	}
}

func TestHandlerAnalyzeRecommendExplain(t *testing.T) {
	h, _, _, _ := newAIHandler(t)
	tenantID := "tenant-handler-2"

	incidentReq := httptest.NewRequest(http.MethodPost, "/ai/analyze/incident", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"incident_id":"inc-1",
		"title":"Suspicious login failures"
	}`))
	incidentReq.Header.Set("Content-Type", "application/json")
	incidentRR := httptest.NewRecorder()
	h.ServeHTTP(incidentRR, incidentReq)
	if incidentRR.Code != http.StatusOK {
		t.Fatalf("incident status=%d body=%s", incidentRR.Code, incidentRR.Body.String())
	}

	recoReq := httptest.NewRequest(http.MethodPost, "/ai/recommend/posture", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"focus":"pci dss 4.0"
	}`))
	recoReq.Header.Set("Content-Type", "application/json")
	recoRR := httptest.NewRecorder()
	h.ServeHTTP(recoRR, recoReq)
	if recoRR.Code != http.StatusOK {
		t.Fatalf("recommendation status=%d body=%s", recoRR.Code, recoRR.Body.String())
	}

	explainReq := httptest.NewRequest(http.MethodPost, "/ai/explain/policy", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"policy":{"id":"p1","name":"rotate"}
	}`))
	explainReq.Header.Set("Content-Type", "application/json")
	explainRR := httptest.NewRecorder()
	h.ServeHTTP(explainRR, explainReq)
	if explainRR.Code != http.StatusOK {
		t.Fatalf("explain status=%d body=%s", explainRR.Code, explainRR.Body.String())
	}
}
