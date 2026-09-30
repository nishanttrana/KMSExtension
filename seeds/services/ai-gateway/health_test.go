package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type pingStore struct {
	Store
	err error
}

func (p pingStore) Ping(context.Context) error { return p.err }

// Health reports what its checks found; a failed database is not "ok".
func TestHealthReportsRealChecks(t *testing.T) {
	for _, tc := range []struct {
		store    Store
		code     int
		database string
	}{
		{pingStore{}, http.StatusOK, "ok"},
		{pingStore{err: errors.New("connection refused")}, http.StatusServiceUnavailable, "failed: connection refused"},
		{nil, http.StatusServiceUnavailable, "not checked"},
	} {
		h := &Handler{store: tc.store}
		rr := httptest.NewRecorder()
		h.handleHealth(rr, httptest.NewRequest(http.MethodGet, "/ai-gateway/v1/health", nil))
		var out HealthResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if rr.Code != tc.code || out.Checks["database"] != tc.database || out.Checks["dlp"] != "ok" || out.Checks["guardrails"] != "ok" {
			t.Fatalf("%d %+v", rr.Code, out)
		}
	}
}
