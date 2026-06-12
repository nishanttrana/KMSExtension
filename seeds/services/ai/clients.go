package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type httpJSONClient struct {
	baseURL string
	client  *http.Client
}

func newHTTPJSONClient(baseURL string, timeout time.Duration) *httpJSONClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &httpJSONClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *httpJSONClient) doJSON(ctx context.Context, method string, path string, payload interface{}, headers map[string]string) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("base url is empty")
	}
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	out := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, errors.New(sanitizeErrorMessage(out))
	}
	return out, nil
}

type HTTPKeyCoreClient struct {
	http *httpJSONClient
}

func NewHTTPKeyCoreClient(baseURL string, timeout time.Duration) *HTTPKeyCoreClient {
	return &HTTPKeyCoreClient{http: newHTTPJSONClient(baseURL, timeout)}
}

func (c *HTTPKeyCoreClient) ListKeys(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconvItoa(limit))
	out, err := c.http.doJSON(ctx, http.MethodGet, "/keys?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeObjectList(out["items"]), nil
}

type HTTPPolicyClient struct {
	http *httpJSONClient
}

func NewHTTPPolicyClient(baseURL string, timeout time.Duration) *HTTPPolicyClient {
	return &HTTPPolicyClient{http: newHTTPJSONClient(baseURL, timeout)}
}

func (c *HTTPPolicyClient) ListPolicies(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconvItoa(limit))
	out, err := c.http.doJSON(ctx, http.MethodGet, "/policies?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeObjectList(out["items"]), nil
}

type HTTPAuditClient struct {
	http *httpJSONClient
}

func NewHTTPAuditClient(baseURL string, timeout time.Duration) *HTTPAuditClient {
	return &HTTPAuditClient{http: newHTTPJSONClient(baseURL, timeout)}
}

func (c *HTTPAuditClient) ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconvItoa(limit))
	out, err := c.http.doJSON(ctx, http.MethodGet, "/audit/events?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeObjectList(out["items"]), nil
}

type HTTPComplianceClient struct {
	http *httpJSONClient
}

func NewHTTPComplianceClient(baseURL string, timeout time.Duration) *HTTPComplianceClient {
	return &HTTPComplianceClient{http: newHTTPJSONClient(baseURL, timeout)}
}

func (c *HTTPComplianceClient) GetPosture(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	out, err := c.http.doJSON(ctx, http.MethodGet, "/compliance/posture?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	posture, _ := out["posture"].(map[string]interface{})
	if posture == nil {
		return map[string]interface{}{}, nil
	}
	return posture, nil
}

type HTTPReportingClient struct {
	http *httpJSONClient
}

func NewHTTPReportingClient(baseURL string, timeout time.Duration) *HTTPReportingClient {
	return &HTTPReportingClient{http: newHTTPJSONClient(baseURL, timeout)}
}

func (c *HTTPReportingClient) ListAlerts(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconvItoa(limit))
	out, err := c.http.doJSON(ctx, http.MethodGet, "/alerts?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeObjectList(out["items"]), nil
}

type HTTPSecretsClient struct {
	http *httpJSONClient
}

func NewHTTPSecretsClient(baseURL string, timeout time.Duration) *HTTPSecretsClient {
	return &HTTPSecretsClient{http: newHTTPJSONClient(baseURL, timeout)}
}

func (c *HTTPSecretsClient) GetSecretValue(ctx context.Context, tenantID string, id string) (string, error) {
	if strings.TrimSpace(id) == "" {
		return "", errors.New("secret id is required")
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	out, err := c.http.doJSON(ctx, http.MethodGet, "/secrets/"+url.PathEscape(strings.TrimSpace(id))+"/value?"+q.Encode(), nil, nil)
	if err != nil {
		return "", err
	}
	return firstString(out["value"]), nil
}

func decodeObjectList(v interface{}) []map[string]interface{} {
	raw, ok := v.([]interface{})
	if !ok {
		return []map[string]interface{}{}
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if ok {
			out = append(out, m)
		}
	}
	return out
}

func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
