package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPKeyCoreClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPKeyCoreClient(baseURL string, timeout time.Duration) *HTTPKeyCoreClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPKeyCoreClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPKeyCoreClient) GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return map[string]interface{}{}, nil
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	path := c.baseURL + "/keys/" + url.PathEscape(strings.TrimSpace(keyID)) + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
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
	item, _ := out["key"].(map[string]interface{})
	if item == nil {
		return map[string]interface{}{}, nil
	}
	return item, nil
}

type HTTPClusterClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPClusterClient(baseURL string, timeout time.Duration) *HTTPClusterClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPClusterClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPClusterClient) ListMembers(ctx context.Context) ([]string, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return []string{}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/cluster/members", nil)
	if err != nil {
		return nil, err
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
	rawItems, _ := out["items"].([]interface{})
	members := make([]string, 0, len(rawItems))
	for _, it := range rawItems {
		if s := strings.TrimSpace(firstString(it)); s != "" {
			members = append(members, s)
			continue
		}
		obj, _ := it.(map[string]interface{})
		if obj == nil {
			continue
		}
		if id := strings.TrimSpace(firstString(obj["id"], obj["name"], obj["node_id"])); id != "" {
			members = append(members, id)
		}
	}
	return uniqueStrings(members), nil
}

func sanitizeErrorMessage(v map[string]interface{}) string {
	errAny, ok := v["error"]
	if !ok {
		return "request failed"
	}
	errMap, ok := errAny.(map[string]interface{})
	if !ok {
		return "request failed"
	}
	msg, _ := errMap["message"].(string)
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "request failed"
	}
	return msg
}
