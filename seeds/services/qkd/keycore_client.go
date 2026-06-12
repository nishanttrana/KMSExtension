package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type KeyCoreClient interface {
	ImportAES256Key(ctx context.Context, tenantID string, name string, purpose string, materialB64 string, labels map[string]string) (string, error)
}

type HTTPKeyCoreClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPKeyCoreClient(baseURL string, timeout time.Duration) *HTTPKeyCoreClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPKeyCoreClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPKeyCoreClient) ImportAES256Key(ctx context.Context, tenantID string, name string, purpose string, materialB64 string, labels map[string]string) (string, error) {
	payload := map[string]interface{}{
		"tenant_id": strings.TrimSpace(tenantID),
		"name":      strings.TrimSpace(name),
		"algorithm": "AES-256",
		"key_type":  "symmetric",
		"purpose":   defaultString(purpose, "encrypt"),
		"labels":    labels,
		"material":  strings.TrimSpace(materialB64),
	}
	out, err := c.doJSON(ctx, http.MethodPost, "/keys/import", payload)
	if err != nil {
		return "", err
	}
	keyID, _ := out["key_id"].(string)
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return "", errors.New("keycore import response missing key_id")
	}
	return keyID, nil
}

func (c *HTTPKeyCoreClient) doJSON(ctx context.Context, method string, path string, payload interface{}) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("keycore base url is empty")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
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
		msg := extractErrorMessage(out)
		if msg == "" {
			msg = "keycore request failed"
		}
		return nil, errors.New(msg)
	}
	return out, nil
}

func extractErrorMessage(v map[string]interface{}) string {
	errAny, ok := v["error"]
	if !ok {
		return ""
	}
	errMap, ok := errAny.(map[string]interface{})
	if !ok {
		return ""
	}
	msg, _ := errMap["message"].(string)
	return strings.TrimSpace(msg)
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}
