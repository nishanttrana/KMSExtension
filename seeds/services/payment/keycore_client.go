package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"vecta-kms/pkg/delegation"
	"vecta-kms/pkg/servicetoken"
)

type KeyCoreClient interface {
	GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error)
	// ExportKey returns key material for usage, performed for the user in
	// ctx: keycore decides with that user's grants (pkg/delegation).
	ExportKey(ctx context.Context, tenantID string, keyID string, usage string) (map[string]interface{}, error)
	ImportKey(ctx context.Context, tenantID string, name string, algorithm string, keyType string, purpose string, materialB64 string) (string, error)
	RotateKey(ctx context.Context, tenantID string, keyID string, reason string) (map[string]interface{}, error)
	Encrypt(ctx context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, referenceID string) (map[string]interface{}, error)
	Decrypt(ctx context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error)
	Sign(ctx context.Context, tenantID string, keyID string, dataB64 string) (map[string]interface{}, error)
	Verify(ctx context.Context, tenantID string, keyID string, dataB64 string, signatureB64 string) (map[string]interface{}, error)
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

func (c *HTTPKeyCoreClient) GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "?tenant_id=" + strings.TrimSpace(tenantID)
	out, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	keyAny, ok := out["key"]
	if !ok {
		return map[string]interface{}{}, nil
	}
	keyMap, ok := keyAny.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid key payload")
	}
	return keyMap, nil
}

func (c *HTTPKeyCoreClient) ExportKey(ctx context.Context, tenantID string, keyID string, usage string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/export?tenant_id=" + strings.TrimSpace(tenantID)
	return c.doJSONAs(ctx, http.MethodPost, path, map[string]interface{}{}, usage)
}

func (c *HTTPKeyCoreClient) ImportKey(ctx context.Context, tenantID string, name string, algorithm string, keyType string, purpose string, materialB64 string) (string, error) {
	out, err := c.doJSON(ctx, http.MethodPost, "/keys/import", map[string]interface{}{
		"tenant_id":  strings.TrimSpace(tenantID),
		"name":       defaultString(name, "payment-import"),
		"algorithm":  defaultString(algorithm, "AES-256"),
		"key_type":   defaultString(keyType, "symmetric"),
		"purpose":    defaultString(purpose, "encrypt"),
		"owner":      "payment",
		"iv_mode":    "internal",
		"created_by": "payment-engine",
		"material":   strings.TrimSpace(materialB64),
	})
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

func (c *HTTPKeyCoreClient) RotateKey(ctx context.Context, tenantID string, keyID string, reason string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/rotate?tenant_id=" + strings.TrimSpace(tenantID)
	return c.doJSON(ctx, http.MethodPost, path, map[string]interface{}{"reason": defaultString(reason, "payment-rotation")})
}

func (c *HTTPKeyCoreClient) Encrypt(ctx context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, referenceID string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/encrypt"
	return c.doJSONAs(ctx, http.MethodPost, path, map[string]interface{}{
		"tenant_id":    strings.TrimSpace(tenantID),
		"plaintext":    strings.TrimSpace(plaintextB64),
		"iv":           strings.TrimSpace(ivB64),
		"reference_id": strings.TrimSpace(referenceID),
	}, "encrypt")
}

func (c *HTTPKeyCoreClient) Decrypt(ctx context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/decrypt"
	return c.doJSONAs(ctx, http.MethodPost, path, map[string]interface{}{
		"tenant_id":  strings.TrimSpace(tenantID),
		"ciphertext": strings.TrimSpace(ciphertextB64),
		"iv":         strings.TrimSpace(ivB64),
	}, "decrypt")
}

func (c *HTTPKeyCoreClient) Sign(ctx context.Context, tenantID string, keyID string, dataB64 string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/sign"
	return c.doJSONAs(ctx, http.MethodPost, path, map[string]interface{}{
		"tenant_id": strings.TrimSpace(tenantID),
		"data":      strings.TrimSpace(dataB64),
	}, "sign")
}

func (c *HTTPKeyCoreClient) Verify(ctx context.Context, tenantID string, keyID string, dataB64 string, signatureB64 string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/verify"
	return c.doJSONAs(ctx, http.MethodPost, path, map[string]interface{}{
		"tenant_id": strings.TrimSpace(tenantID),
		"data":      strings.TrimSpace(dataB64),
		"signature": strings.TrimSpace(signatureB64),
	}, "verify")
}

func (c *HTTPKeyCoreClient) doJSON(ctx context.Context, method string, path string, payload interface{}) (map[string]interface{}, error) {
	return c.doJSONAs(ctx, method, path, payload, "")
}

// doJSONAs calls keycore; a non-empty usage is performed for the user in ctx
// (pkg/delegation), so keycore decides key access with that user's grants.
func (c *HTTPKeyCoreClient) doJSONAs(ctx context.Context, method string, path string, payload interface{}, usage string) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("keycore base url is empty")
	}
	var body []byte
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	servicetoken.Authorize(ctx, req)
	if usage != "" {
		delegation.Attach(ctx, req, usage)
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
