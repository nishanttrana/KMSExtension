// Package kmsclient is the single integration point between KMS Extension
// services and the core Vecta KMS. All extension features consume keys and
// emit audit events through the KMS REST APIs — extension services never
// hold key material or implement crypto themselves.
package kmsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL  string // e.g. https://kms.internal:8443 (keycore API root)
	Token    string // service-account bearer token issued by the KMS auth service
	TenantID string // sent as X-Tenant-ID on every request
	HTTP     *http.Client
}

func New(baseURL, token, tenantID string) *Client {
	return &Client{
		BaseURL:  baseURL,
		Token:    token,
		TenantID: tenantID,
		HTTP:     &http.Client{Timeout: 15 * time.Second},
	}
}

// Do performs an authenticated JSON request against the KMS and decodes the
// response into out (out may be nil to discard the body).
func (c *Client) Do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Tenant-ID", c.TenantID)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("kms %s %s: status %d: %s", method, path, resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// KeyExists checks that a key id is visible to this tenant in the KMS.
func (c *Client) KeyExists(ctx context.Context, keyID string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/keys/"+keyID, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Tenant-ID", c.TenantID)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close() //nolint:errcheck
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, nil
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("kms GET /keys/%s: status %d", keyID, resp.StatusCode)
	}
}
