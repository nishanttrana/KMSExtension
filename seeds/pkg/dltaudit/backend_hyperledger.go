package dltaudit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// FabricBackend anchors audit hashes on a Hyperledger Fabric network
// via its REST gateway API.
type FabricBackend struct {
	gatewayURL    string
	channelName   string
	chaincodeName string
	identity      string
	httpClient    *http.Client
}

// NewFabricBackend creates a new Hyperledger Fabric backend.
// gatewayURL should point to the Fabric REST gateway (e.g., "http://fabric-gateway:8080").
func NewFabricBackend(gatewayURL, channelName, chaincodeName, identity string) *FabricBackend {
	return &FabricBackend{
		gatewayURL:    gatewayURL,
		channelName:   channelName,
		chaincodeName: chaincodeName,
		identity:      identity,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// fabricTransactionRequest is the payload for submitting a transaction.
type fabricTransactionRequest struct {
	ChannelName   string   `json:"channelName"`
	ChaincodeName string   `json:"chaincodeName"`
	Function      string   `json:"function"`
	Args          []string `json:"args"`
	Identity      string   `json:"identity"`
}

// fabricTransactionResponse is the response from a transaction submission.
type fabricTransactionResponse struct {
	TransactionID string `json:"transactionId"`
	Status        string `json:"status"`
	Payload       string `json:"payload,omitempty"`
}

// fabricQueryRequest is the payload for querying chaincode.
type fabricQueryRequest struct {
	ChannelName   string   `json:"channelName"`
	ChaincodeName string   `json:"chaincodeName"`
	Function      string   `json:"function"`
	Args          []string `json:"args"`
	Identity      string   `json:"identity"`
}

// fabricQueryResponse is the response from a chaincode query.
type fabricQueryResponse struct {
	Payload string `json:"payload"`
	Status  int    `json:"status"`
}

// Submit invokes the StoreAuditHash chaincode function to anchor a hash on Fabric.
func (b *FabricBackend) Submit(ctx context.Context, hash []byte, metadata map[string]string) (string, error) {
	hashHex := hex.EncodeToString(hash)

	// Serialize metadata to JSON for the chaincode argument
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	reqBody := fabricTransactionRequest{
		ChannelName:   b.channelName,
		ChaincodeName: b.chaincodeName,
		Function:      "StoreAuditHash",
		Args:          []string{hashHex, string(metaJSON)},
		Identity:      b.identity,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("dltaudit/fabric: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/transactions", b.gatewayURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("dltaudit/fabric: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("dltaudit/fabric: send transaction: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("dltaudit/fabric: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("dltaudit/fabric: transaction failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var txResp fabricTransactionResponse
	if err := json.Unmarshal(respBody, &txResp); err != nil {
		return "", fmt.Errorf("dltaudit/fabric: unmarshal response: %w", err)
	}

	if txResp.Status != "VALID" && txResp.Status != "SUCCESS" && txResp.Status != "" {
		return "", fmt.Errorf("dltaudit/fabric: transaction status: %s", txResp.Status)
	}

	return txResp.TransactionID, nil
}

// Verify queries the chaincode to check whether the expected hash was stored.
func (b *FabricBackend) Verify(ctx context.Context, txID string, expectedHash []byte) (bool, error) {
	hashHex := hex.EncodeToString(expectedHash)

	reqBody := fabricQueryRequest{
		ChannelName:   b.channelName,
		ChaincodeName: b.chaincodeName,
		Function:      "VerifyAuditHash",
		Args:          []string{hashHex, txID},
		Identity:      b.identity,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("dltaudit/fabric: marshal query: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/query", b.gatewayURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("dltaudit/fabric: create query request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("dltaudit/fabric: query: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("dltaudit/fabric: read query response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("dltaudit/fabric: query failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var queryResp fabricQueryResponse
	if err := json.Unmarshal(respBody, &queryResp); err != nil {
		return false, fmt.Errorf("dltaudit/fabric: unmarshal query response: %w", err)
	}

	// The chaincode should return "true" or "false" as payload
	return queryResp.Payload == "true" || queryResp.Payload == hashHex, nil
}
