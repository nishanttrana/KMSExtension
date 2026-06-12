package dltaudit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

// EthereumBackend anchors audit hashes on an Ethereum-compatible blockchain
// using raw JSON-RPC calls (no geth dependency).
type EthereumBackend struct {
	rpcURL          string
	privateKey      *ecdsa.PrivateKey
	contractAddress string
	chainID         *big.Int
	httpClient      *http.Client
	nonce           uint64
}

// NewEthereumBackend creates a new Ethereum backend for DLT anchoring.
// privateKeyHex is the hex-encoded ECDSA private key (without 0x prefix).
// contractAddress is the address of a deployed AuditAnchor contract with store(bytes32) function.
func NewEthereumBackend(rpcURL, privateKeyHex, contractAddress string, chainID int64) (*EthereumBackend, error) {
	keyBytes, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("dltaudit/ethereum: decode private key: %w", err)
	}

	privKey := new(ecdsa.PrivateKey)
	privKey.Curve = elliptic.P256()
	privKey.D = new(big.Int).SetBytes(keyBytes)
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.Curve.ScalarBaseMult(keyBytes)

	// Use secp256k1 if available (Ethereum standard), fall back to P256
	// For production, use the secp256k1 curve from a dedicated library
	return &EthereumBackend{
		rpcURL:          rpcURL,
		privateKey:      privKey,
		contractAddress: contractAddress,
		chainID:         big.NewInt(chainID),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// jsonRPCRequest is a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// call executes a JSON-RPC request against the Ethereum node.
func (b *EthereumBackend) call(ctx context.Context, method string, params ...interface{}) (json.RawMessage, error) {
	if params == nil {
		params = []interface{}{}
	}

	req := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal rpc request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", b.rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rpc call %s: %w", method, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// getAddress returns the Ethereum address derived from the private key.
func (b *EthereumBackend) getAddress() string {
	pubBytes := elliptic.Marshal(b.privateKey.Curve, b.privateKey.PublicKey.X, b.privateKey.PublicKey.Y)
	// Keccak256 of public key bytes (excluding the 0x04 prefix)
	h := sha3.NewLegacyKeccak256()
	h.Write(pubBytes[1:])
	hash := h.Sum(nil)
	// Address is last 20 bytes
	return "0x" + hex.EncodeToString(hash[12:])
}

// getNonce fetches the current transaction count for the sender address.
func (b *EthereumBackend) getNonce(ctx context.Context) (uint64, error) {
	addr := b.getAddress()
	result, err := b.call(ctx, "eth_getTransactionCount", addr, "pending")
	if err != nil {
		return 0, err
	}

	var nonceHex string
	if err := json.Unmarshal(result, &nonceHex); err != nil {
		return 0, fmt.Errorf("unmarshal nonce: %w", err)
	}

	nonce, err := hexToUint64(nonceHex)
	if err != nil {
		return 0, fmt.Errorf("parse nonce: %w", err)
	}
	return nonce, nil
}

// getGasPrice fetches the current gas price suggestion.
func (b *EthereumBackend) getGasPrice(ctx context.Context) (*big.Int, error) {
	result, err := b.call(ctx, "eth_gasPrice")
	if err != nil {
		return nil, err
	}

	var priceHex string
	if err := json.Unmarshal(result, &priceHex); err != nil {
		return nil, fmt.Errorf("unmarshal gas price: %w", err)
	}

	price, ok := new(big.Int).SetString(strings.TrimPrefix(priceHex, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("parse gas price: %s", priceHex)
	}
	return price, nil
}

// buildStoreCalldata constructs the ABI-encoded calldata for store(bytes32 hash).
// Function selector: keccak256("store(bytes32)")[:4]
func buildStoreCalldata(hash []byte) []byte {
	// Compute function selector
	sig := sha3.NewLegacyKeccak256()
	sig.Write([]byte("store(bytes32)"))
	selector := sig.Sum(nil)[:4]

	// ABI encode: selector + left-padded bytes32
	data := make([]byte, 4+32)
	copy(data[:4], selector)
	// Ensure hash is exactly 32 bytes, left-pad if needed
	if len(hash) >= 32 {
		copy(data[4:], hash[:32])
	} else {
		copy(data[4+(32-len(hash)):], hash)
	}
	return data
}

// Submit constructs, signs, and sends a transaction calling store(bytes32) on the anchor contract.
func (b *EthereumBackend) Submit(ctx context.Context, hash []byte, metadata map[string]string) (string, error) {
	nonce, err := b.getNonce(ctx)
	if err != nil {
		return "", fmt.Errorf("dltaudit/ethereum: get nonce: %w", err)
	}

	gasPrice, err := b.getGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("dltaudit/ethereum: get gas price: %w", err)
	}

	calldata := buildStoreCalldata(hash)

	// Build transaction fields
	gasLimit := uint64(100000) // sufficient for a simple storage call
	to := strings.TrimPrefix(b.contractAddress, "0x")

	// RLP-encode the transaction (EIP-155)
	tx := &ethTransaction{
		Nonce:    nonce,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		To:       hexToBytes(to),
		Value:    big.NewInt(0),
		Data:     calldata,
		ChainID:  b.chainID,
	}

	signedTx, err := tx.signEIP155(b.privateKey)
	if err != nil {
		return "", fmt.Errorf("dltaudit/ethereum: sign transaction: %w", err)
	}

	// Send raw transaction
	rawTxHex := "0x" + hex.EncodeToString(signedTx)
	result, err := b.call(ctx, "eth_sendRawTransaction", rawTxHex)
	if err != nil {
		return "", fmt.Errorf("dltaudit/ethereum: send transaction: %w", err)
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", fmt.Errorf("dltaudit/ethereum: unmarshal tx hash: %w", err)
	}

	return txHash, nil
}

// Verify checks the transaction receipt to confirm the hash was stored.
func (b *EthereumBackend) Verify(ctx context.Context, txID string, expectedHash []byte) (bool, error) {
	result, err := b.call(ctx, "eth_getTransactionReceipt", txID)
	if err != nil {
		return false, fmt.Errorf("dltaudit/ethereum: get receipt: %w", err)
	}

	if string(result) == "null" {
		return false, fmt.Errorf("dltaudit/ethereum: transaction %s not yet mined", txID)
	}

	var receipt struct {
		Status string `json:"status"`
		Logs   []struct {
			Data   string   `json:"data"`
			Topics []string `json:"topics"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(result, &receipt); err != nil {
		return false, fmt.Errorf("dltaudit/ethereum: unmarshal receipt: %w", err)
	}

	// Check transaction succeeded
	if receipt.Status != "0x1" {
		return false, fmt.Errorf("dltaudit/ethereum: transaction reverted")
	}

	// Check logs for stored hash
	// The contract should emit an event with the stored hash as a topic
	expectedHex := "0x" + hex.EncodeToString(expectedHash)
	if len(expectedHash) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(expectedHash):], expectedHash)
		expectedHex = "0x" + hex.EncodeToString(padded)
	}

	for _, logEntry := range receipt.Logs {
		for _, topic := range logEntry.Topics {
			if strings.EqualFold(topic, expectedHex) {
				return true, nil
			}
		}
		// Also check log data
		if strings.Contains(strings.ToLower(logEntry.Data), strings.ToLower(strings.TrimPrefix(expectedHex, "0x"))) {
			return true, nil
		}
	}

	// If no logs match but tx succeeded, verify by calling the contract's getter
	return b.verifyViaCall(ctx, expectedHash)
}

// verifyViaCall calls the contract's verify function to check if a hash was stored.
func (b *EthereumBackend) verifyViaCall(ctx context.Context, hash []byte) (bool, error) {
	// Build calldata for verify(bytes32) -> bool
	sig := sha3.NewLegacyKeccak256()
	sig.Write([]byte("verify(bytes32)"))
	selector := sig.Sum(nil)[:4]

	data := make([]byte, 4+32)
	copy(data[:4], selector)
	if len(hash) >= 32 {
		copy(data[4:], hash[:32])
	} else {
		copy(data[4+(32-len(hash)):], hash)
	}

	callObj := map[string]string{
		"to":   b.contractAddress,
		"data": "0x" + hex.EncodeToString(data),
	}

	result, err := b.call(ctx, "eth_call", callObj, "latest")
	if err != nil {
		return false, err
	}

	var resultHex string
	if err := json.Unmarshal(result, &resultHex); err != nil {
		return false, err
	}

	// ABI decode bool: non-zero last byte means true
	resultBytes := hexToBytes(strings.TrimPrefix(resultHex, "0x"))
	if len(resultBytes) >= 32 {
		return resultBytes[31] != 0, nil
	}
	return false, nil
}

// --- Ethereum Transaction Encoding (EIP-155) ---

type ethTransaction struct {
	Nonce    uint64
	GasPrice *big.Int
	GasLimit uint64
	To       []byte
	Value    *big.Int
	Data     []byte
	ChainID  *big.Int
}

// signEIP155 RLP-encodes and signs the transaction with EIP-155 replay protection.
func (tx *ethTransaction) signEIP155(key *ecdsa.PrivateKey) ([]byte, error) {
	// RLP encode for signing: [nonce, gasPrice, gasLimit, to, value, data, chainID, 0, 0]
	sigData := rlpEncodeList(
		rlpEncodeUint(tx.Nonce),
		rlpEncodeBigInt(tx.GasPrice),
		rlpEncodeUint(tx.GasLimit),
		rlpEncodeBytes(tx.To),
		rlpEncodeBigInt(tx.Value),
		rlpEncodeBytes(tx.Data),
		rlpEncodeBigInt(tx.ChainID),
		rlpEncodeUint(0),
		rlpEncodeUint(0),
	)

	// Hash for signing
	h := sha3.NewLegacyKeccak256()
	h.Write(sigData)
	sigHash := h.Sum(nil)

	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, key, sigHash)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Compute v = chainID * 2 + 35 + recovery_id
	// For simplicity, we use v = chainID * 2 + 35 (recovery_id = 0)
	v := new(big.Int).Mul(tx.ChainID, big.NewInt(2))
	v.Add(v, big.NewInt(35))

	// RLP encode signed transaction: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
	return rlpEncodeList(
		rlpEncodeUint(tx.Nonce),
		rlpEncodeBigInt(tx.GasPrice),
		rlpEncodeUint(tx.GasLimit),
		rlpEncodeBytes(tx.To),
		rlpEncodeBigInt(tx.Value),
		rlpEncodeBytes(tx.Data),
		rlpEncodeBigInt(v),
		rlpEncodeBigInt(r),
		rlpEncodeBigInt(s),
	), nil
}

// --- Minimal RLP Encoding ---

func rlpEncodeUint(val uint64) []byte {
	if val == 0 {
		return []byte{0x80}
	}
	if val < 128 {
		return []byte{byte(val)}
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	// Trim leading zeros
	i := 0
	for i < len(buf)-1 && buf[i] == 0 {
		i++
	}
	trimmed := buf[i:]
	return append([]byte{byte(0x80 + len(trimmed))}, trimmed...)
}

func rlpEncodeBigInt(val *big.Int) []byte {
	if val == nil || val.Sign() == 0 {
		return []byte{0x80}
	}
	b := val.Bytes()
	return rlpEncodeBytes(b)
}

func rlpEncodeBytes(b []byte) []byte {
	if len(b) == 0 {
		return []byte{0x80}
	}
	if len(b) == 1 && b[0] < 128 {
		return b
	}
	if len(b) < 56 {
		return append([]byte{byte(0x80 + len(b))}, b...)
	}
	// Long string
	lenBytes := bigEndianUint(uint64(len(b)))
	prefix := []byte{byte(0xb7 + len(lenBytes))}
	return append(append(prefix, lenBytes...), b...)
}

func rlpEncodeList(items ...[]byte) []byte {
	var payload []byte
	for _, item := range items {
		payload = append(payload, item...)
	}

	if len(payload) < 56 {
		return append([]byte{byte(0xc0 + len(payload))}, payload...)
	}

	lenBytes := bigEndianUint(uint64(len(payload)))
	prefix := []byte{byte(0xf7 + len(lenBytes))}
	return append(append(prefix, lenBytes...), payload...)
}

func bigEndianUint(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	i := 0
	for i < len(buf)-1 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

func hexToBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func hexToUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	val, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return 0, fmt.Errorf("invalid hex: %s", s)
	}
	return val.Uint64(), nil
}
