package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgmpc "vecta-kms/pkg/mpc"
)

func thresholdSignWithSecret(secret *big.Int, algorithm string, messageInput string) (map[string]interface{}, error) {
	message, digestHex, err := parseThresholdMessage(messageInput)
	if err != nil {
		return nil, err
	}

	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	if usesFROST(alg) {
		return pkgmpc.SignEd25519WithSecret(secret, defaultString(strings.TrimSpace(algorithm), "Ed25519"), message, digestHex)
	}
	return pkgmpc.SignECDSAWithSecret(secret, alg, message, digestHex)
}

func thresholdDecryptWithSecret(secret *big.Int, ciphertextInput string) ([]byte, map[string]interface{}, error) {
	key := pkgmpc.DeriveAES256Key(secret)
	defer pkgcrypto.Zeroize(key)

	nonce, ciphertext, aad, payloadType, parseErr := parseThresholdCiphertext(ciphertextInput)
	if parseErr == nil && len(ciphertext) > 0 && len(nonce) > 0 {
		plaintext, err := pkgmpc.GCMOpenFlexibleNonce(key, nonce, ciphertext, aad)
		if err == nil {
			meta := map[string]interface{}{
				"cipher":       "AES-256-GCM",
				"nonce_size":   len(nonce),
				"aad_len":      len(aad),
				"payload_type": payloadType,
			}
			if utf8.Valid(plaintext) {
				meta["plaintext_utf8"] = string(plaintext)
			}
			return plaintext, meta, nil
		}
		if !strings.Contains(strings.ToLower(err.Error()), "message authentication failed") {
			return nil, nil, fmt.Errorf("aes-gcm decrypt failed: %w", err)
		}
	}

	legacyCiphertext, err := decodeFlexibleBinary(ciphertextInput)
	if err != nil {
		if parseErr != nil {
			return nil, nil, parseErr
		}
		return nil, nil, fmt.Errorf("invalid ciphertext encoding")
	}
	plaintext := xorDecryptWithSecret(secret, legacyCiphertext)
	meta := map[string]interface{}{
		"cipher":              "XOR-LEGACY",
		"compatibility_mode":  "legacy_xor_fallback",
		"fallback_reason":     "ciphertext_not_aes_gcm_payload",
		"legacy_payload_size": len(legacyCiphertext),
	}
	if utf8.Valid(plaintext) {
		meta["plaintext_utf8"] = string(plaintext)
	}
	return plaintext, meta, nil
}

func parseThresholdMessage(messageInput string) ([]byte, string, error) {
	raw := strings.TrimSpace(messageInput)
	if raw == "" {
		return nil, "", errors.New("message hash is required")
	}
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		raw = raw[2:]
	}
	if b, err := tryDecodeHex(raw); err == nil && len(b) > 0 {
		return b, strings.ToLower(hex.EncodeToString(b)), nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) > 0 {
		return b, strings.ToLower(hex.EncodeToString(b)), nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(b) > 0 {
		return b, strings.ToLower(hex.EncodeToString(b)), nil
	}
	b := []byte(raw)
	sum := sha256.Sum256(b)
	return sum[:], strings.ToLower(hex.EncodeToString(sum[:])), nil
}

func parseThresholdCiphertext(raw string) ([]byte, []byte, []byte, string, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return nil, nil, nil, "", errors.New("ciphertext is required")
	}

	if strings.HasPrefix(input, "{") {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(input), &payload); err == nil {
			nonceRaw := firstString(payload["nonce"], payload["iv"])
			cipherRaw := firstString(payload["ciphertext"], payload["ct"], payload["data"])
			if nonceRaw == "" || cipherRaw == "" {
				return nil, nil, nil, "", errors.New("json payload requires nonce/iv and ciphertext")
			}
			nonce, err := decodeFlexibleBinary(nonceRaw)
			if err != nil {
				return nil, nil, nil, "", fmt.Errorf("invalid nonce/iv encoding")
			}
			ciphertext, err := decodeFlexibleBinary(cipherRaw)
			if err != nil {
				return nil, nil, nil, "", fmt.Errorf("invalid ciphertext encoding")
			}

			aad := []byte{}
			if aadRaw := firstString(payload["aad"], payload["associated_data"]); aadRaw != "" {
				aadEncoding := strings.ToLower(firstString(payload["aad_encoding"]))
				if aadEncoding == "utf8" || aadEncoding == "text" {
					aad = []byte(aadRaw)
				} else if decodedAAD, err := decodeFlexibleBinary(aadRaw); err == nil {
					aad = decodedAAD
				} else {
					aad = []byte(aadRaw)
				}
			}
			return nonce, ciphertext, aad, "json", nil
		}
	}

	if strings.Contains(input, ":") {
		parts := strings.SplitN(input, ":", 2)
		if len(parts) == 2 {
			nonce, err := decodeFlexibleBinary(parts[0])
			if err != nil {
				return nil, nil, nil, "", fmt.Errorf("invalid nonce encoding")
			}
			ciphertext, err := decodeFlexibleBinary(parts[1])
			if err != nil {
				return nil, nil, nil, "", fmt.Errorf("invalid ciphertext encoding")
			}
			return nonce, ciphertext, nil, "nonce:ciphertext", nil
		}
	}

	packed, err := decodeFlexibleBinary(input)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid ciphertext encoding")
	}
	if len(packed) <= 12 {
		return nil, nil, nil, "", errors.New("packed ciphertext must include 12-byte nonce + encrypted payload")
	}
	nonce := make([]byte, 12)
	copy(nonce, packed[:12])
	ciphertext := make([]byte, len(packed)-12)
	copy(ciphertext, packed[12:])
	return nonce, ciphertext, nil, "packed", nil
}

func tryDecodeHex(v string) ([]byte, error) {
	in := strings.TrimSpace(v)
	if in == "" {
		return nil, errors.New("empty")
	}
	if len(in)%2 != 0 {
		return nil, errors.New("odd length")
	}
	return hex.DecodeString(in)
}
