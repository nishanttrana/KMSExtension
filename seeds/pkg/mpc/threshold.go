package mpc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Threshold-share signing and decryption primitives for the MPC engine.
// The reconstructed secret share is mapped deterministically onto the target
// scheme's key space; these are the only sanctioned implementations.

// SignECDSAWithSecret signs message with an ECDSA key derived from the
// reconstructed threshold secret on the curve selected by algorithm.
func SignECDSAWithSecret(secret *big.Int, algorithm string, message []byte, digestHex string) (map[string]interface{}, error) {
	curve, curveName, compat := resolveECDSACurve(algorithm)
	orderMinusOne := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d := new(big.Int).Mod(secret, orderMinusOne)
	d.Add(d, big.NewInt(1))

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         d,
	}
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	sigASN1, err := ecdsa.SignASN1(pkgcrypto.Reader, priv, message)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign failed: %w", err)
	}
	out := map[string]interface{}{
		"signature":          base64.StdEncoding.EncodeToString(sigASN1),
		"signature_b64":      base64.StdEncoding.EncodeToString(sigASN1),
		"signature_hex":      hex.EncodeToString(sigASN1),
		"signature_encoding": "ASN.1 DER",
		"algorithm":          fmt.Sprintf("ECDSA-%s", curveName),
		"message_digest":     digestHex,
	}
	pubDER, pubErr := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if pubErr == nil {
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		pubFP := sha256.Sum256(pubDER)
		out["public_key_pem"] = string(pubPEM)
		out["public_key_fingerprint"] = hex.EncodeToString(pubFP[:])
	} else {
		pubRaw := elliptic.Marshal(curve, priv.PublicKey.X, priv.PublicKey.Y)
		pubFP := sha256.Sum256(pubRaw)
		out["public_key_format"] = "SEC1_UNCOMPRESSED"
		out["public_key_uncompressed_hex"] = hex.EncodeToString(pubRaw)
		out["public_key_fingerprint"] = hex.EncodeToString(pubFP[:])
		compat = append(compat, "pkix_public_key_encoding_unavailable_for_curve")
	}
	if len(compat) > 0 {
		out["compatibility_notes"] = compat
	}
	return out, nil
}

// SignEd25519WithSecret signs message with an Ed25519 key seeded from the
// reconstructed threshold secret.
func SignEd25519WithSecret(secret *big.Int, algorithm string, message []byte, digestHex string) (map[string]interface{}, error) {
	seedHash := sha256.Sum256(secret.Bytes())
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, seedHash[:])
	defer pkgcrypto.Zeroize(seed)

	priv := ed25519.NewKeyFromSeed(seed)
	defer pkgcrypto.Zeroize(priv)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, message)

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key failed: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubFP := sha256.Sum256(pubDER)

	alg := strings.TrimSpace(algorithm)
	if alg == "" {
		alg = "Ed25519"
	}
	return map[string]interface{}{
		"signature":              base64.StdEncoding.EncodeToString(sig),
		"signature_b64":          base64.StdEncoding.EncodeToString(sig),
		"signature_hex":          hex.EncodeToString(sig),
		"signature_encoding":     "RAW",
		"algorithm":              alg,
		"message_digest":         digestHex,
		"public_key_pem":         string(pubPEM),
		"public_key_fingerprint": hex.EncodeToString(pubFP[:]),
	}, nil
}

// DeriveAES256Key derives the AES-256 key for threshold decryption from the
// reconstructed secret.
func DeriveAES256Key(secret *big.Int) []byte {
	sum := sha256.Sum256(secret.Bytes())
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return key
}

// GCMOpenFlexibleNonce decrypts AES-GCM accepting any caller-supplied nonce
// size (threshold payloads arrive from external tooling with varied formats).
func GCMOpenFlexibleNonce(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, fmt.Errorf("gcm init failed: %w", err)
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// XORDecryptWithSecret implements the legacy XOR fallback for ciphertexts
// produced before AES-GCM threshold payloads were introduced.
func XORDecryptWithSecret(secret *big.Int, ciphertext []byte) []byte {
	secretBytes := secret.Bytes()
	if len(secretBytes) == 0 {
		secretBytes = []byte{0}
	}
	defer pkgcrypto.Zeroize(secretBytes)

	key := sha256.Sum256(secretBytes)
	keyBytes := key[:]
	defer pkgcrypto.Zeroize(keyBytes)

	out := make([]byte, len(ciphertext))
	for i := range ciphertext {
		out[i] = ciphertext[i] ^ keyBytes[i%len(keyBytes)]
	}
	return out
}

func resolveECDSACurve(algorithm string) (elliptic.Curve, string, []string) {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "P521"):
		return elliptic.P521(), "P-521", nil
	case strings.Contains(alg, "P384"):
		return elliptic.P384(), "P-384", nil
	case strings.Contains(alg, "SECP256K1"):
		return secp256k1.S256(), "secp256k1", nil
	default:
		return elliptic.P256(), "P-256", nil
	}
}
