package payment

import (
	"bytes"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type TR31Block struct {
	Version   string
	Algorithm string
	Usage     string
	Key       []byte
	KCV       string
}

func BuildTR31(block TR31Block) (string, error) {
	if block.Version != "B" && block.Version != "D" {
		return "", errors.New("unsupported TR-31 version")
	}
	payload := base64.StdEncoding.EncodeToString(block.Key)
	return fmt.Sprintf("%s|%s|%s|%s|%s", block.Version, block.Algorithm, block.Usage, payload, block.KCV), nil
}

func ParseTR31(raw string) (TR31Block, error) {
	parts := strings.Split(raw, "|")
	if len(parts) != 5 {
		return TR31Block{}, errors.New("invalid TR-31 payload")
	}
	key, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return TR31Block{}, err
	}
	return TR31Block{
		Version:   parts[0],
		Algorithm: parts[1],
		Usage:     parts[2],
		Key:       key,
		KCV:       parts[4],
	}, nil
}

func TranslatePINBlockISO0ToISO4(iso0 string) (string, error) {
	if len(iso0) != 16 {
		return "", errors.New("iso-0 block must be 16 hex chars")
	}
	return "4" + iso0[1:], nil
}

func TranslatePINBlockISO4ToISO0(iso4 string) (string, error) {
	if len(iso4) != 16 {
		return "", errors.New("iso-4 block must be 16 hex chars")
	}
	return "0" + iso4[1:], nil
}

func ComputeCVV(cvk []byte, pan string, expiryYYMM string, serviceCode string) (string, error) {
	mac := hmac.New(sha1.New, cvk)
	_, _ = mac.Write([]byte(pan + expiryYYMM + serviceCode))
	sum := mac.Sum(nil)
	v := int(sum[0])<<8 | int(sum[1])
	return fmt.Sprintf("%03d", v%1000), nil
}

// RetailMACANSI919 computes a two-key 3DES retail MAC.
func RetailMACANSI919(key16 []byte, msg []byte) ([]byte, error) {
	if len(key16) != 16 {
		return nil, errors.New("key must be 16 bytes (K1||K2)")
	}
	k1 := key16[:8]
	k2 := key16[8:]
	blk1, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 8)
	padded := iso9797M2Pad(msg, 8)
	state := make([]byte, 8)
	copy(state, iv)
	for i := 0; i < len(padded); i += 8 {
		block := xor8(state, padded[i:i+8])
		blk1.Encrypt(state, block)
	}
	blk2, err := des.NewCipher(k2)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	blk2.Decrypt(out, state)
	blk1.Encrypt(out, out)
	return out, nil
}

func iso9797M2Pad(data []byte, bs int) []byte {
	out := append([]byte{}, data...)
	out = append(out, 0x80)
	for len(out)%bs != 0 {
		out = append(out, 0x00)
	}
	return out
}

func xor8(a []byte, b []byte) []byte {
	out := bytes.Repeat([]byte{0}, 8)
	for i := 0; i < 8; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func MustDecimal(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
