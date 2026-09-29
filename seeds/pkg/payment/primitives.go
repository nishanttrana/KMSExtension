// primitives.go holds the payment-industry cryptographic primitives required
// by retail payment standards (PVV, CVV, PIN blocks, ISO 9797 MACs, key check
// values). DES/TDES use here is mandated by the standards themselves; this
// package is the only sanctioned home for it — services must not implement
// these primitives locally.
package payment

import (
	"crypto/aes"
	"crypto/des"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// NormalizeTDESKey expands a 16-byte double-length key to 24 bytes (K1K2K1)
// or copies a 24-byte triple-length key.
func NormalizeTDESKey(raw []byte) ([]byte, error) {
	switch len(raw) {
	case 16:
		out := make([]byte, 24)
		copy(out[:16], raw)
		copy(out[16:], raw[:8])
		return out, nil
	case 24:
		out := make([]byte, 24)
		copy(out, raw)
		return out, nil
	default:
		return nil, errors.New("3DES key must be 16 or 24 bytes")
	}
}

// TDESECBEncrypt encrypts a single 8-byte block with 3DES in ECB mode, as
// required by PVV/CVV computation.
func TDESECBEncrypt(key24 []byte, block8 []byte) ([]byte, error) {
	if len(block8) != 8 {
		return nil, errors.New("block must be 8 bytes")
	}
	c, err := des.NewTripleDESCipher(key24)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	c.Encrypt(out, block8)
	return out, nil
}

// TDESECBDecrypt decrypts a single 8-byte 3DES ECB block.
func TDESECBDecrypt(key24 []byte, block8 []byte) ([]byte, error) {
	if len(block8) != 8 {
		return nil, errors.New("block must be 8 bytes")
	}
	c, err := des.NewTripleDESCipher(key24)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	c.Decrypt(out, block8)
	return out, nil
}

// ISO9797Alg1MAC computes an ISO 9797-1 Algorithm 1 (CBC-MAC) over msg with
// single-DES, using method 2 padding.
func ISO9797Alg1MAC(key []byte, msg []byte) ([]byte, error) {
	if len(key) != 8 {
		return nil, errors.New("iso9797 alg1 key must be 8 bytes")
	}
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := ISO9797Method2Pad(msg, 8)
	state := make([]byte, 8)
	tmp := make([]byte, 8)
	for i := 0; i < len(padded); i += 8 {
		copy(tmp, padded[i:i+8])
		for j := 0; j < 8; j++ {
			tmp[j] ^= state[j]
		}
		blk.Encrypt(state, tmp)
	}
	return append([]byte{}, state...), nil
}

// ISO9797Method2Pad appends 0x80 then zero bytes up to the block size.
func ISO9797Method2Pad(data []byte, blockSize int) []byte {
	out := append([]byte{}, data...)
	out = append(out, 0x80)
	for len(out)%blockSize != 0 {
		out = append(out, 0x00)
	}
	return out
}

// AESCMAC computes AES-CMAC (NIST SP 800-38B) over msg.
func AESCMAC(key []byte, msg []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("cmac key must be 16/24/32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	constRb := byte(0x87)
	zero := make([]byte, 16)
	l := make([]byte, 16)
	block.Encrypt(l, zero)
	k1 := leftShiftOne(l)
	if (l[0] & 0x80) != 0 {
		k1[15] ^= constRb
	}
	k2 := leftShiftOne(k1)
	if (k1[0] & 0x80) != 0 {
		k2[15] ^= constRb
	}

	m := ISO9797Method2Pad(msg, 16)
	lastComplete := len(msg) > 0 && len(msg)%16 == 0
	if lastComplete {
		m = append([]byte{}, msg...)
		xorInPlace(m[len(m)-16:], k1)
	} else {
		xorInPlace(m[len(m)-16:], k2)
	}

	x := make([]byte, 16)
	tmp := make([]byte, 16)
	for i := 0; i < len(m); i += 16 {
		copy(tmp, m[i:i+16])
		xorInPlace(tmp, x)
		block.Encrypt(x, tmp)
	}
	return append([]byte{}, x...), nil
}

func leftShiftOne(in []byte) []byte {
	out := make([]byte, len(in))
	carry := byte(0)
	for i := len(in) - 1; i >= 0; i-- {
		nextCarry := (in[i] >> 7) & 0x01
		out[i] = (in[i] << 1) | carry
		carry = nextCarry
	}
	return out
}

func xorInPlace(dst []byte, src []byte) {
	for i := 0; i < len(dst) && i < len(src); i++ {
		dst[i] ^= src[i]
	}
}

// ComputeKCV derives a 3-byte key check value by encrypting a zero block
// with the key (AES or DES/TDES selected by hint or key length).
func ComputeKCV(key []byte, algorithmHint string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("empty key material")
	}
	algo := strings.ToUpper(strings.TrimSpace(algorithmHint))
	var first []byte

	switch {
	case strings.Contains(algo, "AES"):
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return "", errors.New("aes key must be 16/24/32 bytes for kcv")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		out := make([]byte, aes.BlockSize)
		block.Encrypt(out, make([]byte, aes.BlockSize))
		first = out[:3]
	case strings.Contains(algo, "TDES"), strings.Contains(algo, "3DES"), strings.Contains(algo, "DES"), len(key) == 8, len(key) == 16:
		if len(key) == 8 {
			block, err := des.NewCipher(key)
			if err != nil {
				return "", err
			}
			out := make([]byte, 8)
			block.Encrypt(out, make([]byte, 8))
			first = out[:3]
			break
		}
		tdesKey, err := NormalizeTDESKey(key)
		if err != nil {
			return "", err
		}
		out, err := TDESECBEncrypt(tdesKey, make([]byte, 8))
		if err != nil {
			return "", err
		}
		first = out[:3]
	default:
		switch len(key) {
		case 24:
			tdesKey, err := NormalizeTDESKey(key)
			if err != nil {
				return "", err
			}
			out, err := TDESECBEncrypt(tdesKey, make([]byte, 8))
			if err != nil {
				return "", err
			}
			first = out[:3]
		case 32:
			block, err := aes.NewCipher(key)
			if err != nil {
				return "", err
			}
			out := make([]byte, aes.BlockSize)
			block.Encrypt(out, make([]byte, aes.BlockSize))
			first = out[:3]
		default:
			return "", errors.New("unsupported key length for kcv")
		}
	}
	return strings.ToUpper(hex.EncodeToString(first)), nil
}

// XORHex XORs two equal-length even-sized hex strings.
func XORHex(a string, b string) (string, error) {
	a = strings.ToUpper(strings.TrimSpace(a))
	b = strings.ToUpper(strings.TrimSpace(b))
	if len(a) != len(b) || len(a)%2 != 0 {
		return "", errors.New("hex values must have equal even length")
	}
	ab, err := hex.DecodeString(a)
	if err != nil {
		return "", errors.New("invalid hex value")
	}
	bb, err := hex.DecodeString(b)
	if err != nil {
		return "", errors.New("invalid hex value")
	}
	out := make([]byte, len(ab))
	for i := range ab {
		out[i] = ab[i] ^ bb[i]
	}
	return strings.ToUpper(hex.EncodeToString(out)), nil
}

func sanitizeDigits(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errors.New("value is required")
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return "", errors.New("value must be numeric")
		}
	}
	return v, nil
}

func extractPAN12(pan string) (string, error) {
	pan, err := sanitizeDigits(pan)
	if err != nil {
		return "", errors.New("pan is required and must be numeric")
	}
	if len(pan) < 13 {
		return "", errors.New("pan must be at least 13 digits")
	}
	noCheck := pan[:len(pan)-1]
	if len(noCheck) < 12 {
		return "", errors.New("pan must contain at least 12 digits excluding check digit")
	}
	return noCheck[len(noCheck)-12:], nil
}

// BuildPINClearBlock constructs an ISO 9564 clear PIN block (ISO-0/1/3).
func BuildPINClearBlock(format string, pin string, pan string) ([]byte, error) {
	pin, err := sanitizeDigits(pin)
	if err != nil {
		return nil, errors.New("pin is required and must be numeric")
	}
	if len(pin) < 4 || len(pin) > 12 {
		return nil, errors.New("pin length must be between 4 and 12")
	}
	var formatNibble string
	switch format {
	case "ISO-0":
		formatNibble = "0"
	case "ISO-1":
		formatNibble = "1"
	case "ISO-3":
		formatNibble = "3"
	default:
		return nil, errors.New("unsupported pin format for block construction")
	}
	pinField := formatNibble + strings.ToUpper(fmt.Sprintf("%X", len(pin))) + pin
	fill := "F"
	if format == "ISO-3" {
		fill = "A"
	}
	for len(pinField) < 16 {
		pinField += fill
	}
	clearHex := pinField
	if format == "ISO-0" || format == "ISO-3" {
		pan12, err := extractPAN12(pan)
		if err != nil {
			return nil, err
		}
		panField := "0000" + pan12
		clearHex, err = XORHex(pinField, panField)
		if err != nil {
			return nil, err
		}
	}
	block, err := hex.DecodeString(clearHex)
	if err != nil {
		return nil, errors.New("failed to construct pin block")
	}
	return block, nil
}

// DecodePINFromClearBlock extracts the PIN from an ISO 9564 clear PIN block.
func DecodePINFromClearBlock(format string, clear []byte, pan string) (string, error) {
	if len(clear) != 8 {
		return "", errors.New("clear pin block must be 8 bytes")
	}
	clearHex := strings.ToUpper(hex.EncodeToString(clear))
	pinField := clearHex
	if format == "ISO-0" || format == "ISO-3" {
		pan12, err := extractPAN12(pan)
		if err != nil {
			return "", err
		}
		pinField, err = XORHex(clearHex, "0000"+pan12)
		if err != nil {
			return "", err
		}
	}
	if len(pinField) != 16 {
		return "", errors.New("invalid pin field length")
	}
	formatNibble := pinField[:1]
	switch format {
	case "ISO-0":
		if formatNibble != "0" {
			return "", errors.New("pin field format nibble mismatch")
		}
	case "ISO-1":
		if formatNibble != "1" {
			return "", errors.New("pin field format nibble mismatch")
		}
	case "ISO-3":
		if formatNibble != "3" {
			return "", errors.New("pin field format nibble mismatch")
		}
	default:
		return "", errors.New("unsupported pin format for parsing")
	}
	pinLen, err := strconv.ParseInt(pinField[1:2], 16, 0)
	if err != nil {
		return "", errors.New("invalid pin length nibble")
	}
	if pinLen < 4 || pinLen > 12 {
		return "", errors.New("invalid pin length")
	}
	pin := pinField[2 : 2+pinLen]
	for _, c := range pin {
		if c < '0' || c > '9' {
			return "", errors.New("decoded pin is not numeric")
		}
	}
	return pin, nil
}

// ComputePVVTDES computes a VISA PIN Verification Value with 3DES.
func ComputePVVTDES(key []byte, pin string, pan string, pvki string, decimalizationTable string) (string, error) {
	pin, err := sanitizeDigits(pin)
	if err != nil {
		return "", errors.New("pin is required and must be numeric")
	}
	if len(pin) < 4 {
		return "", errors.New("pin must contain at least 4 digits")
	}
	pan, err = sanitizeDigits(pan)
	if err != nil {
		return "", errors.New("pan is required and must be numeric")
	}
	if len(pan) < 12 {
		return "", errors.New("pan must be at least 12 digits")
	}
	pvki = strings.TrimSpace(pvki)
	if pvki == "" {
		pvki = "1"
	}
	pvki, err = sanitizeDigits(pvki)
	if err != nil {
		return "", errors.New("pvki must be numeric")
	}
	if len(pvki) != 1 {
		return "", errors.New("pvki must be one digit")
	}
	tdesKey, err := NormalizeTDESKey(key)
	if err != nil {
		return "", err
	}
	noCheck := pan
	if len(noCheck) > 0 {
		noCheck = pan[:len(pan)-1]
	}
	if len(noCheck) < 11 {
		return "", errors.New("pan must contain at least 11 digits excluding check digit")
	}
	pan11 := noCheck[len(noCheck)-11:]
	input := pan11 + pvki + pin[:4]
	if len(input) != 16 {
		return "", errors.New("invalid pvv input data length")
	}
	in, err := hex.DecodeString(input)
	if err != nil {
		return "", errors.New("invalid pvv input")
	}
	out, err := TDESECBEncrypt(tdesKey, in)
	if err != nil {
		return "", err
	}
	hexOut := strings.ToUpper(hex.EncodeToString(out))
	if len(decimalizationTable) != 16 {
		decimalizationTable = "0123456789012345"
	}
	table := []byte(decimalizationTable)
	dec := make([]byte, 0, 4)
	for i := 0; i < len(hexOut) && len(dec) < 4; i++ {
		c := hexOut[i]
		var nibble int
		switch {
		case c >= '0' && c <= '9':
			nibble = int(c - '0')
		case c >= 'A' && c <= 'F':
			nibble = int(c-'A') + 10
		default:
			continue
		}
		dec = append(dec, table[nibble])
	}
	for len(dec) < 4 {
		dec = append(dec, '0')
	}
	return string(dec), nil
}

// ComputeCVVTDES computes a card verification value with the standard
// 3DES-based algorithm (CVV/CVC). This is the real algorithm; the legacy
// HMAC-based ComputeCVV in payment.go is retained only for callers that
// stored its outputs.
func ComputeCVVTDES(cvk []byte, pan string, expiryYYMM string, serviceCode string) (string, error) {
	pan, err := sanitizeDigits(pan)
	if err != nil {
		return "", errors.New("pan is required and must be numeric")
	}
	expiryYYMM, err = sanitizeDigits(expiryYYMM)
	if err != nil {
		return "", errors.New("expiry_yymm is required and must be numeric")
	}
	if len(expiryYYMM) != 4 {
		return "", errors.New("expiry_yymm must be 4 digits")
	}
	serviceCode, err = sanitizeDigits(serviceCode)
	if err != nil {
		return "", errors.New("service_code is required and must be numeric")
	}
	if len(serviceCode) != 3 {
		return "", errors.New("service_code must be 3 digits")
	}
	key24, err := NormalizeTDESKey(cvk)
	if err != nil {
		return "", err
	}
	data := pan + expiryYYMM + serviceCode
	for len(data) < 32 {
		data += "0"
	}
	if len(data) > 32 {
		data = data[:32]
	}
	left, err := hex.DecodeString(data[:16])
	if err != nil {
		return "", errors.New("invalid cvv input block")
	}
	right, err := hex.DecodeString(data[16:])
	if err != nil {
		return "", errors.New("invalid cvv input block")
	}
	iRes, err := TDESECBEncrypt(key24, left)
	if err != nil {
		return "", err
	}
	x := make([]byte, 8)
	for i := 0; i < 8; i++ {
		x[i] = iRes[i] ^ right[i]
	}
	oRes, err := TDESECBEncrypt(key24, x)
	if err != nil {
		return "", err
	}
	hexOut := strings.ToUpper(hex.EncodeToString(oRes))
	out := make([]byte, 0, 3)
	for i := 0; i < len(hexOut) && len(out) < 3; i++ {
		c := hexOut[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	for i := 0; i < len(hexOut) && len(out) < 3; i++ {
		c := hexOut[i]
		if c >= 'A' && c <= 'F' {
			out = append(out, byte('0'+(c-'A')))
		}
	}
	for len(out) < 3 {
		out = append(out, '0')
	}
	return string(out), nil
}

// GeneratePINOffset computes the decimal offset between a chosen PIN and a
// derived reference PIN (IBM 3624 method).
func GeneratePINOffset(pin string, referencePIN string) (string, error) {
	pin = strings.TrimSpace(pin)
	referencePIN = strings.TrimSpace(referencePIN)
	if pin == "" || referencePIN == "" {
		return "", errors.New("pin and reference_pin are required")
	}
	if len(pin) != len(referencePIN) {
		return "", errors.New("pin and reference_pin must have same length")
	}
	offset := make([]byte, len(pin))
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' || referencePIN[i] < '0' || referencePIN[i] > '9' {
			return "", errors.New("pin and reference_pin must be numeric")
		}
		d := int(pin[i]-'0') - int(referencePIN[i]-'0')
		if d < 0 {
			d += 10
		}
		offset[i] = byte('0' + d)
	}
	return string(offset), nil
}

// VerifyPINOffset checks a PIN offset in constant time.
func VerifyPINOffset(pin string, referencePIN string, offset string) bool {
	gen, err := GeneratePINOffset(pin, referencePIN)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(gen), []byte(strings.TrimSpace(offset))) == 1
}
