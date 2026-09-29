package payment

import (
	"encoding/hex"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

func TestTR31RoundTrip(t *testing.T) {
	b := TR31Block{
		Version:   "B",
		Algorithm: "AES",
		Usage:     "K0",
		Key:       []byte("1234567890ABCDEF"),
		KCV:       "A1B2C3",
	}
	raw, err := BuildTR31(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseTR31(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != b.Version || out.Algorithm != b.Algorithm || out.Usage != b.Usage || out.KCV != b.KCV || string(out.Key) != string(b.Key) {
		t.Fatalf("round-trip mismatch: %#v vs %#v", out, b)
	}
}

func TestRetailMAC(t *testing.T) {
	fipstest.SkipIfStrict(t, "DES retail MAC (ISO 9797-1 alg 3)")
	key := []byte("12345678ABCDEFGH")
	mac, err := RetailMACANSI919(key, []byte("hello-payment"))
	if err != nil {
		t.Fatal(err)
	}
	if len(mac) != 8 {
		t.Fatal("retail mac length should be 8")
	}
	if hex.EncodeToString(mac) == "0000000000000000" {
		t.Fatal("retail mac should be non-zero")
	}
}

func TestStrictModeRefusesDESMAC(t *testing.T) {
	fipstest.StrictOnly(t)
	if _, err := RetailMACANSI919([]byte("12345678ABCDEFGH"), []byte("hello-payment")); err == nil {
		t.Fatal("strict mode must refuse the DES retail MAC with an error")
	}
}
