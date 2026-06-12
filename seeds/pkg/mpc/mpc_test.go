package mpc

import (
	"math/big"
	"testing"
)

func TestShamirSplitCombine(t *testing.T) {
	secret := big.NewInt(424242)
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Combine(shares[:3])
	if err != nil {
		t.Fatal(err)
	}
	if out.Cmp(secret) != 0 {
		t.Fatalf("got %s want %s", out.String(), secret.String())
	}
}
