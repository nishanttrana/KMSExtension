package mpc

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type Share struct {
	X *big.Int
	Y *big.Int
}

var Prime = mustPrime("170141183460469231731687303715884105727") // 2^127-1

func Split(secret *big.Int, threshold int, parts int) ([]Share, error) {
	if threshold < 2 || threshold > parts {
		return nil, errors.New("invalid threshold")
	}
	coeffs := make([]*big.Int, threshold)
	coeffs[0] = new(big.Int).Mod(secret, Prime)
	for i := 1; i < threshold; i++ {
		r, err := rand.Int(rand.Reader, Prime)
		if err != nil {
			return nil, err
		}
		coeffs[i] = r
	}
	shares := make([]Share, 0, parts)
	for i := 1; i <= parts; i++ {
		x := big.NewInt(int64(i))
		y := eval(coeffs, x)
		shares = append(shares, Share{X: x, Y: y})
	}
	return shares, nil
}

func Combine(shares []Share) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares")
	}
	secret := big.NewInt(0)
	for i := range shares {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := range shares {
			if i == j {
				continue
			}
			num.Mul(num, new(big.Int).Neg(shares[j].X))
			num.Mod(num, Prime)
			diff := new(big.Int).Sub(shares[i].X, shares[j].X)
			den.Mul(den, diff)
			den.Mod(den, Prime)
		}
		denInv := new(big.Int).ModInverse(den, Prime)
		if denInv == nil {
			return nil, errors.New("non-invertible share set")
		}
		term := new(big.Int).Mul(shares[i].Y, num)
		term.Mod(term, Prime)
		term.Mul(term, denInv)
		term.Mod(term, Prime)
		secret.Add(secret, term)
		secret.Mod(secret, Prime)
	}
	return secret, nil
}

func FeldmanCommit(coeffs []*big.Int, generator *big.Int) []*big.Int {
	out := make([]*big.Int, len(coeffs))
	for i, c := range coeffs {
		out[i] = new(big.Int).Exp(generator, c, Prime)
	}
	return out
}

func FeldmanVerify(share Share, commitments []*big.Int, generator *big.Int) bool {
	left := new(big.Int).Exp(generator, share.Y, Prime)
	right := big.NewInt(1)
	xPow := big.NewInt(1)
	for _, c := range commitments {
		term := new(big.Int).Exp(c, xPow, Prime)
		right.Mul(right, term)
		right.Mod(right, Prime)
		xPow.Mul(xPow, share.X)
		xPow.Mod(xPow, Prime)
	}
	return left.Cmp(right) == 0
}

func eval(coeffs []*big.Int, x *big.Int) *big.Int {
	res := big.NewInt(0)
	pow := big.NewInt(1)
	for _, c := range coeffs {
		term := new(big.Int).Mul(c, pow)
		term.Mod(term, Prime)
		res.Add(res, term)
		res.Mod(res, Prime)
		pow.Mul(pow, x)
		pow.Mod(pow, Prime)
	}
	return res
}

func mustPrime(v string) *big.Int {
	n, ok := new(big.Int).SetString(v, 10)
	if !ok {
		panic("invalid prime")
	}
	return n
}
