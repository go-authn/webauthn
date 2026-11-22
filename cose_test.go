// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
)

func ec2Key(alg int64, kty, crv int64, x, y []byte) []byte {
	return enc(m(int64(1), kty, int64(3), alg, int64(-1), crv, int64(-2), x, int64(-3), y))
}

func TestCOSEKeysAccepted(t *testing.T) {
	for _, alg := range allAlgs {
		a := newAuthn(t, alg)
		k, err := parseCOSEKey(a.cose)
		if err != nil || k.alg != alg {
			t.Fatalf("alg %d: %v", alg, err)
		}
		msg := []byte("message")
		if err := k.verify(msg, a.sign(msg)); err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		if err := k.verify(msg, []byte("no")); !errors.Is(err, ErrSignature) {
			t.Fatalf("alg %d: %v", alg, err)
		}
	}
}

func TestCOSEKeyRefusals(t *testing.T) {
	es := newAuthn(t, AlgES256)
	em, _ := decodeCBORExact(es.cose)
	x, _ := bytesParam(em.(cborMap), coseX)
	y, _ := bytesParam(em.(cborMap), coseY)
	flip := func(b []byte) []byte { c := bytes.Clone(b); c[31] ^= 1; return c }
	rsaN := func(bits int, mut func(*big.Int)) []byte {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		n.Add(n, big.NewInt(12345))
		n.SetBit(n, 0, 1)
		if mut != nil {
			mut(n)
		}
		return n.Bytes()
	}
	rsaKey := func(n, e []byte) []byte {
		return enc(m(int64(1), int64(3), int64(3), int64(-257), int64(-1), n, int64(-2), e))
	}
	// An Ed25519 y that is below p but lies on no point: found, not assumed.
	var offY []byte
	for v := byte(2); v < 100; v++ {
		c := make([]byte, 32)
		c[0] = v
		if !ed25519OnCurve(c) {
			offY = c
			break
		}
	}
	if offY == nil {
		t.Fatal("no off-curve y found")
	}
	pEnc := ed25519P.FillBytes(make([]byte, 32)) // big-endian p, reversed below
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		pEnc[i], pEnc[j] = pEnc[j], pEnc[i]
	}
	negZero := make([]byte, 32)
	negZero[0], negZero[31] = 1, 0x80 // y = 1 (x = 0) with the sign bit set
	okZero := make([]byte, 32)
	okZero[0] = 1
	okp := func(alg, kty, crv int64, x []byte) []byte {
		return enc(m(int64(1), kty, int64(3), alg, int64(-1), crv, int64(-2), x))
	}
	for _, tc := range []struct {
		name string
		key  []byte
		want error
	}{
		{"trailing byte", append(bytes.Clone(es.cose), 0), ErrTrailingBytes},
		{"garbage", []byte{0xff}, ErrCBOR},
		{"not a map", enc([]any{}), ErrKey},
		{"text label", enc(m(int64(1), int64(2), "alg", int64(-7))), ErrKey},
		{"no alg", enc(m(int64(1), int64(2))), ErrKey},
		{"no kty", enc(m(int64(3), int64(-7))), ErrKey},
		{"alg not an int", enc(m(int64(1), int64(2), int64(3), "ES256")), ErrKey},
		{"unknown alg ES384", enc(m(int64(1), int64(2), int64(3), int64(-35))), ErrAlgorithm},
		{"unknown alg RS1", enc(m(int64(1), int64(3), int64(3), int64(-65535))), ErrAlgorithm},
		{"unknown alg PS256", enc(m(int64(1), int64(3), int64(3), int64(-37))), ErrAlgorithm},

		{"ES256 with kty OKP", ec2Key(AlgES256, 1, 1, x, y), ErrKey},
		{"ES256 with P-384", ec2Key(AlgES256, 2, 2, x, y), ErrKey},
		{"ES256 short x", ec2Key(AlgES256, 2, 1, x[:31], y), ErrKey},
		{"ES256 long y", ec2Key(AlgES256, 2, 1, x, append(bytes.Clone(y), 0)), ErrKey},
		{"ES256 x not bytes", enc(m(int64(1), int64(2), int64(3), int64(-7), int64(-1), int64(1), int64(-2), "x", int64(-3), y)), ErrKey},
		{"ES256 off the curve", ec2Key(AlgES256, 2, 1, x, flip(y)), ErrKey},
		{"ES256 infinity", ec2Key(AlgES256, 2, 1, make([]byte, 32), make([]byte, 32)), ErrKey},
		{"ES256 extra label", enc(m(int64(1), int64(2), int64(2), []byte{1}, int64(3), int64(-7), int64(-1), int64(1), int64(-2), x, int64(-3), y)), ErrKey},
		{"ES256 missing y", enc(m(int64(1), int64(2), int64(3), int64(-7), int64(-1), int64(1), int64(-2), x, int64(-4), y)), ErrKey},
		{"ES256 crv absent", enc(m(int64(1), int64(2), int64(3), int64(-7), int64(-2), x, int64(-3), y, int64(-5), y)), ErrKey},

		{"EdDSA with kty EC2", okp(AlgEdDSA, 2, 6, okZero), ErrKey},
		{"EdDSA with X25519", okp(AlgEdDSA, 1, 4, okZero), ErrKey},
		{"EdDSA short key", okp(AlgEdDSA, 1, 6, okZero[:31]), ErrKey},
		{"EdDSA off the curve", okp(AlgEdDSA, 1, 6, offY), ErrKey},
		{"EdDSA y not below p", okp(AlgEdDSA, 1, 6, pEnc), ErrKey},
		{"EdDSA negative zero", okp(AlgEdDSA, 1, 6, negZero), ErrKey},
		{"EdDSA extra y", enc(m(int64(1), int64(1), int64(3), int64(-8), int64(-1), int64(6), int64(-2), okZero, int64(-3), okZero)), ErrKey},

		{"RS256 with kty EC2", enc(m(int64(1), int64(2), int64(3), int64(-257), int64(-1), rsaN(2048, nil), int64(-2), []byte{1, 0, 1})), ErrKey},
		{"RS256 1024 bits", rsaKey(rsaN(1024, nil), []byte{1, 0, 1}), ErrKey},
		{"RS256 2047 bits", rsaKey(rsaN(2047, nil), []byte{1, 0, 1}), ErrKey},
		{"RS256 8193 bits", rsaKey(rsaN(8193, nil), []byte{1, 0, 1}), ErrKey},
		{"RS256 even modulus", rsaKey(rsaN(2048, func(n *big.Int) { n.SetBit(n, 0, 0) }), []byte{1, 0, 1}), ErrKey},
		{"RS256 leading zero in n", rsaKey(append([]byte{0}, rsaN(2048, nil)...), []byte{1, 0, 1}), ErrKey},
		{"RS256 leading zero in e", rsaKey(rsaN(2048, nil), []byte{0, 1, 0, 1}), ErrKey},
		{"RS256 e = 3", rsaKey(rsaN(2048, nil), []byte{3}), ErrKey},
		{"RS256 e even", rsaKey(rsaN(2048, nil), []byte{1, 0, 2}), ErrKey},
		{"RS256 e = 2^31+1", rsaKey(rsaN(2048, nil), []byte{0x80, 0, 0, 1}), ErrKey},
		{"RS256 e five bytes", rsaKey(rsaN(2048, nil), []byte{1, 0, 0, 0, 1}), ErrKey},
		{"RS256 n empty", rsaKey(nil, []byte{1, 0, 1}), ErrKey},
		{"RS256 n not bytes", enc(m(int64(1), int64(3), int64(3), int64(-257), int64(-1), "n", int64(-2), []byte{1, 0, 1})), ErrKey},
		{"RS256 extra label", enc(m(int64(1), int64(3), int64(3), int64(-257), int64(-1), rsaN(2048, nil), int64(-2), []byte{1, 0, 1}, int64(-3), []byte{1})), ErrKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCOSEKey(tc.key)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
	// Control: the accepted edge cases next to the refused ones.
	if !ed25519OnCurve(okZero) {
		t.Fatal("y = 1, sign clear, is the identity point and exists")
	}
	if _, err := parseCOSEKey(okp(AlgEdDSA, 1, 6, okZero)); !errors.Is(err, ErrKey) {
		t.Fatalf("the identity point is a point and not a key: %v", err)
	}
	if _, err := parseCOSEKey(rsaKey(rsaN(2048, nil), []byte{1, 0, 1})); err != nil {
		t.Fatalf("2048 bits: %v", err)
	}
	if _, err := parseCOSEKey(rsaKey(rsaN(8192, nil), []byte{0x7f, 0xff, 0xff, 0xff})); err != nil {
		t.Fatalf("8192 bits, e 2^31-1: %v", err)
	}
	if _, err := parseCOSEKey(rsaKey(rsaN(2048, nil), []byte{1, 0, 1})); err != nil {
		t.Fatal(err)
	}
}

func TestEd25519OnCurveAgreesWithStdlibVerify(t *testing.T) {
	// A key the standard library generated is on the curve by our check.
	for i := 0; i < 50; i++ {
		a := newAuthn(t, AlgEdDSA)
		if _, err := parseCOSEKey(a.cose); err != nil {
			t.Fatal(err)
		}
	}
}
