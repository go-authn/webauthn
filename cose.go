// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// COSE algorithm identifiers (RFC 9053 §2.1, §2.2; RFC 8812 §2 for RS256).
const (
	AlgES256 int64 = -7   // ECDSA with P-256 and SHA-256
	AlgEdDSA int64 = -8   // EdDSA, here Ed25519
	AlgRS256 int64 = -257 // RSASSA-PKCS1-v1_5 with SHA-256
)

// COSE_Key parameter labels (RFC 9052 §7.1) and key-type parameters
// (RFC 9053 §7.1 and §7.2 for EC2 and OKP, RFC 8230 §4 for RSA).
const (
	coseKty  int64 = 1
	coseAlg  int64 = 3
	coseCrv  int64 = -1 // EC2/OKP crv; RSA n
	coseX    int64 = -2 // EC2/OKP x;   RSA e
	coseY    int64 = -3 // EC2 y
	ktyOKP   int64 = 1
	ktyEC2   int64 = 2
	ktyRSA   int64 = 3
	crvP256  int64 = 1
	crvEd255 int64 = 6
)

const (
	minRSABits = 2048
	maxRSABits = 8192
	maxRSAExp  = 1<<31 - 1
)

// coseKey is a parsed, validated public key.
type coseKey struct {
	alg int64
	pub crypto.PublicKey // *ecdsa.PublicKey, ed25519.PublicKey or *rsa.PublicKey
}

// parseCOSEKey reads a COSE_Key (RFC 9052 §7) as a CTAP2 authenticator
// writes it, and refuses it unless it is one of the three keys this package
// verifies, exactly: the labels of its key type and no others, the
// coordinate lengths RFC 9053 fixes, a point ON the curve, and an RSA modulus
// of at least 2048 bits.
func parseCOSEKey(raw []byte) (*coseKey, error) {
	v, err := decodeCBORExact(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: COSE key: %w", ErrKey, err)
	}
	m, ok := v.(cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: COSE key is %T, not a map", ErrKey, v)
	}
	for _, p := range m {
		if _, ok := p.Key.(int64); !ok {
			return nil, fmt.Errorf("%w: COSE key has the text label %q", ErrKey, p.Key)
		}
	}
	kty, okK := intParam(m, coseKty)
	alg, okA := intParam(m, coseAlg)
	if !okK || !okA {
		return nil, fmt.Errorf("%w: COSE key lacks kty or alg", ErrKey)
	}
	switch alg {
	case AlgES256:
		return parseEC2(m, kty)
	case AlgEdDSA:
		return parseOKP(m, kty)
	case AlgRS256:
		return parseRSA(m, kty)
	}
	return nil, fmt.Errorf("%w: %d (only ES256 -7, EdDSA -8 and RS256 -257)", ErrAlgorithm, alg)
}

func intParam(m cborMap, label int64) (int64, bool) {
	v, ok := m.get(label)
	if !ok {
		return 0, false
	}
	n, ok := v.(int64)
	return n, ok
}

func bytesParam(m cborMap, label int64) ([]byte, bool) {
	v, _ := m.get(label)
	b, ok := v.([]byte)
	return b, ok
}

// onlyLabels refuses a key carrying a label outside the set its type defines:
// an authenticator emits none, and what is not read must not be there.
func onlyLabels(m cborMap, labels ...int64) error {
	if len(m) != len(labels) {
		return fmt.Errorf("%w: COSE key has %d parameters, its type has %d", ErrKey, len(m), len(labels))
	}
	for _, l := range labels {
		if _, ok := m.get(l); !ok {
			return fmt.Errorf("%w: COSE key lacks parameter %d", ErrKey, l)
		}
	}
	return nil
}

func parseEC2(m cborMap, kty int64) (*coseKey, error) {
	if kty != ktyEC2 {
		return nil, fmt.Errorf("%w: ES256 needs kty 2 (EC2), got %d", ErrKey, kty)
	}
	if err := onlyLabels(m, coseKty, coseAlg, coseCrv, coseX, coseY); err != nil {
		return nil, err
	}
	if crv, _ := intParam(m, coseCrv); crv != crvP256 {
		return nil, fmt.Errorf("%w: ES256 needs crv 1 (P-256), got %d", ErrKey, crv)
	}
	x, okx := bytesParam(m, coseX)
	y, oky := bytesParam(m, coseY)
	if !okx || !oky || len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: P-256 coordinates must be 32-byte strings (RFC 9053 §7.1.1)", ErrKey)
	}
	// ParseUncompressedPublicKey rejects a point that is not on the curve
	// and the point at infinity.
	pt := make([]byte, 0, 65)
	pt = append(append(append(pt, 4), x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		return nil, fmt.Errorf("%w: the point is not on P-256", ErrKey)
	}
	return &coseKey{alg: AlgES256, pub: pub}, nil
}

func parseOKP(m cborMap, kty int64) (*coseKey, error) {
	if kty != ktyOKP {
		return nil, fmt.Errorf("%w: EdDSA needs kty 1 (OKP), got %d", ErrKey, kty)
	}
	if err := onlyLabels(m, coseKty, coseAlg, coseCrv, coseX); err != nil {
		return nil, err
	}
	if crv, _ := intParam(m, coseCrv); crv != crvEd255 {
		return nil, fmt.Errorf("%w: EdDSA needs crv 6 (Ed25519), got %d", ErrKey, crv)
	}
	x, ok := bytesParam(m, coseX)
	if !ok || len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 key must be a 32-byte string (RFC 8032 §5.1.5)", ErrKey)
	}
	if !ed25519OnCurve(x) {
		return nil, fmt.Errorf("%w: the point is not on edwards25519", ErrKey)
	}
	return &coseKey{alg: AlgEdDSA, pub: ed25519.PublicKey(append([]byte(nil), x...))}, nil
}

func parseRSA(m cborMap, kty int64) (*coseKey, error) {
	if kty != ktyRSA {
		return nil, fmt.Errorf("%w: RS256 needs kty 3 (RSA), got %d", ErrKey, kty)
	}
	if err := onlyLabels(m, coseKty, coseAlg, coseCrv, coseX); err != nil {
		return nil, err
	}
	nb, okn := bytesParam(m, coseCrv)
	eb, oke := bytesParam(m, coseX)
	if !okn || !oke || len(nb) == 0 || len(eb) == 0 {
		return nil, fmt.Errorf("%w: RSA n and e must be byte strings", ErrKey)
	}
	// RFC 8017 integers are big-endian and unsigned; a leading zero is a
	// second encoding of the same number.
	if nb[0] == 0 || eb[0] == 0 {
		return nil, fmt.Errorf("%w: RSA n or e has a leading zero byte", ErrKey)
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < minRSABits || n.BitLen() > maxRSABits {
		return nil, fmt.Errorf("%w: RSA modulus of %d bits (need %d to %d)", ErrKey, n.BitLen(), minRSABits, maxRSABits)
	}
	if n.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: RSA modulus is even", ErrKey)
	}
	if len(eb) > 4 {
		return nil, fmt.Errorf("%w: RSA exponent too large", ErrKey)
	}
	e := new(big.Int).SetBytes(eb)
	if e.Cmp(big.NewInt(65537)) < 0 || e.Cmp(big.NewInt(maxRSAExp)) > 0 || e.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: RSA exponent must be odd and in 65537..2^31-1", ErrKey)
	}
	return &coseKey{alg: AlgRS256, pub: &rsa.PublicKey{N: n, E: int(e.Int64())}}, nil
}

// verify checks sig over msg with the key's algorithm. ES256 takes the ASN.1
// DER signature WebAuthn defines (§6.5.5), RS256 PKCS#1 v1.5, EdDSA the raw
// 64 bytes.
func (k *coseKey) verify(msg, sig []byte) error {
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(pub, h[:], sig) {
			return fmt.Errorf("%w: ES256", ErrSignature)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, msg, sig) {
			return fmt.Errorf("%w: EdDSA", ErrSignature)
		}
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) != nil {
			return fmt.Errorf("%w: RS256", ErrSignature)
		}
	}
	return nil
}

var (
	ed25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// d = -121665/121666 mod p (RFC 8032 §5.1).
	ed25519D = func() *big.Int {
		inv := new(big.Int).ModInverse(big.NewInt(121666), ed25519P)
		d := new(big.Int).Mul(big.NewInt(-121665), inv)
		return d.Mod(d, ed25519P)
	}()
)

// ed25519OnCurve decodes a point as RFC 8032 §5.1.3 does and reports whether
// it exists: y canonical (below p), x^2 = (y^2-1)/(d y^2+1) a square, and no
// "negative zero". Verification would fail on an off-curve key anyway; this
// refuses it at enrolment, where it can be named.
func ed25519OnCurve(enc []byte) bool {
	var le [32]byte
	copy(le[:], enc)
	sign := le[31] >> 7
	le[31] &= 0x7f
	var be [32]byte
	for i := range le {
		be[31-i] = le[i]
	}
	y := new(big.Int).SetBytes(be[:])
	if y.Cmp(ed25519P) >= 0 {
		return false
	}
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, ed25519P)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, ed25519P)
	v := new(big.Int).Mul(ed25519D, y2)
	v.Add(v, big.NewInt(1))
	v.Mod(v, ed25519P)
	x2 := u.Mul(u, new(big.Int).ModInverse(v, ed25519P))
	x2.Mod(x2, ed25519P)
	if x2.Sign() == 0 {
		return sign == 0
	}
	// Euler's criterion: x2 is a square iff x2^((p-1)/2) == 1.
	exp := new(big.Int).Rsh(new(big.Int).Sub(ed25519P, big.NewInt(1)), 1)
	return new(big.Int).Exp(x2, exp, ed25519P).Cmp(big.NewInt(1)) == 0
}
