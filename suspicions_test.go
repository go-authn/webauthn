// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

// The eight points of order dividing 8 on edwards25519, canonical encodings
// (the non-canonical ones are refused by the y < p check).
var smallOrder = []string{
	"0100000000000000000000000000000000000000000000000000000000000000", // identity
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
}

// Suspicion 8: a small-order public key makes signatures forgeable without a
// secret (the identity point verifies R = identity, S = 0 over ANY message),
// so it is not a credential. The registration refuses every one.
func TestSmallOrderEd25519KeysAreRefused(t *testing.T) {
	for _, h := range smallOrder {
		pub, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519OnCurve(pub) {
			t.Fatalf("%s is not a point: the list is wrong", h)
		}
		key := enc(m(int64(1), int64(1), int64(3), int64(-8), int64(-1), int64(6), int64(-2), pub))
		if _, err := parseCOSEKey(key); !errors.Is(err, ErrKey) {
			t.Errorf("%s: small-order key accepted (%v)", h, err)
		}
	}
	// The forgery the refusal is about, with the identity key: R = identity,
	// S = 0 verifies over a message nobody signed.
	id, _ := hex.DecodeString(smallOrder[0])
	forged := append(append([]byte(nil), id...), make([]byte, 32)...)
	if !ed25519.Verify(ed25519.PublicKey(id), []byte("anything"), forged) {
		t.Skip("this toolchain's ed25519.Verify refuses small-order keys itself")
	}
}

// Suspicion 7: verify has no default case, so a coseKey whose pub is none of
// the three types would verify anything. Nothing builds one -- parseCOSEKey is
// the only constructor and returns exactly those three -- but the method must
// not rest on that.
func TestVerifyFailsClosedOnAnUnknownKey(t *testing.T) {
	k := &coseKey{alg: AlgES256, pub: "not a key"}
	if err := k.verify([]byte("m"), []byte("s")); !errors.Is(err, ErrKey) {
		t.Fatalf("an unknown key type verified: %v", err)
	}
}
