// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"errors"
	"testing"
)

// Security audit 2026-11-21, proof F1. WebAuthn L3 §6.1.1: "If either is
// non-zero, and the new signCount value is less than or equal to the stored
// value, a cloned authenticator may exist". VerifyAssertion requires BOTH to
// be non-zero, so a credential whose stored counter is 5 is accepted with a
// presented counter of 0, and the Result tells the caller to store 0 back:
// from then on the clone check is off for that credential.
func TestSecAudit5CounterResetToZeroIsRefused(t *testing.T) {
	a := newAuthn(t, AlgES256)
	regCD, regAO := register(a)
	cred, err := testRP.VerifyRegistration(testChall, regCD, regAO, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	cred.SignCount = 5 // the genuine authenticator has signed five times

	// The clone reports zero.
	cd, ad, sig := assert(a, flagsOK, 0)
	res, err := testRP.VerifyAssertion(testChall, cred, cd, ad, sig, Policy{})
	if !errors.Is(err, ErrSignCount) {
		t.Errorf("stored 5, presented 0: want ErrSignCount, got err=%v result=%+v", err, res)
	}

	// What follows when the caller stores the Result back, as documented: the
	// clone and the original now both pass with ANY counter, replayed or not.
	// A refused assertion yields no Result worth storing: the caller keeps 5.
	if err == nil {
		cred.SignCount = res.SignCount
	}
	cd, ad, sig = assert(a, flagsOK, 3) // below the 5 already seen
	if _, err := testRP.VerifyAssertion(testChall, cred, cd, ad, sig, Policy{}); !errors.Is(err, ErrSignCount) {
		t.Errorf("counter 3 (below the 5 once stored): want ErrSignCount, got %v", err)
	}
	cd, ad, sig = assert(a, flagsOK, 6)
	if _, err := testRP.VerifyAssertion(testChall, cred, cd, ad, sig, Policy{}); err != nil {
		t.Errorf("counter 6 after 5 must pass: %v", err)
	}
}
