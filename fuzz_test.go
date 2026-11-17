// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Every parser here reads what arrives from a browser the attacker drives.
// Each target states a property, not only "does not panic". The committed
// corpus under testdata/fuzz is replayed by plain `go test`.

func seedVectors(f *testing.F) (regAO, regCD, authAD, authCD, authSig [][]byte) {
	v := loadVectors(f)
	for _, r := range v.Registration {
		regAO = append(regAO, unhex(f, r["attestationObject"]))
		regCD = append(regCD, unhex(f, r["clientDataJSON"]))
	}
	for _, r := range v.Authentication {
		authAD = append(authAD, unhex(f, r["authenticatorData"]))
		authCD = append(authCD, unhex(f, r["clientDataJSON"]))
		authSig = append(authSig, unhex(f, r["signature"]))
	}
	return
}

// FuzzCBOR: whatever decodes re-encodes to the same bytes. That is the
// definition of "one value, one encoding", and it fails on any overlong
// form, unsorted or duplicate key, or indefinite length that slipped by.
func FuzzCBOR(f *testing.F) {
	regAO, _, _, _, _ := seedVectors(f)
	for _, s := range regAO {
		f.Add(s)
	}
	for _, alg := range allAlgs {
		f.Add(newAuthn(f, alg).cose)
	}
	f.Add([]byte{0xa2, 0x01, 0x00, 0x61, 'a', 0x80})
	f.Fuzz(func(t *testing.T, b []byte) {
		v, n, err := decodeCBOR(b)
		if err != nil {
			return
		}
		if n <= 0 || n > len(b) {
			t.Fatalf("consumed %d of %d", n, len(b))
		}
		if got := enc(v); !bytes.Equal(got, b[:n]) {
			t.Fatalf("decoded %#v re-encodes to %x, not %x", v, got, b[:n])
		}
	})
}

// FuzzAuthenticatorData: what parses is exactly what was there, field by
// field, with the credential ID inside its bound.
func FuzzAuthenticatorData(f *testing.F) {
	_, _, authAD, _, _ := seedVectors(f)
	for _, s := range authAD {
		f.Add(s, false)
	}
	a := newAuthn(f, AlgES256)
	f.Add(authData(testRP.ID, flagsAT, 1, attested(testID, a.cose)), true)
	f.Add(authData(testRP.ID, flagsAT|FlagED, 1, attested(testID, a.cose), enc(m("a", true))), true)
	f.Fuzz(func(t *testing.T, b []byte, attested bool) {
		ad, err := ParseAuthenticatorData(b, attested)
		if err != nil {
			return
		}
		if attested != (ad.Flags&FlagAT != 0) {
			t.Fatal("AT flag disagrees with the request")
		}
		if attested && (len(ad.CredentialID) == 0 || len(ad.CredentialID) > MaxCredentialIDLength) {
			t.Fatalf("credential ID of %d bytes", len(ad.CredentialID))
		}
		rebuilt := append(append([]byte(nil), ad.RPIDHash[:]...), ad.Flags, byte(ad.SignCount>>24), byte(ad.SignCount>>16), byte(ad.SignCount>>8), byte(ad.SignCount))
		if attested {
			rebuilt = append(rebuilt, ad.AAGUID[:]...)
			rebuilt = append(rebuilt, byte(len(ad.CredentialID)>>8), byte(len(ad.CredentialID)))
			rebuilt = append(append(rebuilt, ad.CredentialID...), ad.PublicKeyCOSE...)
		}
		rebuilt = append(rebuilt, ad.Extensions...)
		if !bytes.Equal(rebuilt, b) {
			t.Fatalf("fields do not add up to the input")
		}
	})
}

// FuzzAttestationObject: parsing and verifying never panic, and a registration
// that is accepted yields a key that parses and an ID within bounds.
func FuzzAttestationObject(f *testing.F) {
	regAO, regCD, _, _, _ := seedVectors(f)
	for i := range regAO {
		f.Add(regAO[i], regCD[i])
	}
	a := newAuthn(f, AlgEdDSA)
	cd, ao := register(a)
	f.Add(ao, cd)
	f.Fuzz(func(t *testing.T, ao, cd []byte) {
		_, _ = ParseAttestationObject(ao)
		for _, rp := range []RelyingParty{testRP, specRP} {
			for _, ch := range [][]byte{testChall, bytes.Repeat([]byte{0}, 32)} {
				c, err := rp.VerifyRegistration(ch, cd, ao, Policy{RequireUV: true})
				if err != nil {
					continue
				}
				if _, err := parseCOSEKey(c.PublicKeyCOSE); err != nil {
					t.Fatalf("accepted a registration whose key does not parse: %v", err)
				}
				if len(c.ID) == 0 || len(c.ID) > MaxCredentialIDLength {
					t.Fatalf("accepted an ID of %d bytes", len(c.ID))
				}
			}
		}
	})
}

// FuzzCOSEKey: a key that parses is one of the three algorithms, and
// verifying with it never panics.
func FuzzCOSEKey(f *testing.F) {
	for _, alg := range allAlgs {
		f.Add(newAuthn(f, alg).cose)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := parseCOSEKey(b)
		if err != nil {
			return
		}
		if k.alg != AlgES256 && k.alg != AlgEdDSA && k.alg != AlgRS256 {
			t.Fatalf("alg %d", k.alg)
		}
		_ = k.verify([]byte("m"), b)
	})
}

// FuzzAssertion: nothing panics, and a refusal never returns a Result.
func FuzzAssertion(f *testing.F) {
	_, _, authAD, authCD, authSig := seedVectors(f)
	a := newAuthn(f, AlgES256)
	for i := range authAD {
		f.Add(authCD[i], authAD[i], authSig[i])
	}
	cd, ad, sig := assert(a, flagsOK, 1)
	f.Add(cd, ad, sig)
	cred := Credential{ID: testID, PublicKeyCOSE: a.cose, BackupEligible: true, SignCount: 0}
	f.Fuzz(func(t *testing.T, cd, ad, sig []byte) {
		res, err := testRP.VerifyAssertion(testChall, cred, cd, ad, sig, Policy{RequireUV: true})
		if err != nil && res != (Result{}) {
			t.Fatalf("a refusal returned %+v", res)
		}
	})
}

// FuzzClientData: the challenge and origin checks hold for any JSON.
func FuzzClientData(f *testing.F) {
	_, regCD, _, authCD, _ := seedVectors(f)
	for _, s := range append(regCD, authCD...) {
		f.Add(s)
	}
	f.Add(clientDataJSON("webauthn.get", testChall, "https://login.example.org", `,"crossOrigin":false`))
	f.Fuzz(func(t *testing.T, b []byte) {
		err := parseClientData(b, "webauthn.get", testChall, testRP.Origins)
		if err != nil {
			return
		}
		if !json.Valid(b) {
			t.Fatal("accepted something that is not JSON")
		}
		var o map[string]any
		if json.Unmarshal(b, &o) != nil || o["origin"] != testRP.Origins[0] || o["type"] != "webauthn.get" {
			t.Fatalf("accepted %q", b)
		}
	})
}
