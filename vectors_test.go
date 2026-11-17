// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// testdata/w3c-vectors.json holds the end-to-end test vectors of W3C WebAuthn
// Level 3 section 16, written by the specification's authors with their own
// authenticator and not by this code. They are transcribed from go-webauthn's
// test of the same section (see testdata/README) by extract, a Go program.
type vectorFile struct {
	Registration   []map[string]string `json:"registration"`
	Authentication []map[string]string `json:"authentication"`
}

func loadVectors(t testing.TB) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/w3c-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var specRP = RelyingParty{ID: "example.org", Origins: []string{"https://example.org"}}

// What each vector must do here. Names are the vectors' own.
var specRegistration = map[string]error{
	"NoneES256":                      nil,
	"PackedSelfES256":                nil,
	"NoneES256CrossOriginNotAllowed": ErrCrossOrigin,
	"NoneES256CrossOrigin":           ErrCrossOrigin, // we never accept crossOrigin
	"NoneES256TopOriginNotAllowed":   ErrCrossOrigin,
	"NoneES256TopOrigin":             ErrCrossOrigin,
	"NoneES256LongCredentialID":      nil,            // long, but within the 1023 bytes of section 6.3
	"PackedES256WithMDS":             ErrAttestation, // a certificate chain: not trusted here
	"PackedES384WithMDS":             ErrAlgorithm,
	"PackedES512WithMDS":             ErrAlgorithm,
	"PackedRS256WithMDS":             ErrAttestation,
	"PackedEdDSAWithMDS":             ErrAttestation,
	"TPMES256":                       ErrAttestation,
	"AndroidKeyES256":                ErrAttestation,
	"AppleAnonymousES256":            ErrAttestation, // format apple: a chain, not trusted here
	"FIDOU2FES256":                   ErrAttestation,
}

func TestW3CRegistrationVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Registration) != len(specRegistration) {
		t.Fatalf("%d vectors, %d expectations", len(v.Registration), len(specRegistration))
	}
	for _, row := range v.Registration {
		t.Run(row["name"], func(t *testing.T) {
			want, ok := specRegistration[row["name"]]
			if !ok {
				t.Fatalf("no expectation for %s", row["name"])
			}
			cred, err := specRP.VerifyRegistration(unhex(t, row["challenge"]), unhex(t, row["clientDataJSON"]), unhex(t, row["attestationObject"]), Policy{})
			switch {
			case want == nil && err != nil:
				t.Fatalf("refused: %v", err)
			case want != nil && !errors.Is(err, want):
				t.Fatalf("want %v, got %v", want, err)
			}
			if want == nil && hex.EncodeToString(cred.ID) != row["credentialID"] {
				t.Fatalf("credential ID %x, vector says %s", cred.ID, row["credentialID"])
			}
		})
	}
}

var specAssertion = map[string]error{
	"NoneES256":                      nil,
	"PackedSelfES256":                nil,
	"NoneES256CrossOriginNotAllowed": ErrCrossOrigin,
	"NoneES256CrossOrigin":           ErrCrossOrigin,
	"NoneES256TopOrigin":             ErrCrossOrigin,
	"NoneES256LongCredentialID":      nil,
	"PackedES256Full":                nil,
	"PackedES384":                    ErrAlgorithm,
	"PackedES512":                    ErrAlgorithm,
	"PackedRS256":                    nil,
	"PackedEdDSA":                    nil,
	"TPMES256":                       nil,
	"AndroidKeyES256":                nil,
	"AppleAnonymousES256":            nil,
	"FIDOU2FES256":                   nil,
}

func TestW3CAssertionVectors(t *testing.T) {
	v := loadVectors(t)
	seen := 0
	for i, row := range v.Authentication {
		name := row["name"]
		t.Run(name+"/"+string(rune('a'+i)), func(t *testing.T) {
			want, ok := specAssertion[name]
			if !ok {
				t.Fatalf("no expectation for %s", name)
			}
			seen++
			ad := unhex(t, row["authenticatorData"])
			cred := Credential{ID: unhex(t, row["credentialID"]), PublicKeyCOSE: unhex(t, row["credentialPubKey"]), BackupEligible: ad[32]&FlagBE != 0}
			res, err := specRP.VerifyAssertion(unhex(t, row["challenge"]), cred, unhex(t, row["clientDataJSON"]), ad, unhex(t, row["signature"]), Policy{})
			switch {
			case want == nil && err != nil:
				t.Fatalf("refused: %v", err)
			case want != nil && !errors.Is(err, want):
				t.Fatalf("want %v, got %v", want, err)
			}
			if want == nil && res.UV != (ad[32]&FlagUV != 0) {
				t.Fatalf("UV %v for flags %#x", res.UV, ad[32])
			}
		})
	}
}
