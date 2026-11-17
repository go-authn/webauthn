// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

var allAlgs = []int64{AlgES256, AlgEdDSA, AlgRS256}

func TestNewChallenge(t *testing.T) {
	a, err := NewChallenge()
	if err != nil || len(a) != ChallengeSize {
		t.Fatalf("%x %v", a, err)
	}
	b, _ := NewChallenge()
	if bytes.Equal(a, b) {
		t.Fatal("two challenges are equal")
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestNewChallengeEntropyFailure(t *testing.T) {
	old := randReader
	randReader = failReader{}
	defer func() { randReader = old }()
	if c, err := NewChallenge(); err == nil || c != nil {
		t.Fatalf("%x %v", c, err)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, alg := range allAlgs {
		a := newAuthn(t, alg)
		cd, ao := register(a)
		cred, err := testRP.VerifyRegistration(testChall, cd, ao, Policy{RequireUV: true})
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		if !bytes.Equal(cred.ID, testID) || !bytes.Equal(cred.PublicKeyCOSE, a.cose) || !cred.BackupEligible || cred.SignCount != 0 {
			t.Fatalf("alg %d: %+v", alg, cred)
		}
		cd, ad, sig := assert(a, flagsOK, 5)
		res, err := testRP.VerifyAssertion(testChall, cred, cd, ad, sig, Policy{RequireUV: true})
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		if res != (Result{SignCount: 5, BackupState: true, UV: true}) {
			t.Fatalf("alg %d: %+v", alg, res)
		}
		// A different message does not verify under the same key.
		cd2, ad2, _ := assert(a, flagsOK, 6)
		if _, err := testRP.VerifyAssertion(testChall, cred, cd2, ad2, sig, Policy{}); !errors.Is(err, ErrSignature) {
			t.Fatalf("alg %d: a signature over other data: %v", alg, err)
		}
	}
}

func TestPackedSelfAttestation(t *testing.T) {
	for _, alg := range allAlgs {
		a := newAuthn(t, alg)
		cd := clientDataJSON("webauthn.create", testChall, "https://login.example.org", "")
		ad := authData(testRP.ID, flagsAT, 0, attested(testID, a.cose))
		h := sha256.Sum256(cd)
		sig := a.sign(append(append([]byte(nil), ad...), h[:]...))
		good := m("alg", alg, "sig", sig)
		if _, err := testRP.VerifyRegistration(testChall, cd, attObj("packed", good, ad), Policy{}); err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		for name, stmt := range map[string]cborMap{
			"wrong alg":     m("alg", alg+1, "sig", sig),
			"bad signature": m("alg", alg, "sig", append([]byte{^sig[0]}, sig[1:]...)),
			"x5c":           m("alg", alg, "sig", sig, "x5c", []any{[]byte{1}}),
			"ecdaa":         m("alg", alg, "ecdaaKeyId", []byte{1}, "sig", sig),
			"sig not bytes": m("alg", alg, "sig", "x"),
			"alg not int":   m("alg", "x", "sig", sig),
			"empty":         m(),
			"no sig":        m("alg", alg, "foo", sig),
		} {
			if _, err := testRP.VerifyRegistration(testChall, cd, attObj("packed", stmt, ad), Policy{}); !errors.Is(err, ErrAttestation) {
				t.Errorf("alg %d, %s: %v", alg, name, err)
			}
		}
	}
}

func TestAttestationFormats(t *testing.T) {
	a := newAuthn(t, AlgES256)
	cd, _ := register(a)
	ad := authData(testRP.ID, flagsAT, 0, attested(testID, a.cose))
	for name, ao := range map[string][]byte{
		"none with a statement": attObj("none", m("x", int64(1)), ad),
		"tpm":                   attObj("tpm", m(), ad),
		"fido-u2f":              attObj("fido-u2f", m(), ad),
		"android-key":           attObj("android-key", m(), ad),
		"empty format":          attObj("", m(), ad),
	} {
		if _, err := testRP.VerifyRegistration(testChall, cd, ao, Policy{}); !errors.Is(err, ErrAttestation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRegistrationRefusals(t *testing.T) {
	a := newAuthn(t, AlgES256)
	okCD, okAO := register(a)
	at := func(rp string, flags byte, extra ...[]byte) []byte {
		return attObj("none", m(), authData(rp, flags, 0, extra...))
	}
	good := attested(testID, a.cose)
	longID := bytes.Repeat([]byte{7}, MaxCredentialIDLength+1)
	maxID := bytes.Repeat([]byte{7}, MaxCredentialIDLength)
	for _, tc := range []struct {
		name      string
		challenge []byte
		cd, ao    []byte
		policy    Policy
		want      error
	}{
		{"baseline", testChall, okCD, okAO, Policy{RequireUV: true}, nil},
		{"wrong type", testChall, clientDataJSON("webauthn.get", testChall, "https://login.example.org", ""), okAO, Policy{}, ErrType},
		{"empty type", testChall, clientDataJSON("", testChall, "https://login.example.org", ""), okAO, Policy{}, ErrType},
		{"wrong challenge", []byte("another challenge value 0123456"), okCD, okAO, Policy{}, ErrChallenge},
		{"short issued challenge", testChall[:15], clientDataJSON("webauthn.create", testChall[:15], "https://login.example.org", ""), okAO, Policy{}, ErrChallenge},
		{"wrong origin", testChall, clientDataJSON("webauthn.create", testChall, "https://evil.example.org", ""), okAO, Policy{}, ErrOrigin},
		{"origin with a path", testChall, clientDataJSON("webauthn.create", testChall, "https://login.example.org/", ""), okAO, Policy{}, ErrOrigin},
		{"cross origin", testChall, clientDataJSON("webauthn.create", testChall, "https://login.example.org", `,"crossOrigin":true`), okAO, Policy{}, ErrCrossOrigin},
		{"cross origin false is fine", testChall, clientDataJSON("webauthn.create", testChall, "https://login.example.org", `,"crossOrigin":false,"extra":{"a":[1]}`), okAO, Policy{}, nil},
		{"top origin", testChall, clientDataJSON("webauthn.create", testChall, "https://login.example.org", `,"topOrigin":"https://login.example.org"`), okAO, Policy{}, ErrCrossOrigin},
		{"wrong rpIdHash", testChall, okCD, at("other.example.org", flagsAT, good), Policy{}, ErrRPIDHash},
		{"UP not set", testChall, okCD, at(testRP.ID, FlagAT|FlagUV, good), Policy{}, ErrUserPresence},
		{"UV not set, not required", testChall, okCD, at(testRP.ID, FlagAT|FlagUP, good), Policy{}, nil},
		{"UV not set, required", testChall, okCD, at(testRP.ID, FlagAT|FlagUP, good), Policy{RequireUV: true}, ErrUserVerification},
		{"BS without BE", testChall, okCD, at(testRP.ID, FlagAT|FlagUP|FlagBS, good), Policy{}, ErrBackup},
		{"AT not set", testChall, okCD, at(testRP.ID, flagsOK, good), Policy{}, ErrAuthData},
		{"credential ID of 1024", testChall, okCD, at(testRP.ID, flagsAT, attested(longID, a.cose)), Policy{}, ErrCredentialID},
		{"credential ID of 1023", testChall, okCD, at(testRP.ID, flagsAT, attested(maxID, a.cose)), Policy{}, nil},
		{"credential ID of 0", testChall, okCD, at(testRP.ID, flagsAT, attested(nil, a.cose)), Policy{}, ErrCredentialID},
		{"trailing byte in authData", testChall, okCD, at(testRP.ID, flagsAT, good, []byte{0}), Policy{}, ErrTrailingBytes},
		{"trailing byte after attObj", testChall, okCD, append(append([]byte(nil), okAO...), 0), Policy{}, ErrTrailingBytes},
		{"attObj not a map", testChall, okCD, enc([]any{}), Policy{}, ErrAttestation},
		{"attObj with a 4th key", testChall, okCD, enc(m("fmt", "none", "zzz", int64(1), "attStmt", m(), "authData", []byte{})), Policy{}, ErrAttestation},
		{"attObj missing authData", testChall, okCD, enc(m("x", int64(1), "fmt", "none", "attStmt", m())), Policy{}, ErrAttestation},
		{"attObj garbage", testChall, okCD, []byte{0xff}, Policy{}, ErrAttestation},
		{"attObj indefinite", testChall, okCD, []byte{0xbf, 0xff}, Policy{}, ErrAttestation},
		{"attObj keys unsorted", testChall, okCD, enc(m("attStmt", m(), "fmt", "none", "authData", []byte{})), Policy{}, ErrAttestation},
		{"clientData garbage", testChall, []byte("not json"), okAO, Policy{}, ErrClientData},
		{"clientData empty", testChall, nil, okAO, Policy{}, ErrClientData},
		{"clientData value missing", testChall, []byte(`{"type":}`), okAO, Policy{}, ErrClientData},
		{"clientData wrong closer", testChall, []byte(`{"type":"x"]`), okAO, Policy{}, ErrClientData},
		{"clientData array", testChall, []byte(`[]`), okAO, Policy{}, ErrClientData},
		{"clientData unterminated", testChall, []byte(`{"type":"webauthn.create"`), okAO, Policy{}, ErrClientData},
		{"clientData trailing", testChall, append(append([]byte(nil), okCD...), []byte(` {}`)...), okAO, Policy{}, ErrClientData},
		{"clientData duplicate member", testChall, clientDataJSON("webauthn.create", testChall, "https://login.example.org", `,"type":"webauthn.get"`), okAO, Policy{}, ErrClientData},
		{"clientData too big", testChall, clientDataJSON("webauthn.create", testChall, "https://login.example.org", `,"x":"`+strings.Repeat("a", maxClientData)+`"`), okAO, Policy{}, ErrClientData},
		{"clientData type not a string", testChall, []byte(`{"type":1}`), okAO, Policy{}, ErrClientData},
		{"clientData challenge not a string", testChall, []byte(`{"type":"webauthn.create","challenge":1}`), okAO, Policy{}, ErrClientData},
		{"clientData origin not a string", testChall, []byte(`{"type":"webauthn.create","challenge":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY","origin":1}`), okAO, Policy{}, ErrClientData},
		{"clientData crossOrigin not a bool", testChall, clientDataJSON("webauthn.create", testChall, "https://login.example.org", `,"crossOrigin":"no"`), okAO, Policy{}, ErrClientData},
		{"challenge padded", testChall, []byte(`{"type":"webauthn.create","challenge":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","origin":"https://login.example.org"}`), okAO, Policy{}, ErrChallenge},
		{"challenge not base64", testChall, []byte(`{"type":"webauthn.create","challenge":"!!!","origin":"https://login.example.org"}`), okAO, Policy{}, ErrChallenge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := testRP.VerifyRegistration(tc.challenge, tc.cd, tc.ao, tc.policy)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestRegistrationKeyRefusals(t *testing.T) {
	a := newAuthn(t, AlgES256)
	cd, _ := register(a)
	for name, cose := range map[string][]byte{
		"unknown alg ES384": enc(m(int64(1), int64(2), int64(3), int64(-35), int64(-1), int64(2), int64(-2), make([]byte, 48), int64(-3), make([]byte, 48))),
		"alg 0":             enc(m(int64(1), int64(2), int64(3), int64(0))),
		"alg ES256 but OKP": enc(m(int64(1), int64(1), int64(3), int64(-7), int64(-1), int64(6), int64(-2), make([]byte, 32))),
		"not a map":         enc([]any{}),
		"garbage":           {0xff},
	} {
		ao := attObj("none", m(), authData(testRP.ID, flagsAT, 0, attested(testID, cose)))
		_, err := testRP.VerifyRegistration(testChall, cd, ao, Policy{})
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ao := attObj("none", m(), authData(testRP.ID, flagsAT, 0, attested(testID, enc(m(int64(1), int64(2), int64(3), int64(-35))))))
	if _, err := testRP.VerifyRegistration(testChall, cd, ao, Policy{}); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("unknown alg: %v", err)
	}
}

func TestAssertionRefusals(t *testing.T) {
	a := newAuthn(t, AlgES256)
	regCD, regAO := register(a)
	cred, err := testRP.VerifyRegistration(testChall, regCD, regAO, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	signed := func(cd, ad []byte) []byte {
		h := sha256.Sum256(cd)
		return a.sign(append(append([]byte(nil), ad...), h[:]...))
	}
	getCD := clientDataJSON("webauthn.get", testChall, "https://login.example.org", "")
	adWith := func(rp string, flags byte, count uint32) []byte { return authData(rp, flags, count) }
	stored := func(c Credential, count uint32) Credential { c.SignCount = count; return c }
	bad := func(c Credential, mutate func(*Credential)) Credential { mutate(&c); return c }

	for _, tc := range []struct {
		name   string
		cred   Credential
		cd, ad []byte
		sig    []byte // nil: sign
		policy Policy
		want   error
	}{
		{"baseline", cred, getCD, adWith(testRP.ID, flagsOK, 1), nil, Policy{RequireUV: true}, nil},
		{"wrong type", cred, clientDataJSON("webauthn.create", testChall, "https://login.example.org", ""), adWith(testRP.ID, flagsOK, 1), nil, Policy{}, ErrType},
		{"wrong challenge", cred, clientDataJSON("webauthn.get", []byte("another challenge value 0123456"), "https://login.example.org", ""), adWith(testRP.ID, flagsOK, 1), nil, Policy{}, ErrChallenge},
		{"wrong origin", cred, clientDataJSON("webauthn.get", testChall, "https://evil.example.org", ""), adWith(testRP.ID, flagsOK, 1), nil, Policy{}, ErrOrigin},
		{"cross origin", cred, clientDataJSON("webauthn.get", testChall, "https://login.example.org", `,"crossOrigin":true`), adWith(testRP.ID, flagsOK, 1), nil, Policy{}, ErrCrossOrigin},
		{"wrong rpIdHash", cred, getCD, adWith("other.example.org", flagsOK, 1), nil, Policy{}, ErrRPIDHash},
		{"UP not set", cred, getCD, adWith(testRP.ID, FlagUV|FlagBE|FlagBS, 1), nil, Policy{}, ErrUserPresence},
		{"UV not set, required", cred, getCD, adWith(testRP.ID, FlagUP|FlagBE|FlagBS, 1), nil, Policy{RequireUV: true}, ErrUserVerification},
		{"UV not set, not required", cred, getCD, adWith(testRP.ID, FlagUP|FlagBE|FlagBS, 1), nil, Policy{}, nil},
		{"BS without BE", bad(cred, func(c *Credential) { c.BackupEligible = false }), getCD, adWith(testRP.ID, FlagUP|FlagBS, 1), nil, Policy{}, ErrBackup},
		{"BE changed", cred, getCD, adWith(testRP.ID, FlagUP|FlagUV, 1), nil, Policy{}, ErrBackup},
		{"AT set", cred, getCD, adWith(testRP.ID, flagsAT, 1), nil, Policy{}, ErrAuthData},
		{"short authData", cred, getCD, []byte{1, 2, 3}, []byte{0}, Policy{}, ErrAuthData},
		{"trailing in authData", cred, getCD, append(adWith(testRP.ID, flagsOK, 1), 0), nil, Policy{}, ErrTrailingBytes},
		{"bad signature", cred, getCD, adWith(testRP.ID, flagsOK, 1), []byte{1, 2, 3}, Policy{}, ErrSignature},
		{"counter equal", stored(cred, 7), getCD, adWith(testRP.ID, flagsOK, 7), nil, Policy{}, ErrSignCount},
		{"counter regressed", stored(cred, 7), getCD, adWith(testRP.ID, flagsOK, 3), nil, Policy{}, ErrSignCount},
		{"counter advanced", stored(cred, 7), getCD, adWith(testRP.ID, flagsOK, 8), nil, Policy{}, nil},
		{"counter zero and zero", stored(cred, 0), getCD, adWith(testRP.ID, flagsOK, 0), nil, Policy{}, nil},
		{"counter stored, new zero", stored(cred, 7), getCD, adWith(testRP.ID, flagsOK, 0), nil, Policy{}, nil},
		{"counter new, stored zero", stored(cred, 0), getCD, adWith(testRP.ID, flagsOK, 9), nil, Policy{}, nil},
		{"credential ID too long", bad(cred, func(c *Credential) { c.ID = make([]byte, MaxCredentialIDLength+1) }), getCD, adWith(testRP.ID, flagsOK, 1), nil, Policy{}, ErrCredentialID},
		{"credential ID empty", bad(cred, func(c *Credential) { c.ID = nil }), getCD, adWith(testRP.ID, flagsOK, 1), nil, Policy{}, ErrCredentialID},
		{"stored key unknown alg", bad(cred, func(c *Credential) { c.PublicKeyCOSE = enc(m(int64(1), int64(2), int64(3), int64(-35))) }), getCD, adWith(testRP.ID, flagsOK, 1), nil, Policy{}, ErrAlgorithm},
		{"stored key garbage", bad(cred, func(c *Credential) { c.PublicKeyCOSE = []byte{0xff} }), getCD, adWith(testRP.ID, flagsOK, 1), nil, Policy{}, ErrKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := tc.sig
			if sig == nil {
				sig = signed(tc.cd, tc.ad)
			}
			_, err := testRP.VerifyAssertion(testChall, tc.cred, tc.cd, tc.ad, sig, tc.policy)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestSignatureOfAnotherKeyIsRefused(t *testing.T) {
	a, b := newAuthn(t, AlgES256), newAuthn(t, AlgES256)
	cd, ao := register(a)
	cred, err := testRP.VerifyRegistration(testChall, cd, ao, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	cd, ad, sig := assert(b, flagsOK, 1)
	if _, err := testRP.VerifyAssertion(testChall, cred, cd, ad, sig, Policy{}); !errors.Is(err, ErrSignature) {
		t.Fatal(err)
	}
}

func TestRelyingPartyConfig(t *testing.T) {
	a := newAuthn(t, AlgES256)
	cd, ao := register(a)
	for name, rp := range map[string]RelyingParty{
		"empty ID":          {ID: "", Origins: []string{"https://login.example.org"}},
		"upper case":        {ID: "Login.Example.org", Origins: []string{"https://login.example.org"}},
		"ID with a scheme":  {ID: "https://login.example.org", Origins: []string{"https://login.example.org"}},
		"ID with a port":    {ID: "login.example.org:443", Origins: []string{"https://login.example.org"}},
		"ID too long":       {ID: strings.Repeat("a", 254), Origins: []string{"https://x"}},
		"no origins":        {ID: "login.example.org"},
		"http origin":       {ID: "login.example.org", Origins: []string{"http://login.example.org"}},
		"origin with path":  {ID: "login.example.org", Origins: []string{"https://login.example.org/"}},
		"origin not a URL":  {ID: "login.example.org", Origins: []string{"https://%zz"}},
		"origin with user":  {ID: "login.example.org", Origins: []string{"https://u@login.example.org"}},
		"opaque origin":     {ID: "login.example.org", Origins: []string{"mailto:a@b"}},
		"no host":           {ID: "login.example.org", Origins: []string{"https://"}},
		"outside the ID":    {ID: "login.example.org", Origins: []string{"https://example.org"}},
		"suffix not label":  {ID: "example.org", Origins: []string{"https://evilexample.org"}},
		"ID is a suffix of": {ID: "login.example.org", Origins: []string{"https://login.example.org.evil.com"}},
	} {
		if _, err := rp.VerifyRegistration(testChall, cd, ao, Policy{}); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := rp.VerifyAssertion(testChall, Credential{}, cd, nil, nil, Policy{}); !errors.Is(err, ErrConfig) {
			t.Errorf("%s (assertion): %v", name, err)
		}
	}
	for name, rp := range map[string]RelyingParty{
		"parent domain":  {ID: "example.org", Origins: []string{"https://login.example.org", "https://example.org:8443"}},
		"localhost http": {ID: "localhost", Origins: []string{"http://localhost:8080"}},
		"loopback v4":    {ID: "127.0.0.1", Origins: []string{"http://127.0.0.1:8080"}},
	} {
		if err := rp.validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The ::1 literal has colons, which an RP ID may not.
	if err := (RelyingParty{ID: "::1", Origins: []string{"http://[::1]:80"}}).validate(); !errors.Is(err, ErrConfig) {
		t.Error("an IPv6 literal RP ID was accepted")
	}
	// An http origin on ::1 is local, with a name-valued RP ID.
	if err := (RelyingParty{ID: "localhost", Origins: []string{"http://[::1]:80"}}).validate(); !errors.Is(err, ErrConfig) {
		t.Error("::1 is not below localhost")
	}
}

func TestExtensionsAreParsedAndBounded(t *testing.T) {
	a := newAuthn(t, AlgES256)
	cd, _ := register(a)
	good := attested(testID, a.cose)
	flags := flagsAT | FlagED
	reg := func(ext []byte) error {
		ao := attObj("none", m(), authData(testRP.ID, flags, 0, good, ext))
		_, err := testRP.VerifyRegistration(testChall, cd, ao, Policy{})
		return err
	}
	if err := reg(enc(m("credProtect", int64(2)))); err != nil {
		t.Fatal(err)
	}
	if err := reg(enc([]any{})); !errors.Is(err, ErrAuthData) {
		t.Fatalf("extensions not a map: %v", err)
	}
	if err := reg([]byte{0xbf, 0xff}); !errors.Is(err, ErrAuthData) {
		t.Fatalf("indefinite extensions: %v", err)
	}
	if err := reg(append(enc(m()), 0)); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("trailing after extensions: %v", err)
	}
	if err := reg(nil); !errors.Is(err, ErrAuthData) {
		t.Fatalf("ED set, nothing there: %v", err)
	}
	// And in an assertion, where there is no attested data.
	cdg, _, _ := assert(a, flagsOK, 1)
	ad := authData(testRP.ID, flagsOK|FlagED, 1, enc(m("hmac-secret", true)))
	h := sha256.Sum256(cdg)
	sig := a.sign(append(append([]byte(nil), ad...), h[:]...))
	cred := Credential{ID: testID, PublicKeyCOSE: a.cose, BackupEligible: true}
	if _, err := testRP.VerifyAssertion(testChall, cred, cdg, ad, sig, Policy{}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatorDataShape(t *testing.T) {
	a := newAuthn(t, AlgES256)
	good := authData(testRP.ID, flagsAT, 3, attested(testID, a.cose))
	ad, err := ParseAuthenticatorData(good, true)
	if err != nil {
		t.Fatal(err)
	}
	if !ad.UserPresent() || !ad.UserVerified() || !ad.BackupEligible() || !ad.BackupState() || ad.SignCount != 3 || ad.Extensions != nil {
		t.Fatalf("%+v", ad)
	}
	for name, b := range map[string][]byte{
		"36 bytes":                good[:36],
		"attested data truncated": good[:37+10],
		"credential ID truncated": good[:37+18+4],
		"key missing":             good[:37+18+len(testID)],
		"key truncated":           good[:len(good)-3],
		"key CBOR deep":           authData(testRP.ID, flagsAT, 0, attested(testID, nested(maxCBORDepth+1))),
		"over the size cap":       append(append([]byte(nil), good...), make([]byte, MaxCBORInput)...),
	} {
		if _, err := ParseAuthenticatorData(b, true); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseAuthenticatorData(authData(testRP.ID, flagsOK, 0), true); !errors.Is(err, ErrAuthData) {
		t.Fatal("AT clear, wanted set")
	}
}

func TestAttestationObjectParse(t *testing.T) {
	a := newAuthn(t, AlgEdDSA)
	_, ao := register(a)
	got, err := ParseAttestationObject(ao)
	if err != nil || got.Format != "none" || !bytes.Equal(got.AuthData.CredentialID, testID) || len(got.RawAuthData) == 0 {
		t.Fatalf("%+v %v", got, err)
	}
}
