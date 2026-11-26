// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

// nativeArgs splits an attestation object into the CTAP2-native fields.
func nativeArgs(t testing.TB, ao []byte) (format string, authData, attStmt []byte) {
	t.Helper()
	p, err := ParseAttestationObject(ao)
	if err != nil {
		t.Fatal(err)
	}
	return p.Format, p.RawAuthData, enc(p.attStmt)
}

// selfPacked builds a self-attested registration over hash.
func selfPacked(t testing.TB, flags byte, hash [32]byte) (ad, stmt []byte) {
	t.Helper()
	a := newAuthn(t, AlgES256)
	ad = authData(testRP.ID, flags, 0, attested(testID, a.cose))
	sig := a.sign(append(append([]byte(nil), ad...), hash[:]...))
	return ad, enc(m("alg", AlgES256, "sig", sig))
}

func TestVerifyAttestationStatementNativeHash(t *testing.T) {
	// A hash that is the sha256 of no clientDataJSON: domain tag || nonce || name.
	hash := sha256.Sum256([]byte("go-vcs enrol v1\x00nonce\x00key-name"))
	ad, stmt := selfPacked(t, flagsAT, hash)
	cred, att, err := VerifyAttestationStatement(testRP.ID, "packed", ad, stmt, hash, Policy{RequireUV: true})
	if err != nil {
		t.Fatal(err)
	}
	if att.Type != AttestationSelf || string(cred.ID) != string(testID) || !cred.BackupEligible {
		t.Fatalf("%+v %+v", cred, att)
	}
	// Another hash must not verify the same statement.
	other := sha256.Sum256([]byte("other"))
	if _, _, err := VerifyAttestationStatement(testRP.ID, "packed", ad, stmt, other, Policy{}); !errors.Is(err, ErrAttestation) {
		t.Fatalf("%v", err)
	}
}

func TestVerifyAttestationStatementChain(t *testing.T) {
	root := newTestCA(t, "root")
	leaf, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(t, testAAGUID, key, leaf.Raw)
	f, ad, stmt := nativeArgs(t, ao)
	cred, att, err := VerifyAttestationStatement(testRP.ID, f, ad, stmt, sha256.Sum256(cd), Policy{RequireAAGUIDExtension: true})
	if err != nil {
		t.Fatal(err)
	}
	if att.Type != AttestationBasic || cred.AAGUID != testAAGUID {
		t.Fatalf("%+v", att)
	}
	if err := att.VerifyTrustPath([]*x509.Certificate{root.cert}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAttestationStatementRPID(t *testing.T) {
	hash := sha256.Sum256([]byte("h"))
	ad, stmt := selfPacked(t, flagsAT, hash)
	if _, _, err := VerifyAttestationStatement("other.example.org", "packed", ad, stmt, hash, Policy{}); !errors.Is(err, ErrRPIDHash) {
		t.Fatalf("mismatch: %v", err)
	}
	for _, id := range []string{"", "Login.Example.org", "https://login.example.org", "a/b", "login.example.org:443"} {
		if _, _, err := VerifyAttestationStatement(id, "packed", ad, stmt, hash, Policy{}); !errors.Is(err, ErrConfig) {
			t.Errorf("%q: %v", id, err)
		}
	}
}

func TestVerifyAttestationStatementMalformedInput(t *testing.T) {
	hash := sha256.Sum256([]byte("h"))
	ad, stmt := selfPacked(t, flagsAT, hash)
	for name, c := range map[string]struct {
		ad, stmt []byte
		want     error
		text     string
	}{
		"stmt not CBOR":     {ad, []byte{0xff}, ErrAttestation, "attStmt: "},
		"stmt not a map":    {ad, enc("x"), ErrAttestation, "must be a CBOR map"},
		"stmt trailing":     {ad, append(append([]byte(nil), stmt...), 0), ErrAttestation, "attStmt: "},
		"authData short":    {ad[:10], stmt, ErrAuthData, ""},
		"authData no AT":    {authData(testRP.ID, flagsOK, 0), stmt, ErrAuthData, ""},
		"authData trailing": {append(append([]byte(nil), ad...), 0), stmt, ErrTrailingBytes, ""},
	} {
		_, _, err := VerifyAttestationStatement(testRP.ID, "packed", c.ad, c.stmt, hash, Policy{})
		if !errors.Is(err, c.want) || (err != nil && !strings.Contains(err.Error(), c.text)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestRefusalsThroughBothPaths: every refusal the clientDataJSON path reaches
// is reached, with the same sentinel, through the native entry point given
// sha256(clientDataJSON) -- one implementation behind both.
func TestRefusalsThroughBothPaths(t *testing.T) {
	root := newTestCA(t, "root")
	good, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	noExt, keyNoExt := root.leaf(t, leafOpts{subject: defaultSubject()})
	otherAAGUID := [16]byte{9}
	mismatch, keyMis := root.leaf(t, leafOpts{aaguid: otherAAGUID[:], subject: defaultSubject()})

	cd := clientDataJSON("webauthn.create", testChall, "https://login.example.org", "")
	hash := sha256.Sum256(cd)
	selfFlags := func(flags byte) []byte {
		a := newAuthn(t, AlgES256)
		ad := authData(testRP.ID, flags, 0, attested(testID, a.cose))
		sig := a.sign(append(append([]byte(nil), ad...), hash[:]...))
		return attObj("packed", m("alg", AlgES256, "sig", sig), ad)
	}
	_, chainGood := packedChain(t, testAAGUID, key, good.Raw)
	_, chainNoExt := packedChain(t, testAAGUID, keyNoExt, noExt.Raw)
	_, chainMis := packedChain(t, testAAGUID, keyMis, mismatch.Raw)
	_, chainWrongKey := packedChain(t, testAAGUID, keyMis, good.Raw)
	badRP := func() []byte {
		a := newAuthn(t, AlgES256)
		ad := authData("elsewhere.example.org", flagsAT, 0, attested(testID, a.cose))
		sig := a.sign(append(append([]byte(nil), ad...), hash[:]...))
		return attObj("packed", m("alg", AlgES256, "sig", sig), ad)
	}()
	adNone := authData(testRP.ID, flagsAT, 0, attested(testID, newAuthn(t, AlgES256).cose))

	for name, c := range map[string]struct {
		ao   []byte
		p    Policy
		want error
	}{
		"rpIdHash":          {badRP, Policy{}, ErrRPIDHash},
		"user presence":     {selfFlags(flagsAT &^ FlagUP), Policy{}, ErrUserPresence},
		"user verification": {selfFlags(FlagUP | FlagBE | FlagAT), Policy{RequireUV: true}, ErrUserVerification},
		"backup state":      {selfFlags(FlagUP | FlagUV | FlagBS | FlagAT), Policy{}, ErrBackup},
		"none with stmt":    {attObj("none", m("x", int64(1)), adNone), Policy{}, ErrAttestation},
		"unknown format":    {attObj("tpm", m(), adNone), Policy{}, ErrAttestation},
		"signature":         {chainWrongKey, Policy{}, ErrAttestation},
		"ext missing":       {chainNoExt, Policy{RequireAAGUIDExtension: true}, ErrAAGUIDExtensionMissing},
		"ext mismatch":      {chainMis, Policy{}, ErrAAGUIDExtensionMismatch},
	} {
		_, _, err1 := testRP.VerifyRegistrationAttested(testChall, cd, c.ao, c.p)
		f, ad, stmt := nativeArgs(t, c.ao)
		_, _, err2 := VerifyAttestationStatement(testRP.ID, f, ad, stmt, hash, c.p)
		if !errors.Is(err1, c.want) || !errors.Is(err2, c.want) {
			t.Errorf("%s: want %v, wrapper %v, native %v", name, c.want, err1, err2)
		}
	}
	// The same accepted object passes both, so the refusals above are the options', not the fixture's.
	if _, _, err := testRP.VerifyRegistrationAttested(testChall, cd, chainGood, Policy{RequireAAGUIDExtension: true}); err != nil {
		t.Fatal(err)
	}
	f, ad, stmt := nativeArgs(t, chainGood)
	if _, _, err := VerifyAttestationStatement(testRP.ID, f, ad, stmt, hash, Policy{RequireAAGUIDExtension: true}); err != nil {
		t.Fatal(err)
	}
}

// FuzzVerifyAttestationStatement: nothing panics, and an accepted statement
// yields a bounded trust path and a credential ID within bound.
func FuzzVerifyAttestationStatement(f *testing.F) {
	root := newTestCA(f, "root")
	leaf, key := root.leaf(f, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(f, testAAGUID, key, leaf.Raw)
	format, ad, stmt := nativeArgs(f, ao)
	f.Add(format, ad, stmt, true)
	hash := sha256.Sum256(cd)
	sad, sstmt := selfPacked(f, flagsAT, hash)
	f.Add("packed", sad, sstmt, false)
	f.Add("none", sad, []byte{0xa0}, false)
	f.Fuzz(func(t *testing.T, format string, ad, stmt []byte, ext bool) {
		cred, att, err := VerifyAttestationStatement(testRP.ID, format, ad, stmt, hash, Policy{RequireAAGUIDExtension: ext})
		if err != nil {
			return
		}
		if n := len(att.TrustPath); n > maxX5C || (att.Type == AttestationBasic) != (n > 0) {
			t.Fatalf("trust path of %d for %v", n, att.Type)
		}
		if l := len(cred.ID); l == 0 || l > MaxCredentialIDLength {
			t.Fatalf("credential ID of %d", l)
		}
	})
}
