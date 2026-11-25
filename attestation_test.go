// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testAAGUID = [16]byte{0x9d, 0xd8, 0xd5, 0x93, 0x22, 0x13, 0x43, 0x8a, 0xa6, 0xd8, 0xb6, 0xf8, 0x13, 0xc2, 0x7c, 0x51}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t testing.TB, cn string) testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{c, k}
}

type leafOpts struct {
	aaguid   []byte // extension content; nil = no extension
	critical bool
	subject  pkix.Name
	isCA     bool
	noBC     bool
	pad      int // bytes of an unrelated extension, to make the certificate large
}

func defaultSubject() pkix.Name {
	return pkix.Name{Country: []string{"SE"}, Organization: []string{"Yubico AB"}, OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Test EE"}
}

func (ca testCA) leaf(t testing.TB, o leafOpts) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: o.subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: o.isCA, BasicConstraintsValid: !o.noBC,
	}
	if o.aaguid != nil {
		v, _ := asn1.Marshal(o.aaguid)
		tpl.ExtraExtensions = []pkix.Extension{{Id: oidFIDOGenCEAAGUID, Critical: o.critical, Value: v}}
	}
	if o.pad > 0 {
		v, _ := asn1.Marshal(make([]byte, o.pad))
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: v})
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

// packedChain builds a registration whose statement is signed by leafKey.
func packedChain(t testing.TB, aaguid [16]byte, leafKey *ecdsa.PrivateKey, chain ...[]byte) (cd, ao []byte) {
	t.Helper()
	a := newAuthn(t, AlgES256)
	cd = clientDataJSON("webauthn.create", testChall, "https://login.example.org", "")
	att := attested(testID, a.cose)
	copy(att, aaguid[:])
	ad := authData(testRP.ID, flagsAT, 0, att)
	h := sha256.Sum256(cd)
	d := sha256.Sum256(append(append([]byte(nil), ad...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, leafKey, d[:])
	x5c := make([]any, len(chain))
	for i, c := range chain {
		x5c[i] = c
	}
	return cd, attObj("packed", m("alg", AlgES256, "sig", sig, "x5c", x5c), ad)
}

func TestPackedChainAccepted(t *testing.T) {
	root := newTestCA(t, "root")
	leaf, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(t, testAAGUID, key, leaf.Raw)
	cred, att, err := testRP.VerifyRegistrationAttested(testChall, cd, ao, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if att.Type != AttestationBasic || att.AAGUID != testAAGUID || len(att.TrustPath) != 1 || cred.AAGUID != testAAGUID {
		t.Fatalf("%+v", att)
	}
	if err := att.VerifyTrustPath([]*x509.Certificate{root.cert}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// VerifyRegistration, which does not trust chains, refuses the same statement.
	if _, err := testRP.VerifyRegistration(testChall, cd, ao, Policy{}); !errors.Is(err, ErrAttestation) {
		t.Fatalf("%v", err)
	}
}

func TestPackedChainWithoutAAGUIDExtension(t *testing.T) {
	root := newTestCA(t, "root")
	leaf, key := root.leaf(t, leafOpts{subject: defaultSubject()})
	cd, ao := packedChain(t, testAAGUID, key, leaf.Raw)
	if _, att, err := testRP.VerifyRegistrationAttested(testChall, cd, ao, Policy{}); err != nil || att.AAGUID != testAAGUID {
		t.Fatalf("%+v %v", att, err)
	}
}

func TestTrustPathRefusals(t *testing.T) {
	root := newTestCA(t, "root")
	other := newTestCA(t, "other")
	leaf, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(t, testAAGUID, key, leaf.Raw)
	_, att, err := testRP.VerifyRegistrationAttested(testChall, cd, ao, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	for name, roots := range map[string][]*x509.Certificate{"other root": {other.cert}, "no roots": nil} {
		if err := att.VerifyTrustPath(roots, time.Now()); !errors.Is(err, ErrAttestation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := att.VerifyTrustPath(nil, time.Now()); err == nil || !strings.Contains(err.Error(), "no trust anchors") {
		t.Errorf("no roots must be refused as such: %v", err)
	}
	if err := att.VerifyTrustPath([]*x509.Certificate{root.cert}, time.Now().Add(100*24*time.Hour)); !errors.Is(err, ErrAttestation) {
		t.Errorf("expired: %v", err)
	}
	for _, a := range []Attestation{{}, {Type: AttestationSelf}, {Type: AttestationNone}} {
		if err := a.VerifyTrustPath([]*x509.Certificate{root.cert}, time.Now()); !errors.Is(err, ErrAttestation) {
			t.Errorf("%+v: %v", a, err)
		}
	}
}

func TestPackedChainRefusals(t *testing.T) {
	root := newTestCA(t, "root")
	good, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	noOU := defaultSubject()
	noOU.OrganizationalUnit = nil
	noC := defaultSubject()
	noC.Country = nil
	wrong := make([]byte, 16)
	short := testAAGUID[:15]
	cases := map[string]struct {
		o    leafOpts
		sign *ecdsa.PrivateKey // nil = the leaf's own key
		aag  [16]byte
	}{
		"signed by another key":    {leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()}, otherKey, testAAGUID},
		"aaguid extension differs": {leafOpts{aaguid: wrong, subject: defaultSubject()}, nil, testAAGUID},
		"aaguid extension short":   {leafOpts{aaguid: short, subject: defaultSubject()}, nil, testAAGUID},
		"aaguid critical":          {leafOpts{aaguid: testAAGUID[:], critical: true, subject: defaultSubject()}, nil, testAAGUID},
		"no OU":                    {leafOpts{aaguid: testAAGUID[:], subject: noOU}, nil, testAAGUID},
		"no C":                     {leafOpts{aaguid: testAAGUID[:], subject: noC}, nil, testAAGUID},
		"CA leaf":                  {leafOpts{aaguid: testAAGUID[:], subject: defaultSubject(), isCA: true}, nil, testAAGUID},
		"no basic constraints":     {leafOpts{aaguid: testAAGUID[:], subject: defaultSubject(), noBC: true}, nil, testAAGUID},
	}
	_ = good
	_ = key
	for name, c := range cases {
		leaf, lk := root.leaf(t, c.o)
		if c.sign != nil {
			lk = c.sign
		}
		cd, ao := packedChain(t, c.aag, lk, leaf.Raw)
		if _, _, err := testRP.VerifyRegistrationAttested(testChall, cd, ao, Policy{}); !errors.Is(err, ErrAttestation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPackedChainStatementShapes(t *testing.T) {
	root := newTestCA(t, "root")
	leaf, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(t, testAAGUID, key, leaf.Raw)
	parsed, err := ParseAttestationObject(ao)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := lookup[[]byte](parsed.attStmt, "sig")
	many := make([]any, maxX5C+1)
	for i := range many {
		many[i] = leaf.Raw
	}
	for name, stmt := range map[string]cborMap{
		"empty x5c":     m("alg", AlgES256, "sig", sig, "x5c", []any{}),
		"too many":      m("alg", AlgES256, "sig", sig, "x5c", many),
		"not an array":  m("alg", AlgES256, "sig", sig, "x5c", []byte{1}),
		"element text":  m("alg", AlgES256, "sig", sig, "x5c", []any{"x"}),
		"garbage cert":  m("alg", AlgES256, "sig", sig, "x5c", []any{[]byte{1, 2, 3}}),
		"oversize cert": m("alg", AlgES256, "sig", sig, "x5c", []any{make([]byte, maxCertDER+1)}),
		"extra member":  m("alg", AlgES256, "sig", sig, "x5c", []any{leaf.Raw}, "ecdaaKeyId", []byte{1}),
		"no alg":        m("sig", sig, "x5c", []any{leaf.Raw}),
		"alg text":      m("alg", "x", "sig", sig, "x5c", []any{leaf.Raw}),
		"no sig":        m("alg", AlgES256, "x5c", []any{leaf.Raw}),
		"empty element": m("alg", AlgES256, "sig", sig, "x5c", []any{[]byte{}}),
		"self extra":    m("alg", AlgES256, "sig", sig, "ecdaaKeyId", []byte{1}),
		"alg vs key":    m("alg", AlgEdDSA, "sig", sig, "x5c", []any{leaf.Raw}),
		"alg unknown":   m("alg", int64(-35), "sig", sig, "x5c", []any{leaf.Raw}),
		"sig not bytes": m("alg", AlgES256, "sig", "x", "x5c", []any{leaf.Raw}),
	} {
		ao2 := attObj("packed", stmt, parsed.RawAuthData)
		if _, _, err := testRP.VerifyRegistrationAttested(testChall, cd, ao2, Policy{}); !errors.Is(err, ErrAttestation) && !errors.Is(err, ErrAlgorithm) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTrustPathThroughAnIntermediate(t *testing.T) {
	root := newTestCA(t, "root")
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "inter"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, root.cert, &ik.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	ic, _ := x509.ParseCertificate(der)
	inter := testCA{ic, ik}
	leaf, key := inter.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(t, testAAGUID, key, leaf.Raw, ic.Raw)
	_, att, err := testRP.VerifyRegistrationAttested(testChall, cd, ao, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := att.VerifyTrustPath([]*x509.Certificate{root.cert}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestAValidButOversizeCertificateIsRefused(t *testing.T) {
	root := newTestCA(t, "root")
	for pad, ok := range map[int]bool{maxCertDER - 1000: true, maxCertDER: false} {
		leaf, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject(), pad: pad})
		cd, ao := packedChain(t, testAAGUID, key, leaf.Raw)
		_, _, err := testRP.VerifyRegistrationAttested(testChall, cd, ao, Policy{})
		if (err == nil) != ok || (err != nil && !strings.Contains(err.Error(), "at most")) {
			t.Errorf("pad %d (%d bytes): %v", pad, len(leaf.Raw), err)
		}
	}
}

func TestPackedStatementNeedsAlgAndSig(t *testing.T) {
	root := newTestCA(t, "root")
	leaf, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(t, testAAGUID, key, leaf.Raw)
	parsed, _ := ParseAttestationObject(ao)
	sig, _ := lookup[[]byte](parsed.attStmt, "sig")
	for name, stmt := range map[string]cborMap{
		"no alg":   m("sig", sig, "x5c", []any{leaf.Raw}),
		"alg text": m("alg", "x", "sig", sig, "x5c", []any{leaf.Raw}),
		"no sig":   m("alg", AlgES256, "x5c", []any{leaf.Raw}),
	} {
		_, _, err := testRP.VerifyRegistrationAttested(testChall, cd, attObj("packed", stmt, parsed.RawAuthData), Policy{})
		if err == nil || !strings.Contains(err.Error(), "well-typed alg and sig") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAttestationKeyTypes(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, minRSABits)
	for name, c := range map[string]struct {
		alg int64
		pub any
		ok  bool
	}{
		"ed25519":      {AlgEdDSA, edPub, true},
		"rsa":          {AlgRS256, &rsaKey.PublicKey, true},
		"rsa vs es256": {AlgES256, &rsaKey.PublicKey, false},
		"ed vs rsa":    {AlgRS256, edPub, false},
	} {
		_, err := attestationKey(c.alg, &x509.Certificate{PublicKey: c.pub})
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCertificateVersionRefused(t *testing.T) {
	c := &x509.Certificate{Version: 1}
	if err := checkAttestationCert(c, testAAGUID); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatal(err)
	}
}

func TestAAGUIDExtensionEncodings(t *testing.T) {
	good, _ := asn1.Marshal(testAAGUID[:])
	s := defaultSubject()
	for name, c := range map[string]struct {
		val []byte
		ok  bool
	}{
		"exact":          {good, true},
		"garbage":        {[]byte{1, 2}, false},
		"trailing bytes": {append(append([]byte(nil), good...), 0), false},
		"empty":          {nil, false},
	} {
		cert := &x509.Certificate{
			Version: 3, Subject: s, BasicConstraintsValid: true,
			Extensions: []pkix.Extension{{Id: oidFIDOGenCEAAGUID, Value: c.val}},
		}
		err := checkAttestationCert(cert, testAAGUID)
		if (err == nil) != c.ok || (err != nil && !strings.Contains(err.Error(), "16-byte OCTET STRING")) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSelfAndNoneYieldNoAAGUID(t *testing.T) {
	a := newAuthn(t, AlgES256)
	cd := clientDataJSON("webauthn.create", testChall, "https://login.example.org", "")
	att := attested(testID, a.cose)
	copy(att, testAAGUID[:]) // the authenticator CLAIMS a model
	ad := authData(testRP.ID, flagsAT, 0, att)
	h := sha256.Sum256(cd)
	self := attObj("packed", m("alg", AlgES256, "sig", a.sign(append(append([]byte(nil), ad...), h[:]...))), ad)
	selfSig := a.sign(append(append([]byte(nil), ad...), h[:]...))
	extra := attObj("packed", m("alg", AlgES256, "sig", selfSig, "ecdaaKeyId", []byte{1}), ad)
	if _, _, err := testRP.VerifyRegistrationAttested(testChall, cd, extra, Policy{}); err == nil || !strings.Contains(err.Error(), "not self attestation") {
		t.Errorf("a validly signed self attestation with an extra member: %v", err)
	}
	for name, ao := range map[string][]byte{"self": self, "none": attObj("none", m(), ad)} {
		cred, got, err := testRP.VerifyRegistrationAttested(testChall, cd, ao, Policy{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.AAGUID != ([16]byte{}) || len(got.TrustPath) != 0 || got.Type == AttestationBasic {
			t.Errorf("%s: %+v", name, got)
		}
		if cred.AAGUID != testAAGUID { // the claim stays visible, as a claim
			t.Errorf("%s: %x", name, cred.AAGUID)
		}
		if err := got.VerifyTrustPath(nil, time.Now()); err == nil {
			t.Errorf("%s: a statement with no chain verified", name)
		}
	}
}

// FuzzAttestationStatement: a packed statement that verifies yields a trust
// path of parsed certificates within bound, a self or none attestation never
// yields an AAGUID, and nothing panics.
func FuzzAttestationStatement(f *testing.F) {
	root := newTestCA(f, "root")
	leaf, key := root.leaf(f, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(f, testAAGUID, key, leaf.Raw)
	f.Add(ao, cd)
	a := newAuthn(f, AlgES256)
	cd2, ao2 := register(a)
	f.Add(ao2, cd2)
	f.Fuzz(func(t *testing.T, ao, cd []byte) {
		_, att, err := testRP.VerifyRegistrationAttested(testChall, cd, ao, Policy{})
		if err != nil {
			return
		}
		switch att.Type {
		case AttestationBasic:
			if n := len(att.TrustPath); n == 0 || n > maxX5C {
				t.Fatalf("trust path of %d", n)
			}
		default:
			if att.AAGUID != ([16]byte{}) || len(att.TrustPath) != 0 {
				t.Fatalf("%+v", att)
			}
		}
	})
}

// TestWriteAttestationCorpus regenerates the committed seeds of
// FuzzAttestationStatement: WRITE_CORPUS=1 go test -run TestWriteAttestationCorpus.
func TestWriteAttestationCorpus(t *testing.T) {
	if os.Getenv("WRITE_CORPUS") == "" {
		t.Skip("set WRITE_CORPUS=1 to rewrite testdata/fuzz/FuzzAttestationStatement")
	}
	dir := filepath.Join("testdata", "fuzz", "FuzzAttestationStatement")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	root := newTestCA(t, "root")
	leaf, key := root.leaf(t, leafOpts{aaguid: testAAGUID[:], subject: defaultSubject()})
	cd, ao := packedChain(t, testAAGUID, key, leaf.Raw)
	_, aoSelf := register(newAuthn(t, AlgES256))
	seeds := map[string][2][]byte{"packed-x5c": {ao, cd}, "none": {aoSelf, cd}}
	parsed, _ := ParseAttestationObject(ao)
	sig, _ := lookup[[]byte](parsed.attStmt, "sig")
	seeds["x5c-garbage-cert"] = [2][]byte{attObj("packed", m("alg", AlgES256, "sig", sig, "x5c", []any{[]byte{1, 2, 3}}), parsed.RawAuthData), cd}
	seeds["x5c-empty"] = [2][]byte{attObj("packed", m("alg", AlgES256, "sig", sig, "x5c", []any{}), parsed.RawAuthData), cd}
	for name, s := range seeds {
		body := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n[]byte(%q)\n", s[0], s[1])
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
