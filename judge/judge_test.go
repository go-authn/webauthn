// SPDX-License-Identifier: BSD-3-Clause

// Package judge checks github.com/go-authn/webauthn against code nobody here
// wrote. A verifier tested only with registrations it generated itself agrees
// with itself and proves nothing else, so this module (separate, so that the
// library has no dependency) uses:
//
//   - github.com/go-webauthn/webauthn, an independent relying-party
//     implementation, as a SECOND VERIFIER: everything generated here must be
//     accepted by both, and every refusal made by it must also be made by
//     ours (ours is stricter on purpose: canonical CBOR, no certificate
//     chains);
//   - github.com/fxamacker/cbor/v2 in its CTAP2 canonical mode, an
//     independent CBOR ENCODER, to write the attestation objects and COSE keys
//     the way a CTAP2 authenticator does;
//   - the standard library's ecdsa, ed25519 and rsa as the signers.
//
// The W3C Web Authentication Level 3 section 16 vectors, which the
// specification's authors generated, are in the library's own tests.
package judge

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	wa "github.com/go-authn/webauthn"
)

const (
	rpID   = "login.example.org"
	origin = "https://login.example.org"
)

var rp = wa.RelyingParty{ID: rpID, Origins: []string{origin}}

var enc = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type authenticator struct {
	alg  int64
	cose []byte
	sign func(msg []byte) []byte
}

func mustCBOR(t testing.TB, v any) []byte {
	t.Helper()
	b, err := enc.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newAuthenticator(t testing.TB, alg int64) *authenticator {
	t.Helper()
	switch alg {
	case wa.AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pt, _ := k.PublicKey.Bytes()
		cose := mustCBOR(t, map[int]any{1: 2, 3: -7, -1: 1, -2: pt[1:33], -3: pt[33:65]})
		return &authenticator{alg, cose, func(msg []byte) []byte {
			h := sha256.Sum256(msg)
			s, _ := ecdsa.SignASN1(rand.Reader, k, h[:])
			return s
		}}
	case wa.AlgEdDSA:
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		cose := mustCBOR(t, map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(pub)})
		return &authenticator{alg, cose, func(msg []byte) []byte { return ed25519.Sign(priv, msg) }}
	default:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		cose := mustCBOR(t, map[int]any{1: 3, 3: -257, -1: k.N.Bytes(), -2: []byte{1, 0, 1}})
		return &authenticator{alg, cose, func(msg []byte) []byte {
			h := sha256.Sum256(msg)
			s, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
			return s
		}}
	}
}

type params struct {
	typ       string
	challenge []byte
	origin    string
	rpID      string
	flags     byte
	count     uint32
	extraCD   map[string]any
}

func goodParams(typ string, ch []byte) params {
	return params{typ: typ, challenge: ch, origin: origin, rpID: rpID, flags: wa.FlagUP | wa.FlagUV | wa.FlagBE | wa.FlagBS, count: 0}
}

func (p params) clientData(t testing.TB) []byte {
	m := map[string]any{"type": p.typ, "challenge": b64(p.challenge), "origin": p.origin, "crossOrigin": false}
	for k, v := range p.extraCD {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (p params) authData(extra ...[]byte) []byte {
	h := sha256.Sum256([]byte(p.rpID))
	out := append(h[:], p.flags)
	out = binary.BigEndian.AppendUint32(out, p.count)
	for _, e := range extra {
		out = append(out, e...)
	}
	return out
}

func (a *authenticator) registration(t testing.TB, p params, credID []byte) (cd, ao []byte) {
	cd = p.clientData(t)
	att := append(make([]byte, 16), byte(len(credID)>>8), byte(len(credID)))
	att = append(append(att, credID...), a.cose...)
	ad := p.authData(att)
	ao = mustCBOR(t, map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	return
}

func (a *authenticator) assertion(t testing.TB, p params) (cd, ad, sig []byte) {
	cd = p.clientData(t)
	ad = p.authData()
	h := sha256.Sum256(cd)
	return cd, ad, a.sign(append(append([]byte(nil), ad...), h[:]...))
}

// independent verdicts ------------------------------------------------------

var credParams = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

// detail adds go-webauthn's developer information to its terse errors, so a
// refusal can be told from a parse failure of the generator's own making.
func detail(err error) error {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return fmt.Errorf("%s (%s)", pe.Details, pe.DevInfo)
	}
	return err
}

// otherRegistration is go-webauthn's verdict on a registration.
func otherRegistration(challenge []byte, id, cd, ao []byte, uv bool) error {
	body, _ := json.Marshal(map[string]any{
		"id": b64(id), "rawId": b64(id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(cd), "attestationObject": b64(ao)},
	})
	pcc, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return detail(err)
	}
	_, err = pcc.Verify(b64(challenge), rpID, []string{origin}, nil, nil, protocol.TopOriginExplicitVerificationMode, false, uv, true, nil, credParams, protocol.AttestationPolicy{}, protocol.SignaturePolicy{})
	return err
}

// otherAssertion is go-webauthn's verdict on an assertion.
func otherAssertion(challenge []byte, id, pubCOSE, cd, ad, sig []byte, uv bool) error {
	body, _ := json.Marshal(map[string]any{
		"id": b64(id), "rawId": b64(id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sig), "userHandle": b64([]byte("u"))},
	})
	par, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return err
	}
	return par.Verify(b64(challenge), rpID, "", []string{origin}, nil, nil, protocol.TopOriginExplicitVerificationMode, false, uv, true, pubCOSE, protocol.SignaturePolicy{})
}

var challenge = bytes.Repeat([]byte{0x5a}, 32)

var algs = []int64{wa.AlgES256, wa.AlgEdDSA, wa.AlgRS256}

func credID(n int) []byte { return bytes.Repeat([]byte{0xc1}, n) }

// A canonical CTAP2 encoder's output is accepted by both verifiers, and both
// return the same credential.
func TestBothVerifiersAcceptWhatACTAP2EncoderWrites(t *testing.T) {
	for _, alg := range algs {
		a := newAuthenticator(t, alg)
		for _, n := range []int{16, 32, 64, 255, 1023} {
			id := credID(n)
			cd, ao := a.registration(t, goodParams("webauthn.create", challenge), id)
			if err := otherRegistration(challenge, id, cd, ao, true); err != nil {
				t.Fatalf("alg %d, id %d: the independent verifier refused the generator's output: %v", alg, n, err)
			}
			cred, err := rp.VerifyRegistration(challenge, cd, ao, wa.Policy{RequireUV: true})
			if err != nil {
				t.Fatalf("alg %d, id %d: %v", alg, n, err)
			}
			if !bytes.Equal(cred.ID, id) || !bytes.Equal(cred.PublicKeyCOSE, a.cose) {
				t.Fatalf("alg %d: credential differs", alg)
			}
			p := goodParams("webauthn.get", challenge)
			p.count = 1
			acd, ad, sig := a.assertion(t, p)
			if err := otherAssertion(challenge, id, a.cose, acd, ad, sig, true); err != nil {
				t.Fatalf("alg %d: the independent verifier refused the assertion: %v", alg, err)
			}
			res, err := rp.VerifyAssertion(challenge, cred, acd, ad, sig, wa.Policy{RequireUV: true})
			if err != nil || res.SignCount != 1 || !res.UV || !res.BackupState {
				t.Fatalf("alg %d: %+v %v", alg, res, err)
			}
		}
	}
}

// Each refusal, aimed at both: ours must refuse it, and wherever the
// independent verifier refuses, so must ours.
func TestRefusalsAgree(t *testing.T) {
	type mut struct {
		name string
		edit func(p *params)
	}
	muts := []mut{
		{"wrong type", func(p *params) { p.typ = "webauthn.other" }},
		{"wrong challenge", func(p *params) { p.challenge = bytes.Repeat([]byte{1}, 32) }},
		{"wrong origin", func(p *params) { p.origin = "https://evil.example.org" }},
		{"wrong rpIdHash", func(p *params) { p.rpID = "evil.example.org" }},
		{"UP clear", func(p *params) { p.flags &^= wa.FlagUP }},
		{"UV clear", func(p *params) { p.flags &^= wa.FlagUV }},
		{"cross origin", func(p *params) { p.extraCD = map[string]any{"crossOrigin": true} }},
	}
	for _, alg := range algs {
		a := newAuthenticator(t, alg)
		id := credID(32)
		for _, mu := range muts {
			p := goodParams("webauthn.create", challenge)
			mu.edit(&p)
			cd, ao := a.registration(t, p, id)
			other := otherRegistration(challenge, id, cd, ao, true)
			_, ours := rp.VerifyRegistration(challenge, cd, ao, wa.Policy{RequireUV: true})
			if ours == nil {
				t.Errorf("alg %d, registration, %s: accepted", alg, mu.name)
			}
			if other == nil {
				t.Errorf("alg %d, registration, %s: the independent verifier accepted it, so the mutation does not test what it names", alg, mu.name)
			}

			q := goodParams("webauthn.get", challenge)
			q.count = 1
			mu.edit(&q)
			cd2, ad, sig := a.assertion(t, q)
			other = otherAssertion(challenge, id, a.cose, cd2, ad, sig, true)
			cred := wa.Credential{ID: id, PublicKeyCOSE: a.cose, BackupEligible: true}
			_, ours = rp.VerifyAssertion(challenge, cred, cd2, ad, sig, wa.Policy{RequireUV: true})
			if ours == nil {
				t.Errorf("alg %d, assertion, %s: accepted", alg, mu.name)
			}
			if other == nil {
				t.Errorf("alg %d, assertion, %s: the independent verifier accepted it", alg, mu.name)
			}
		}
		// A signature made by another key, and one of a different message.
		b := newAuthenticator(t, alg)
		p := goodParams("webauthn.get", challenge)
		p.count = 1
		cd, ad, _ := a.assertion(t, p)
		_, _, sig := b.assertion(t, p)
		cred := wa.Credential{ID: id, PublicKeyCOSE: a.cose, BackupEligible: true}
		if err := otherAssertion(challenge, id, a.cose, cd, ad, sig, true); err == nil {
			t.Errorf("alg %d: the independent verifier accepted another key's signature", alg)
		}
		if _, err := rp.VerifyAssertion(challenge, cred, cd, ad, sig, wa.Policy{}); err == nil {
			t.Errorf("alg %d: accepted another key's signature", alg)
		}
	}
}

// Whatever ours accepts after a random corruption, the independent verifier
// accepts too, with the same credential. (The converse does not hold: ours
// refuses non-canonical CBOR on purpose.)
func TestAcceptedImpliesAcceptedByTheOther(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	for _, alg := range algs {
		a := newAuthenticator(t, alg)
		id := credID(32)
		cd, ao := a.registration(t, goodParams("webauthn.create", challenge), id)
		accepted := 0
		for i := 0; i < 4000; i++ {
			mut := bytes.Clone(ao)
			for k := 0; k <= rng.IntN(3); k++ {
				mut[rng.IntN(len(mut))] ^= byte(1 << rng.IntN(8))
			}
			cred, err := rp.VerifyRegistration(challenge, cd, mut, wa.Policy{})
			if err != nil {
				continue
			}
			accepted++
			if other := otherRegistration(challenge, cred.ID, cd, mut, false); other != nil {
				t.Fatalf("alg %d: ours accepted %x which the independent verifier refuses: %v", alg, mut, other)
			}
		}
		t.Logf("alg %d: %d of 4000 corrupted registrations accepted by ours, all by the other too", alg, accepted)
	}
}

// Overlong and non-canonical forms: a CBOR encoder in its non-canonical mode
// writes them, the independent verifier takes them, and ours refuses.
func TestNonCanonicalCBORIsRefusedByUsOnly(t *testing.T) {
	a := newAuthenticator(t, wa.AlgES256)
	id := credID(32)
	cd, _ := a.registration(t, goodParams("webauthn.create", challenge), id)
	att := append(make([]byte, 16), 0, 32)
	att = append(append(att, id...), a.cose...)
	ad := goodParams("webauthn.create", challenge).authData(att)
	// Same content, keys in the other order: valid CBOR, not deterministic.
	m, err := cbor.EncOptions{Sort: cbor.SortNone}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	ao, _ := m.Marshal(struct {
		AuthData []byte         `cbor:"authData"`
		AttStmt  map[string]any `cbor:"attStmt"`
		Fmt      string         `cbor:"fmt"`
	}{ad, map[string]any{}, "none"})
	if err := otherRegistration(challenge, id, cd, ao, true); err != nil {
		t.Skipf("the independent verifier also refuses this form: %v", err)
	}
	if _, err := rp.VerifyRegistration(challenge, cd, ao, wa.Policy{}); err == nil {
		t.Fatal("ours accepted a non-deterministic attestation object")
	}
}
