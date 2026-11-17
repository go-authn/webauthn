// SPDX-License-Identifier: BSD-3-Clause

// Package webauthntest is a software authenticator for tests of a relying
// party: it makes the registrations and assertions a browser would hand over,
// for ES256, EdDSA and RS256, with the flags, counter and origin a test asks
// for, so that a refusal can be aimed at each field.
//
// It is for tests only. Its output is checked against an independent
// verifier (github.com/go-webauthn/webauthn) in this repository's judge
// module, so a test that uses it is not only checking the verifier against
// code written alongside it.
package webauthntest

import (
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
	"fmt"

	"github.com/go-authn/webauthn"
)

// Authenticator is one credential: a key, its ID and a signature counter.
type Authenticator struct {
	// ID is the credential ID the authenticator reports.
	ID []byte
	// COSE is the credential public key as registered.
	COSE []byte
	// Alg is the COSE algorithm.
	Alg int64
	// Counter is the signature counter; Assert increments it first. Set it to
	// zero and NoCounter to model a synced passkey.
	Counter   uint32
	NoCounter bool

	sign func(msg []byte) []byte
}

// Options are the fields of one ceremony a test may bend.
type Options struct {
	// Type overrides clientData.type ("webauthn.create" / "webauthn.get").
	Type string
	// Origin overrides clientData.origin; RPID the rpId that is hashed.
	Origin string
	RPID   string
	// Flags replaces the default flags (UP, UV, BE, BS) when NoDefaultFlags.
	Flags          byte
	NoDefaultFlags bool
	// ClientExtra is spliced into clientDataJSON after its members, as
	// `,"crossOrigin":true`.
	ClientExtra string
	// UserHandle is returned with an assertion by the caller; not signed.
}

// DefaultFlags are user present, user verified, backup eligible and backed up.
const DefaultFlags = webauthn.FlagUP | webauthn.FlagUV | webauthn.FlagBE | webauthn.FlagBS

// New makes an authenticator with a fresh key and a random 32-byte ID.
func New(alg int64) (*Authenticator, error) {
	a := &Authenticator{Alg: alg, ID: make([]byte, 32)}
	if _, err := rand.Read(a.ID); err != nil {
		return nil, err
	}
	switch alg {
	case webauthn.AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pt, err := k.PublicKey.Bytes()
		if err != nil {
			return nil, err
		}
		a.COSE = cborMap(1, 2, 3, -7, -1, 1, -2, pt[1:33], -3, pt[33:65])
		a.sign = func(msg []byte) []byte {
			h := sha256.Sum256(msg)
			s, _ := ecdsa.SignASN1(rand.Reader, k, h[:])
			return s
		}
	case webauthn.AlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		a.COSE = cborMap(1, 1, 3, -8, -1, 6, -2, []byte(pub))
		a.sign = func(msg []byte) []byte { return ed25519.Sign(priv, msg) }
	case webauthn.AlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		a.COSE = cborMap(1, 3, 3, -257, -1, k.N.Bytes(), -2, []byte{1, 0, 1})
		a.sign = func(msg []byte) []byte {
			h := sha256.Sum256(msg)
			s, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
			return s
		}
	default:
		return nil, fmt.Errorf("webauthntest: algorithm %d", alg)
	}
	return a, nil
}

func (o Options) flags() byte {
	if o.NoDefaultFlags {
		return o.Flags
	}
	return DefaultFlags
}

func clientData(typ string, challenge []byte, o Options, origin string) []byte {
	if o.Type != "" {
		typ = o.Type
	}
	if o.Origin != "" {
		origin = o.Origin
	}
	return fmt.Appendf(nil, `{"type":%q,"challenge":%q,"origin":%q,"crossOrigin":false%s}`,
		typ, base64.RawURLEncoding.EncodeToString(challenge), origin, o.ClientExtra)
}

func authData(rpID string, o Options, count uint32, attested []byte) []byte {
	if o.RPID != "" {
		rpID = o.RPID
	}
	h := sha256.Sum256([]byte(rpID))
	out := append(h[:], o.flags())
	out = binary.BigEndian.AppendUint32(out, count)
	return append(out, attested...)
}

// Register answers navigator.credentials.create() for rpID and origin, with
// attestation "none".
func (a *Authenticator) Register(rpID, origin string, challenge []byte, o Options) (clientDataJSON, attestationObject []byte) {
	cd := clientData("webauthn.create", challenge, o, origin)
	att := append(make([]byte, 16), byte(len(a.ID)>>8), byte(len(a.ID)))
	att = append(append(att, a.ID...), a.COSE...)
	o.Flags, o.NoDefaultFlags = o.flags()|webauthn.FlagAT, true
	ad := authData(rpID, o, a.Counter, att)
	return cd, enc(map2("fmt", "none", "attStmt", cmap{}, "authData", ad))
}

// Assert answers navigator.credentials.get(): it increments the counter (unless
// NoCounter), and signs authData || SHA-256(clientDataJSON).
func (a *Authenticator) Assert(rpID, origin string, challenge []byte, o Options) (clientDataJSON, authenticatorData, signature []byte) {
	if !a.NoCounter {
		a.Counter++
	}
	cd := clientData("webauthn.get", challenge, o, origin)
	ad := authData(rpID, o, a.Counter, nil)
	h := sha256.Sum256(cd)
	return cd, ad, a.sign(append(append([]byte(nil), ad...), h[:]...))
}

// JSON is a response as a page's script would post it: every binary value
// base64url without padding.
func JSON(v map[string][]byte) []byte {
	m := map[string]string{}
	for k, b := range v {
		m[k] = base64.RawURLEncoding.EncodeToString(b)
	}
	out, _ := json.Marshal(m)
	return out
}

// a minimal deterministic CBOR encoder, enough for the objects above ----------

type cmap []any // alternating key, value; keys already in deterministic order

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	}
	return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
}

func enc(v any) []byte {
	switch v := v.(type) {
	case int:
		if v >= 0 {
			return head(0, uint64(v))
		}
		return head(1, uint64(-1-v))
	case []byte:
		return append(head(2, uint64(len(v))), v...)
	case string:
		return append(head(3, uint64(len(v))), v...)
	case cmap:
		out := head(5, uint64(len(v)/2))
		for _, e := range v {
			out = append(out, enc(e)...)
		}
		return out
	}
	panic(fmt.Sprintf("webauthntest: cannot encode %T", v))
}

func map2(kv ...any) cmap { return cmap(kv) }

// cborMap encodes integer-labelled maps; the callers list labels in the order
// the encoding requires (1, 3, -1, -2, -3).
func cborMap(kv ...any) []byte { return enc(cmap(kv)) }
