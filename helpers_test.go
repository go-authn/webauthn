// SPDX-License-Identifier: BSD-3-Clause

package webauthn

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
	"fmt"
	"sync"
	"testing"
)

// This file is a small CBOR ENCODER and a software authenticator, test-only.
// They exist to build inputs the refusals can be aimed at; they are written
// by the same hand as the verifier, so the independent evidence is elsewhere
// (the W3C vectors in vectors_test.go, and the judge module in ./judge).

// raw is spliced into the output verbatim, so a test can write a
// non-canonical encoding on purpose.
type raw []byte

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	case n < 1<<32:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
	return binary.BigEndian.AppendUint64([]byte{major<<5 | 27}, n)
}

func enc(v any) []byte {
	switch v := v.(type) {
	case raw:
		return v
	case int:
		return enc(int64(v))
	case int64:
		if v >= 0 {
			return cborHead(0, uint64(v))
		}
		return cborHead(1, uint64(-1-v))
	case []byte:
		return append(cborHead(2, uint64(len(v))), v...)
	case string:
		return append(cborHead(3, uint64(len(v))), v...)
	case bool:
		if v {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case nil:
		return []byte{0xf6}
	case []any:
		out := cborHead(4, uint64(len(v)))
		for _, e := range v {
			out = append(out, enc(e)...)
		}
		return out
	case cborMap:
		out := cborHead(5, uint64(len(v)))
		for _, p := range v {
			out = append(out, enc(p.Key)...)
			out = append(out, enc(p.Val)...)
		}
		return out
	}
	panic(fmt.Sprintf("enc: %T", v))
}

func m(kv ...any) cborMap {
	var out cborMap
	for i := 0; i < len(kv); i += 2 {
		out = append(out, cborPair{Key: kv[i], Val: kv[i+1]})
	}
	return out
}

// software authenticator ----------------------------------------------------

type authn struct {
	alg  int64
	cose []byte
	sign func(msg []byte) []byte
}

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func newAuthn(tb testing.TB, alg int64) *authn {
	tb.Helper()
	switch alg {
	case AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		pt, _ := k.PublicKey.Bytes()
		cose := enc(m(int64(1), int64(2), int64(3), int64(-7), int64(-1), int64(1), int64(-2), pt[1:33], int64(-3), pt[33:65]))
		return &authn{alg, cose, func(msg []byte) []byte {
			h := sha256.Sum256(msg)
			s, err := ecdsa.SignASN1(rand.Reader, k, h[:])
			if err != nil {
				tb.Fatal(err)
			}
			return s
		}}
	case AlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		cose := enc(m(int64(1), int64(1), int64(3), int64(-8), int64(-1), int64(6), int64(-2), []byte(pub)))
		return &authn{alg, cose, func(msg []byte) []byte { return ed25519.Sign(priv, msg) }}
	case AlgRS256:
		rsaOnce.Do(func() {
			var err error
			if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
				tb.Fatal(err)
			}
		})
		cose := enc(m(int64(1), int64(3), int64(3), int64(-257), int64(-1), rsaKey.N.Bytes(), int64(-2), []byte{1, 0, 1}))
		return &authn{alg, cose, func(msg []byte) []byte {
			h := sha256.Sum256(msg)
			s, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])
			if err != nil {
				tb.Fatal(err)
			}
			return s
		}}
	}
	tb.Fatalf("alg %d", alg)
	return nil
}

func rpHash(id string) []byte { h := sha256.Sum256([]byte(id)); return h[:] }

func authData(rpID string, flags byte, count uint32, attested ...[]byte) []byte {
	out := append(rpHash(rpID), flags)
	out = binary.BigEndian.AppendUint32(out, count)
	for _, a := range attested { // aaguid+len+id, then the key, then extensions
		out = append(out, a...)
	}
	return out
}

// attested builds the attested credential data for authData.
func attested(id, cose []byte) []byte {
	out := make([]byte, 16)
	out = binary.BigEndian.AppendUint16(out, uint16(len(id)))
	out = append(out, id...)
	return append(out, cose...)
}

func clientDataJSON(typ string, challenge []byte, origin, extra string) []byte {
	return []byte(fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":%q%s}`,
		typ, base64.RawURLEncoding.EncodeToString(challenge), origin, extra))
}

func attObj(format string, stmt cborMap, ad []byte) []byte {
	return enc(m("fmt", format, "attStmt", stmt, "authData", ad))
}

var (
	testRP    = RelyingParty{ID: "login.example.org", Origins: []string{"https://login.example.org"}}
	testChall = []byte("0123456789abcdef0123456789abcdef")
	testID    = []byte("credential-id-0123456789")
)

const (
	flagsOK = FlagUP | FlagUV | FlagBE | FlagBS
	flagsAT = flagsOK | FlagAT
)

// register returns a registration response from a, none attestation.
func register(a *authn) (cd, ao []byte) {
	cd = clientDataJSON("webauthn.create", testChall, "https://login.example.org", "")
	ao = attObj("none", m(), authData(testRP.ID, flagsAT, 0, attested(testID, a.cose)))
	return
}

// assert returns an assertion from a.
func assert(a *authn, flags byte, count uint32) (cd, ad, sig []byte) {
	cd = clientDataJSON("webauthn.get", testChall, "https://login.example.org", "")
	ad = authData(testRP.ID, flags, count)
	h := sha256.Sum256(cd)
	sig = a.sign(append(append([]byte(nil), ad...), h[:]...))
	return
}
