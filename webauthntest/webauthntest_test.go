// SPDX-License-Identifier: BSD-3-Clause

package webauthntest_test

import (
	"errors"
	"testing"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
)

var rp = webauthn.RelyingParty{ID: "login.example.org", Origins: []string{"https://login.example.org"}}

func TestRoundTrip(t *testing.T) {
	ch, _ := webauthn.NewChallenge()
	for _, alg := range []int64{webauthn.AlgES256, webauthn.AlgEdDSA, webauthn.AlgRS256} {
		a, err := webauthntest.New(alg)
		if err != nil {
			t.Fatal(err)
		}
		cd, ao := a.Register(rp.ID, rp.Origins[0], ch, webauthntest.Options{})
		cred, err := rp.VerifyRegistration(ch, cd, ao, webauthn.Policy{RequireUV: true})
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		for i := uint32(1); i <= 2; i++ {
			cd, ad, sig := a.Assert(rp.ID, rp.Origins[0], ch, webauthntest.Options{})
			res, err := rp.VerifyAssertion(ch, cred, cd, ad, sig, webauthn.Policy{RequireUV: true})
			if err != nil || res.SignCount != i {
				t.Fatalf("alg %d: %+v %v", alg, res, err)
			}
			cred.SignCount = res.SignCount
		}
	}
}

func TestOptionsBendEachField(t *testing.T) {
	ch, _ := webauthn.NewChallenge()
	a, _ := webauthntest.New(webauthn.AlgES256)
	cd, ao := a.Register(rp.ID, rp.Origins[0], ch, webauthntest.Options{})
	cred, err := rp.VerifyRegistration(ch, cd, ao, webauthn.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		o    webauthntest.Options
		want error
	}{
		"type":   {webauthntest.Options{Type: "webauthn.create"}, webauthn.ErrType},
		"origin": {webauthntest.Options{Origin: "https://evil.example.org"}, webauthn.ErrOrigin},
		"rpid":   {webauthntest.Options{RPID: "evil.example.org"}, webauthn.ErrRPIDHash},
		"no UP":  {webauthntest.Options{NoDefaultFlags: true, Flags: webauthn.FlagUV | webauthn.FlagBE | webauthn.FlagBS}, webauthn.ErrUserPresence},
		"no UV":  {webauthntest.Options{NoDefaultFlags: true, Flags: webauthn.FlagUP | webauthn.FlagBE | webauthn.FlagBS}, webauthn.ErrUserVerification},
		"cross":  {webauthntest.Options{ClientExtra: `,"topOrigin":"https://x.example"`}, webauthn.ErrCrossOrigin},
	} {
		cd, ad, sig := a.Assert(rp.ID, rp.Origins[0], ch, c.o)
		if _, err := rp.VerifyAssertion(ch, cred, cd, ad, sig, webauthn.Policy{RequireUV: true}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	a.NoCounter, a.Counter = true, 0
	cd, ad, sig := a.Assert(rp.ID, rp.Origins[0], ch, webauthntest.Options{})
	if res, err := rp.VerifyAssertion(ch, cred, cd, ad, sig, webauthn.Policy{}); err != nil || res.SignCount != 0 {
		t.Fatalf("a synced passkey: %+v %v", res, err)
	}
	if _, err := webauthntest.New(1); err == nil {
		t.Fatal("an unknown algorithm")
	}
	if len(webauthntest.JSON(map[string][]byte{"a": {1, 2, 3}})) == 0 {
		t.Fatal("json")
	}
}
