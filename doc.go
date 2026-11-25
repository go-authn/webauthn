// SPDX-License-Identifier: BSD-3-Clause

// Package webauthn is the relying-party half of WebAuthn: it verifies the
// registration and assertion a browser sends back, and nothing else. It makes
// no HTTP request, keeps no state and has no dependency outside the standard
// library.
//
//	rp := webauthn.RelyingParty{ID: "login.example.org", Origins: []string{"https://login.example.org"}}
//
//	ch, _ := webauthn.NewChallenge()           // keep it, single-use, bound to the session
//	// ... navigator.credentials.create(...) in the browser ...
//	cred, err := rp.VerifyRegistration(ch, clientDataJSON, attestationObject, webauthn.Policy{RequireUV: true})
//
//	ch, _ = webauthn.NewChallenge()
//	// ... navigator.credentials.get(...) ...
//	res, err := rp.VerifyAssertion(ch, cred, clientDataJSON, authenticatorData, signature, webauthn.Policy{RequireUV: true})
//	// store res.SignCount and res.BackupState back into cred
//
// Specifications, as opened for this package: W3C Web Authentication Level 3
// (registration section 7.1, assertion section 7.2, authenticator data 6.1,
// attested credential data 6.5.1, packed attestation 8.2, "none" attestation
// 8.7, challenges 13.4.3, test vectors 16), RFC 9052 and 9053 (COSE keys and
// algorithms), RFC 8812 (RS256), RFC 8032 (Ed25519) and RFC 8949 (CBOR,
// deterministic encoding in 4.2).
//
// What is refused, each with its own error to test against: a wrong type,
// challenge, origin or rpIdHash; user presence not set; user verification not
// set when required; backup flags that contradict each other or the
// credential; a signature counter that did not advance (both non-zero); an
// unknown algorithm, a key off its curve or an RSA key under 2048 bits; any
// non-deterministic, overlong, indefinite-length or deeply nested CBOR; bytes
// after a structure; a credential ID of 0 or more than 1023 bytes;
// crossOrigin and topOrigin ceremonies; and any attestation format other than
// "none" and "packed". VerifyRegistration refuses a packed statement with a
// certificate chain; VerifyRegistrationAttested verifies it (8.2, 8.2.1) and
// Attestation.VerifyTrustPath checks the chain against the caller's roots.
package webauthn
