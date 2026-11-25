# webauthn

The relying-party half of WebAuthn in pure Go: it verifies what a browser sends
back from `navigator.credentials.create()` and `.get()`, and does nothing else.
No dependency outside the standard library, `CGO_ENABLED=0`, 100 % statement
coverage, fuzzed.

```go
rp := webauthn.RelyingParty{ID: "login.example.org", Origins: []string{"https://login.example.org"}}

ch, _ := webauthn.NewChallenge() // keep it server-side: single use, short lived
cred, err := rp.VerifyRegistration(ch, clientDataJSON, attestationObject, webauthn.Policy{RequireUV: true})

ch, _ = webauthn.NewChallenge()
res, err := rp.VerifyAssertion(ch, cred, clientDataJSON, authenticatorData, signature, webauthn.Policy{RequireUV: true})
// store res.SignCount and res.BackupState back into cred
```

- Algorithms: ES256 (-7), EdDSA / Ed25519 (-8), RS256 (-257, 2048 bits or more).
- Attestation: `none` (section 8.7) and `packed` (8.2) in both forms. `VerifyRegistration`
  accepts none and self attestation and refuses a statement with a certificate chain.
  `VerifyRegistrationAttested` also verifies the x5c signature and the attestation
  certificate requirements (8.2.1, including id-fido-gen-ce-aaguid against authData)
  and returns an `Attestation` with the AAGUID and the trust path;
  `Attestation.VerifyTrustPath(roots, now)` then checks the chain against the roots
  the caller took from its metadata (FIDO MDS3). Self attestation and none yield NO
  trusted AAGUID. Other formats (tpm, android-key, apple, fido-u2f) are refused.
  The id-fido-gen-ce-aaguid extension is checked only when present (8.2.1);
  `Policy{RequireAAGUIDExtension: true}` demands it (non-critical, an OCTET STRING of
  16 bytes, equal to authData's AAGUID), and a refusal matches
  `ErrAAGUIDExtensionMissing`, `ErrAAGUIDExtensionMalformed` or
  `ErrAAGUIDExtensionMismatch` as well as `ErrAttestation`. Off by default.
- Spec: W3C Web Authentication Level 3 sections 7.1, 7.2, 6.1, 6.5.1, 8.2, 8.7,
  13.4.3; RFC 9052/9053 (COSE), RFC 8949 section 4.2 (deterministic CBOR).

## Refusals

Each wraps its own sentinel (`errors.Is`): wrong type (`ErrType`), challenge
(`ErrChallenge`), origin (`ErrOrigin`), rpIdHash (`ErrRPIDHash`); UP clear
(`ErrUserPresence`); UV clear when required (`ErrUserVerification`); BS without
BE, or BE different from the registered one (`ErrBackup`); a counter that did not
advance when either is non-zero (`ErrSignCount`); an unknown algorithm
(`ErrAlgorithm`); a key off the curve, a weak or malformed key (`ErrKey`);
non-canonical, overlong, indefinite or deep CBOR (`ErrCBOR`); trailing bytes
(`ErrTrailingBytes`); a credential ID of 0 or over 1023 bytes (`ErrCredentialID`);
`crossOrigin` / `topOrigin` (`ErrCrossOrigin`); an unaccepted attestation
(`ErrAttestation`).

The CBOR decoder is deliberately small and strict: shortest-form integers and
lengths, no indefinite lengths, no tags or floats, map keys integers or text in
bytewise order with no duplicates, UTF-8 text, depth 8, 1024 items, 64 KiB, and a
declared length is checked against the bytes present before anything is
allocated. The signature counter rule follows the specification; a synced
passkey reports zero throughout and is not refused. Credential-ID uniqueness
(step 24 of 7.1) and the user-handle check of 7.2 belong to the caller's store.

## How it is checked

- `testdata/w3c-vectors.json`: the end-to-end vectors of WebAuthn Level 3
  section 16, produced by the specification's authors (transcribed from
  go-webauthn's test of that section; `extract` reads them from its source).
- `judge/` (a separate module, so the library has no dependency): an independent
  verifier, `github.com/go-webauthn/webauthn`, and an independent CBOR encoder,
  `github.com/fxamacker/cbor/v2` in CTAP2 canonical mode, write and verify
  registrations and assertions for the three algorithms. Everything generated is
  accepted by both, every refusal aimed at both is made by both, and of 12000
  random corruptions everything we accept the other accepts too.
- `webauthntest`: a software authenticator (ES256, EdDSA, RS256; flags, counter,
  origin and rpId bendable per ceremony) for tests of a relying party. Its output
  is accepted by the independent verifier in `judge/`, so a test using it is not
  only checking the verifier against code written beside it.
- Fuzz targets for the CBOR decoder (re-encoding must reproduce the input),
  authenticator data, attestation objects, COSE keys, assertions and client data;
  the corpus is committed under `testdata/fuzz`.
- CI: Linux, macOS, Windows; race detector; 100 % coverage gate; fuzz smoke
  lanes; `govulncheck`; builds for eight architectures, with six run under qemu.

## Licence

BSD-3-Clause.
