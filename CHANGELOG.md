# Changelog

## v0.4.0

- `Policy.RequireAAGUIDExtension` (default false, behaviour unchanged): makes
  `VerifyRegistrationAttested` refuse an attestation certificate that lacks
  id-fido-gen-ce-aaguid (WebAuthn Level 3 section 8.2.1). Three new sentinels,
  each also matching `ErrAttestation`: `ErrAAGUIDExtensionMissing`,
  `ErrAAGUIDExtensionMalformed` (critical, or not a 16-byte OCTET STRING) and
  `ErrAAGUIDExtensionMismatch` (differs from authData). Malformed and Mismatch
  are also raised when the extension is present without the option; the error
  texts are unchanged. New fuzz target `FuzzAAGUIDExtension`.

## v0.3.0

- `RelyingParty.VerifyRegistrationAttested` verifies `packed` attestation with
  an x5c chain (WebAuthn Level 3 section 8.2): the signature under the
  attestation certificate, the certificate requirements of 8.2.1 (version 3,
  subject C/O/OU "Authenticator Attestation"/CN, Basic Constraints CA false,
  non-critical id-fido-gen-ce-aaguid equal to authData's AAGUID). It returns an
  `Attestation` (type, verified AAGUID, trust path). `none` and self attestation
  yield no AAGUID.
- `Attestation.VerifyTrustPath(roots, now)` builds the chain to caller-supplied
  roots. Trusting a root for an AAGUID stays the caller's decision.
- `VerifyRegistration` is unchanged: it still refuses a statement with a chain.
- Fuzz target `FuzzAttestationStatement`, corpus committed.

## v0.2.0

Security audit 2026-11-21.

- Registration refuses an Ed25519 public key that is a point of small order
  (the eight points of order dividing 8): the identity verifies R = identity,
  S = 0 over any message, so such a key has no secret behind it. Breaking for
  a credential that registered one.
- `coseKey.verify` fails closed (`ErrKey`) on a key type it has no verifier
  for. Not reachable before: `parseCOSEKey` is the only constructor and
  returns the three supported types.
