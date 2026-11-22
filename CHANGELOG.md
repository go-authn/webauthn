# Changelog

## v0.2.0

Security audit 2026-11-21.

- Registration refuses an Ed25519 public key that is a point of small order
  (the eight points of order dividing 8): the identity verifies R = identity,
  S = 0 over any message, so such a key has no secret behind it. Breaking for
  a credential that registered one.
- `coseKey.verify` fails closed (`ErrKey`) on a key type it has no verifier
  for. Not reachable before: `parseCOSEKey` is the only constructor and
  returns the three supported types.
