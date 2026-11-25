// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import "errors"

// Every refusal wraps exactly one of these, so a caller (and a test) can tell
// WHICH rule refused with errors.Is, and the message carries the detail.
var (
	// ErrConfig: the RelyingParty itself is unusable (empty or malformed ID,
	// an origin that is not https, an origin outside the RP ID's domain).
	ErrConfig = errors.New("webauthn: invalid relying party")
	// ErrClientData: clientDataJSON is not the JSON object the spec describes.
	ErrClientData = errors.New("webauthn: invalid clientDataJSON")
	// ErrType: clientData.type is not webauthn.create / webauthn.get (§7.1 step 7, §7.2 step 10).
	ErrType = errors.New("webauthn: wrong clientData type")
	// ErrChallenge: the challenge is not the one issued (§7.1 step 8, §7.2 step 11),
	// or the issued one is shorter than 16 bytes (§13.4.3).
	ErrChallenge = errors.New("webauthn: challenge mismatch")
	// ErrOrigin: the origin is not one of the RP's (§7.1 step 9, §7.2 step 12).
	ErrOrigin = errors.New("webauthn: origin not allowed")
	// ErrCrossOrigin: crossOrigin is true or topOrigin is present (§7.1 steps 9-10).
	ErrCrossOrigin = errors.New("webauthn: cross-origin ceremony refused")
	// ErrRPIDHash: authData.rpIdHash is not SHA-256 of the RP ID (§7.1 step 13, §7.2 step 14).
	ErrRPIDHash = errors.New("webauthn: rpIdHash mismatch")
	// ErrUserPresence: the UP flag is not set (§7.1 step 14, §7.2 step 15).
	ErrUserPresence = errors.New("webauthn: user presence not set")
	// ErrUserVerification: UV is required and not set (§7.1 step 15, §7.2 step 16).
	ErrUserVerification = errors.New("webauthn: user verification required")
	// ErrBackup: BS set without BE, or BE differs from the credential's (§6.1.3, §7.2 step 17).
	ErrBackup = errors.New("webauthn: inconsistent backup flags")
	// ErrSignCount: the counter did not advance although either is non-zero (§6.1.1, §7.2 step 21).
	ErrSignCount = errors.New("webauthn: signature counter regression")
	// ErrAuthData: authenticator data is malformed (§6.1).
	ErrAuthData = errors.New("webauthn: invalid authenticator data")
	// ErrAttestation: an attestation object that is malformed or whose format
	// or statement this library does not accept (§6.5, §8.2, §8.7).
	ErrAttestation = errors.New("webauthn: attestation refused")
	// ErrAAGUIDExtensionMissing: Policy.RequireAAGUIDExtension is set and the
	// attestation certificate has no id-fido-gen-ce-aaguid (§8.2.1). Like the
	// two below it also matches ErrAttestation.
	ErrAAGUIDExtensionMissing = errors.New("webauthn: id-fido-gen-ce-aaguid missing")
	// ErrAAGUIDExtensionMalformed: id-fido-gen-ce-aaguid is critical or is not
	// the DER of a 16-byte OCTET STRING (§8.2.1). Raised whenever the extension
	// is present, required or not.
	ErrAAGUIDExtensionMalformed = errors.New("webauthn: id-fido-gen-ce-aaguid malformed")
	// ErrAAGUIDExtensionMismatch: id-fido-gen-ce-aaguid differs from authData's
	// AAGUID (§8.2 step 2). Raised whenever the extension is present.
	ErrAAGUIDExtensionMismatch = errors.New("webauthn: id-fido-gen-ce-aaguid mismatch")
	// ErrCredentialID: empty or longer than 1023 bytes (§6.3).
	ErrCredentialID = errors.New("webauthn: invalid credential ID")
	// ErrAlgorithm: a COSE algorithm other than ES256, EdDSA or RS256 (RFC 9053).
	ErrAlgorithm = errors.New("webauthn: unsupported algorithm")
	// ErrKey: a COSE key that is malformed, off its curve or too weak (RFC 9052, 9053).
	ErrKey = errors.New("webauthn: invalid public key")
	// ErrSignature: the signature does not verify (§7.2 step 20).
	ErrSignature = errors.New("webauthn: signature invalid")
	// ErrTrailingBytes: bytes follow a structure that must end exactly there.
	ErrTrailingBytes = errors.New("webauthn: trailing bytes")
	// ErrCBOR: the input is not the strict, deterministic, bounded CBOR
	// subset this package reads (RFC 8949 §4.2).
	ErrCBOR = errors.New("webauthn: invalid CBOR")
)
