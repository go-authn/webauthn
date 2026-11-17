// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"encoding/binary"
	"fmt"
)

// Authenticator data flags (W3C WebAuthn Level 3 §6.1, Table "Flags").
const (
	FlagUP byte = 1 << 0 // user present
	FlagUV byte = 1 << 2 // user verified
	FlagBE byte = 1 << 3 // backup eligible (§6.1.3)
	FlagBS byte = 1 << 4 // backup state (§6.1.3)
	FlagAT byte = 1 << 6 // attested credential data included (§6.5.1)
	FlagED byte = 1 << 7 // extension data included
)

// MaxCredentialIDLength is the longest credential ID WebAuthn allows (§6.3).
const MaxCredentialIDLength = 1023

// AuthenticatorData is the parsed form of §6.1.
type AuthenticatorData struct {
	RPIDHash  [32]byte
	Flags     byte
	SignCount uint32

	// Present only when FlagAT is set (§6.5.1).
	AAGUID        [16]byte
	CredentialID  []byte
	PublicKeyCOSE []byte // the COSE_Key exactly as the authenticator wrote it

	// Extensions is the raw CBOR map when FlagED is set.
	Extensions []byte
}

// UserPresent reports the UP flag.
func (a *AuthenticatorData) UserPresent() bool { return a.Flags&FlagUP != 0 }

// UserVerified reports the UV flag.
func (a *AuthenticatorData) UserVerified() bool { return a.Flags&FlagUV != 0 }

// BackupEligible reports the BE flag.
func (a *AuthenticatorData) BackupEligible() bool { return a.Flags&FlagBE != 0 }

// BackupState reports the BS flag.
func (a *AuthenticatorData) BackupState() bool { return a.Flags&FlagBS != 0 }

func authErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrAuthData}, a...)...)
}

// ParseAuthenticatorData parses §6.1 and refuses what does not end where it
// says: attested credential data (when present) is read with the COSE key
// decoded by the strict CBOR reader, the extensions map likewise, and any byte
// left over is ErrTrailingBytes. wantAttested says whether the caller needs
// the AT flag set (registration) or clear (assertion); a mismatch is refused.
func ParseAuthenticatorData(b []byte, wantAttested bool) (*AuthenticatorData, error) {
	if len(b) < 37 {
		return nil, authErr("%d bytes, need at least 37", len(b))
	}
	if len(b) > MaxCBORInput {
		return nil, authErr("%d bytes exceeds %d", len(b), MaxCBORInput)
	}
	a := &AuthenticatorData{Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	copy(a.RPIDHash[:], b[:32])
	if (a.Flags&FlagAT != 0) != wantAttested {
		return nil, authErr("AT flag is %t, expected %t", a.Flags&FlagAT != 0, wantAttested)
	}
	rest := b[37:]
	if wantAttested {
		if len(rest) < 18 {
			return nil, authErr("attested credential data truncated")
		}
		copy(a.AAGUID[:], rest[:16])
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > MaxCredentialIDLength {
			return nil, fmt.Errorf("%w: length %d (1..%d)", ErrCredentialID, n, MaxCredentialIDLength)
		}
		if len(rest) < n {
			return nil, authErr("credential ID of %d bytes with %d left", n, len(rest))
		}
		a.CredentialID = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
		// The credentialPublicKey is the one CBOR item that follows; its extent
		// is found by decoding it, never by trusting a length.
		_, used, err := decodeCBOR(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: credentialPublicKey: %w", ErrAuthData, err)
		}
		a.PublicKeyCOSE = append([]byte(nil), rest[:used]...)
		rest = rest[used:]
	}
	if a.Flags&FlagED != 0 {
		v, used, err := decodeCBOR(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: extensions: %w", ErrAuthData, err)
		}
		if _, ok := v.(cborMap); !ok {
			return nil, authErr("extensions are %T, not a map", v)
		}
		a.Extensions = append([]byte(nil), rest[:used]...)
		rest = rest[used:]
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d byte(s) after the authenticator data", ErrTrailingBytes, len(rest))
	}
	return a, nil
}

// AttestationObject is the parsed form of §6.5 (an attestation object is a
// CBOR map of exactly fmt, attStmt and authData).
type AttestationObject struct {
	Format   string
	AuthData *AuthenticatorData
	// RawAuthData is authData as signed, byte for byte.
	RawAuthData []byte
	attStmt     cborMap
}

// ParseAttestationObject reads an attestationObject. It checks structure
// only: the statement is verified by VerifyRegistration, and only for the
// formats this package accepts.
func ParseAttestationObject(b []byte) (*AttestationObject, error) {
	v, err := decodeCBORExact(b)
	if err != nil {
		return nil, fmt.Errorf("%w: attestationObject: %w", ErrAttestation, err)
	}
	m, ok := v.(cborMap)
	if !ok || len(m) != 3 {
		return nil, fmt.Errorf("%w: attestationObject must be a map of fmt, attStmt, authData", ErrAttestation)
	}
	format, okF := lookup[string](m, "fmt")
	stmt, okS := lookup[cborMap](m, "attStmt")
	raw, okA := lookup[[]byte](m, "authData")
	if !okF || !okS || !okA {
		return nil, fmt.Errorf("%w: attestationObject lacks a well-typed fmt, attStmt or authData", ErrAttestation)
	}
	ad, err := ParseAuthenticatorData(raw, true)
	if err != nil {
		return nil, err
	}
	return &AttestationObject{Format: format, AuthData: ad, RawAuthData: raw, attStmt: stmt}, nil
}

func lookup[T any](m cborMap, key string) (T, bool) {
	v, ok := m.get(key)
	t, ok2 := v.(T)
	return t, ok && ok2
}
