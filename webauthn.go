// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// ChallengeSize is the length NewChallenge returns. §13.4.3 asks for at
// least 16 bytes from a cryptographic source; 32 leaves no argument.
const ChallengeSize = 32

const minChallenge = 16

// maxClientData bounds clientDataJSON; real ones are a few hundred bytes.
const maxClientData = 16 << 10

// randReader is the entropy source; a variable so a test can fail it.
var randReader io.Reader = rand.Reader

// NewChallenge returns a fresh random challenge (§13.4.3). The caller keeps
// it server-side, bound to the session, single-use and short-lived, and sends
// it to the browser base64url-encoded without padding.
func NewChallenge() ([]byte, error) {
	c := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(randReader, c); err != nil {
		return nil, fmt.Errorf("webauthn: challenge: %w", err)
	}
	return c, nil
}

// RelyingParty is the verifier's identity (§5.1.2, §3).
type RelyingParty struct {
	// ID is the RP ID: a registrable domain suffix of every origin, such as
	// "login.example.org" or "example.org". Lower case, no scheme, no port.
	ID string
	// Origins are the exact origins ("https://login.example.org", with the
	// port when not the default) pages may run the ceremony from.
	Origins []string
}

// Policy is what the relying party requires of one ceremony.
type Policy struct {
	// RequireUV demands the user-verified flag (§7.1 step 15, §7.2 step 16).
	RequireUV bool
}

// Credential is what the relying party stores per passkey.
type Credential struct {
	ID             []byte
	PublicKeyCOSE  []byte // the COSE_Key as registered (RFC 9052 §7)
	SignCount      uint32
	BackupEligible bool
	Transports     []string // as reported by the browser; informational, set by the caller
	AAGUID         [16]byte
}

// Result is what VerifyAssertion learned, to be stored back.
type Result struct {
	SignCount   uint32
	BackupState bool
	UV          bool
}

// validate checks the relying party's configuration: the ID is a bare lower
// case host name and every origin is an exact https origin (http only for
// localhost) at or below it.
func (rp RelyingParty) validate() error {
	id := rp.ID
	if id == "" || len(id) > 253 || id != strings.ToLower(id) || strings.ContainsAny(id, "/:@?# \t") {
		return fmt.Errorf("%w: RP ID %q must be a bare lower-case host name", ErrConfig, id)
	}
	if len(rp.Origins) == 0 {
		return fmt.Errorf("%w: no origins", ErrConfig)
	}
	for _, o := range rp.Origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || o != u.Scheme+"://"+u.Host {
			return fmt.Errorf("%w: origin %q must be scheme://host[:port]", ErrConfig, o)
		}
		host := u.Hostname()
		local := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if u.Scheme != "https" && !(u.Scheme == "http" && local) {
			return fmt.Errorf("%w: origin %q is not https", ErrConfig, o)
		}
		if host != id && !strings.HasSuffix(host, "."+id) {
			return fmt.Errorf("%w: origin %q is outside RP ID %q", ErrConfig, o, id)
		}
	}
	return nil
}

// clientData is the checked content of clientDataJSON (§5.8.1).
type clientData struct {
	typ       string
	challenge []byte
	origin    string
}

// parseClientData reads clientDataJSON as a JSON object with no duplicate
// member (a duplicate is two answers to one question, and decoders disagree
// about which counts), then checks type, challenge, origin and crossOrigin.
func parseClientData(raw []byte, wantType string, challenge []byte, origins []string) error {
	if len(raw) == 0 || len(raw) > maxClientData {
		return fmt.Errorf("%w: %d bytes", ErrClientData, len(raw))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("%w: not a JSON object", ErrClientData)
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrClientData, err)
		}
		key := kt.(string)
		if _, dup := members[key]; dup {
			return fmt.Errorf("%w: duplicate member %q", ErrClientData, key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("%w: %v", ErrClientData, err)
		}
		members[key] = v
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return fmt.Errorf("%w: %v", ErrClientData, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: data after the object", ErrClientData)
	}
	str := func(k string) (string, bool) {
		var s string
		raw, ok := members[k]
		if !ok || json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		return s, true
	}
	typ, ok := str("type")
	if !ok {
		return fmt.Errorf("%w: no string member type", ErrClientData)
	}
	if typ != wantType {
		return fmt.Errorf("%w: %q, expected %q", ErrType, typ, wantType)
	}
	ch, ok := str("challenge")
	if !ok {
		return fmt.Errorf("%w: no string member challenge", ErrClientData)
	}
	got, err := base64.RawURLEncoding.Strict().DecodeString(ch)
	if err != nil {
		return fmt.Errorf("%w: challenge is not unpadded base64url", ErrChallenge)
	}
	if len(challenge) < minChallenge {
		return fmt.Errorf("%w: the issued challenge is %d bytes, §13.4.3 asks for %d", ErrChallenge, len(challenge), minChallenge)
	}
	if subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrChallenge
	}
	origin, ok := str("origin")
	if !ok {
		return fmt.Errorf("%w: no string member origin", ErrClientData)
	}
	allowed := false
	for _, o := range origins {
		if origin == o {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("%w: %q", ErrOrigin, origin)
	}
	if cr, present := members["crossOrigin"]; present {
		var b bool
		if json.Unmarshal(cr, &b) != nil {
			return fmt.Errorf("%w: crossOrigin is not a boolean", ErrClientData)
		}
		if b {
			return fmt.Errorf("%w: crossOrigin is true", ErrCrossOrigin)
		}
	}
	if _, present := members["topOrigin"]; present {
		return fmt.Errorf("%w: topOrigin present", ErrCrossOrigin)
	}
	return nil
}

// checkAuthData applies the flag and rpIdHash rules both ceremonies share.
func (rp RelyingParty) checkAuthData(a *AuthenticatorData, p Policy) error {
	if a.RPIDHash != sha256.Sum256([]byte(rp.ID)) {
		return ErrRPIDHash
	}
	if !a.UserPresent() {
		return ErrUserPresence
	}
	if p.RequireUV && !a.UserVerified() {
		return ErrUserVerification
	}
	if a.BackupState() && !a.BackupEligible() {
		return fmt.Errorf("%w: BS set while BE is clear (§6.1.3)", ErrBackup)
	}
	return nil
}

// VerifyRegistration verifies the response to navigator.credentials.create()
// by W3C WebAuthn Level 3 §7.1 and returns the credential to store.
//
// challenge is the value issued for this ceremony. Attestation is accepted in
// format "none" (§8.7) and "packed" self attestation (§8.2, no x5c): a
// statement that carries a certificate chain is refused rather than ignored,
// because this package does not decide whom to trust (ask the browser for
// attestation "none"). Step 24, that the credential ID is not already
// registered, belongs to the caller's store.
func (rp RelyingParty) VerifyRegistration(challenge, clientDataJSON, attestationObject []byte, p Policy) (Credential, error) {
	if err := rp.validate(); err != nil {
		return Credential{}, err
	}
	if err := parseClientData(clientDataJSON, "webauthn.create", challenge, rp.Origins); err != nil { // steps 7-10
		return Credential{}, err
	}
	ao, err := ParseAttestationObject(attestationObject) // step 12
	if err != nil {
		return Credential{}, err
	}
	ad := ao.AuthData
	if err := rp.checkAuthData(ad, p); err != nil { // steps 13-16
		return Credential{}, err
	}
	key, err := parseCOSEKey(ad.PublicKeyCOSE) // step 17
	if err != nil {
		return Credential{}, err
	}
	hash := sha256.Sum256(clientDataJSON)                       // step 11
	if err := verifyAttestation(ao, key, hash[:]); err != nil { // steps 19-21
		return Credential{}, err
	}
	return Credential{
		ID:             ad.CredentialID,
		PublicKeyCOSE:  ad.PublicKeyCOSE,
		SignCount:      ad.SignCount,
		BackupEligible: ad.BackupEligible(),
		AAGUID:         ad.AAGUID,
	}, nil
}

// verifyAttestation checks the statement for the two accepted formats.
func verifyAttestation(ao *AttestationObject, key *coseKey, clientDataHash []byte) error {
	switch ao.Format {
	case "none": // §8.7
		if len(ao.attStmt) != 0 {
			return fmt.Errorf("%w: format none carries a statement (§8.7)", ErrAttestation)
		}
		return nil
	case "packed": // §8.2, the self-attestation case of §8.2.1
		if len(ao.attStmt) != 2 {
			return fmt.Errorf("%w: packed statement is not self attestation (only alg and sig, no certificate chain)", ErrAttestation)
		}
		alg, okA := lookup[int64](ao.attStmt, "alg")
		sig, okS := lookup[[]byte](ao.attStmt, "sig")
		if !okA || !okS {
			return fmt.Errorf("%w: packed statement lacks a well-typed alg and sig", ErrAttestation)
		}
		if alg != key.alg {
			return fmt.Errorf("%w: packed alg %d is not the credential's %d", ErrAttestation, alg, key.alg)
		}
		msg := append(append([]byte(nil), ao.RawAuthData...), clientDataHash...)
		if err := key.verify(msg, sig); err != nil {
			return fmt.Errorf("%w: self attestation: %w", ErrAttestation, err)
		}
		return nil
	}
	return fmt.Errorf("%w: format %q (only none and packed self attestation)", ErrAttestation, ao.Format)
}

// VerifyAssertion verifies the response to navigator.credentials.get() by
// W3C WebAuthn Level 3 §7.2 against the stored credential c, and returns what
// to store back: the new counter, the backup state and whether the user was
// verified.
//
// Steps 5-7 (that this credential is the one the user handle names, and that
// it was allowed for the ceremony) belong to the caller, which looked c up.
//
// The counter is refused when both the stored and the presented values are
// non-zero and the new one is not greater (§6.1.1, step 21): a synced passkey
// reports zero throughout and is not refused.
func (rp RelyingParty) VerifyAssertion(challenge []byte, c Credential, clientDataJSON, authenticatorData, signature []byte, p Policy) (Result, error) {
	if err := rp.validate(); err != nil {
		return Result{}, err
	}
	if n := len(c.ID); n == 0 || n > MaxCredentialIDLength {
		return Result{}, fmt.Errorf("%w: length %d (1..%d)", ErrCredentialID, n, MaxCredentialIDLength)
	}
	key, err := parseCOSEKey(c.PublicKeyCOSE) // step 7
	if err != nil {
		return Result{}, err
	}
	if err := parseClientData(clientDataJSON, "webauthn.get", challenge, rp.Origins); err != nil { // steps 10-13
		return Result{}, err
	}
	ad, err := ParseAuthenticatorData(authenticatorData, false)
	if err != nil {
		return Result{}, err
	}
	if err := rp.checkAuthData(ad, p); err != nil { // steps 14-16
		return Result{}, err
	}
	if ad.BackupEligible() != c.BackupEligible { // step 17
		return Result{}, fmt.Errorf("%w: BE is %t, the credential registered %t", ErrBackup, ad.BackupEligible(), c.BackupEligible)
	}
	hash := sha256.Sum256(clientDataJSON) // step 19
	msg := append(append([]byte(nil), authenticatorData...), hash[:]...)
	if err := key.verify(msg, signature); err != nil { // step 20
		return Result{}, err
	}
	if ad.SignCount != 0 && c.SignCount != 0 && ad.SignCount <= c.SignCount { // step 21
		return Result{}, fmt.Errorf("%w: %d after %d, the authenticator may be cloned", ErrSignCount, ad.SignCount, c.SignCount)
	}
	return Result{SignCount: ad.SignCount, BackupState: ad.BackupState(), UV: ad.UserVerified()}, nil
}
