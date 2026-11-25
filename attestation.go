// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

// AttestationType is how the statement vouches for the credential (§6.5.3).
type AttestationType int

const (
	// AttestationNone: format "none" (§8.7); nothing is vouched for.
	AttestationNone AttestationType = iota
	// AttestationSelf: packed self attestation (§8.2): signed by the
	// credential's own key, which proves nothing about the hardware.
	AttestationSelf
	// AttestationBasic: packed with an x5c chain (§8.2): signed by an
	// attestation key whose certificate the caller must still trust-check
	// (Basic or AttCA, which the statement does not distinguish).
	AttestationBasic
)

// Attestation is what VerifyRegistrationAttested learned from the statement.
type Attestation struct {
	Format string
	Type   AttestationType
	// AAGUID is the authenticator model, set ONLY for AttestationBasic, once
	// the signature verified and the certificate's id-fido-gen-ce-aaguid (when
	// present) agreed with authData. It is trustworthy only after
	// VerifyTrustPath accepted TrustPath: a self-signed chain a test made up
	// verifies just as well. For none and self attestation it is zero, because
	// the authData AAGUID is then the authenticator's own claim.
	AAGUID [16]byte
	// TrustPath is the attestation trust path (§6.5.3): the x5c certificates,
	// attestation certificate first. Empty for none and self attestation.
	TrustPath []*x509.Certificate
}

// Bounds on the x5c array: a real chain is one to three certificates.
const (
	maxX5C     = 8
	maxCertDER = 8 << 10
)

// oidFIDOGenCEAAGUID is id-fido-gen-ce-aaguid (§8.2.1).
var oidFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// VerifyTrustPath checks that the attestation certificate chains to one of
// roots at time now, with the intermediates the statement carried. It does
// not decide WHICH roots to trust for an AAGUID: the caller takes them from
// its metadata (FIDO MDS3 attestationRootCertificates). An Attestation with
// no trust path never verifies.
func (a Attestation) VerifyTrustPath(roots []*x509.Certificate, now time.Time) error {
	if a.Type != AttestationBasic || len(a.TrustPath) == 0 {
		return fmt.Errorf("%w: no certificate chain to verify", ErrAttestation)
	}
	if len(roots) == 0 {
		return fmt.Errorf("%w: no trust anchors", ErrAttestation)
	}
	rp, ip := x509.NewCertPool(), x509.NewCertPool()
	for _, r := range roots {
		rp.AddCert(r)
	}
	for _, c := range a.TrustPath[1:] {
		ip.AddCert(c)
	}
	_, err := a.TrustPath[0].Verify(x509.VerifyOptions{
		Roots:         rp,
		Intermediates: ip,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("%w: chain: %w", ErrAttestation, err)
	}
	return nil
}

// VerifyRegistrationAttested is VerifyRegistration that also accepts packed
// attestation with an x5c chain (§8.2) and reports what the statement
// proves. The statement's signature and the attestation certificate's
// requirements (§8.2.1) are checked here; whether the chain is TRUSTED is
// Attestation.VerifyTrustPath's question, asked with the caller's roots.
// Format "none" and packed self attestation are accepted as in
// VerifyRegistration and yield no AAGUID.
func (rp RelyingParty) VerifyRegistrationAttested(challenge, clientDataJSON, attestationObject []byte, p Policy) (Credential, Attestation, error) {
	return rp.verifyRegistration(challenge, clientDataJSON, attestationObject, p, true)
}

// verifyPacked is the §8.2 verification procedure for both branches.
func verifyPacked(ao *AttestationObject, key *coseKey, clientDataHash []byte, allowChain bool) (Attestation, error) {
	att := Attestation{Format: "packed"}
	alg, okA := lookup[int64](ao.attStmt, "alg")
	sig, okS := lookup[[]byte](ao.attStmt, "sig")
	if !okA || !okS {
		return att, fmt.Errorf("%w: packed statement lacks a well-typed alg and sig", ErrAttestation)
	}
	msg := append(append([]byte(nil), ao.RawAuthData...), clientDataHash...)
	x5c, hasChain := ao.attStmt.get("x5c")
	if !hasChain { // self attestation: step 3
		if len(ao.attStmt) != 2 {
			return att, fmt.Errorf("%w: packed statement is not self attestation (only alg and sig, no certificate chain)", ErrAttestation)
		}
		if alg != key.alg {
			return att, fmt.Errorf("%w: packed alg %d is not the credential's %d", ErrAttestation, alg, key.alg)
		}
		if err := key.verify(msg, sig); err != nil {
			return att, fmt.Errorf("%w: self attestation: %w", ErrAttestation, err)
		}
		att.Type = AttestationSelf
		return att, nil
	}
	if !allowChain {
		return att, fmt.Errorf("%w: packed statement carries a certificate chain, which VerifyRegistration does not trust; use VerifyRegistrationAttested", ErrAttestation)
	}
	if len(ao.attStmt) != 3 { // alg, sig, x5c and nothing else (no ecdaaKeyId)
		return att, fmt.Errorf("%w: packed statement has members besides alg, sig and x5c", ErrAttestation)
	}
	list, ok := x5c.([]any)
	if !ok || len(list) == 0 || len(list) > maxX5C {
		return att, fmt.Errorf("%w: x5c must be one to %d certificates", ErrAttestation, maxX5C)
	}
	for _, e := range list {
		der, _ := e.([]byte) // an element that is not a byte string leaves der empty
		if len(der) == 0 || len(der) > maxCertDER {
			return att, fmt.Errorf("%w: x5c holds an element that is not a certificate of at most %d bytes", ErrAttestation, maxCertDER)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return att, fmt.Errorf("%w: x5c certificate: %v", ErrAttestation, err)
		}
		att.TrustPath = append(att.TrustPath, c)
	}
	leaf := att.TrustPath[0]
	attKey, err := attestationKey(alg, leaf)
	if err != nil {
		return att, err
	}
	if err := attKey.verify(msg, sig); err != nil { // step 2, first bullet
		return att, fmt.Errorf("%w: attestation signature: %w", ErrAttestation, err)
	}
	if err := checkAttestationCert(leaf, ao.AuthData.AAGUID); err != nil { // §8.2.1, and the aaguid bullet
		return att, err
	}
	att.Type = AttestationBasic
	att.AAGUID = ao.AuthData.AAGUID
	return att, nil
}

// attestationKey wraps the attestation certificate's public key for alg,
// refusing a key that is not the algorithm's.
func attestationKey(alg int64, leaf *x509.Certificate) (*coseKey, error) {
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if alg == AlgES256 && pub.Curve == elliptic.P256() {
			return &coseKey{alg: alg, pub: pub}, nil
		}
	case ed25519.PublicKey:
		if alg == AlgEdDSA {
			return &coseKey{alg: alg, pub: pub}, nil
		}
	case *rsa.PublicKey:
		if alg == AlgRS256 && pub.N.BitLen() >= minRSABits && pub.N.BitLen() <= maxRSABits {
			return &coseKey{alg: alg, pub: pub}, nil
		}
	}
	return nil, fmt.Errorf("%w: alg %d does not fit the attestation certificate's key (%T)", ErrAlgorithm, alg, leaf.PublicKey)
}

// checkAttestationCert applies §8.2.1 to the attestation certificate and,
// from §8.2 step 2, compares id-fido-gen-ce-aaguid with authData's AAGUID.
func checkAttestationCert(c *x509.Certificate, aaguid [16]byte) error {
	if c.Version != 3 {
		return fmt.Errorf("%w: attestation certificate is version %d, §8.2.1 requires 3", ErrAttestation, c.Version)
	}
	s := c.Subject
	if len(s.Country) == 0 || len(s.Organization) == 0 || len(s.CommonName) == 0 ||
		len(s.OrganizationalUnit) != 1 || s.OrganizationalUnit[0] != "Authenticator Attestation" {
		return fmt.Errorf("%w: attestation certificate subject lacks C, O, CN or OU \"Authenticator Attestation\" (§8.2.1)", ErrAttestation)
	}
	if !c.BasicConstraintsValid || c.IsCA {
		return fmt.Errorf("%w: attestation certificate must carry Basic Constraints with CA false (§8.2.1)", ErrAttestation)
	}
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidFIDOGenCEAAGUID) {
			continue
		}
		if e.Critical {
			return fmt.Errorf("%w: id-fido-gen-ce-aaguid is marked critical (§8.2.1)", ErrAttestation)
		}
		var got []byte                                                                  // the extension value is the DER of an OCTET STRING
		if rest, _ := asn1.Unmarshal(e.Value, &got); len(rest) != 0 || len(got) != 16 { // unparsable leaves got empty
			return fmt.Errorf("%w: id-fido-gen-ce-aaguid is not a 16-byte OCTET STRING (§8.2.1)", ErrAttestation)
		}
		if !bytes.Equal(got, aaguid[:]) {
			return fmt.Errorf("%w: certificate AAGUID %x differs from authData AAGUID %x (§8.2 step 2)", ErrAttestation, got, aaguid[:])
		}
	}
	return nil
}
