package dnp3

import (
	"crypto/dsa" //nolint:staticcheck // IEEE 1815-2012 A.45.8 requires DSA signatures
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// User certificate (g120v8, A.45.8): a key change method, a certificate
// type (1 ID certificate, 2 attribute certificate) and an X.509
// certificate carrying the IEC/TS 62351-8 IECUserRoles extension (OID
// 1.2.840.10070.8.1) with the user's roles, area of responsibility,
// operation and status change sequence number (Table A-8). The
// certificate's signature is the authority's: DSA (id-dsa-with-sha1 for
// method 67, id-dsa-with-sha256 for 68 to 71) or, for IEC/TS 62351-8,
// RSA and ECDSA, verified against the configured authority certificate.

// Certificate types of g120v8.
const (
	CertID        = 1
	CertAttribute = 2
)

// OIDIECUserRoles is the IEC 62351-8:2020 access token OID (10.3), used
// when issuing; OIDIECUserRolesLegacy (IEC/TS 62351-8:2011) is accepted
// too (10.5.1.2).
var (
	OIDIECUserRoles       = asn1.ObjectIdentifier{1, 0, 62351, 8, 1}
	OIDIECUserRolesLegacy = asn1.ObjectIdentifier{1, 2, 840, 10070, 8, 1}
)

var (
	oidDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidDSASHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
)

// UserRoleInfo is one IECUserRoles entry.
type UserRoleInfo struct {
	Roles          []int
	AOR            string `asn1:"utf8"`
	Revision       int
	RoleDefinition string          `asn1:"optional,utf8"`
	Operation      asn1.Enumerated `asn1:"optional"`
	SCS            int64           `asn1:"optional"`
}

// UserCertificate is a g120v8.
type UserCertificate struct {
	Method uint8
	Type   uint8
	Cert   []byte
}

// Encode is the object data.
func (u UserCertificate) Encode() []byte { return append([]byte{u.Method, u.Type}, u.Cert...) }

// ParseUserCertificate decodes a g120v8.
func ParseUserCertificate(b []byte) (UserCertificate, error) {
	if len(b) < 3 {
		return UserCertificate{}, errors.New("g120v8 too short")
	}
	return UserCertificate{Method: b[0], Type: b[1], Cert: b[2:]}, nil
}

// CertifiedUser is what a verified user certificate says.
type CertifiedUser struct {
	Name      string
	PublicKey any // ID certificates
	Roles     []UserRoleInfo
	NotBefore time.Time
	NotAfter  time.Time
	// Token is the IEC 62351-8 access token as the role authority read it
	// (its signature checked by VerifyUserCertificate).
	Token iotsec.AccessToken
}

// Role is the first role of the first entry whose area of responsibility
// applies to an outstation with the areas aors (remote access), as ra
// matches areas (IEC 62351-8 10.4.4.9), or false.
func (c CertifiedUser) Role(ra iotsec.RoleAuthority, aors []string) (UserRoleInfo, bool) {
	if ra == nil {
		return UserRoleInfo{}, false
	}
	for _, r := range c.Roles {
		if len(r.Roles) > 0 && ra.MatchArea(r.AOR, aors) {
			return r, true
		}
	}
	return UserRoleInfo{}, false
}

func fromToken(tok iotsec.AccessToken) []UserRoleInfo {
	var out []UserRoleInfo
	for _, u := range tok.Roles {
		r := UserRoleInfo{AOR: u.AoR, Revision: u.Revision, RoleDefinition: u.Definition, Operation: asn1.Enumerated(u.Operation)}
		if u.HasSequence {
			r.SCS = int64(u.Sequence)
		}
		r.Roles = append(r.Roles, u.IDs...)
		out = append(out, r)
	}
	return out
}

func dsaHash(alg asn1.ObjectIdentifier, data []byte) ([]byte, bool) {
	switch {
	case alg.Equal(oidDSASHA1):
		h := sha1.Sum(data)
		return h[:], true
	case alg.Equal(oidDSASHA256):
		h := sha256.Sum256(data)
		return h[:], true
	}
	return nil, false
}

func verifyWith(authority *x509.Certificate, alg asn1.ObjectIdentifier, tbs, sig []byte) error {
	if h, ok := dsaHash(alg, tbs); ok {
		pub, ok := authority.PublicKey.(*dsa.PublicKey)
		if !ok {
			return errors.New("a DSA-signed certificate needs a DSA authority key")
		}
		var v dsaSig
		if rest, err := asn1.Unmarshal(sig, &v); err != nil || len(rest) != 0 || !dsa.Verify(pub, h, v.R, v.S) {
			return errors.New("the certificate's DSA signature does not verify with the authority key")
		}
		return nil
	}
	return errors.New("unsupported signature algorithm")
}

// ErrNoRoleAuthority refuses a g120v8 user certificate when no IEC
// 62351-8 role authority is configured to read its roles.
var ErrNoRoleAuthority = errors.New("no IEC 62351-8 role authority is configured to read user certificates")

// VerifyUserCertificate checks a g120v8 certificate against the authority
// certificate and returns what it certifies; ra reads the IEC 62351-8
// access token (and checks the signature of attribute certificates that
// are not DSA-signed).
func VerifyUserCertificate(u UserCertificate, authority *x509.Certificate, ra iotsec.RoleAuthority) (CertifiedUser, error) {
	if ra == nil {
		return CertifiedUser{}, ErrNoRoleAuthority
	}
	switch u.Type {
	case CertID:
		c, err := x509.ParseCertificate(u.Cert)
		if err != nil {
			return CertifiedUser{}, fmt.Errorf("ID certificate: %w", err)
		}
		switch c.SignatureAlgorithm {
		case x509.DSAWithSHA1, x509.DSAWithSHA256:
			var outer struct {
				TBS asn1.RawValue
				Alg pkix.AlgorithmIdentifier
				Sig asn1.BitString
			}
			if _, err := asn1.Unmarshal(u.Cert, &outer); err != nil {
				return CertifiedUser{}, err
			}
			if err := verifyWith(authority, outer.Alg.Algorithm, c.RawTBSCertificate, c.Signature); err != nil {
				return CertifiedUser{}, err
			}
		default:
			if err := c.CheckSignatureFrom(authority); err != nil {
				return CertifiedUser{}, fmt.Errorf("the certificate is not signed by the authority: %w", err)
			}
		}
		tok, err := ra.ReadToken(u.Cert, false)
		if err != nil {
			return CertifiedUser{}, err
		}
		return CertifiedUser{Name: c.Subject.CommonName, PublicKey: c.PublicKey, Roles: fromToken(tok), NotBefore: c.NotBefore, NotAfter: c.NotAfter, Token: tok}, nil
	case CertAttribute:
		return verifyAttributeCert(ra, u.Cert, authority, u.Method == KeyChangeRSA1024SHA1)
	}
	return CertifiedUser{}, fmt.Errorf("certificate type %d is not 1 (ID) or 2 (attribute)", u.Type)
}

// Attribute certificates (IEC 62351-8:2020 10.5.2, RFC 5755): read by the
// role authority; the roles are the values of the id-IECUserRoles
// attribute (10.5.2.3), the holder the entity name (a directory name whose
// common name is the user) or a public key certificate. The signature is
// DSA (IEEE 1815 A.45.8, checked here) or RSA/ECDSA (IEC 62351-8, checked
// by the role authority); SHA-1 only for method 67.
func verifyAttributeCert(ra iotsec.RoleAuthority, der []byte, authority *x509.Certificate, sha1OK bool) (CertifiedUser, error) {
	tok, err := ra.ReadToken(der, true)
	if err != nil {
		return CertifiedUser{}, fmt.Errorf("attribute certificate: %w", err)
	}
	if _, ok := dsaHash(tok.SignatureAlgorithm, nil); ok {
		if err := verifyWith(authority, tok.SignatureAlgorithm, tok.TBS, tok.Signature); err != nil {
			return CertifiedUser{}, err
		}
	} else if err := ra.CheckSignature(tok, authority, sha1OK); err != nil {
		return CertifiedUser{}, fmt.Errorf("the attribute certificate is not signed by the authority: %w", err)
	}
	if tok.Holder == "" {
		return CertifiedUser{}, errors.New("the attribute certificate holder has no directory name")
	}
	return CertifiedUser{Name: tok.Holder, Roles: fromToken(tok), NotBefore: tok.NotBefore, NotAfter: tok.NotAfter, Token: tok}, nil
}

// Issuing (the static authority, 7.5.4.5): ID certificates signed with
// the authority's DSA key.

type tbsCertificate struct {
	Version    int `asn1:"optional,explicit,default:0,tag:0"`
	Serial     *big.Int
	Sig        pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	Validity   struct{ NotBefore, NotAfter time.Time }
	Subject    asn1.RawValue
	SPKI       asn1.RawValue
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// IssueDSAUserCertificate issues an ID certificate for user (public key
// SubjectPublicKeyInfo spki) with the given roles, signed with the
// authority's DSA key (SHA-1 for method 67, SHA-256 otherwise).
func IssueDSAUserCertificate(method uint8, key *dsa.PrivateKey, issuer string, user string, spki []byte, roles []UserRoleInfo, notBefore, notAfter time.Time) ([]byte, error) {
	alg := oidDSASHA256
	if method == KeyChangeRSA1024SHA1 {
		alg = oidDSASHA1
	}
	iss, err := asn1.Marshal(pkix.Name{CommonName: issuer}.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	sub, err := asn1.Marshal(pkix.Name{CommonName: user}.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	ext, err := asn1.Marshal(roles)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tbs := tbsCertificate{Version: 2, Serial: serial, Sig: pkix.AlgorithmIdentifier{Algorithm: alg}, Issuer: asn1.RawValue{FullBytes: iss},
		Subject: asn1.RawValue{FullBytes: sub}, SPKI: asn1.RawValue{FullBytes: spki},
		Extensions: []pkix.Extension{{Id: OIDIECUserRoles, Value: ext}}}
	tbs.Validity.NotBefore, tbs.Validity.NotAfter = notBefore.UTC().Truncate(time.Second), notAfter.UTC().Truncate(time.Second)
	raw, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	h, _ := dsaHash(alg, raw)
	r, s, err := dsa.Sign(rand.Reader, key, h)
	if err != nil {
		return nil, err
	}
	sig, err := asn1.Marshal(dsaSig{r, s})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: raw}, pkix.AlgorithmIdentifier{Algorithm: alg}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
}

// SelfSignedDSAAuthority is an authority certificate for a DSA key (for
// configuring the outstation's trust in a DSA authority).
func SelfSignedDSAAuthority(key *dsa.PrivateKey, name string, notBefore, notAfter time.Time) ([]byte, error) {
	spki, err := MarshalDSAPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return IssueDSAUserCertificate(KeyChangeRSA2048SHA256, key, name, name, spki, []UserRoleInfo{{Roles: []int{RoleSecAdm}, AOR: "authority", Revision: 0}}, notBefore, notAfter)
}
