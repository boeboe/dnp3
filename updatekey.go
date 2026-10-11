package dnp3

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // key change methods 67 to 69 use DSA (IEEE 1815-2012 Table 7-16)
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// Remote update key change (IEEE 1815-2012 7.5.4.5, 7.5.4.6, 7.5.5.5,
// 7.5.5.6; objects g120v10 to g120v15, A.45.10 to A.45.15). The master
// forwards a user status change certified by an authority, asks for an
// update key change, sends the new update key encrypted (by the authority
// for the symmetric methods, with the outstation's public key for the
// asymmetric ones) and both sides prove knowledge of the new key with an
// update key change confirmation MAC.
//
// Where Annex A leaves an encoding open we chose (the findings register
// F-585 to F-587): certification data and confirmation MACs are the full
// HMAC output, DSA signatures are ASN.1 DER SEQUENCE{r, s}, and the
// encrypted update key data is the user name, the key and the outstation
// challenge data concatenated, zero-padded to a multiple of 8 octets for
// AES key wrap.

// Update key change methods (Table 7-16). 0 to 2 and 64 to 66 are
// obsolete or unused.
const (
	KeyChangeAES128SHA1    = 3
	KeyChangeAES256SHA256  = 4 // the mandatory default
	KeyChangeAES256GMAC    = 5
	KeyChangeRSA1024SHA1   = 67
	KeyChangeRSA2048SHA256 = 68
	KeyChangeRSA3072SHA256 = 69
	KeyChangeRSA2048GMAC   = 70
	KeyChangeRSA3072GMAC   = 71
)

// User status change operations (A.45.10).
const (
	UserAdd    = 1
	UserDelete = 2
	UserChange = 3
)

// User roles (Table 7-12).
const (
	RoleViewer     = 0
	RoleOperator   = 1
	RoleEngineer   = 2
	RoleInstaller  = 3
	RoleSecAdm     = 4
	RoleSecAud     = 5
	RoleRBACMnt    = 6
	RoleSingleUser = 32768
)

// Symmetric reports a symmetric key change method (below 64).
func Symmetric(method uint8) bool { return method < 64 }

// MethodHash is the hash of a method (its HMAC, or the digest its DSA
// signatures use) and the update key length.
func MethodHash(method uint8) (func() hash.Hash, int, error) {
	switch method {
	case KeyChangeAES128SHA1, KeyChangeRSA1024SHA1:
		return sha1.New, 16, nil
	case KeyChangeAES256SHA256, KeyChangeRSA2048SHA256, KeyChangeRSA3072SHA256, KeyChangeAES256GMAC,
		KeyChangeRSA2048GMAC, KeyChangeRSA3072GMAC:
		return sha256.New, 32, nil
	}
	return nil, 0, fmt.Errorf("update key change method %d is not supported", method)
}

// GMACMethod reports the methods authenticating with AES-GMAC (5, 70, 71).
func GMACMethod(method uint8) bool {
	return method == KeyChangeAES256GMAC || method == KeyChangeRSA2048GMAC || method == KeyChangeRSA3072GMAC
}

// methodMAC is the MAC of a method: full HMAC, or AES-GMAC with iv.
func methodMAC(method uint8, key, iv []byte, parts ...[]byte) ([]byte, error) {
	h, _, err := MethodHash(method)
	if err != nil {
		return nil, err
	}
	if GMACMethod(method) {
		return GMAC(key, iv, parts...)
	}
	m := hmac.New(h, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil), nil
}

// ChallengeLen is the challenge data size of a method (Table 7-17).
func ChallengeLen(method uint8) int {
	if h, _, err := MethodHash(method); err == nil && h().Size() == 20 {
		return 20
	}
	return 32
}

// UserStatus is the user status information of a g120v10.
type UserStatus struct {
	Method    uint8
	Operation uint8
	SCS       uint32 // status change sequence number
	Role      uint16
	Expiry    uint16 // days after reception
	Name      string
	PublicKey []byte // asymmetric methods: the user's SubjectPublicKeyInfo
	CertData  []byte
}

// StatusInfo is the data the authority certifies (Table A-10, in order).
func (u UserStatus) StatusInfo() []byte {
	out := []byte{u.Operation}
	out = binary.LittleEndian.AppendUint32(out, u.SCS)
	out = binary.LittleEndian.AppendUint16(out, u.Role)
	out = binary.LittleEndian.AppendUint16(out, u.Expiry)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(u.Name)))
	if !Symmetric(u.Method) {
		out = binary.LittleEndian.AppendUint16(out, uint16(len(u.PublicKey)))
	}
	out = append(out, u.Name...)
	if !Symmetric(u.Method) {
		out = append(out, u.PublicKey...)
	}
	return out
}

// Encode is the g120v10 object data.
func (u UserStatus) Encode() []byte {
	out := []byte{u.Method, u.Operation}
	out = binary.LittleEndian.AppendUint32(out, u.SCS)
	out = binary.LittleEndian.AppendUint16(out, u.Role)
	out = binary.LittleEndian.AppendUint16(out, u.Expiry)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(u.Name)))
	out = binary.LittleEndian.AppendUint16(out, uint16(len(u.PublicKey)))
	out = binary.LittleEndian.AppendUint16(out, uint16(len(u.CertData)))
	out = append(out, u.Name...)
	out = append(out, u.PublicKey...)
	return append(out, u.CertData...)
}

// ParseUserStatus decodes g120v10 object data.
func ParseUserStatus(d []byte) (UserStatus, error) {
	if len(d) < 16 {
		return UserStatus{}, errors.New("g120v10 too short")
	}
	u := UserStatus{Method: d[0], Operation: d[1], SCS: binary.LittleEndian.Uint32(d[2:]), Role: binary.LittleEndian.Uint16(d[6:]), Expiry: binary.LittleEndian.Uint16(d[8:])}
	nl, pl, cl := int(binary.LittleEndian.Uint16(d[10:])), int(binary.LittleEndian.Uint16(d[12:])), int(binary.LittleEndian.Uint16(d[14:]))
	if len(d) != 16+nl+pl+cl {
		return UserStatus{}, errors.New("g120v10 lengths do not match the object")
	}
	u.Name = string(d[16 : 16+nl])
	u.PublicKey = d[16+nl : 16+nl+pl]
	u.CertData = d[16+nl+pl:]
	return u, nil
}

// UpdateKeyRequest is g120v11.
type UpdateKeyRequest struct {
	Method    uint8
	Name      string
	Challenge []byte
}

// Encode is the g120v11 object data.
func (r UpdateKeyRequest) Encode() []byte {
	out := []byte{r.Method}
	out = binary.LittleEndian.AppendUint16(out, uint16(len(r.Name)))
	out = binary.LittleEndian.AppendUint16(out, uint16(len(r.Challenge)))
	return append(append(out, r.Name...), r.Challenge...)
}

// ParseUpdateKeyRequest decodes g120v11 object data.
func ParseUpdateKeyRequest(d []byte) (UpdateKeyRequest, error) {
	if len(d) < 5 {
		return UpdateKeyRequest{}, errors.New("g120v11 too short")
	}
	nl, cl := int(binary.LittleEndian.Uint16(d[1:])), int(binary.LittleEndian.Uint16(d[3:]))
	if len(d) != 5+nl+cl {
		return UpdateKeyRequest{}, errors.New("g120v11 lengths do not match the object")
	}
	return UpdateKeyRequest{Method: d[0], Name: string(d[5 : 5+nl]), Challenge: d[5+nl:]}, nil
}

// UpdateKeyReply is g120v12 (and, with Data the encrypted key, the head of
// g120v13).
type UpdateKeyReply struct {
	KSQ  uint32
	User uint16
	Data []byte // outstation challenge data (v12) or encrypted update key data (v13)
}

// Encode is the g120v12 or g120v13 object data.
func (r UpdateKeyReply) Encode() []byte {
	out := binary.LittleEndian.AppendUint32(nil, r.KSQ)
	out = binary.LittleEndian.AppendUint16(out, r.User)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(r.Data)))
	return append(out, r.Data...)
}

// ParseUpdateKeyReply decodes g120v12 or g120v13 object data.
func ParseUpdateKeyReply(d []byte) (UpdateKeyReply, error) {
	if len(d) < 8 || len(d) != 8+int(binary.LittleEndian.Uint16(d[6:])) {
		return UpdateKeyReply{}, errors.New("g120v12/v13 lengths do not match the object")
	}
	return UpdateKeyReply{KSQ: binary.LittleEndian.Uint32(d), User: binary.LittleEndian.Uint16(d[4:]), Data: d[8:]}, nil
}

// UpdateKeyData is the plaintext of the encrypted update key data (Table
// A-11), zero-padded to a multiple of 8 octets when pad is set.
func UpdateKeyData(name string, key, ostnChallenge []byte, pad bool) []byte {
	out := append(append([]byte(name), key...), ostnChallenge...)
	for pad && len(out)%8 != 0 {
		out = append(out, 0)
	}
	return out
}

// ConfirmationMAC is the g120v15 MAC (Table A-13): the receiver's name,
// the sender's then the receiver's challenge data, the KSQ and the user
// number, keyed with the new update key.
func ConfirmationMAC(method uint8, newKey []byte, receiver string, senderChal, receiverChal []byte, ksq uint32, usr uint16) ([]byte, error) {
	return ConfirmationMACIV(method, newKey, nil, receiver, senderChal, receiverChal, ksq, usr)
}

// ConfirmationMACIV is ConfirmationMAC with the AES-GMAC IV of the GMAC
// methods (Table 7-21: sender, user, last KSQ, last CSQ).
func ConfirmationMACIV(method uint8, newKey, iv []byte, receiver string, senderChal, receiverChal []byte, ksq uint32, usr uint16) ([]byte, error) {
	return methodMAC(method, newKey, iv, []byte(receiver), senderChal, receiverChal,
		binary.LittleEndian.AppendUint32(nil, ksq), binary.LittleEndian.AppendUint16(nil, usr))
}

// SignatureData is what the user's g120v14 signature covers (Table A-12).
func SignatureData(outstation string, masterChal, ostnChal []byte, ksq uint32, usr uint16, encrypted []byte) []byte {
	out := append([]byte(outstation), masterChal...)
	out = append(out, ostnChal...)
	out = binary.LittleEndian.AppendUint32(out, ksq)
	out = binary.LittleEndian.AppendUint16(out, usr)
	return append(out, encrypted...)
}

type dsaSig struct{ R, S *big.Int }

// DSASign signs data with the method's hash (SHA-1 for 67, SHA-256
// otherwise), DER encoded.
func DSASign(method uint8, key *dsa.PrivateKey, data []byte) ([]byte, error) {
	h, _, err := MethodHash(method)
	if err != nil {
		return nil, err
	}
	d := h()
	d.Write(data)
	sum := d.Sum(nil)
	r, s, err := dsa.Sign(rand.Reader, key, sum)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(dsaSig{r, s})
}

// DSAVerify checks a DSASign signature.
func DSAVerify(method uint8, key *dsa.PublicKey, data, sig []byte) bool {
	h, _, err := MethodHash(method)
	if err != nil {
		return false
	}
	var v dsaSig
	if rest, err := asn1.Unmarshal(sig, &v); err != nil || len(rest) != 0 || v.R == nil || v.S == nil {
		return false
	}
	d := h()
	d.Write(data)
	return dsa.Verify(key, d.Sum(nil), v.R, v.S)
}

// Authority is the key distribution authority as the master sees it
// (7.5.4.5): it certifies user status changes and, for the symmetric
// methods, encrypts new update keys for the outstation. The standard
// keeps it apart from the master and leaves the master–authority protocol
// open.
type Authority interface {
	Method() uint8
	// Certify returns the certification data of a user status change.
	Certify(u UserStatus) ([]byte, error)
	// EncryptUpdateKey returns the encrypted update key data (symmetric
	// methods only).
	EncryptUpdateKey(name string, key, ostnChallenge []byte) ([]byte, error)
}

// SymmetricAuthority is an authority sharing the authority certification
// key with the outstation (methods 3, 4 and 5). MasterAddress is the
// sender address of the AES-GMAC IV (method 5).
type SymmetricAuthority struct {
	KeyChangeMethod uint8
	Key             []byte // AES-128 for method 3, AES-256 for methods 4 and 5
	MasterAddress   uint16
}

// Method is the key change method.
func (s SymmetricAuthority) Method() uint8 { return s.KeyChangeMethod }

// Certify is the HMAC of the status information with the authority key.
func (s SymmetricAuthority) Certify(u UserStatus) ([]byte, error) {
	if !Symmetric(s.KeyChangeMethod) {
		return nil, fmt.Errorf("method %d is not a supported symmetric method", s.KeyChangeMethod)
	}
	return CertifyStatus(s.KeyChangeMethod, s.Key, s.MasterAddress, u)
}

// CertifyStatus is the symmetric certification data of a user status
// (Table A-10): the method's MAC of the status information with the
// authority certification key; for AES-GMAC the IV is the master's
// address, user number 0 (not yet assigned), the SCS and CSQ 0 (Table
// 7-21 row 10, F-593).
func CertifyStatus(method uint8, key []byte, master uint16, u UserStatus) ([]byte, error) {
	return methodMAC(method, key, GMACIV(master, 0, u.SCS, 0), u.StatusInfo())
}

// EncryptUpdateKey wraps the update key data with the authority key.
func (s SymmetricAuthority) EncryptUpdateKey(name string, key, ostnChallenge []byte) ([]byte, error) {
	return WrapKey(s.Key, UpdateKeyData(name, key, ostnChallenge, true))
}

// AsymmetricAuthority certifies user status changes with its DSA private
// key (methods 67 to 69).
type AsymmetricAuthority struct {
	KeyChangeMethod uint8
	Key             *dsa.PrivateKey
}

// Method is the key change method.
func (a AsymmetricAuthority) Method() uint8 { return a.KeyChangeMethod }

// Certify signs the status information.
func (a AsymmetricAuthority) Certify(u UserStatus) ([]byte, error) {
	return DSASign(a.KeyChangeMethod, a.Key, u.StatusInfo())
}

// EncryptUpdateKey is not used with asymmetric methods.
func (AsymmetricAuthority) EncryptUpdateKey(string, []byte, []byte) ([]byte, error) {
	return nil, errors.New("the asymmetric methods encrypt with the outstation's public key")
}

// UpdateKeyChange describes one user status and update key change.
type UpdateKeyChange struct {
	Authority  Authority
	Operation  uint8 // UserAdd (default), UserChange or UserDelete
	SCS        uint32
	UserName   string
	Role       uint16
	Expiry     uint16 // days
	Outstation string // the outstation's name, as configured at the authority
	NewKey     []byte // generated when empty
	// Asymmetric methods: the user's key pair (the public key goes to the
	// outstation in the status change) and the outstation's RSA key.
	UserKey       *dsa.PrivateKey
	UserPublicKey []byte // SubjectPublicKeyInfo octets
	OutstationKey *rsa.PublicKey
	// Certificate, for the asymmetric methods, is an IEC/TS 62351-8
	// certificate from the authority sent as a g120v8 instead of the
	// g120v10 (CertificateType 1 ID or 2 attribute; default 1).
	Certificate     []byte
	CertificateType uint8
}

// ChangeUpdateKey runs the user status change and update key change and,
// when they succeed, makes the new update key and user number current and
// changes the session keys with them. Delete stops after the status
// change.
func (m *Master) ChangeUpdateKey(ctx context.Context, c UpdateKeyChange) error {
	a := m.cfg.Auth
	if a == nil {
		return errors.New("secure authentication is not configured")
	}
	err := m.changeUpdateKey(ctx, a, c)
	if err != nil {
		a.stat(StatFailedUpdateKeyChanges)
		return err
	}
	if c.Operation != UserDelete {
		a.stat(StatUpdateKeyChanges)
		return m.ChangeSessionKeys(ctx)
	}
	return nil
}

func (m *Master) authRequest(ctx context.Context, objects []byte) (uint8, []byte, error) {
	frags, err := m.request(ctx, FCAuthRequest, objects)
	if err != nil {
		return 0, nil, err
	}
	if len(frags) == 0 || len(frags[len(frags)-1].Objects) == 0 {
		return 0, nil, nil
	}
	v, d, err := ParseAuthObject(frags[len(frags)-1].Objects)
	if err != nil {
		return 0, nil, err
	}
	if v == AuthErrorObj {
		m.cfg.Auth.stat(StatErrorsReceived)
		return v, d, authErrorOf(d)
	}
	return v, d, nil
}

func (m *Master) changeUpdateKey(ctx context.Context, a *Auth, c UpdateKeyChange) error {
	if c.Authority == nil || c.UserName == "" {
		return errors.New("an update key change needs an authority and a user name")
	}
	method := c.Authority.Method()
	_, keyLen, err := MethodHash(method)
	if err != nil {
		return err
	}
	if c.Operation == 0 {
		c.Operation = UserAdd
	}
	u := UserStatus{Method: method, Operation: c.Operation, SCS: c.SCS, Role: c.Role, Expiry: c.Expiry, Name: c.UserName}
	if !Symmetric(method) {
		if c.UserKey == nil || c.OutstationKey == nil || (len(c.UserPublicKey) == 0 && c.Certificate == nil) {
			return errors.New("an asymmetric update key change needs the user's key pair and the outstation's public key")
		}
		u.PublicKey = c.UserPublicKey
	}
	status := AppendAuthObject(nil, AuthUserStatusChange, nil)
	if c.Certificate != nil {
		if Symmetric(method) {
			return errors.New("a user certificate (g120v8) is only used with the asymmetric methods")
		}
		ct := c.CertificateType
		if ct == 0 {
			ct = CertID
		}
		status = AppendAuthObject(nil, AuthUserCertificate, UserCertificate{Method: method, Type: ct, Cert: c.Certificate}.Encode())
	} else {
		if u.CertData, err = c.Authority.Certify(u); err != nil {
			return fmt.Errorf("certifying the user status: %w", err)
		}
		status = AppendAuthObject(nil, AuthUserStatusChange, u.Encode())
	}
	m.rmu.Lock()
	defer m.rmu.Unlock()
	if _, _, err := m.authRequest(ctx, status); err != nil {
		return fmt.Errorf("user status change: %w", err)
	}
	if c.Operation == UserDelete {
		return nil
	}
	mchal := make([]byte, ChallengeLen(method))
	_, _ = rand.Read(mchal)
	v, d, err := m.authRequest(ctx, AppendAuthObject(nil, AuthUpdateKeyChgReq, UpdateKeyRequest{Method: method, Name: c.UserName, Challenge: mchal}.Encode()))
	if err != nil {
		return fmt.Errorf("update key change request: %w", err)
	}
	if v != AuthUpdateKeyChgReply {
		return &AuthError{Msg: fmt.Sprintf("expected an update key change reply (g120v12), got g120v%d", v)}
	}
	reply, err := ParseUpdateKeyReply(d)
	if err != nil {
		return err
	}
	key := c.NewKey
	if len(key) == 0 {
		key = make([]byte, keyLen)
		_, _ = rand.Read(key)
	}
	if len(key) != keyLen {
		return fmt.Errorf("method %d needs a %d-octet update key", method, keyLen)
	}
	var enc []byte
	if Symmetric(method) {
		enc, err = c.Authority.EncryptUpdateKey(c.UserName, key, reply.Data)
	} else {
		h, _, _ := MethodHash(method)
		enc, err = rsa.EncryptOAEP(h(), rand.Reader, c.OutstationKey, UpdateKeyData(c.UserName, key, reply.Data, false), nil)
	}
	if err != nil {
		return fmt.Errorf("encrypting the update key: %w", err)
	}
	obj := AppendAuthObject(nil, AuthUpdateKeyChg, UpdateKeyReply{KSQ: reply.KSQ, User: reply.User, Data: enc}.Encode())
	a.mu.Lock()
	lastCSQ := a.lastCSQ
	a.mu.Unlock()
	if Symmetric(method) {
		mac, err := ConfirmationMACIV(method, key, a.ivTo(reply.User, reply.KSQ, lastCSQ), c.Outstation, mchal, reply.Data, reply.KSQ, reply.User)
		if err != nil {
			return err
		}
		obj = AppendAuthObject(obj, AuthUpdateKeyChgConf, mac)
	} else {
		sig, err := DSASign(method, c.UserKey, SignatureData(c.Outstation, mchal, reply.Data, reply.KSQ, reply.User, enc))
		if err != nil {
			return err
		}
		obj = AppendAuthObject(obj, AuthUpdateKeyChgSig, sig)
	}
	v, d, err = m.authRequest(ctx, obj)
	if err != nil {
		return fmt.Errorf("update key change: %w", err)
	}
	if v != AuthUpdateKeyChgConf {
		return &AuthError{Msg: fmt.Sprintf("expected an update key change confirmation (g120v15), got g120v%d", v)}
	}
	want, err := ConfirmationMACIV(method, key, a.ivFrom(reply.User, reply.KSQ, lastCSQ), c.UserName, reply.Data, mchal, reply.KSQ, reply.User)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, d) {
		a.stat(StatAuthFailures)
		return &AuthError{Msg: "the outstation's update key change confirmation does not verify"}
	}
	a.mu.Lock()
	a.UpdateKey, a.User = key, reply.User
	a.mu.Unlock()
	a.invalidate()
	return nil
}

// MarshalDSAPublicKey encodes a DSA public key as an X.509
// SubjectPublicKeyInfo (RFC 3279 2.3.2), the form a g120v10 carries
// (A.45.10); the standard library parses but does not write it.
func MarshalDSAPublicKey(pub *dsa.PublicKey) ([]byte, error) {
	params, err := asn1.Marshal(struct{ P, Q, G *big.Int }{pub.P, pub.Q, pub.G})
	if err != nil {
		return nil, err
	}
	y, err := asn1.Marshal(pub.Y)
	if err != nil {
		return nil, err
	}
	type algo struct {
		OID    asn1.ObjectIdentifier
		Params asn1.RawValue
	}
	return asn1.Marshal(struct {
		Algo algo
		Key  asn1.BitString
	}{algo{asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}, asn1.RawValue{FullBytes: params}}, asn1.BitString{Bytes: y, BitLength: 8 * len(y)}})
}
