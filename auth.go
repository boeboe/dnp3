package dnp3

import (
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"sync"
	"time"
)

// Secure Authentication version 5 (IEEE 1815-2012 clause 7, group 120),
// master side: session keys are set with a key status request (g120v4),
// key status (g120v5) and session key change (g120v6), the session keys
// wrapped with the per-outstation update key (RFC 3394 AES key wrap); a
// critical request the outstation challenges (g120v1) is answered with a
// reply (g120v2) carrying an HMAC; critical requests can be sent in
// aggressive mode (g120v3 ... g120v9); a response that asks for an
// aggressive-mode confirmation is confirmed so; responses can be
// challenged by the master; an error (g120v7) fails the request. Update
// key change (g120v10 to g120v15) is in updatekey.go. The octets each MAC
// covers follow Annex A.45 (Tables A-3, A-4, A-5, A-9); where our earlier
// reading differed it is recorded in the findings register (F-580
// onwards; see PROVENANCE.md). Secure Authentication is verified against
// this module's own outstation and the dnp3-sim simulator only.

// Group 120 variations.
const (
	AuthChallenge         = 1
	AuthReply             = 2
	AuthAggressive        = 3
	AuthKeyStatusReq      = 4
	AuthKeyStatus         = 5
	AuthSessionKeyChg     = 6
	AuthErrorObj          = 7
	AuthUserCertificate   = 8
	AuthMACObj            = 9
	AuthUserStatusChange  = 10
	AuthUpdateKeyChgReq   = 11
	AuthUpdateKeyChgReply = 12
	AuthUpdateKeyChg      = 13
	AuthUpdateKeyChgSig   = 14
	AuthUpdateKeyChgConf  = 15
	authFreeFormatQual    = 0x5B // one object, two-octet object size prefix
	AuthReasonCritical    = 1
	KeyWrapAES128         = 1
	KeyWrapAES256         = 2
	KeyStatusOK           = 1
	KeyStatusNotInit      = 2
	KeyStatusCommFail     = 3
	KeyStatusAuthFail     = 4
	// UserUnknown and UserDefault are the reserved user numbers (Table 7-11).
	UserUnknown = 0
	UserDefault = 1
)

// Authentication error codes (g120v7, A.45.7).
const (
	AuthErrAuthFailed         = 1
	AuthErrUnexpectedResponse = 2 // SAv2 only
	AuthErrNoResponse         = 3 // SAv2 only
	AuthErrAggressiveNotSupp  = 4
	AuthErrMACNotSupp         = 5
	AuthErrKeyWrapNotSupp     = 6
	AuthErrAuthorization      = 7
	AuthErrUpdateMethod       = 8
	AuthErrInvalidSignature   = 9
	AuthErrInvalidCertData    = 10
	AuthErrUnknownUser        = 11
	AuthErrMaxKeyStatus       = 12
)

var authErrNames = map[uint8]string{
	1: "authentication failed", 2: "unexpected response", 3: "no response", 4: "aggressive mode not supported",
	5: "MAC algorithm not supported", 6: "key wrap algorithm not supported", 7: "authorization failed",
	8: "update key change method not permitted", 9: "invalid signature", 10: "invalid certification data",
	11: "unknown user", 12: "max session key status requests exceeded",
}

// AuthErrorName names an authentication error code.
func AuthErrorName(c uint8) string {
	if n, ok := authErrNames[c]; ok {
		return n
	}
	if c >= 128 {
		return fmt.Sprintf("vendor error %d", c)
	}
	return fmt.Sprintf("error %d", c)
}

// Security statistics (Table 7-6): the point indexes of g121/g122; the
// master keeps the same counters for its side of the association.
const (
	StatUnexpected = iota
	StatAuthorizationFailures
	StatAuthFailures
	StatReplyTimeouts
	StatRekeysAuthFailure
	StatMessagesSent
	StatMessagesReceived
	StatCriticalSent
	StatCriticalReceived
	StatDiscarded
	StatErrorsSent
	StatErrorsReceived
	StatSuccessfulAuth
	StatSessionKeyChanges
	StatFailedSessionKeyChanges
	StatUpdateKeyChanges
	StatFailedUpdateKeyChanges
	StatRekeysRestart
	NumSecurityStatistics // 18 in this version (7.5.2.2)
)

var statNames = [NumSecurityStatistics]string{
	"unexpected-messages", "authorization-failures", "authentication-failures", "reply-timeouts",
	"rekeys-due-to-authentication-failure", "total-messages-sent", "total-messages-received",
	"critical-messages-sent", "critical-messages-received", "discarded-messages", "error-messages-sent",
	"error-messages-received", "successful-authentications", "session-key-changes", "failed-session-key-changes",
	"update-key-changes", "failed-update-key-changes", "rekeys-due-to-restarts",
}

// StatisticName names a security statistic by its index (modulo 18, as
// further associations report in blocks of 18).
func StatisticName(i uint32) string { return statNames[i%NumSecurityStatistics] }

// MAC algorithm codes (g120 MAL) this implementation computes.
// Code 1 (HMAC-SHA-1 truncated to 4 octets) was SAv2 only and code 6
// (AES-GMAC) is optional; neither is computed, so a challenge naming one
// fails.
const (
	MACSHA1Trunc4    = 1
	MACSHA1Trunc10   = 2
	MACSHA256Trunc8  = 3
	MACSHA256Trunc16 = 4
	MACSHA1Trunc8    = 5
	MACAESGMAC       = 6
)

var macNames = map[string]uint8{
	"hmac-sha1-10": MACSHA1Trunc10, "hmac-sha256-8": MACSHA256Trunc8,
	"hmac-sha256-16": MACSHA256Trunc16, "hmac-sha1-8": MACSHA1Trunc8, "aes-gmac": MACAESGMAC,
}

// MAC computes the truncated HMAC of algorithm mal over the parts.
func MAC(mal uint8, key []byte, parts ...[]byte) ([]byte, error) {
	var h func() hash.Hash
	var n int
	switch mal {
	case MACSHA1Trunc10:
		h, n = sha1.New, 10
	case MACSHA1Trunc8:
		h, n = sha1.New, 8
	case MACSHA256Trunc8:
		h, n = sha256.New, 8
	case MACSHA256Trunc16:
		h, n = sha256.New, 16
	case MACAESGMAC:
		return nil, errors.New("AES-GMAC needs an IV (MACIV)")
	default:
		return nil, fmt.Errorf("MAC algorithm %d is not supported", mal)
	}
	m := hmac.New(h, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:n], nil
}

// Secret is a configuration value that never appears in logs or
// formatted output.
type Secret string

// String hides the value.
func (Secret) String() string { return "[redacted]" }

// GoString hides the value from %#v.
func (Secret) GoString() string { return "[redacted]" }

// LogValue hides the value from slog.
func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// AuthConfig enables Secure Authentication v5 on a master association.
type AuthConfig struct {
	// User is the user number (Table 7-11); 0 is taken as the default
	// user 1.
	User uint16
	// UpdateKey is the user's update key: 16 octets (AES-128 key wrap) or
	// 32 (AES-256 key wrap).
	UpdateKey []byte
	// MAC is the MAC algorithm (one of the MAC constants) of the master's
	// own challenges; 0 is HMAC-SHA-256 truncated to 16 octets. MACByName
	// reads the usual names.
	MAC uint8
	// AggressiveMode sends the critical requests of Table 7-7 with their
	// authentication (g120v3 ... g120v9) once a challenge has been
	// answered since the last session key change (7.5.3.3).
	AggressiveMode bool
	// ChallengeResponses has the master challenge every solicited and
	// unsolicited response that carries objects before using it
	// (7.5.2.3.2 c).
	ChallengeResponses bool
	// KeyChangeCount changes the session keys after this many
	// authentication messages in either direction (7.6.1.4.4); 0: never
	// by count.
	KeyChangeCount int
	// The statistic thresholds that act as moving limits (7.5.2.2, Table
	// 7-15); 0 takes the defaults of Table 7-6: 5, 3, 3 and 3.
	MaxAuthenticationFailures int
	MaxReplyTimeouts          int
	MaxAuthenticationRekeys   int
	MaxRekeysDueToRestarts    int
}

// MACByName is the MAC algorithm code of a name: hmac-sha256-16,
// hmac-sha256-8, hmac-sha1-10, hmac-sha1-8 or aes-gmac; 0 for any other.
func MACByName(name string) uint8 { return macNames[name] }

// Auth is a master's Secure Authentication state for one association.
type Auth struct {
	User       uint16
	UpdateKey  []byte // AES-128 or AES-256 key
	MAL        uint8  // MAC algorithm for the master's own challenges
	Aggressive bool
	// ChallengeResponses challenges responses with objects (see AuthConfig).
	ChallengeResponses bool
	// KeyChangeCount is the authentication message count after which the
	// session keys are changed (0: never by count).
	KeyChangeCount int

	mu      sync.Mutex
	ctrl    []byte // control direction session key
	mon     []byte // monitoring direction session key
	prevMon []byte // last valid monitoring key, kept across invalidation
	changed time.Time
	lastChg []byte // the latest session key change fragment as sent
	count   int    // authentication messages since the last key change

	// The most recent challenge received from the outstation (fragment as
	// received, CSQ and MAC algorithm) and the number of replies and
	// aggressive-mode requests sent since (7.5.2.3.3 rule d).
	chal      []byte
	chalCSQ   uint32
	chalMAL   uint8
	sinceChal uint32
	replied   bool // a challenge was answered since the keys changed
	aggrOff   bool // the outstation refused aggressive mode (error 4)

	// The master's own challenges (of responses).
	ourCSQ  uint32
	ourChal []byte

	stats [NumSecurityStatistics]uint32

	// The statistic limits (Table 7-15): thresholds, the moving maxima
	// (reset at startup to the thresholds), rekeys suspended after Max
	// Authentication Rekeys or Max Rekeys Due to Restarts, and a pending
	// rekey after Max Authentication Failures.
	thrAF, thrRT, thrAR, thrRR uint32
	maxAF, maxRT, maxAR, maxRR uint32
	noAFRekey, noRestartRekey  bool
	afExceeded                 bool
	// Subject and Tenant name the association in security events.
	Subject, Tenant string

	// For AES-GMAC IVs (Table 7-21): our and the outstation's DNP3
	// addresses, the last KSQ the outstation sent and the last CSQ
	// exchanged in either direction.
	addr, peer uint16
	lastKSQ    uint32
	lastCSQ    uint32
}

// ivFrom is the AES-GMAC IV of an object the outstation sends; ivTo of one
// the master sends.
func (a *Auth) ivFrom(usr uint16, ksq, csq uint32) []byte { return GMACIV(a.peer, usr, ksq, csq) }
func (a *Auth) ivTo(usr uint16, ksq, csq uint32) []byte   { return GMACIV(a.addr, usr, ksq, csq) }

// NewAuth builds a master's Secure Authentication state (nil for a nil
// configuration).
func NewAuth(c *AuthConfig) (*Auth, error) {
	if c == nil {
		return nil, nil
	}
	k := c.UpdateKey
	if len(k) != 16 && len(k) != 32 {
		return nil, errors.New("the update key must be 16 or 32 octets")
	}
	user, mal := c.User, c.MAC
	if user == UserUnknown {
		user = UserDefault
	}
	if mal == 0 {
		mal = MACSHA256Trunc16
	}
	thr := func(n, def int) uint32 {
		if n <= 0 {
			return uint32(def)
		}
		return uint32(n)
	}
	a := &Auth{User: user, UpdateKey: append([]byte(nil), k...), MAL: mal, Aggressive: c.AggressiveMode,
		ChallengeResponses: c.ChallengeResponses, KeyChangeCount: c.KeyChangeCount,
		thrAF: thr(c.MaxAuthenticationFailures, 5), thrRT: thr(c.MaxReplyTimeouts, 3), thrAR: thr(c.MaxAuthenticationRekeys, 3),
		thrRR: thr(c.MaxRekeysDueToRestarts, 3)}
	a.maxAF, a.maxRT, a.maxAR, a.maxRR = a.thrAF, a.thrRT, a.thrAR, a.thrRR
	return a, nil
}

// ErrAuthLimit ends a session: the authentication failures passed Max
// Authentication Failures while rekeys due to them passed Max
// Authentication Rekeys (Table 7-8: close the TCP connection and log).
var ErrAuthLimit = errors.New("secure authentication: max authentication rekeys exceeded; closing the connection")

// authFailure counts an authentication failure (a.mu held); past Max
// Authentication Failures the limit moves on and a rekey is due.
func (a *Auth) authFailure() {
	a.stats[StatAuthFailures]++
	if a.stats[StatAuthFailures] > a.maxAF {
		a.maxAF = a.stats[StatAuthFailures] + a.thrAF
		a.afExceeded = true
	}
}

func (a *Auth) authFailed() {
	a.mu.Lock()
	a.authFailure()
	a.mu.Unlock()
}

// rekeyForAuthFailure changes the session keys because of authentication
// failures (Table 7-8 "Max Authentication Failures Exceeded") unless
// Rekeys Due to Authentication Failure passed Max Authentication Rekeys:
// then no more such rekeys until the keys change for another reason, and
// ErrAuthLimit closes the connection. An error message from the
// outstation also asks for new keys (F-1465).
func (a *Auth) rekeyForAuthFailure() error {
	a.mu.Lock()
	if a.noAFRekey || a.stats[StatRekeysAuthFailure] >= a.maxAR {
		a.noAFRekey = true
		n := a.stats[StatRekeysAuthFailure]
		a.mu.Unlock()
		recordSecurity(a.Tenant, a.subject(), SecEventMaxAuthRekeys, map[string]string{"rekeysDueToAuthenticationFailure": fmt.Sprint(n), "action": "connection closed"})
		return ErrAuthLimit
	}
	a.stats[StatRekeysAuthFailure]++
	a.mu.Unlock()
	a.invalidate()
	return nil
}

// limitAction carries out a rekey that Max Authentication Failures made
// due while a request was handled.
func (a *Auth) limitAction() error {
	a.mu.Lock()
	due := a.afExceeded
	a.afExceeded = false
	a.mu.Unlock()
	if !due {
		return nil
	}
	return a.rekeyForAuthFailure()
}

// replyTimeout counts a challenge the outstation did not answer; past
// Max Reply Timeouts the master asks for the key status again, that is
// changes the session keys (Table 7-8 "Max Reply Timeouts Exceeded").
func (a *Auth) replyTimeout() {
	a.mu.Lock()
	a.stats[StatReplyTimeouts]++
	over := a.stats[StatReplyTimeouts] > a.maxRT
	if over {
		a.maxRT = a.stats[StatReplyTimeouts] + a.thrRT
	}
	n := a.stats[StatReplyTimeouts]
	a.mu.Unlock()
	if over {
		recordSecurity(a.Tenant, a.subject(), SecEventMaxReplyTimeouts, map[string]string{"replyTimeouts": fmt.Sprint(n), "action": "session keys changed"})
		a.invalidate()
	}
}

// RestartRekey reports whether the master is to change the session keys
// because the outstation restarted (Table 7-8, master only): not once
// Rekeys Due to Restarts passed Max Rekeys Due to Restarts, until the
// next key change for the interval.
func (a *Auth) RestartRekey() bool {
	a.mu.Lock()
	if a.noRestartRekey {
		a.mu.Unlock()
		return false
	}
	a.stats[StatRekeysRestart]++
	if a.stats[StatRekeysRestart] > a.maxRR {
		a.noRestartRekey = true
		a.maxRR = a.stats[StatRekeysRestart] + a.thrRR
		n := a.stats[StatRekeysRestart]
		a.mu.Unlock()
		recordSecurity(a.Tenant, a.subject(), SecEventMaxRekeysDueRestarts, map[string]string{"rekeysDueToRestarts": fmt.Sprint(n), "action": "restart rekeys suspended"})
		return false
	}
	a.mu.Unlock()
	return true
}

// ScheduledKeyChange notes a session key change for the interval or the
// message count: rekeys due to authentication failures and restarts
// resume and Max Authentication Rekeys is reset (Table 7-8).
func (a *Auth) ScheduledKeyChange() {
	a.mu.Lock()
	a.noAFRekey, a.noRestartRekey = false, false
	a.maxAR = a.stats[StatRekeysAuthFailure] + a.thrAR
	a.mu.Unlock()
}

func (a *Auth) subject() string {
	if a.Subject != "" {
		return a.Subject
	}
	return "dnp3 master"
}

// KeysAge is how long ago the session keys were set (0 when they are not).
func (a *Auth) KeysAge() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctrl == nil {
		return 0
	}
	return time.Since(a.changed)
}

// KeyChangeDue reports that the authentication message count since the
// last session key change reached KeyChangeCount.
func (a *Auth) KeyChangeDue() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ctrl != nil && a.KeyChangeCount > 0 && a.count >= a.KeyChangeCount
}

// Statistics is a copy of the master's security statistics (Table 7-6).
func (a *Auth) Statistics() map[string]uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]uint32, NumSecurityStatistics)
	for i, v := range a.stats {
		out[statNames[i]] = v
	}
	return out
}

func (a *Auth) stat(i int) {
	a.mu.Lock()
	a.stats[i]++
	a.mu.Unlock()
}

func (a *Auth) invalidate() {
	a.mu.Lock()
	if a.mon != nil {
		a.prevMon = a.mon
	}
	a.ctrl, a.mon, a.replied = nil, nil, false
	a.mu.Unlock()
}

// AuthError is a g120v7 error from the outstation, or a failed key change.
type AuthError struct {
	Code uint8
	Msg  string
}

// Error names the code and the detail.
func (e *AuthError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("secure authentication failed: the outstation reported error %d (%s)%s", e.Code, AuthErrorName(e.Code), e.Msg)
	}
	return "secure authentication failed: " + e.Msg
}

// AppendAuthObject appends one group 120 object with the free-format
// qualifier (count 1, two-octet size) or, for g120v4, a count of one.
func AppendAuthObject(out []byte, variation uint8, data []byte) []byte {
	if variation == AuthKeyStatusReq {
		return append(AppendHeader(out, 120, variation, Q8Count, 1, 0), data...)
	}
	out = append(out, 120, variation, authFreeFormatQual, 1)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}

// ParseAuthObject returns the variation and object data of the first
// group 120 object in a fragment's objects.
func ParseAuthObject(b []byte) (uint8, []byte, error) {
	if len(b) < 4 || b[0] != 120 {
		return 0, nil, errors.New("not a group 120 object")
	}
	v := b[1]
	switch b[2] {
	case authFreeFormatQual:
		if len(b) < 6 || b[3] != 1 {
			return 0, nil, errors.New("g120: expected one free-format object")
		}
		n := int(binary.LittleEndian.Uint16(b[4:]))
		if len(b) < 6+n {
			return 0, nil, errors.New("g120: truncated object")
		}
		return v, b[6 : 6+n], nil
	case Q8Count:
		return v, b[4:], nil
	}
	return 0, nil, fmt.Errorf("g120v%d: qualifier 0x%02x is not supported", v, b[2])
}

// KeyStatus is a decoded g120v5.
type KeyStatus struct {
	KSQ       uint32
	User      uint16
	KeyWrap   uint8
	Status    uint8
	MAL       uint8
	Challenge []byte
	MAC       []byte
}

// ParseKeyStatus decodes g120v5 object data.
func ParseKeyStatus(d []byte) (KeyStatus, error) {
	if len(d) < 11 {
		return KeyStatus{}, errors.New("g120v5 too short")
	}
	k := KeyStatus{KSQ: binary.LittleEndian.Uint32(d), User: binary.LittleEndian.Uint16(d[4:]), KeyWrap: d[6], Status: d[7], MAL: d[8]}
	n := int(binary.LittleEndian.Uint16(d[9:]))
	if len(d) < 11+n {
		return KeyStatus{}, errors.New("g120v5 challenge data truncated")
	}
	k.Challenge, k.MAC = d[11:11+n], d[11+n:]
	return k, nil
}

// Unauthenticated is the key status object data without its MAC: what the
// key wrap data carries (A.45.6 Table A-5).
func (k KeyStatus) Unauthenticated(d []byte) []byte { return d[:11+len(k.Challenge)] }

// AppendKeyStatus encodes g120v5 object data.
func AppendKeyStatus(out []byte, k KeyStatus) []byte {
	out = binary.LittleEndian.AppendUint32(out, k.KSQ)
	out = binary.LittleEndian.AppendUint16(out, k.User)
	out = append(out, k.KeyWrap, k.Status, k.MAL)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(k.Challenge)))
	out = append(out, k.Challenge...)
	return append(out, k.MAC...)
}

// SessionKeyData is the plaintext wrapped in a g120v6: the key length,
// the control and monitoring direction session keys and the key status
// object data being answered, zero-padded to a multiple of 8 octets.
func SessionKeyData(ctrl, mon, keyStatus []byte) []byte {
	out := binary.LittleEndian.AppendUint16(nil, uint16(len(ctrl)))
	out = append(out, ctrl...)
	out = append(out, mon...)
	out = append(out, keyStatus...)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	return out
}

// ParseSessionKeyData splits unwrapped g120v6 key data; keyStatus is the
// key status data the master claims to answer (padding included).
func ParseSessionKeyData(b []byte) (ctrl, mon, keyStatus []byte, err error) {
	if len(b) < 2 {
		return nil, nil, nil, errors.New("key data too short")
	}
	n := int(binary.LittleEndian.Uint16(b))
	if n < 16 || n > 32 || len(b) < 2+2*n {
		return nil, nil, nil, errors.New("key data has a bad key length")
	}
	return b[2 : 2+n], b[2+n : 2+2*n], b[2+2*n:], nil
}

var wrapIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// WrapKey is RFC 3394 AES key wrap of key (a multiple of 8 octets, at
// least 16) with kek.
func WrapKey(kek, key []byte) ([]byte, error) {
	if len(key) < 16 || len(key)%8 != 0 {
		return nil, errors.New("a wrapped key must be a multiple of 8 octets and at least 16")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("the update key must be an AES key: %w", err)
	}
	n := len(key) / 8
	a := append([]byte(nil), wrapIV...)
	r := append([]byte(nil), key...)
	b := make([]byte, 16)
	for j := range 6 {
		for i := range n {
			copy(b, a)
			copy(b[8:], r[i*8:i*8+8])
			block.Encrypt(b, b)
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(b[:8])^t)
			copy(r[i*8:], b[8:])
		}
	}
	return append(a, r...), nil
}

// UnwrapKey reverses WrapKey and checks the integrity value.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, errors.New("a wrapped key must be a multiple of 8 octets and at least 24")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("the update key must be an AES key: %w", err)
	}
	n := len(wrapped)/8 - 1
	a := append([]byte(nil), wrapped[:8]...)
	r := append([]byte(nil), wrapped[8:]...)
	b := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(b, binary.BigEndian.Uint64(a)^t)
			copy(b[8:], r[i*8:i*8+8])
			block.Decrypt(b, b)
			copy(a, b[:8])
			copy(r[i*8:], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, wrapIV) != 1 {
		return nil, errors.New("the wrapped key does not unwrap with this update key")
	}
	return r, nil
}

// ChangeSessionKeys sets new session keys: key status request, then a
// session key change answering the key status, then a check of the MAC in
// the outstation's new key status (A.45.5 Table A-4: over the whole
// session key change fragment, with the new monitoring direction key).
func (m *Master) ChangeSessionKeys(ctx context.Context) error {
	a := m.cfg.Auth
	if a == nil {
		return errors.New("secure authentication is not configured")
	}
	m.rmu.Lock()
	defer m.rmu.Unlock()
	err := m.changeSessionKeys(ctx, a)
	if err != nil {
		a.stat(StatFailedSessionKeyChanges)
	} else {
		a.stat(StatSessionKeyChanges)
	}
	return err
}

func (m *Master) changeSessionKeys(ctx context.Context, a *Auth) error {
	usr := binary.LittleEndian.AppendUint16(nil, a.User)
	frags, err := m.request(ctx, FCAuthRequest, AppendAuthObject(nil, AuthKeyStatusReq, usr))
	if err != nil {
		return fmt.Errorf("key status request: %w", err)
	}
	ksData, ks, err := keyStatusOf(frags)
	if err != nil {
		return err
	}
	// A key status carrying a MAC is checked against the last valid
	// monitoring direction key; a mismatch indicates an attack (7.5.4.2).
	a.mu.Lock()
	prevMon, prevChg := a.mon, a.lastChg
	if prevMon == nil {
		prevMon = a.prevMon
	}
	a.mu.Unlock()
	a.mu.Lock()
	a.lastKSQ = ks.KSQ
	ivKS := a.ivFrom(ks.User, ks.KSQ, a.lastCSQ)
	a.mu.Unlock()
	if ks.MAL != 0 && len(ks.MAC) > 0 && prevMon != nil && prevChg != nil {
		if want, err := MACIV(ks.MAL, prevMon, ivKS, prevChg); err != nil || !hmac.Equal(want, ks.MAC) {
			a.authFailed()
			return &AuthError{Msg: "the key status MAC does not verify with the last monitoring direction key (possible attack)"}
		}
	}
	a.invalidate()
	if ks.User != a.User {
		return &AuthError{Msg: fmt.Sprintf("the key status is for user %d, not %d", ks.User, a.User)}
	}
	kwa := uint8(KeyWrapAES128)
	if len(a.UpdateKey) == 32 {
		kwa = KeyWrapAES256
	}
	if ks.KeyWrap != kwa {
		return &AuthError{Msg: fmt.Sprintf("the outstation uses key wrap algorithm %d, the update key needs %d", ks.KeyWrap, kwa)}
	}
	ctrl, mon := make([]byte, len(a.UpdateKey)), make([]byte, len(a.UpdateKey))
	_, _ = rand.Read(ctrl)
	_, _ = rand.Read(mon)
	wrapped, err := WrapKey(a.UpdateKey, SessionKeyData(ctrl, mon, ks.Unauthenticated(ksData)))
	if err != nil {
		return err
	}
	chg := binary.LittleEndian.AppendUint32(nil, ks.KSQ)
	chg = binary.LittleEndian.AppendUint16(chg, a.User)
	chg = append(chg, wrapped...)
	frags, err = m.request(ctx, FCAuthRequest, AppendAuthObject(nil, AuthSessionKeyChg, chg))
	sent := m.lastReq
	if err != nil {
		return fmt.Errorf("session key change: %w", err)
	}
	_, ks2, err := keyStatusOf(frags)
	if err != nil {
		return err
	}
	if ks2.Status != KeyStatusOK {
		return &AuthError{Msg: fmt.Sprintf("the outstation answered key status %d after the session key change", ks2.Status)}
	}
	a.mu.Lock()
	a.lastKSQ = ks2.KSQ
	iv2 := a.ivFrom(ks2.User, ks2.KSQ, a.lastCSQ)
	a.mu.Unlock()
	want, err := MACIV(ks2.MAL, mon, iv2, sent)
	if err != nil {
		return &AuthError{Msg: err.Error()}
	}
	if !hmac.Equal(want, ks2.MAC) {
		a.authFailed()
		return &AuthError{Msg: "the key status MAC does not verify with the new session key"}
	}
	a.mu.Lock()
	a.ctrl, a.mon, a.changed, a.lastChg, a.count = ctrl, mon, time.Now(), sent, 0
	a.mu.Unlock()
	return nil
}

func keyStatusOf(frags []Fragment) ([]byte, KeyStatus, error) {
	if len(frags) == 0 {
		return nil, KeyStatus{}, errors.New("no key status")
	}
	v, d, err := ParseAuthObject(frags[len(frags)-1].Objects)
	if err != nil {
		return nil, KeyStatus{}, err
	}
	if v == AuthErrorObj {
		return nil, KeyStatus{}, authErrorOf(d)
	}
	if v != AuthKeyStatus {
		return nil, KeyStatus{}, fmt.Errorf("expected a key status (g120v5), got g120v%d", v)
	}
	ks, err := ParseKeyStatus(d)
	return d, ks, err
}

func authErrorOf(d []byte) error {
	if len(d) < 9 {
		return &AuthError{Msg: "malformed error object"}
	}
	msg := ""
	if len(d) > 15 {
		msg = fmt.Sprintf(" (%q)", d[15:])
	}
	return &AuthError{Code: d[8], Msg: msg}
}

// Challenge is a decoded g120v1.
type Challenge struct {
	CSQ    uint32
	User   uint16
	MAL    uint8
	Reason uint8
	Data   []byte
}

// ParseChallenge decodes g120v1 object data (at least 4 octets of
// challenge data, A.45.1).
func ParseChallenge(d []byte) (Challenge, error) {
	if len(d) < 12 {
		return Challenge{}, errors.New("g120v1 too short")
	}
	return Challenge{CSQ: binary.LittleEndian.Uint32(d), User: binary.LittleEndian.Uint16(d[4:]), MAL: d[6], Reason: d[7], Data: d[8:]}, nil
}

// Encode is the g120v1 object data.
func (c Challenge) Encode() []byte {
	out := binary.LittleEndian.AppendUint32(nil, c.CSQ)
	out = binary.LittleEndian.AppendUint16(out, c.User)
	return append(append(out, c.MAL, c.Reason), c.Data...)
}

// MACLen is the MAC length of an algorithm (0 when not computed here).
func MACLen(mal uint8) int {
	switch mal {
	case MACSHA1Trunc10:
		return 10
	case MACSHA256Trunc8, MACSHA1Trunc8:
		return 8
	case MACSHA256Trunc16:
		return 16
	case MACAESGMAC:
		return 12
	}
	return 0
}

// noteChallenge records a challenge received in fragment f (as received).
func (a *Auth) noteChallenge(f []byte, c Challenge) {
	a.mu.Lock()
	a.chal, a.chalCSQ, a.chalMAL, a.sinceChal, a.lastCSQ = append([]byte(nil), f...), c.CSQ, c.MAL, 0, c.CSQ
	a.stats[StatCriticalSent]++
	a.mu.Unlock()
}

// answerChallenge builds the g120v2 reply to a challenge fragment for the
// critical request req (both as sent on the wire, Table A-3).
func (a *Auth) answerChallenge(challenge Fragment, req []byte) ([]byte, error) {
	_, d, err := ParseAuthObject(challenge.Objects)
	if err != nil {
		return nil, err
	}
	c, err := ParseChallenge(d)
	if err != nil {
		return nil, err
	}
	a.noteChallenge(challenge.Encode(), c)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctrl == nil {
		return nil, &AuthError{Msg: "challenged before session keys were set"}
	}
	csq := a.chalCSQ + a.sinceChal
	mac, err := MACIV(c.MAL, a.ctrl, a.ivTo(a.User, a.lastKSQ, csq), challenge.Encode(), req)
	if err != nil {
		return nil, &AuthError{Msg: err.Error()}
	}
	a.lastCSQ = csq
	out := binary.LittleEndian.AppendUint32(nil, csq)
	out = binary.LittleEndian.AppendUint16(out, a.User)
	a.sinceChal++
	a.count++
	return AppendAuthObject(nil, AuthReply, append(out, mac...)), nil
}

// replied records that a reply was accepted (the outstation answered the
// challenged request); aggressive mode may be used from now on.
func (a *Auth) accepted() {
	a.mu.Lock()
	a.replied = true
	a.stats[StatSuccessfulAuth]++
	a.mu.Unlock()
}

// CriticalMandatory lists the request function codes Table 7-7 marks
// mandatory critical; the master sends these in aggressive mode.
func CriticalMandatory(fc byte) bool {
	switch fc {
	case FCWrite, FCSelect, FCOperate, FCDirectOperate, FCDirectOperateNR, FCColdRestart, FCWarmRestart,
		FCInitializeAppl, FCStartAppl, FCStopAppl, FCSaveConfig, FCEnableUnsolicited, FCDisableUnsolicited,
		FCRecordCurrentTime, FCOpenFile, FCCloseFile, FCDeleteFile, FCGetFileInfo, FCAuthenticateFile,
		FCAbortFile, FCActivateConfig:
		return true
	}
	return false
}

// aggressive returns the request f in aggressive mode (g120v3 first,
// g120v9 last; the MAC over the last challenge received and everything
// before the MAC value, Table A-9), or nil when aggressive mode is not
// configured, was refused, or no challenge has been answered since the
// keys changed (7.5.3.3).
func (a *Auth) aggressive(f Fragment, force bool) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if (!force && (!a.Aggressive || a.aggrOff || !a.replied)) || a.chal == nil || a.ctrl == nil {
		return nil
	}
	n := MACLen(a.chalMAL)
	if n == 0 {
		return nil
	}
	csq := a.chalCSQ + a.sinceChal
	obj := binary.LittleEndian.AppendUint32(nil, csq)
	obj = binary.LittleEndian.AppendUint16(obj, a.User)
	body := append(AppendHeader(nil, 120, AuthAggressive, Q8Count, 1, 0), obj...)
	body = append(body, f.Objects...)
	body = append(body, 120, AuthMACObj, authFreeFormatQual, 1)
	body = binary.LittleEndian.AppendUint16(body, uint16(n))
	pre := Fragment{Control: f.Control, Func: f.Func, IIN: f.IIN, Objects: body}.Encode()
	mac, err := MACIV(a.chalMAL, a.ctrl, a.ivTo(a.User, a.lastKSQ, csq), a.chal, pre)
	if err != nil {
		return nil
	}
	a.lastCSQ = csq
	a.sinceChal++
	a.count++
	a.stats[StatCriticalSent]++
	return append(pre, mac...)
}

// refuseAggressive records error 4: aggressive mode is not used again on
// this association.
func (a *Auth) refuseAggressive() {
	a.mu.Lock()
	a.aggrOff = true
	a.mu.Unlock()
}

// SplitAggressive finds an aggressive-mode fragment's parts: the g120v3
// object data, the objects between, the MAC and the length of the
// fragment objects before the MAC value. ok is false when the objects do
// not start with g120v3 and end with g120v9.
func SplitAggressive(objects []byte) (req []byte, inner []byte, mac []byte, macAt int, ok bool) {
	if len(objects) < 10 || objects[0] != 120 || objects[1] != AuthAggressive || objects[2] != Q8Count || objects[3] != 1 {
		return nil, nil, nil, 0, false
	}
	blocks, err := ParseObjects(objects, true)
	if err != nil || len(blocks) < 2 {
		return nil, nil, nil, 0, false
	}
	last := blocks[len(blocks)-1]
	if last.Header.Group != 120 || last.Header.Var != AuthMACObj || len(last.Points) != 1 {
		return nil, nil, nil, 0, false
	}
	mac = last.Points[0].Raw
	macAt = len(objects) - len(mac)
	hdrAt := macAt - 6 // g120v9 header (3), count (1), size (2)
	if hdrAt < 10 {
		return nil, nil, nil, 0, false
	}
	return objects[4:10], objects[10:hdrAt], mac, macAt, true
}

// trailingChallenge reports a g120v1 as the last object of a response's
// objects (an outstation asking for an aggressive-mode confirmation,
// 7.5.2.3.2 d) and returns the objects before it.
func trailingChallenge(objects []byte) (Challenge, []byte, bool) {
	blocks, err := ParseObjects(objects, true)
	if err != nil || len(blocks) == 0 {
		return Challenge{}, nil, false
	}
	last := blocks[len(blocks)-1]
	if last.Header.Group != 120 || last.Header.Var != AuthChallenge || len(last.Points) != 1 {
		return Challenge{}, nil, false
	}
	c, err := ParseChallenge(last.Points[0].Raw)
	if err != nil {
		return Challenge{}, nil, false
	}
	at := len(objects) - len(last.Points[0].Raw) - 6
	return c, objects[:at], true
}

// challengeResponse builds the master's challenge of a response with
// sequence seq (user Default, reason critical, Table 7-11).
func (a *Auth) challengeResponse(seq uint8) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ourCSQ++
	a.lastCSQ = a.ourCSQ
	data := make([]byte, 16)
	_, _ = rand.Read(data)
	c := Challenge{CSQ: a.ourCSQ, User: UserDefault, MAL: a.MAL, Reason: AuthReasonCritical, Data: data}
	f := Fragment{Control: AppFIR | AppFIN | seq&0x0F, Func: FCAuthRequest, Objects: AppendAuthObject(nil, AuthChallenge, c.Encode())}
	a.ourChal = f.Encode()
	a.stats[StatCriticalReceived]++
	return a.ourChal
}

// verifyReply checks the outstation's g120v2 to the master's last
// challenge of the response resp (as received).
func (a *Auth) verifyReply(d, resp []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(d) < 6 || a.ourChal == nil || a.mon == nil {
		a.authFailure()
		return &AuthError{Msg: "malformed or unexpected authentication reply"}
	}
	usr := binary.LittleEndian.Uint16(d[4:])
	want, err := MACIV(a.MAL, a.mon, a.ivFrom(usr, a.lastKSQ, a.ourCSQ), a.ourChal, resp)
	if err != nil || binary.LittleEndian.Uint32(d) != a.ourCSQ || !hmac.Equal(want, d[6:]) {
		a.authFailure()
		return &AuthError{Msg: "the outstation's reply to the master's challenge does not verify"}
	}
	a.count++
	a.stats[StatSuccessfulAuth]++
	return nil
}

// verifyAggressive checks an outstation's aggressive-mode response
// against the master's last challenge (Table A-9, monitoring direction
// key).
func (a *Auth) verifyAggressive(f Fragment) error {
	_, _, mac, macAt, ok := SplitAggressive(f.Objects)
	if !ok {
		return &AuthError{Msg: "malformed aggressive-mode response"}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ourChal == nil || a.mon == nil {
		a.authFailure()
		return &AuthError{Msg: "an aggressive-mode response before the master challenged the outstation"}
	}
	pre := Fragment{Control: f.Control, Func: f.Func, IIN: f.IIN, Objects: f.Objects[:macAt]}.Encode()
	obj, _, _, _, _ := SplitAggressive(f.Objects)
	want, err := MACIV(a.MAL, a.mon, a.ivFrom(binary.LittleEndian.Uint16(obj[4:]), a.lastKSQ, binary.LittleEndian.Uint32(obj)), a.ourChal, pre)
	if err != nil || !hmac.Equal(want, mac) {
		a.authFailure()
		return &AuthError{Msg: "the aggressive-mode response MAC does not verify"}
	}
	a.count++
	a.stats[StatSuccessfulAuth]++
	return nil
}

// UpdateKeyOf returns the user's current update key and user number (after
// a change-update-key, the new ones).
func (a *Auth) UpdateKeyOf() ([]byte, uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.UpdateKey...), a.User
}

// SetUpdateKey replaces the update key and user number, for an
// application that stored a changed update key and restores it.
func (a *Auth) SetUpdateKey(key []byte, user uint16) {
	a.mu.Lock()
	a.UpdateKey, a.User = append([]byte(nil), key...), user
	a.mu.Unlock()
}
