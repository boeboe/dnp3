package dnp3

import (
	"bytes"
	"context"
	"crypto/dsa" //nolint:staticcheck // asymmetric update key change methods
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// Secure Authentication v5 as outstation (IEEE 1815-2012 7.5.2, 7.5.3,
// 7.5.5): key status and session key change per user, challenges of
// critical requests and checks of replies and aggressive-mode requests,
// replies to the master's challenges of responses, optional
// aggressive-mode confirmations of event responses, user status changes
// (g120v10, g120v8) and update key changes (g120v11 to g120v15), roles
// (Table 7-12), errors (g120v7) and the security statistics (g121).

// OutstationUser is one user of the outstation.
type OutstationUser struct {
	Number    uint16
	Name      string
	UpdateKey []byte
	Role      uint16
	Expires   time.Time // zero: never
}

// OutstationAuthConfig configures Secure Authentication as outstation.
type OutstationAuthConfig struct {
	Users []OutstationUser // user 1 (default) is required
	// MAL is the MAC algorithm of our challenges (default 4).
	MAL uint8
	// Critical is the request function codes challenged (default: the
	// mandatory ones of Table 7-7).
	Critical map[byte]bool
	// Aggressive accepts aggressive-mode requests (7.6.1.4.7; default on).
	Aggressive *bool
	// ChallengeConfirms asks for aggressive-mode confirmations of
	// responses with events (7.5.2.3.2 d).
	ChallengeConfirms bool
	// Expected session key change interval and count (7.6.1.4.5); the
	// keys become invalid after either (defaults 30 min and 2000).
	KeyInterval time.Duration
	KeyCount    int
	// MaxKeyStatus is the key status requests allowed per user within the
	// key interval before the operator is alerted (7.6.1.4.6; default 5).
	MaxKeyStatus int
	// MaxErrors is how many error messages are sent before they stop
	// until the next key change (Table 7-6; default 2).
	MaxErrors int
	// MaxAuthFailures and MaxReplyTimeouts are the reporting thresholds
	// of those statistics that act as moving limits (7.5.2.2, Table 7-15;
	// defaults 5 and 3 as in Table 7-6). When authentication failures pass
	// theirs the outstation drops a TCP connection (Table 7-8, 7.7.1);
	// when reply timeouts pass theirs the key status of every user
	// becomes COMM_FAIL (Table 7-8). ReplyTimeout is how long a challenge
	// waits for its reply (1.12.3; default 5 s).
	MaxAuthFailures  int
	MaxReplyTimeouts int
	ReplyTimeout     time.Duration
	// Subject and Tenant name the association in security events.
	Subject, Tenant string
	// Update key change (7.5.5.5, 7.5.5.6): the outstation's name, the
	// authority certification key (symmetric methods), the authority's
	// certificate (asymmetric methods and g120v8), our RSA key (key
	// transport), the areas of responsibility, the methods permitted.
	Name          string
	AuthorityKey  []byte
	AuthorityCert *x509.Certificate
	RSAKey        *rsa.PrivateKey
	AORs          []string
	Methods       map[uint8]bool
	// Roles reads and evaluates the IEC 62351-8 access token of g120v8
	// user certificates (role definition, revision, role IDs, areas of
	// responsibility, status change sequence number). When it is nil,
	// NewRoles builds one for this outstation (its name, AORs and users'
	// sequence numbers); when both are nil, user certificates are refused
	// (ErrNoRoleAuthority).
	Roles    iotsec.RoleAuthority
	NewRoles iotsec.NewRoleAuthority
	// UserCertCheck, when set, checks a g120v8 ID certificate that
	// verified against the authority (validity, revocation by CRL and
	// OCSP through IEC 62351-9); an error refuses it.
	UserCertCheck func(c *x509.Certificate) error
	// UserChanged persists a user after an update key change or delete
	// (Update nil: deleted).
	UserChanged func(OutstationUser)
	Log         *slog.Logger
}

type ostUser struct {
	OutstationUser
	ctrl, mon  []byte
	macMon     []byte // last valid monitoring key (key status MACs)
	lastChg    []byte // last session key change fragment
	status     uint8
	lastKS     []byte
	keysAt     time.Time
	count      int
	statusReqs []time.Time
	pending    *UserStatus // status change awaiting its update key change
	pendingPub any
	pendingAt  time.Time
	lastSCS    uint32
	hasSCS     bool
}

type ostPending struct {
	at        time.Time
	req       Fragment
	raw       []byte
	challenge []byte
	csq       uint32
}

type ostUKC struct {
	user   *ostUser
	method uint8
	mchal  []byte
	ochal  []byte
	ksq    uint32
}

// OutstationAuth is the Secure Authentication state of one association.
type OutstationAuth struct {
	cfg        OutstationAuthConfig
	assoc      *Association
	renewedRSA atomic.Pointer[rsa.PrivateKey] // IEC 62351-9 renewal

	mu          sync.Mutex
	users       map[uint16]*ostUser
	ksq         uint32
	csq         uint32
	lastCSQ     uint32
	pending     *ostPending
	pendingUKC  *ostUKC
	lastChal    []byte // our last challenge fragment (for aggressive requests)
	lastChalMAL uint8
	confirmChal [2][]byte // [solicited, unsolicited] challenges asking for aggressive confirms
	emu         sync.Mutex
	errors      int    // under emu
	errSent     uint32 // under emu
	stats       [NumSecurityStatistics]uint32
	lastStat    [NumSecurityStatistics]uint32
	// The moving limits of Table 7-15 (reset at startup to the
	// thresholds) and a pending action once authentication failures
	// passed theirs (the association drops a TCP connection).
	maxAF, maxRT uint32
	dropLink     bool
	// The recent security events of this association for its status
	// (newest last, at most secEventsKept; they are in the security log
	// too) and the broadcasts refused since start.
	secMu        sync.Mutex
	secEvents    []SecurityEventEntry
	bcastRefused uint64
}

// secEventsKept is how many recent security events an association keeps
// for its status.
const secEventsKept = 20

// SecurityEventEntry is one recent Secure Authentication security event
// of an association: its time, name and the detail written to the
// security log (never key material).
type SecurityEventEntry struct {
	At     time.Time
	Event  string
	Detail map[string]string
}

// security records a security event to the security log and keeps it
// among the association's recent events.
func (a *OutstationAuth) security(event string, detail map[string]string) {
	recordSecurity(a.cfg.Tenant, a.subject(), event, detail)
	d := make(map[string]string, len(detail))
	for k, v := range detail {
		d[k] = v
	}
	a.secMu.Lock()
	if event == SecEventBroadcastRefused {
		a.bcastRefused++
	}
	a.secEvents = append(a.secEvents, SecurityEventEntry{At: time.Now().UTC(), Event: event, Detail: d})
	if n := len(a.secEvents); n > secEventsKept {
		a.secEvents = append(a.secEvents[:0:0], a.secEvents[n-secEventsKept:]...)
	}
	a.secMu.Unlock()
}

// RecentSecurityEvents returns the kept security events, newest first,
// and the number of broadcasts refused since start.
func (a *OutstationAuth) RecentSecurityEvents() ([]SecurityEventEntry, uint64) {
	a.secMu.Lock()
	defer a.secMu.Unlock()
	out := make([]SecurityEventEntry, 0, len(a.secEvents))
	for i := len(a.secEvents) - 1; i >= 0; i-- {
		out = append(out, a.secEvents[i])
	}
	return out, a.bcastRefused
}

// SAState describes the association's Secure Authentication exchange:
// "wait-for-reply" while a challenge of ours is unanswered,
// "wait-for-key-change" while an update key change is in progress, else
// "idle"; and the time the session keys last changed (zero if never).
func (a *OutstationAuth) SAState() (string, time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := "idle"
	switch {
	case a.pending != nil && time.Since(a.pending.at) < a.cfg.ReplyTimeout:
		state = "wait-for-reply"
	case a.pendingUKC != nil:
		state = "wait-for-key-change"
	}
	var at time.Time
	for _, u := range a.users {
		if u.keysAt.After(at) {
			at = u.keysAt
		}
	}
	return state, at
}

// NewOutstationAuth checks the settings.
func NewOutstationAuth(c OutstationAuthConfig) (*OutstationAuth, error) {
	if c.MAL == 0 {
		c.MAL = MACSHA256Trunc16
	}
	if MACLen(c.MAL) == 0 {
		return nil, fmt.Errorf("MAC algorithm %d is not supported", c.MAL)
	}
	if c.Critical == nil {
		c.Critical = map[byte]bool{}
		for fc := range 256 {
			if CriticalMandatory(byte(fc)) {
				c.Critical[byte(fc)] = true
			}
		}
	}
	if c.KeyInterval <= 0 {
		c.KeyInterval = 30 * time.Minute
	}
	if c.KeyCount <= 0 {
		c.KeyCount = 2000
	}
	if c.MaxKeyStatus <= 0 {
		c.MaxKeyStatus = 5
	}
	if c.MaxErrors <= 0 {
		c.MaxErrors = 2
	}
	if c.MaxAuthFailures <= 0 {
		c.MaxAuthFailures = 5
	}
	if c.MaxReplyTimeouts <= 0 {
		c.MaxReplyTimeouts = 3
	}
	if c.ReplyTimeout <= 0 {
		c.ReplyTimeout = 5 * time.Second
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	a := &OutstationAuth{cfg: c, users: map[uint16]*ostUser{}, maxAF: uint32(c.MaxAuthFailures), maxRT: uint32(c.MaxReplyTimeouts)}
	for _, u := range c.Users {
		if u.Number == UserUnknown {
			return nil, errors.New("user 0 is reserved")
		}
		if len(u.UpdateKey) != 16 && len(u.UpdateKey) != 32 {
			return nil, fmt.Errorf("user %d: the update key must be 16 or 32 octets", u.Number)
		}
		a.users[u.Number] = &ostUser{OutstationUser: u, status: KeyStatusNotInit}
	}
	if a.users[UserDefault] == nil {
		return nil, errors.New("the default user 1 needs an update key")
	}
	if a.cfg.Roles == nil && a.cfg.NewRoles != nil {
		ra, err := a.cfg.NewRoles(iotsec.RoleScope{Subject: "dnp3 outstation " + c.Name, Areas: c.AORs, Sequences: userSequences{a}, Log: c.Log})
		if err != nil {
			return nil, fmt.Errorf("rbac: %w", err)
		}
		a.cfg.Roles = ra
	}
	return a, nil
}

func (a *OutstationAuth) aggressiveOn() bool { return a.cfg.Aggressive == nil || *a.cfg.Aggressive }

func (a *OutstationAuth) stat(i int) {
	a.mu.Lock()
	a.stats[i]++
	a.mu.Unlock()
}

// authFailure counts an authentication failure (a.mu held); past Max
// Authentication Failures the limit moves on by the threshold and a TCP
// connection is to be dropped (Table 7-8 "Max Authentication Failures
// Exceeded", 7.7.1): the outstation never rekeys, so its Rekeys Due to
// Authentication Failure statistic stays 0 and the condition to drop
// holds (F-1464).
func (a *OutstationAuth) authFailure() {
	a.stats[StatAuthFailures]++
	if a.stats[StatAuthFailures] > a.maxAF {
		a.maxAF = a.stats[StatAuthFailures] + uint32(a.cfg.MaxAuthFailures)
		a.dropLink = true
	}
}

// replyTimeout ends a challenge left unanswered for ReplyTimeout (a.mu
// held): the queued request is discarded (Table 7-8 "Reply Timeout");
// past Max Reply Timeouts every user's key status becomes COMM_FAIL and
// its session keys are no longer used (Table 7-8 "Max Reply Timeouts
// Exceeded").
func (a *OutstationAuth) replyTimeout() bool {
	if a.pending == nil || time.Since(a.pending.at) < a.cfg.ReplyTimeout {
		return false
	}
	a.pending = nil
	a.stats[StatReplyTimeouts]++
	a.stats[StatDiscarded]++
	if a.stats[StatReplyTimeouts] <= a.maxRT {
		return false
	}
	a.maxRT = a.stats[StatReplyTimeouts] + uint32(a.cfg.MaxReplyTimeouts)
	for _, u := range a.users {
		u.ctrl, u.mon, u.status = nil, nil, KeyStatusCommFail
	}
	return true
}

// limits carries out a limit that was passed while handling a message:
// the TCP connection is dropped, and each action is a security event.
func (a *OutstationAuth) limits(rtExceeded bool) {
	a.mu.Lock()
	drop := a.dropLink
	a.dropLink = false
	n := a.stats[StatAuthFailures]
	rt := a.stats[StatReplyTimeouts]
	a.mu.Unlock()
	if rtExceeded {
		a.cfg.Log.Warn("DNP3 secure authentication: max reply timeouts exceeded; session keys set to COMM_FAIL", "reply-timeouts", rt)
		a.security(SecEventMaxReplyTimeouts, map[string]string{"replyTimeouts": fmt.Sprint(rt)})
	}
	if drop {
		a.cfg.Log.Warn("DNP3 secure authentication: max authentication failures exceeded; dropping the connection", "authentication-failures", n)
		a.security(SecEventMaxAuthFailures, map[string]string{"authenticationFailures": fmt.Sprint(n), "action": "connection dropped"})
		if a.assoc != nil {
			a.assoc.dropLink()
		}
	}
}

func (a *OutstationAuth) subject() string {
	if a.cfg.Subject != "" {
		return a.cfg.Subject
	}
	return "dnp3 outstation " + a.cfg.Name
}

// gateBroadcast decides a request received at a broadcast address (4.7)
// under Secure Authentication. A broadcast is never answered, so the
// outstation cannot challenge it (7.5.2.3.1): a critical request (Table
// 7-7 and the configured critical codes) is carried out only when it
// arrives in Aggressive Mode and verifies (7.5.2.3.2 lets a master send
// critical no-acknowledgement requests only in Aggressive Mode or after a
// challenge); the authentication function codes 32 and 33 are never
// taken by broadcast. Other requests are processed. Every refusal is
// counted as a discarded message and recorded as a security event
// (7.3.1 asks that failed authentications be logged).
func (a *OutstationAuth) gateBroadcast(ctx context.Context, req Fragment, dest uint16) (*Fragment, uint16) {
	defer a.statEvents(ctx)
	refuse := func(reason string) (*Fragment, uint16) {
		a.stat(StatDiscarded)
		a.cfg.Log.Warn("DNP3 broadcast refused under secure authentication", "function", FuncName(req.Func), "destination", dest, "reason", reason)
		a.security(SecEventBroadcastRefused, map[string]string{"function": FuncName(req.Func),
			"functionCode": fmt.Sprint(req.Func), "destination": fmt.Sprintf("0x%04X", dest), "reason": reason})
		return nil, 0
	}
	if req.Func == FCAuthRequest || req.Func == FCAuthRequestNoAck {
		return refuse("authentication requests are not taken by broadcast")
	}
	if obj, inner, mac, macAt, ok := SplitAggressive(req.Objects); ok {
		p, usr, _, code := a.aggressiveCheck(req, obj, inner, mac, macAt)
		if p == nil {
			return refuse("aggressive mode request did not verify (" + AuthErrorName(code) + ")")
		}
		return p, usr
	}
	if a.cfg.Critical[req.Func] {
		return refuse("critical function without authentication")
	}
	return &req, UserDefault
}

// Statistics is a copy of the counters (Table 7-6).
func (a *OutstationAuth) Statistics() [NumSecurityStatistics]uint32 {
	a.mu.Lock()
	st := a.stats
	a.mu.Unlock()
	a.emu.Lock()
	st[StatErrorsSent] += a.errSent
	a.emu.Unlock()
	return st
}

// Summary describes the association's Secure Authentication for the
// status: the MAC algorithm, aggressive mode and each user's number,
// name, role and session key status (never a key).
func (a *OutstationAuth) Summary() map[string]any {
	mac := ""
	for n, v := range macNames {
		if v == a.cfg.MAL {
			mac = n
		}
	}
	names := map[uint8]string{KeyStatusOK: "ok", KeyStatusNotInit: "not-init", KeyStatusCommFail: "comm-fail", KeyStatusAuthFail: "auth-fail"}
	a.mu.Lock()
	var users []any
	for _, u := range a.users {
		users = append(users, map[string]any{"number": u.Number, "name": u.Name, "role": u.Role, "keyStatus": names[u.status]})
	}
	a.mu.Unlock()
	sort.Slice(users, func(i, j int) bool {
		return users[i].(map[string]any)["number"].(uint16) < users[j].(map[string]any)["number"].(uint16)
	})
	return map[string]any{"mac": mac, "aggressive": a.aggressiveOn(), "users": users}
}

// statPoints are the g121 static points.
func (a *OutstationAuth) statPoints(idx func(uint32) bool) []DBPoint {
	st := a.Statistics()
	var out []DBPoint
	for i, v := range st {
		if idx == nil || idx(uint32(i)) {
			out = append(out, DBPoint{Type: "security-statistic", Index: uint32(i), Value: float64(v), Flags: 0x01})
		}
	}
	return out
}

// thresholds are the default event thresholds of Table 7-6.
var statThresholds = [NumSecurityStatistics]uint32{3, 5, 5, 3, 3, 100, 100, 100, 100, 10, 2, 10, 100, 10, 5, 1, 1, 3}

// statEvents reports statistics that crossed their threshold as g122
// events.
func (a *OutstationAuth) statEvents(ctx context.Context) {
	a.mu.Lock()
	var evs []Event
	for i, v := range a.stats {
		if v-a.lastStat[i] >= statThresholds[i] {
			a.lastStat[i] = v
			evs = append(evs, Event{Class: 3, Group: 122, Var: 2, Index: uint32(i), Value: float64(v), Flags: 0x01, Time: time.Now()})
		}
	}
	a.mu.Unlock()
	if a.assoc != nil {
		for _, e := range evs {
			a.assoc.cfg.Events.Add(ctx, e)
		}
	}
}

func (a *OutstationAuth) ivOut(usr uint16, ksq, csq uint32) []byte {
	return GMACIV(a.assoc.cfg.Address, usr, ksq, csq)
}
func (a *OutstationAuth) ivIn(usr uint16, ksq, csq uint32) []byte {
	return GMACIV(a.assoc.cfg.Master, usr, ksq, csq)
}

// valid reports a user's session keys as usable (not expired by interval
// or count, 7.6.1.4.5); a.mu held.
func (a *OutstationAuth) valid(u *ostUser) bool {
	if u == nil || u.ctrl == nil {
		return false
	}
	if time.Since(u.keysAt) > a.cfg.KeyInterval || u.count > a.cfg.KeyCount || (!u.Expires.IsZero() && time.Now().After(u.Expires)) {
		u.ctrl, u.mon, u.status = nil, nil, KeyStatusNotInit
		return false
	}
	return true
}

func authFrag(seq uint8, iin IIN, variation uint8, data []byte) Fragment {
	return Fragment{Control: AppFIR | AppFIN | seq&0x0F, Func: FCAuthResponse, IIN: iin, Objects: AppendAuthObject(nil, variation, data)}
}

// errorFrag builds an error answer, or nil once MaxErrors were sent.
func (a *OutstationAuth) errorFrag(seq uint8, csq uint32, usr uint16, code uint8, text string) *Fragment {
	// A separate lock: errors are built with a.mu held too.
	a.emu.Lock()
	a.errors++
	over := a.errors > a.cfg.MaxErrors
	first := a.errors == a.cfg.MaxErrors+1
	if !over {
		a.errSent++ // Error Messages Sent counts the errors sent (Table 7-6)
	}
	a.emu.Unlock()
	a.cfg.Log.Warn("DNP3 secure authentication error", "code", code, "reason", AuthErrorName(code), "user", usr, "detail", text, "sent", !over)
	if first {
		a.security(SecEventMaxErrorMessages, map[string]string{"errorMessagesSent": fmt.Sprint(a.cfg.MaxErrors),
			"action": "error messages suppressed until the session keys change"})
	}
	if over {
		return nil
	}
	d := binary.LittleEndian.AppendUint32(nil, csq)
	d = binary.LittleEndian.AppendUint16(d, usr)
	d = binary.LittleEndian.AppendUint16(d, 0)
	d = append(d, code)
	d = AppendTime48(d, time.Now())
	d = append(d, text...)
	f := authFrag(seq, a.assoc.iin(nil), AuthErrorObj, d)
	return &f
}

// permitted applies the user roles of Table 7-12 to a request.
func permitted(role uint16, fc byte) bool {
	if role == RoleSingleUser {
		return true
	}
	switch fc {
	case FCSelect, FCOperate, FCDirectOperate, FCDirectOperateNR:
		return role == RoleOperator
	case FCRead, FCConfirm, FCDelayMeasure:
		return role != RoleSecAdm
	case FCOpenFile, FCCloseFile, FCDeleteFile, FCGetFileInfo, FCAuthenticateFile, FCAbortFile:
		return role == RoleEngineer || role == RoleInstaller || role == RoleSecAud || role == RoleRBACMnt
	case FCActivateConfig, FCWrite, FCAssignClass, FCInitializeAppl, FCStartAppl, FCStopAppl:
		return role == RoleEngineer || role == RoleInstaller || role == RoleRBACMnt
	}
	return role != RoleViewer && role != RoleSecAud
}

// gate decides what happens to a request: processed (as user), answered
// by the returned fragment (a challenge, key status, error ...), or both
// (a reply that verified releases the challenged request).
func (a *OutstationAuth) gate(ctx context.Context, req Fragment, raw []byte) (*Fragment, uint16, *Fragment) {
	defer a.statEvents(ctx)
	a.mu.Lock()
	rt := a.replyTimeout()
	a.mu.Unlock()
	defer func() { a.limits(rt) }()
	if req.Func == FCAuthRequest || req.Func == FCAuthRequestNoAck {
		p, usr, reply := a.authRequest(ctx, req, raw)
		if req.Func == FCAuthRequestNoAck {
			return p, usr, nil
		}
		return p, usr, reply
	}
	if obj, inner, mac, macAt, ok := SplitAggressive(req.Objects); ok {
		return a.aggressive(req, obj, inner, mac, macAt)
	}
	if !a.cfg.Critical[req.Func] {
		return &req, UserDefault, nil
	}
	a.mu.Lock()
	keys := false
	for _, u := range a.users {
		if a.valid(u) {
			keys = true
		}
	}
	if !keys {
		a.authFailure()
		a.mu.Unlock()
		return nil, 0, a.errorFrag(req.Seq(), 0, UserUnknown, AuthErrAuthFailed, "session keys are not valid")
	}
	a.csq++
	a.lastCSQ = a.csq
	data := make([]byte, 4)
	_, _ = rand.Read(data)
	c := Challenge{CSQ: a.csq, User: UserUnknown, MAL: a.cfg.MAL, Reason: AuthReasonCritical, Data: data}
	f := authFrag(req.Seq(), a.assoc.iin(nil), AuthChallenge, c.Encode())
	a.pending = &ostPending{at: time.Now(), req: req, raw: raw, challenge: f.Encode(), csq: a.csq}
	a.lastChal, a.lastChalMAL = a.pending.challenge, a.cfg.MAL
	a.stats[StatCriticalReceived]++
	a.mu.Unlock()
	return nil, 0, &f
}

func (a *OutstationAuth) aggressive(req Fragment, obj, inner, mac []byte, macAt int) (*Fragment, uint16, *Fragment) {
	p, usr, csq, code := a.aggressiveCheck(req, obj, inner, mac, macAt)
	if p == nil {
		return nil, 0, a.errorFrag(req.Seq(), csq, usr, code, "")
	}
	return p, usr, nil
}

// aggressiveCheck verifies an Aggressive Mode request; on failure it
// returns the error code to report (when an answer can be sent).
func (a *OutstationAuth) aggressiveCheck(req Fragment, obj, inner, mac []byte, macAt int) (*Fragment, uint16, uint32, uint8) {
	csq := binary.LittleEndian.Uint32(obj)
	usr := binary.LittleEndian.Uint16(obj[4:])
	if !a.aggressiveOn() {
		return nil, usr, csq, AuthErrAggressiveNotSupp
	}
	a.mu.Lock()
	u := a.users[usr]
	good := a.valid(u) && a.lastChal != nil && csq > a.lastCSQ-1
	if good {
		pre := Fragment{Control: req.Control, Func: req.Func, Objects: req.Objects[:macAt]}.Encode()
		want, err := MACIV(a.lastChalMAL, u.ctrl, a.ivIn(usr, a.ksq, csq), a.lastChal, pre)
		good = err == nil && hmac.Equal(want, mac)
	}
	if good {
		a.lastCSQ, a.csq = csq, max(a.csq, csq) // 7.5.2.3.3 rule e
		u.count++
		a.stats[StatCriticalReceived]++
		a.stats[StatSuccessfulAuth]++
	} else {
		a.authFailure()
		if u != nil {
			u.status = KeyStatusAuthFail
		}
	}
	var role uint16
	if u != nil {
		role = u.Role
	}
	a.mu.Unlock()
	if !good {
		return nil, usr, csq, AuthErrAuthFailed
	}
	plain := Fragment{Control: req.Control, Func: req.Func, Objects: inner}
	if usr != UserDefault && !permitted(role, req.Func) {
		a.stat(StatAuthorizationFailures)
		return nil, usr, csq, AuthErrAuthorization
	}
	return &plain, usr, csq, 0
}

// keyStatus builds a key status for u (a.mu held; the KSQ advanced).
func (a *OutstationAuth) keyStatus(u *ostUser) []byte {
	data := make([]byte, 4)
	_, _ = rand.Read(data)
	st := u.status
	if st == KeyStatusOK && !a.valid(u) {
		st = KeyStatusNotInit
	}
	kw := uint8(KeyWrapAES128)
	if len(u.UpdateKey) == 32 {
		kw = KeyWrapAES256
	}
	k := KeyStatus{KSQ: a.ksq, User: u.Number, KeyWrap: kw, Status: st, Challenge: data}
	if u.macMon != nil && u.lastChg != nil {
		k.MAL = a.cfg.MAL
		k.MAC, _ = MACIV(a.cfg.MAL, u.macMon, a.ivOut(u.Number, a.ksq, a.lastCSQ), u.lastChg)
	}
	d := AppendKeyStatus(nil, k)
	u.lastKS = k.Unauthenticated(d)
	return d
}

func (a *OutstationAuth) authRequest(ctx context.Context, req Fragment, raw []byte) (*Fragment, uint16, *Fragment) {
	blocks, err := ParseObjects(req.Objects, true)
	if err != nil || len(blocks) == 0 || blocks[0].Header.Group != 120 || len(blocks[0].Points) == 0 {
		a.stat(StatUnexpected)
		return nil, 0, a.errorFrag(req.Seq(), 0, 0, AuthErrAuthFailed, "malformed authentication request")
	}
	v := blocks[0].Header.Var
	d := blocks[0].Points[0].Raw
	seq := req.Seq()
	switch v {
	case AuthKeyStatusReq:
		if len(d) < 2 {
			return nil, 0, a.errorFrag(seq, 0, 0, AuthErrAuthFailed, "")
		}
		usr := binary.LittleEndian.Uint16(d)
		a.mu.Lock()
		u := a.users[usr]
		a.ksq++
		if u == nil {
			// An unknown user gets AUTH_FAIL (A.45.5 note).
			a.mu.Unlock()
			ks := AppendKeyStatus(nil, KeyStatus{KSQ: a.ksq, User: usr, KeyWrap: KeyWrapAES128, Status: KeyStatusAuthFail, Challenge: []byte{0, 0, 0, 0}})
			f := authFrag(seq, a.assoc.iin(nil), AuthKeyStatus, ks)
			return nil, 0, &f
		}
		now := time.Now()
		var recent []time.Time
		for _, t := range u.statusReqs {
			if now.Sub(t) < a.cfg.KeyInterval {
				recent = append(recent, t)
			}
		}
		u.statusReqs = append(recent, now)
		if len(u.statusReqs) > a.cfg.MaxKeyStatus {
			a.cfg.Log.Warn("DNP3 secure authentication: too many key status requests (possible denial of service)", "user", usr, "count", len(u.statusReqs))
		}
		ks := a.keyStatus(u)
		a.mu.Unlock()
		f := authFrag(seq, a.assoc.iin(nil), AuthKeyStatus, ks)
		return nil, 0, &f
	case AuthSessionKeyChg:
		if len(d) < 7 {
			return nil, 0, a.errorFrag(seq, 0, 0, AuthErrAuthFailed, "")
		}
		ksq, usr := binary.LittleEndian.Uint32(d), binary.LittleEndian.Uint16(d[4:])
		a.mu.Lock()
		u := a.users[usr]
		ok := false
		if u != nil && ksq == a.ksq && u.lastKS != nil {
			if plain, err := UnwrapKey(u.UpdateKey, d[6:]); err == nil {
				ctrl, mon, ks, err := ParseSessionKeyData(plain)
				if err == nil && bytes.HasPrefix(ks, u.lastKS) && len(bytes.Trim(ks[len(u.lastKS):], "\x00")) == 0 {
					u.ctrl, u.mon, u.macMon, u.lastChg, u.status, u.keysAt, u.count = ctrl, mon, mon, raw, KeyStatusOK, time.Now(), 0
					a.emu.Lock()
					a.errors = 0
					a.emu.Unlock()
					a.stats[StatSessionKeyChanges]++
					ok = true
				}
			}
		}
		if u == nil {
			a.mu.Unlock()
			return nil, 0, a.errorFrag(seq, ksq, usr, AuthErrUnknownUser, "")
		}
		if !ok {
			u.ctrl, u.mon, u.status = nil, nil, KeyStatusAuthFail
			a.stats[StatFailedSessionKeyChanges]++
		}
		a.ksq++
		ks := a.keyStatus(u)
		a.mu.Unlock()
		f := authFrag(seq, a.assoc.iin(nil), AuthKeyStatus, ks)
		return nil, 0, &f
	case AuthReply:
		a.mu.Lock()
		p := a.pending
		a.pending = nil
		good := false
		var usr uint16
		var u *ostUser
		if p != nil && len(d) > 6 && binary.LittleEndian.Uint32(d) == p.csq {
			usr = binary.LittleEndian.Uint16(d[4:])
			u = a.users[usr]
			if a.valid(u) {
				want, err := MACIV(a.cfg.MAL, u.ctrl, a.ivIn(usr, a.ksq, p.csq), p.challenge, p.raw)
				good = err == nil && hmac.Equal(want, d[6:])
			}
		}
		if good {
			u.count++
			a.stats[StatSuccessfulAuth]++
		} else {
			a.authFailure()
			if u != nil {
				u.status = KeyStatusAuthFail
			}
		}
		a.mu.Unlock()
		if p == nil {
			a.stat(StatUnexpected)
			return nil, 0, a.errorFrag(seq, 0, usr, AuthErrAuthFailed, "no challenge outstanding")
		}
		if !good {
			return nil, 0, a.errorFrag(seq, p.csq, usr, AuthErrAuthFailed, "")
		}
		if usr != UserDefault && !permitted(u.Role, p.req.Func) {
			a.stat(StatAuthorizationFailures)
			return nil, 0, a.errorFrag(seq, p.csq, usr, AuthErrAuthorization, "")
		}
		r := p.req
		return &r, usr, nil
	case AuthChallenge:
		// The master challenges our last response (7.5.2.3.2 c).
		c, err := ParseChallenge(d)
		a.mu.Lock()
		u := a.users[UserDefault]
		var mac []byte
		last := a.assoc.lastSent
		if err == nil && a.valid(u) && last != nil {
			mac, err = MACIV(c.MAL, u.mon, a.ivOut(UserDefault, a.ksq, c.CSQ), raw, last)
		}
		a.lastCSQ = c.CSQ
		a.stats[StatCriticalSent]++
		a.mu.Unlock()
		if err != nil || mac == nil {
			return nil, 0, a.errorFrag(seq, c.CSQ, UserDefault, AuthErrAuthFailed, "")
		}
		out := binary.LittleEndian.AppendUint32(nil, c.CSQ)
		out = binary.LittleEndian.AppendUint16(out, UserDefault)
		f := authFrag(seq, a.assoc.iin(nil), AuthReply, append(out, mac...))
		return nil, 0, &f
	case AuthUserStatusChange:
		return nil, 0, a.userStatus(seq, d)
	case AuthUserCertificate:
		return nil, 0, a.userCertificate(seq, d)
	case AuthUpdateKeyChgReq:
		return nil, 0, a.updateKeyRequest(seq, d)
	case AuthUpdateKeyChg:
		return nil, 0, a.updateKeyChange(seq, blocks)
	case AuthErrorObj:
		a.stat(StatErrorsReceived)
		return nil, 0, nil
	}
	a.stat(StatUnexpected)
	return nil, 0, a.errorFrag(seq, 0, 0, AuthErrAuthFailed, fmt.Sprintf("g120v%d is not accepted here", v))
}

func (a *OutstationAuth) methodOK(method uint8) bool {
	if a.cfg.Methods != nil && !a.cfg.Methods[method] {
		return false
	}
	_, _, err := MethodHash(method)
	if err != nil {
		return false
	}
	if Symmetric(method) {
		return a.cfg.AuthorityKey != nil
	}
	return a.cfg.AuthorityCert != nil && a.rsaKey() != nil
}

// acceptStatus records a verified status change (a.mu held).
func (a *OutstationAuth) acceptStatus(u UserStatus, pub any) {
	var user *ostUser
	for _, x := range a.users {
		if x.Name == u.Name {
			user = x
		}
	}
	if u.Operation == UserDelete {
		if user != nil {
			delete(a.users, user.Number)
			if a.cfg.UserChanged != nil {
				gone := user.OutstationUser
				gone.UpdateKey = nil
				a.cfg.UserChanged(gone)
			}
		}
		return
	}
	if user == nil {
		user = &ostUser{OutstationUser: OutstationUser{Name: u.Name}, status: KeyStatusNotInit}
		// A user number is assigned at the update key change.
	}
	uc := u
	user.pending, user.pendingPub, user.pendingAt = &uc, pub, time.Now()
	user.lastSCS, user.hasSCS = u.SCS, true
	if user.Number != 0 {
		a.users[user.Number] = user
	} else {
		a.users[a.freeNumber()] = user
	}
}

func (a *OutstationAuth) freeNumber() uint16 {
	n := uint16(2)
	for a.users[n] != nil {
		n++
	}
	return n
}

// userSequences gives the verifier the status change sequence numbers kept
// with the users (one store; acceptStatus records a new one).
type userSequences struct{ a *OutstationAuth }

func (u userSequences) Last(name string) (uint32, bool) {
	u.a.mu.Lock()
	defer u.a.mu.Unlock()
	for _, x := range u.a.users {
		if x.Name == name && x.hasSCS {
			return x.lastSCS, true
		}
	}
	return 0, false
}

func (u userSequences) Store(string, uint32) {}

func (a *OutstationAuth) scsOK(name string, scs uint32) bool {
	for _, x := range a.users {
		if x.Name == name && x.hasSCS && scs <= x.lastSCS {
			return false
		}
	}
	return true
}

func (a *OutstationAuth) userStatus(seq uint8, d []byte) *Fragment {
	u, err := ParseUserStatus(d)
	if err != nil {
		return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, err.Error())
	}
	if !a.methodOK(u.Method) {
		return a.errorFrag(seq, 0, 0, AuthErrUpdateMethod, "")
	}
	var pub any
	if Symmetric(u.Method) {
		want, err := CertifyStatus(u.Method, a.cfg.AuthorityKey, a.assoc.cfg.Master, u)
		if err != nil || !hmac.Equal(want, u.CertData) {
			return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, "")
		}
	} else {
		apub, ok := a.cfg.AuthorityCert.PublicKey.(*dsa.PublicKey)
		if !ok || !DSAVerify(u.Method, apub, u.StatusInfo(), u.CertData) {
			return a.errorFrag(seq, 0, 0, AuthErrInvalidSignature, "")
		}
		p, err := x509.ParsePKIXPublicKey(u.PublicKey)
		if err != nil {
			return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, "the user's public key does not parse")
		}
		pub = p
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.scsOK(u.Name, u.SCS) {
		return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, "the status change sequence number did not increase")
	}
	a.acceptStatus(u, pub)
	f := Fragment{Control: AppFIR | AppFIN | seq, Func: FCAuthResponse, IIN: a.assoc.iin(nil)}
	return &f
}

func (a *OutstationAuth) userCertificate(seq uint8, d []byte) *Fragment {
	uc, err := ParseUserCertificate(d)
	if err != nil {
		return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, err.Error())
	}
	if Symmetric(uc.Method) || !a.methodOK(uc.Method) {
		return a.errorFrag(seq, 0, 0, AuthErrUpdateMethod, "")
	}
	cu, err := VerifyUserCertificate(uc, a.cfg.AuthorityCert, a.cfg.Roles)
	if err != nil {
		return a.errorFrag(seq, 0, 0, AuthErrInvalidSignature, err.Error())
	}
	if uc.Type == CertID && a.cfg.UserCertCheck != nil {
		c, err := x509.ParseCertificate(uc.Cert)
		if err == nil {
			err = a.cfg.UserCertCheck(c)
		}
		if err != nil {
			return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, err.Error())
		}
	}
	// IEC 62351-8 clause 12: role definition, revision, role IDs, areas of
	// responsibility and the status change sequence number, the signature
	// having been checked against the authority (the authority certifies
	// the user, IEEE 1815 7.5.5.6).
	granted, err := a.cfg.Roles.Authorize(context.Background(), cu.Token, iotsec.RoleRequest{Peer: cu.Name, Remote: true, TokenVerified: true, SubjectAuthenticated: true})
	if err != nil {
		return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, err.Error())
	}
	if len(granted) == 0 {
		return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, "no role for this outstation's area of responsibility")
	}
	ar := granted[0]
	role := UserRoleInfo{Roles: []int{ar.ID}, AOR: ar.AoR, Revision: ar.Revision, RoleDefinition: ar.Definition, Operation: asn1.Enumerated(ar.Operation)}
	if ar.HasSequence {
		role.SCS = int64(ar.Sequence)
	}
	op := uint8(role.Operation)
	if op == 0 {
		op = UserAdd
	}
	if uc.Type == CertAttribute && op == UserAdd {
		return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, "an attribute certificate may only delete or change")
	}
	days := uint16(0)
	if !cu.NotAfter.IsZero() {
		days = uint16(min(cu.NotAfter.Sub(cu.NotBefore).Hours()/24, 65535))
	}
	us := UserStatus{Method: uc.Method, Operation: op, SCS: uint32(role.SCS), Role: uint16(role.Roles[0]), Expiry: days, Name: cu.Name}
	a.mu.Lock()
	defer a.mu.Unlock()
	if role.SCS != 0 && !a.scsOK(cu.Name, uint32(role.SCS)) {
		return a.errorFrag(seq, 0, 0, AuthErrInvalidCertData, "the status change sequence number did not increase")
	}
	pub := cu.PublicKey
	if pub == nil {
		for _, x := range a.users {
			if x.Name == cu.Name {
				pub = x.pendingPub
			}
		}
	}
	a.acceptStatus(us, pub)
	f := Fragment{Control: AppFIR | AppFIN | seq, Func: FCAuthResponse, IIN: a.assoc.iin(nil)}
	return &f
}

func (a *OutstationAuth) updateKeyRequest(seq uint8, d []byte) *Fragment {
	r, err := ParseUpdateKeyRequest(d)
	if err != nil {
		return a.errorFrag(seq, 0, 0, AuthErrUnknownUser, err.Error())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var u *ostUser
	for _, x := range a.users {
		if x.Name == r.Name {
			u = x
		}
	}
	if u == nil || (u.pending == nil && u.UpdateKey == nil) || (u.pending != nil && u.pending.Method != r.Method) ||
		(!u.Expires.IsZero() && time.Now().After(u.Expires)) {
		return a.errorFrag(seq, 0, 0, AuthErrUnknownUser, "")
	}
	a.ksq++
	if u.Number == 0 {
		for n, x := range a.users {
			if x == u {
				u.Number = n
			}
		}
	}
	ochal := make([]byte, ChallengeLen(r.Method))
	_, _ = rand.Read(ochal)
	a.pendingUKC = &ostUKC{user: u, method: r.Method, mchal: r.Challenge, ochal: ochal, ksq: a.ksq}
	f := authFrag(seq, a.assoc.iin(nil), AuthUpdateKeyChgReply, UpdateKeyReply{KSQ: a.ksq, User: u.Number, Data: ochal}.Encode())
	return &f
}

func (a *OutstationAuth) updateKeyChange(seq uint8, blocks []Block) *Fragment {
	if len(blocks) != 2 || len(blocks[0].Points) != 1 || len(blocks[1].Points) != 1 {
		return a.errorFrag(seq, 0, 0, AuthErrAuthFailed, "")
	}
	chg, err := ParseUpdateKeyReply(blocks[0].Points[0].Raw)
	proof, pv := blocks[1].Points[0].Raw, blocks[1].Header.Var
	a.mu.Lock()
	p := a.pendingUKC
	a.pendingUKC = nil
	a.mu.Unlock()
	if err != nil || p == nil || chg.KSQ != p.ksq || chg.User != p.user.Number {
		a.stat(StatFailedUpdateKeyChanges)
		return a.errorFrag(seq, chg.KSQ, chg.User, AuthErrAuthFailed, "")
	}
	name := p.user.Name
	_, kl, _ := MethodHash(p.method)
	var plain []byte
	if Symmetric(p.method) {
		plain, err = UnwrapKey(a.cfg.AuthorityKey, chg.Data)
	} else {
		h, _, _ := MethodHash(p.method)
		plain, err = rsa.DecryptOAEP(h(), rand.Reader, a.rsaKey(), chg.Data, nil)
	}
	var key []byte
	code := uint8(AuthErrAuthFailed)
	a.mu.Lock()
	lastCSQ := a.lastCSQ
	a.mu.Unlock()
	if err == nil && len(plain) >= len(name)+kl+len(p.ochal) && string(plain[:len(name)]) == name &&
		bytes.Equal(plain[len(name)+kl:len(name)+kl+len(p.ochal)], p.ochal) {
		k := plain[len(name) : len(name)+kl]
		switch {
		case Symmetric(p.method) && pv == AuthUpdateKeyChgConf:
			want, err := ConfirmationMACIV(p.method, k, a.ivIn(p.user.Number, p.ksq, lastCSQ), a.cfg.Name, p.mchal, p.ochal, p.ksq, p.user.Number)
			if err == nil && hmac.Equal(want, proof) {
				key = k
			}
		case !Symmetric(p.method) && pv == AuthUpdateKeyChgSig:
			dp, ok := p.user.pendingPub.(*dsa.PublicKey)
			if ok && DSAVerify(p.method, dp, SignatureData(a.cfg.Name, p.mchal, p.ochal, p.ksq, p.user.Number, chg.Data), proof) {
				key = k
			} else {
				code = AuthErrInvalidSignature
			}
		}
	}
	if key == nil {
		a.stat(StatFailedUpdateKeyChanges)
		return a.errorFrag(seq, chg.KSQ, chg.User, code, "")
	}
	a.mu.Lock()
	u := p.user
	u.UpdateKey = append([]byte(nil), key...)
	if u.pending != nil {
		u.Role = u.pending.Role
		if u.pending.Expiry > 0 {
			u.Expires = u.pendingAt.Add(time.Duration(u.pending.Expiry) * 24 * time.Hour)
		} else {
			u.Expires = time.Time{}
		}
		u.pending = nil
	}
	u.ctrl, u.mon, u.status = nil, nil, KeyStatusNotInit
	a.users[u.Number] = u
	a.stats[StatUpdateKeyChanges]++
	saved := u.OutstationUser
	a.mu.Unlock()
	if a.cfg.UserChanged != nil {
		a.cfg.UserChanged(saved)
	}
	mac, _ := ConfirmationMACIV(p.method, key, a.ivOut(u.Number, p.ksq, lastCSQ), u.Name, p.ochal, p.mchal, p.ksq, u.Number)
	f := authFrag(seq, a.assoc.iin(nil), AuthUpdateKeyChgConf, mac)
	return &f
}

// wrapResponse adds a challenge asking for an aggressive-mode
// confirmation to a response with events (ChallengeConfirms).
func (a *OutstationAuth) wrapResponse(f Fragment) Fragment {
	if !a.cfg.ChallengeConfirms || f.Control&AppCON == 0 || len(f.Objects) == 0 {
		return f
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.valid(a.users[UserDefault]) {
		return f
	}
	a.csq++
	a.lastCSQ = a.csq
	data := make([]byte, 4)
	_, _ = rand.Read(data)
	c := Challenge{CSQ: a.csq, User: UserUnknown, MAL: a.cfg.MAL, Reason: AuthReasonCritical, Data: data}
	f.Objects = AppendAuthObject(append([]byte(nil), f.Objects...), AuthChallenge, c.Encode())
	i := 0
	if f.Control&AppUNS != 0 {
		i = 1
	}
	a.confirmChal[i] = f.Encode()
	a.lastChal, a.lastChalMAL = a.confirmChal[i], a.cfg.MAL
	return f
}

// checkConfirm verifies an aggressive-mode confirmation when one was
// asked for.
func (a *OutstationAuth) checkConfirm(f Fragment) bool {
	i := 0
	if f.Control&AppUNS != 0 {
		i = 1
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	chal := a.confirmChal[i]
	if chal == nil {
		return true
	}
	obj, _, mac, macAt, ok := SplitAggressive(f.Objects)
	if !ok {
		a.authFailure()
		return false
	}
	csq, usr := binary.LittleEndian.Uint32(obj), binary.LittleEndian.Uint16(obj[4:])
	u := a.users[usr]
	if !a.valid(u) {
		a.authFailure()
		return false
	}
	pre := Fragment{Control: f.Control, Func: f.Func, Objects: f.Objects[:macAt]}.Encode()
	want, err := MACIV(a.cfg.MAL, u.ctrl, a.ivIn(usr, a.ksq, csq), chal, pre)
	if err != nil || !hmac.Equal(want, mac) {
		a.authFailure()
		return false
	}
	a.confirmChal[i] = nil
	a.stats[StatSuccessfulAuth]++
	return true
}

// Users is a copy of the users (for status and persistence).
// SetRSAKey replaces the outstation's key transport key (a renewed
// certificate's key, IEC 62351-9 7.6).
func (a *OutstationAuth) SetRSAKey(k *rsa.PrivateKey) { a.renewedRSA.Store(k) }

func (a *OutstationAuth) rsaKey() *rsa.PrivateKey {
	if k := a.renewedRSA.Load(); k != nil {
		return k
	}
	return a.cfg.RSAKey
}

// Users lists the outstation's users (update keys included; never log
// them).
func (a *OutstationAuth) Users() []OutstationUser {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []OutstationUser
	for _, u := range a.users {
		if u.UpdateKey != nil {
			out = append(out, u.OutstationUser)
		}
	}
	return out
}
