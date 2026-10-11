package dnp3

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// MasterConfig configures one master–outstation association.
type MasterConfig struct {
	URL               string // tcp://host:port or udp://host:port
	MasterAddress     uint16
	OutstationAddress uint16
	Timeout           time.Duration // response timeout per fragment
	Log               *slog.Logger
	// OnUnsolicited is called from the receive loop with every unsolicited
	// response (already confirmed when it asked for confirmation).
	OnUnsolicited func(Fragment)
	// Auth enables Secure Authentication: challenges of critical requests
	// are answered and ChangeSessionKeys sets the session keys.
	Auth *Auth
	// KeepAlive, on tcp URLs, sends REQUEST_LINK_STATUS when nothing was
	// received for this long and ends the connection when nothing answers
	// within Timeout (13.2.3.3.1). 0 disables it.
	KeepAlive time.Duration
	// LinkConfirm sends requests as CONFIRMED_USER_DATA, resetting the
	// outstation's link first and retrying each frame LinkRetries times
	// (9.2.6.1, 9.2.6.3); application confirmations stay unconfirmed.
	LinkConfirm bool
	LinkRetries int
	// MaxRequest is the largest request fragment sent (4.3 rule 4); 0 is
	// 2048. A larger request fails before it is sent.
	MaxRequest int
	// TLS, for tcp URLs, runs the connection under a TLS profile, for
	// example the IEC 62351-3 profile with mutual certificates (IEEE
	// 1815-2012 7.4 points to it). A profile that renews keys on the
	// connection may end a connection whose peer does not take part; the
	// caller reconnects. When the connection implements
	// iotsec.KeepaliveConn the master registers REQUEST_LINK_STATUS as
	// its keepalive.
	TLS iotsec.TLSClient
	// Dialer opens tcp connections (nil: a net.Dialer). UDP uses an
	// unconnected socket of its own (see udppeer.go) and serial lines no
	// dialer.
	Dialer iotsec.Dialer
	// LocalPort, for udp URLs, is the local port to send from and listen
	// on (0: any); see udpPeer.
	LocalPort int
}

// Master is a connected association: one outstanding request at a time,
// with unsolicited responses confirmed and handed to OnUnsolicited.
type Master struct {
	cfg  MasterConfig
	conn net.Conn

	wmu  sync.Mutex
	tseq uint8

	rmu sync.Mutex
	seq uint8

	resp chan Fragment
	done chan struct{}
	once sync.Once
	emu  sync.Mutex
	err  error
	iin  IIN

	lastReq  []byte    // the latest request fragment as sent (under rmu)
	sec      Secondary // our secondary station towards the outstation (read loop)
	prim     Primary   // our primary station for confirmed user data (under wmu)
	lrOnce   sync.Once
	linkResp chan Frame
	lastRx   atomic.Int64  // unix nanoseconds of the latest frame received
	learned  atomic.Uint32 // with the self-address: the outstation's address + 1
}

// LearnedAddress is the outstation's own address, learnt from its answer
// to the self-address (false before one arrived).
func (m *Master) LearnedAddress() (uint16, bool) {
	v := m.learned.Load()
	return uint16(v - 1), v != 0
}

// linkResponses carries secondary frames (ACK, NACK, LINK_STATUS) from the
// read loop to a waiting link transaction.
func (m *Master) linkResponses() chan Frame {
	m.lrOnce.Do(func() { m.linkResp = make(chan Frame, 4) })
	return m.linkResp
}

// ErrTimeout is wrapped by errors for requests the outstation did not answer
// in time.
var ErrTimeout = errors.New("no response")

// RejectedError is a request the outstation answered with IIN2
// no-func-code-support, object-unknown or parameter-error.
type RejectedError struct {
	Func byte
	IIN  IIN
}

// Error names the internal indications of the rejection.
func (e *RejectedError) Error() string {
	return fmt.Sprintf("the outstation rejected %s (%s)", FuncName(e.Func), (e.IIN & iinRequestErr).String())
}

// Dial connects to an outstation.
func Dial(ctx context.Context, cfg MasterConfig) (*Master, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	conn, err := dialConn(ctx, cfg)
	if err != nil {
		return nil, err
	}
	m := newMaster(cfg, conn)
	go m.readLoop()
	return m, nil
}

// dialConn opens the connection of a master configuration: TCP (with the
// TLS profile when configured), UDP or a serial line.
func dialConn(ctx context.Context, cfg MasterConfig) (net.Conn, error) {
	u, err := url.Parse(cfg.URL)
	if err == nil && u.Scheme == "serial" {
		return openSerialConn(u)
	}
	if err != nil || u.Host == "" || (u.Scheme != "tcp" && u.Scheme != "udp") {
		return nil, fmt.Errorf("url %q must be tcp://host:port, udp://host:port or serial:///device", cfg.URL)
	}
	if cfg.TLS != nil && u.Scheme != "tcp" {
		return nil, errors.New("TLS needs a tcp:// URL")
	}
	if u.Scheme == "udp" {
		return dialUDP(ctx, u.Host, cfg.LocalPort)
	}
	var d iotsec.Dialer = &net.Dialer{Timeout: cfg.Timeout}
	dctx := ctx
	if cfg.Dialer != nil {
		d = cfg.Dialer
		if cfg.Timeout > 0 {
			var cancel context.CancelFunc
			dctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
			defer cancel()
		}
	}
	conn, err := d.DialContext(dctx, u.Scheme, u.Host)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", u.Host, err)
	}
	if cfg.TLS != nil {
		hctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		tc, err := cfg.TLS.Client(hctx, conn, "")
		cancel()
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("TLS handshake with %s: %w", u.Host, err)
		}
		conn = tc
	}
	return conn, nil
}

func newMaster(cfg MasterConfig, conn net.Conn) *Master {
	if a := cfg.Auth; a != nil {
		a.mu.Lock()
		a.addr, a.peer = cfg.MasterAddress, cfg.OutstationAddress
		a.mu.Unlock()
	}
	m := &Master{cfg: cfg, conn: conn, resp: make(chan Fragment, 32), done: make(chan struct{})}
	// Under a TLS profile that needs traffic before a timed key update on
	// an idle link (IEC 62351-3), the keepalive is REQUEST_LINK_STATUS,
	// the TCP keep-alive of 13.2.3.3.1.
	iotsec.SetKeepalive(conn, m.tlsKeepalive)
	return m
}

// tlsKeepalive sends REQUEST_LINK_STATUS for the TLS profile. It does not
// wait for the link (a confirmed transaction may hold it) or the answer.
func (m *Master) tlsKeepalive() error {
	select {
	case <-m.done:
		return m.Err()
	default:
	}
	go m.sendPrimary(LinkRequestLinkStatus, nil)
	return nil
}

// Close ends the association.
func (m *Master) Close() error {
	m.fail(errors.New("closed"))
	return nil
}

// Done is closed when the connection ends.
func (m *Master) Done() <-chan struct{} { return m.done }

// Err is why the connection ended.
func (m *Master) Err() error {
	m.emu.Lock()
	defer m.emu.Unlock()
	return m.err
}

// IIN is the internal indications of the latest response.
func (m *Master) IIN() IIN {
	m.emu.Lock()
	defer m.emu.Unlock()
	return m.iin
}

func (m *Master) setIIN(i IIN) {
	m.emu.Lock()
	m.iin = i
	m.emu.Unlock()
}

func (m *Master) fail(err error) {
	m.once.Do(func() {
		m.emu.Lock()
		m.err = err
		m.emu.Unlock()
		_ = m.conn.Close()
		close(m.done)
	})
}

func (m *Master) readLoop() {
	m.lastRx.Store(time.Now().UnixNano())
	if m.cfg.KeepAlive > 0 && strings.HasPrefix(m.cfg.URL, "tcp:") {
		go m.keepAlive()
	}
	var lp LinkParser
	var ra Reassembler
	buf := make([]byte, 4096)
	for {
		n, err := m.conn.Read(buf)
		if err != nil {
			m.fail(fmt.Errorf("connection lost: %w", err))
			return
		}
		for _, f := range lp.Feed(buf[:n]) {
			m.frame(f, &ra)
		}
	}
}

func (m *Master) frame(f Frame, ra *Reassembler) {
	m.lastRx.Store(time.Now().UnixNano())
	if IsReservedAddress(f.Dest) {
		return // 9.2.5.2.3: never passed up
	}
	if m.cfg.OutstationAddress == AddrSelf && f.Dest == m.cfg.MasterAddress {
		// Commissioning through the self-address (9.2.5.2.2): the
		// outstation answers from its own address, which is learnt.
		m.learned.Store(uint32(f.Src) + 1)
	} else if (f.Dest != m.cfg.MasterAddress && !IsBroadcast(f.Dest)) || f.Src != m.cfg.OutstationAddress {
		m.cfg.Log.Debug("DNP3 frame for another association ignored", "dest", f.Dest, "src", f.Src)
		return
	}
	if !f.Primary() {
		select {
		case m.linkResponses() <- f:
		default:
		}
		return
	}
	act := m.sec.Handle(f)
	if act.Respond {
		m.sendLink(act.Func, nil)
	}
	if !act.Deliver {
		return
	}
	apdu, err := ra.Add(f.Data)
	if err != nil {
		m.cfg.Log.Warn("DNP3 transport segment dropped", "error", err)
		return
	}
	if apdu == nil {
		return
	}
	frag, err := ParseFragment(apdu)
	if err != nil {
		m.cfg.Log.Warn("DNP3 fragment dropped", "error", err)
		return
	}
	if a := m.cfg.Auth; a != nil {
		a.stat(StatMessagesReceived)
	}
	switch frag.Func {
	case FCUnsolicited:
		m.setIIN(frag.IIN)
		if a := m.cfg.Auth; a != nil && (a.ChallengeResponses || isAggressive(frag)) && len(frag.Objects) > 0 {
			// Authenticating needs a request and its answer; the read
			// loop must keep reading, so it runs apart.
			go m.authenticateUnsolicited(frag)
			return
		}
		m.deliverUnsolicited(frag)
	case FCResponse, FCAuthResponse:
		select {
		case m.resp <- frag:
		default:
			m.cfg.Log.Warn("DNP3 response dropped: nobody is waiting")
		}
	default:
		m.cfg.Log.Debug("DNP3 fragment from the outstation ignored", "function", frag.Func)
	}
}

func isAggressive(f Fragment) bool {
	_, _, _, _, ok := SplitAggressive(f.Objects)
	return ok
}

// deliverUnsolicited confirms an unsolicited response (in aggressive mode
// when it ends with a challenge) and hands it over.
func (m *Master) deliverUnsolicited(frag Fragment) {
	if frag.Control&AppCON != 0 {
		if frag2, ok := m.aggressiveConfirm(frag, true); ok {
			frag = frag2
		} else {
			m.confirm(frag.Seq(), true)
		}
	}
	if m.cfg.OnUnsolicited != nil {
		m.cfg.OnUnsolicited(frag)
	}
}

// authenticateUnsolicited challenges (or checks the aggressive-mode MAC
// of) an unsolicited response before confirming and using it; one that
// does not authenticate is neither confirmed nor used.
func (m *Master) authenticateUnsolicited(frag Fragment) {
	m.rmu.Lock()
	f, err := m.authenticateResponse(context.Background(), frag)
	m.rmu.Unlock()
	if err != nil {
		m.cfg.Log.Warn("DNP3 unsolicited response not authenticated; discarded", "error", err)
		return
	}
	m.deliverUnsolicited(f)
}

// authenticateResponse checks a response the master requires to be
// authentic: an aggressive-mode response's MAC, or a challenge and the
// outstation's reply (rmu held). It returns the fragment with the
// authentication objects removed.
func (m *Master) authenticateResponse(ctx context.Context, f Fragment) (Fragment, error) {
	a := m.cfg.Auth
	if _, inner, _, _, ok := SplitAggressive(f.Objects); ok {
		if err := a.verifyAggressive(f); err != nil {
			return f, err
		}
		f.Objects = inner
		return f, nil
	}
	if !a.ChallengeResponses || len(f.Objects) == 0 {
		return f, nil
	}
	resp := f.Encode()
	if err := m.sendAPDU(a.challengeResponse(f.Seq())); err != nil {
		return f, err
	}
	timer := time.NewTimer(m.cfg.Timeout)
	defer timer.Stop()
	for {
		select {
		case r := <-m.resp:
			if r.Func != FCAuthResponse || r.Seq() != f.Seq() {
				continue
			}
			v, d, err := ParseAuthObject(r.Objects)
			if err != nil {
				return f, err
			}
			if v == AuthErrorObj {
				a.stat(StatErrorsReceived)
				return f, authErrorOf(d)
			}
			if v != AuthReply {
				a.stat(StatUnexpected)
				return f, &AuthError{Msg: fmt.Sprintf("expected a reply to the master's challenge, got g120v%d", v)}
			}
			return f, a.verifyReply(d, resp)
		case <-timer.C:
			a.replyTimeout()
			return f, fmt.Errorf("%w: no reply to the master's challenge", ErrTimeout)
		case <-m.done:
			return f, m.Err()
		case <-ctx.Done():
			return f, ctx.Err()
		}
	}
}

// aggressiveConfirm confirms, in aggressive mode, a response whose last
// object is a challenge (7.5.2.3.2 d, 7.5.3.2), whatever the aggressive
// mode setting (7.6.1.4.7). It returns the fragment without the
// challenge; ok is false when the response carries none.
func (m *Master) aggressiveConfirm(f Fragment, uns bool) (Fragment, bool) {
	a := m.cfg.Auth
	if a == nil {
		return f, false
	}
	c, rest, ok := trailingChallenge(f.Objects)
	if !ok {
		return f, false
	}
	a.noteChallenge(f.Encode(), c)
	ctl := AppFIR | AppFIN | f.Seq()
	if uns {
		ctl |= AppUNS
	}
	b := a.aggressive(Fragment{Control: ctl, Func: FCConfirm}, true)
	if b == nil {
		m.cfg.Log.Warn("DNP3 aggressive-mode confirmation impossible (no session keys or MAC algorithm); confirming plainly")
		m.confirm(f.Seq(), uns)
	} else {
		_ = m.sendUnconfirmed(b)
	}
	f.Objects = rest
	return f, true
}

// keepAlive sends REQUEST_LINK_STATUS after KeepAlive without a received
// frame and ends the connection when nothing arrives within Timeout.
func (m *Master) keepAlive() {
	t := time.NewTimer(m.cfg.KeepAlive)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
		}
		idle := time.Since(time.Unix(0, m.lastRx.Load()))
		if idle < m.cfg.KeepAlive {
			t.Reset(m.cfg.KeepAlive - idle)
			continue
		}
		sent := time.Now()
		m.sendPrimary(LinkRequestLinkStatus, nil)
		select {
		case <-m.done:
			return
		case <-time.After(m.cfg.Timeout):
		}
		if m.lastRx.Load() < sent.UnixNano() {
			m.fail(errors.New("connection lost: no answer to the keep-alive link status request"))
			return
		}
		t.Reset(m.cfg.KeepAlive)
	}
}

// sendPrimary sends a primary link frame without user data.
func (m *Master) sendPrimary(fc byte, data []byte) {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	b, _ := Frame{Ctrl: CtrlDIR | CtrlPRM | fc, Dest: m.cfg.OutstationAddress, Src: m.cfg.MasterAddress, Data: data}.Encode()
	_ = m.conn.SetWriteDeadline(time.Now().Add(m.cfg.Timeout))
	_, _ = m.conn.Write(b)
}

// sendLink sends a secondary link frame.
func (m *Master) sendLink(fc byte, data []byte) {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	f := Frame{Ctrl: CtrlDIR | fc, Dest: m.cfg.OutstationAddress, Src: m.cfg.MasterAddress, Data: data}
	b, _ := f.Encode()
	_ = m.conn.SetWriteDeadline(time.Now().Add(m.cfg.Timeout))
	_, _ = m.conn.Write(b)
}

// sendAPDU sends an application fragment, as confirmed user data when
// LinkConfirm is set.
func (m *Master) sendAPDU(apdu []byte) error {
	if a := m.cfg.Auth; a != nil {
		a.stat(StatMessagesSent)
	}
	if m.cfg.LinkConfirm {
		return m.sendConfirmed(apdu)
	}
	return m.sendUnconfirmed(apdu)
}

func (m *Master) send(apdu []byte) error { return m.sendAPDU(apdu) }

// sendUnconfirmed sends an application fragment as UNCONFIRMED_USER_DATA.
func (m *Master) sendUnconfirmed(apdu []byte) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	for _, seg := range Segment(apdu, &m.tseq) {
		f := Frame{Ctrl: CtrlDIR | CtrlPRM | LinkUnconfirmedUserData, Dest: m.cfg.OutstationAddress, Src: m.cfg.MasterAddress, Data: seg}
		b, err := f.Encode()
		if err != nil {
			return err
		}
		_ = m.conn.SetWriteDeadline(time.Now().Add(m.cfg.Timeout))
		if _, err := m.conn.Write(b); err != nil {
			m.fail(fmt.Errorf("connection lost: %w", err))
			return err
		}
	}
	return nil
}

// sendConfirmed sends each segment as CONFIRMED_USER_DATA after resetting
// the outstation's link states when needed; a NACK resets again.
func (m *Master) sendConfirmed(apdu []byte) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	for _, seg := range Segment(apdu, &m.tseq) {
		for nacks := 0; ; nacks++ {
			if !m.prim.Reset {
				fc, err := m.linkTransact(Frame{Ctrl: CtrlDIR | CtrlPRM | LinkResetLinkStates})
				if err != nil {
					return err
				}
				if fc != LinkAck {
					return fmt.Errorf("the outstation answered link function %d to RESET_LINK_STATES", fc)
				}
				m.prim.ResetDone()
			}
			fc, err := m.linkTransact(Frame{Ctrl: m.prim.Control(CtrlDIR), Data: seg})
			if err != nil {
				return err
			}
			if fc == LinkAck {
				m.prim.Acked()
				break
			}
			m.prim.Reset = false
			if fc != LinkNack || nacks >= 1 {
				return fmt.Errorf("the outstation answered link function %d to CONFIRMED_USER_DATA", fc)
			}
		}
	}
	return nil
}

// linkTransact sends a primary frame and waits for the secondary answer,
// repeating the identical frame on a timeout up to LinkRetries times
// (wmu held).
func (m *Master) linkTransact(f Frame) (byte, error) {
	f.Dest, f.Src = m.cfg.OutstationAddress, m.cfg.MasterAddress
	b, err := f.Encode()
	if err != nil {
		return 0, err
	}
	lr := m.linkResponses()
	for try := 0; try <= m.cfg.LinkRetries; try++ {
		for drained := false; !drained; {
			select {
			case <-lr:
			default:
				drained = true
			}
		}
		_ = m.conn.SetWriteDeadline(time.Now().Add(m.cfg.Timeout))
		if _, err := m.conn.Write(b); err != nil {
			m.fail(fmt.Errorf("connection lost: %w", err))
			return 0, err
		}
		select {
		case r := <-lr:
			return r.Func(), nil
		case <-time.After(m.cfg.Timeout):
		case <-m.done:
			return 0, m.Err()
		}
	}
	return 0, fmt.Errorf("%w: no link confirmation after %d attempts", ErrTimeout, m.cfg.LinkRetries+1)
}

func (m *Master) confirm(seq uint8, uns bool) {
	c := AppFIR | AppFIN | seq&0x0F
	if uns {
		c |= AppUNS
	}
	// Confirmations go unconfirmed at the link layer: the read loop sends
	// them and cannot wait for a link acknowledgement.
	_ = m.sendUnconfirmed(Fragment{Control: c, Func: FCConfirm}.Encode())
}

// Request sends one request and returns every fragment of its response,
// confirming fragments that ask for it. A response whose IIN2 reports the
// request as unsupported or malformed returns a *RejectedError with the
// fragments.
func (m *Master) Request(ctx context.Context, fc byte, objects []byte) ([]Fragment, error) {
	m.rmu.Lock()
	defer m.rmu.Unlock()
	return m.request(ctx, fc, objects)
}

// SelectOperate sends SELECT and then OPERATE with the same objects as
// consecutive requests (no other request in between). check validates
// each response (nil accepts any); the operate is not sent when the
// select fails or took longer than within.
func (m *Master) SelectOperate(ctx context.Context, objects []byte, within time.Duration, check func(fc byte, frags []Fragment) error) error {
	if check == nil {
		check = func(byte, []Fragment) error { return nil }
	}
	m.rmu.Lock()
	defer m.rmu.Unlock()
	start := time.Now()
	frags, err := m.request(ctx, FCSelect, objects)
	if err != nil {
		return err
	}
	if err := check(FCSelect, frags); err != nil {
		return err
	}
	if time.Since(start) > within {
		return fmt.Errorf("the select took longer than the select timeout (%s); not operating", within)
	}
	frags, err = m.request(ctx, FCOperate, objects)
	if err != nil {
		return err
	}
	return check(FCOperate, frags)
}

// request sends one request; a statistic limit passed meanwhile acts
// (a rekey, or ErrAuthLimit ending the session).
func (m *Master) request(ctx context.Context, fc byte, objects []byte) ([]Fragment, error) {
	frags, err := m.request1(ctx, fc, objects)
	if a := m.cfg.Auth; a != nil {
		if lerr := a.limitAction(); lerr != nil {
			return frags, lerr
		}
	}
	return frags, err
}

func (m *Master) request1(ctx context.Context, fc byte, objects []byte) ([]Fragment, error) {
	select {
	case <-m.done:
		return nil, m.Err()
	default:
	}
	max := m.cfg.MaxRequest
	if max <= 0 {
		max = 2048
	}
	seq := m.seq
	m.seq = (m.seq + 1) & 0x0F
	for drained := false; !drained; {
		select {
		case <-m.resp:
		default:
			drained = true
		}
	}
	a := m.cfg.Auth
	req := Fragment{Control: AppFIR | AppFIN | seq, Func: fc, Objects: objects}
	sent := req.Encode()
	aggressive := false
	if a != nil && CriticalMandatory(fc) {
		if b := a.aggressive(req, false); b != nil {
			sent, aggressive = b, true
		}
	}
	if len(sent) > max {
		return nil, fmt.Errorf("the %s request is %d octets; at most %d are sent in one fragment", FuncName(fc), len(sent), max)
	}
	m.lastReq = sent
	if err := m.send(sent); err != nil {
		return nil, err
	}
	// A request without response gets none, unless the outstation may
	// challenge it: then the master waits one response timeout for a
	// challenge (7.5.2.3.2 k).
	waitChallenge := a != nil && !aggressive && fc != FCConfirm && fc != FCAuthRequestNoAck
	if NoResponse(fc) && !waitChallenge {
		return nil, nil
	}
	challenged := false
	var frags []Fragment
	expect := seq
	timer := time.NewTimer(m.cfg.Timeout)
	defer timer.Stop()
	for {
		select {
		case f := <-m.resp:
			if f.Seq() != expect || (len(frags) == 0 && f.Control&AppFIR == 0) {
				m.cfg.Log.Debug("DNP3 response with an unexpected sequence ignored", "seq", f.Seq(), "expected", expect)
				continue
			}
			if f.Func == FCAuthResponse && fc != FCAuthRequest {
				m.setIIN(f.IIN)
				v, d, err := ParseAuthObject(f.Objects)
				switch {
				case err != nil:
					return frags, fmt.Errorf("%s: %w", FuncName(fc), err)
				case v == AuthErrorObj:
					if a != nil {
						a.stat(StatErrorsReceived)
						ae := authErrorOf(d).(*AuthError)
						if ae.Code == AuthErrAggressiveNotSupp && aggressive {
							a.refuseAggressive()
						} else {
							a.mu.Lock()
							a.authFailure()
							a.afExceeded = false
							a.mu.Unlock()
							if lerr := a.rekeyForAuthFailure(); lerr != nil {
								return frags, lerr
							}
						}
					}
					return frags, fmt.Errorf("%s: %w", FuncName(fc), authErrorOf(d))
				case v != AuthChallenge:
					if a != nil {
						a.stat(StatUnexpected)
					}
					return frags, fmt.Errorf("%s: unexpected g120v%d", FuncName(fc), v)
				case a == nil:
					return frags, fmt.Errorf("%s: %w", FuncName(fc), &AuthError{Msg: "the outstation challenged the request but secure authentication is not configured"})
				case challenged:
					a.stat(StatUnexpected)
					return frags, fmt.Errorf("%s: %w", FuncName(fc), &AuthError{Msg: "challenged twice for one request"})
				}
				challenged = true
				reply, err := a.answerChallenge(f, sent)
				if err != nil {
					return frags, fmt.Errorf("%s: %w", FuncName(fc), err)
				}
				if err := m.send(Fragment{Control: AppFIR | AppFIN | expect, Func: FCAuthRequest, Objects: reply}.Encode()); err != nil {
					return frags, err
				}
				timer.Reset(m.cfg.Timeout)
				continue
			}
			if challenged && len(frags) == 0 {
				a.accepted()
			}
			if a != nil && fc != FCAuthRequest && (a.ChallengeResponses || isAggressive(f)) {
				af, err := m.authenticateResponse(ctx, f)
				if err != nil {
					return frags, fmt.Errorf("%s response: %w", FuncName(fc), err)
				}
				f = af
			}
			if f.Control&AppCON != 0 {
				var ok bool
				if f, ok = m.aggressiveConfirm(f, false); !ok {
					m.confirm(f.Seq(), false)
				}
			}
			m.setIIN(f.IIN)
			frags = append(frags, f)
			if f.Control&AppFIN != 0 {
				if f.IIN&iinRequestErr != 0 {
					return frags, &RejectedError{Func: fc, IIN: f.IIN}
				}
				return frags, nil
			}
			expect = (expect + 1) & 0x0F
			timer.Reset(m.cfg.Timeout)
		case <-timer.C:
			if NoResponse(fc) && len(frags) == 0 {
				if challenged {
					a.accepted()
				}
				return nil, nil
			}
			if a != nil && challenged {
				a.replyTimeout()
			}
			return frags, fmt.Errorf("%w to %s from outstation %d within %s", ErrTimeout, FuncName(fc), m.cfg.OutstationAddress, m.cfg.Timeout)
		case <-m.done:
			return frags, m.Err()
		case <-ctx.Done():
			return frags, ctx.Err()
		}
	}
}

// Quiet keeps requests back for d (the delay a restarting outstation
// announced, 4.4.9).
func (m *Master) Quiet(d time.Duration) {
	if d <= 0 {
		return
	}
	m.rmu.Lock()
	go func() {
		defer m.rmu.Unlock()
		select {
		case <-time.After(d):
		case <-m.done:
		}
	}()
}

// Auth is the association's Secure Authentication state (nil without).
func (m *Master) Auth() *Auth { return m.cfg.Auth }
