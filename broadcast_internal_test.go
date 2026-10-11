package dnp3

import (
	"context"
	"encoding/hex"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// secRecorder collects the security events written to the security log.
type secRecorder struct {
	mu  sync.Mutex
	evs []iotsec.SecurityEvent
}

func (r *secRecorder) RecordSecurity(_ context.Context, e iotsec.SecurityEvent) {
	r.mu.Lock()
	r.evs = append(r.evs, e)
	r.mu.Unlock()
}

func (r *secRecorder) events(name string) []iotsec.SecurityEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []iotsec.SecurityEvent
	for _, e := range r.evs {
		if e.Event == name {
			out = append(out, e)
		}
	}
	return out
}

func useRecorder(t *testing.T) *secRecorder {
	t.Helper()
	r := &secRecorder{}
	SetAuditor(r)
	t.Cleanup(func() { SetAuditor(nil) })
	return r
}

type bcHandler struct {
	mu       sync.Mutex
	controls []ControlRequest
	restarts int
	times    int
	apps     int
}

func (h *bcHandler) Control(_ context.Context, c ControlRequest) uint8 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.controls = append(h.controls, c)
	return 0
}
func (h *bcHandler) DataSetControl(context.Context, DataSetControl) uint8 { return 0 }
func (h *bcHandler) Restart(context.Context, bool) time.Duration {
	h.mu.Lock()
	h.restarts++
	h.mu.Unlock()
	return 0
}
func (h *bcHandler) Activate(context.Context, [][]byte) ActivateStatus { return ActivateStatus{} }
func (h *bcHandler) Application(context.Context, byte, [][]byte) IIN {
	h.mu.Lock()
	h.apps++
	h.mu.Unlock()
	return 0
}
func (h *bcHandler) TimeSet(time.Time)                       { h.mu.Lock(); h.times++; h.mu.Unlock() }
func (h *bcHandler) DataSetWritten(context.Context, DataSet) {}

func (h *bcHandler) nControls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.controls)
}

const bcKey = "00112233445566778899aabbccddeeff"

// mustKey decodes a hex key of the tests.
func mustKey(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

// bcOutstation is an outstation (address 10, master 1) on TCP; auth nil
// runs it without Secure Authentication.
func bcOutstation(t *testing.T, auth bool, tune func(*OutstationConfig)) (*Association, *bcHandler, *OutstationAuth, string) {
	t.Helper()
	db := NewPointDB()
	for _, typ := range []string{"binary-output", "counter", "frozen-counter"} {
		if err := db.Define(DBPoint{Type: typ, Index: 0, Class0: true}); err != nil {
			t.Fatal(err)
		}
	}
	h := &bcHandler{}
	cfg := OutstationConfig{Address: 10, Master: 1, DB: db, Handler: h, Broadcast: true, ConfirmTimeout: 300 * time.Millisecond,
		SelectTimeout: time.Second, Attributes: map[uint8]any{}, Writable: map[uint8]bool{}}
	var oa *OutstationAuth
	if auth {
		k, _ := hex.DecodeString(bcKey)
		var err error
		oa, err = NewOutstationAuth(OutstationAuthConfig{Users: []OutstationUser{{Number: 1, Name: "Common", UpdateKey: k, Role: RoleSingleUser}},
			Subject: "test outstation", ReplyTimeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Auth = oa
	}
	if tune != nil {
		tune(&cfg)
	}
	a := NewAssociation(cfg)
	n := &OutstationNet{KeepAlive: time.Minute}
	n.Add(a)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.Run(ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go n.ServeStream(ctx, c)
		}
	}()
	return a, h, oa, "tcp://" + ln.Addr().String()
}

// deliverBroadcast hands a request to the association as if received at
// dest (a broadcast address) from master 1.
func deliverBroadcast(a *Association, dest uint16, apdu []byte) {
	var seq uint8
	for _, s := range Segment(apdu, &seq) {
		a.Deliver(Frame{Ctrl: CtrlDIR | CtrlPRM | LinkUnconfirmedUserData, Dest: dest, Src: 1, Data: s})
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func latchObjects(t *testing.T) []byte {
	t.Helper()
	b, err := EncodeBlock(12, 1, Q8Index8, []Point{{Index: 0, CROB: CROB{Code: OpLatchOn, Count: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// With Secure Authentication on, every critical request function code
// (Table 7-7 mandatory set) received at a broadcast address is refused
// without being carried out, counted as a discarded message and recorded
// as a security event; so are the authentication function codes. A
// broadcast cannot be challenged (it is never answered, 4.7), so only a
// verified Aggressive Mode request (7.5.2.3.2) is carried out, and a
// tampered one is refused. Non-critical requests are processed.
//
// Covers: SIG-IPE-2675
func TestBroadcastCriticalRefusedUnderSA(t *testing.T) {
	rec := useRecorder(t)
	a, h, oa, url := bcOutstation(t, true, nil)
	ctx := context.Background()
	var critical []byte
	for fc := range 32 {
		if CriticalMandatory(byte(fc)) {
			critical = append(critical, byte(fc))
		}
	}
	critical = append(critical, FCAuthRequest, FCAuthRequestNoAck)
	if len(critical) < 22 {
		t.Fatalf("only %d critical codes", len(critical))
	}
	before := oa.Statistics()[StatDiscarded]
	for i, fc := range critical {
		objs := []byte(nil)
		if fc >= FCSelect && fc <= FCDirectOperateNR {
			objs = latchObjects(t)
		}
		deliverBroadcast(a, AddrBroadcastNoConfirm, Fragment{Control: AppFIR | AppFIN | byte(i)&0x0F, Func: fc, Objects: objs}.Encode())
	}
	waitFor(t, "a refusal per critical code", func() bool { return len(rec.events(SecEventBroadcastRefused)) >= len(critical) })
	got := map[string]bool{}
	for _, e := range rec.events(SecEventBroadcastRefused) {
		got[e.Detail["functionCode"]] = true
		if e.Outcome != iotsec.OutcomeFailure || e.Subject != "test outstation" || e.Method != "dnp3-sav5" {
			t.Errorf("event %+v", e)
		}
	}
	for _, fc := range critical {
		if !got[strconv.Itoa(int(fc))] {
			t.Errorf("no security event for broadcast %s", FuncName(fc))
		}
	}
	h.mu.Lock()
	carried := len(h.controls) + h.restarts + h.apps + h.times
	h.mu.Unlock()
	if carried != 0 {
		t.Fatalf("%d refused broadcasts were carried out", carried)
	}
	if d := oa.Statistics()[StatDiscarded] - before; d < uint32(len(critical)) {
		t.Errorf("%d discarded, want %d", d, len(critical))
	}

	// A non-critical request (immediate freeze) is processed.
	frz := AppendHeader(nil, 20, 0, QAll, 0, 0)
	refused := len(rec.events(SecEventBroadcastRefused))
	deliverBroadcast(a, AddrBroadcastNoConfirm, Fragment{Control: AppFIR | AppFIN, Func: FCImmedFreezeNR, Objects: frz}.Encode())
	time.Sleep(100 * time.Millisecond)
	if len(rec.events(SecEventBroadcastRefused)) != refused {
		t.Error("a non-critical broadcast (immediate freeze) was refused")
	}

	// Aggressive Mode by broadcast: the master has session keys and has
	// answered a challenge; its aggressive direct-operate-no-ack is
	// carried out, a tampered copy is refused.
	auth, err := NewAuth(&AuthConfig{UpdateKey: mustKey(bcKey), MAC: MACSHA256Trunc16, User: 1, AggressiveMode: true})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Dial(ctx, MasterConfig{URL: url, MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Request(ctx, FCDirectOperate, latchObjects(t)); err != nil {
		t.Fatal(err)
	}
	n := h.nControls()
	req := Fragment{Control: AppFIR | AppFIN | 0x03, Func: FCDirectOperateNR, Objects: latchObjects(t)}
	good := auth.aggressive(req, true)
	if good == nil {
		t.Fatal("no aggressive request built")
	}
	bad := slices.Clone(good)
	bad[len(bad)-1] ^= 0xFF
	refusedBefore := len(rec.events(SecEventBroadcastRefused))
	deliverBroadcast(a, AddrBroadcastNoConfirm, bad)
	waitFor(t, "the tampered aggressive broadcast refused", func() bool { return len(rec.events(SecEventBroadcastRefused)) > refusedBefore })
	if h.nControls() != n {
		t.Fatal("a tampered aggressive broadcast was carried out")
	}
	deliverBroadcast(a, AddrBroadcastNoConfirm, auth.aggressive(req, true))
	waitFor(t, "the aggressive broadcast carried out", func() bool { return h.nControls() == n+1 })
}

// Without Secure Authentication, broadcast follows the configured
// function codes (the device profile's 1.13 items): enabled codes are
// carried out, others are discarded without an answer.
//
// Covers: SIG-IPE-2676
func TestBroadcastPerFunctionCode(t *testing.T) {
	a, h, _, _ := bcOutstation(t, false, func(c *OutstationConfig) {
		c.BroadcastFuncs = map[byte]bool{FCDirectOperateNR: true, FCWrite: true}
	})
	// Direct operate (FC 5) is not enabled; direct operate no ack (6) is.
	deliverBroadcast(a, AddrBroadcastNoConfirm, Fragment{Control: AppFIR | AppFIN | 1, Func: FCDirectOperate, Objects: latchObjects(t)}.Encode())
	deliverBroadcast(a, AddrBroadcastNoConfirm, Fragment{Control: AppFIR | AppFIN | 2, Func: FCDirectOperateNR, Objects: latchObjects(t)}.Encode())
	waitFor(t, "the enabled broadcast", func() bool { return h.nControls() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if n := h.nControls(); n != 1 {
		t.Fatalf("%d controls carried out, want 1 (FC 6 only)", n)
	}
	for fc := range 32 {
		if !slices.Contains([]byte{FCDirectOperateNR, FCWrite}, byte(fc)) && a.cfg.BroadcastFuncs[byte(fc)] {
			t.Errorf("FC %d enabled", fc)
		}
	}
	// Every Table 7-7 critical code by broadcast with SA off and all
	// functions enabled is carried out as configured (here: controls,
	// restarts, application functions reach the handler).
	b, hb, _, _ := bcOutstation(t, false, nil)
	deliverBroadcast(b, AddrBroadcastNoConfirm, Fragment{Control: AppFIR | AppFIN | 3, Func: FCDirectOperateNR, Objects: latchObjects(t)}.Encode())
	deliverBroadcast(b, AddrBroadcastNoConfirm, Fragment{Control: AppFIR | AppFIN | 4, Func: FCStartAppl, Objects: AppendHeader(nil, 90, 1, QAll, 0, 0)}.Encode())
	waitFor(t, "broadcasts carried out without SA", func() bool {
		hb.mu.Lock()
		defer hb.mu.Unlock()
		return len(hb.controls) == 1 && hb.apps == 1
	})
}

// The outstation's statistic limits (Table 7-6, Table 7-8): past Max
// Reply Timeouts every user's key status becomes COMM_FAIL; past Max
// Authentication Failures the TCP connection is dropped; past Max Error
// Messages Sent no error objects are sent until the keys change. Each
// acting limit is a security event.
//
// Covers: SIG-IPE-2677
func TestOutstationStatisticLimits(t *testing.T) {
	rec := useRecorder(t)
	ctx := context.Background()
	a, _, oa, url := bcOutstation(t, true, nil)
	auth, err := NewAuth(&AuthConfig{UpdateKey: mustKey(bcKey), MAC: MACSHA256Trunc16, User: 1})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Dial(ctx, MasterConfig{URL: url, MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	_ = a
	// Reply timeouts: challenged requests never answered (a write from
	// "another" master path: the gate is driven directly).
	w, _ := EncodeBlock(80, 1, Q8StartStop, []Point{{Index: 7, Value: false}})
	for i := range 5 {
		req := Fragment{Control: AppFIR | AppFIN | byte(i), Func: FCWrite, Objects: w}
		_, _, reply := oa.gate(ctx, req, req.Encode())
		if i < 4 && reply == nil {
			t.Fatalf("request %d not challenged", i)
		}
		time.Sleep(120 * time.Millisecond)
	}
	if st := oa.Statistics(); st[StatReplyTimeouts] < 4 {
		t.Fatalf("reply timeouts %d", st[StatReplyTimeouts])
	}
	oa.mu.Lock()
	status := oa.users[1].status
	oa.mu.Unlock()
	if status != KeyStatusCommFail {
		t.Errorf("key status %d after max reply timeouts, want COMM_FAIL", status)
	}
	if len(rec.events(SecEventMaxReplyTimeouts)) == 0 {
		t.Error("no security event for max reply timeouts")
	}
	// Max error messages: with the keys gone, critical requests are
	// answered with errors until two were sent, then with nothing.
	errs := 0
	for i := range 4 {
		req := Fragment{Control: AppFIR | AppFIN | byte(i), Func: FCWrite, Objects: w}
		if _, _, reply := oa.gate(ctx, req, req.Encode()); reply != nil {
			errs++
		}
	}
	// The fifth request above drew the first error (the keys went to
	// COMM_FAIL); one more is sent, then none (Max Error Messages Sent 2).
	if errs != 1 {
		t.Errorf("%d more error messages sent, want 1 (Max Error Messages Sent)", errs)
	}
	if n := oa.Statistics()[StatErrorsSent]; n != 2 || len(rec.events(SecEventMaxErrorMessages)) != 1 {
		t.Errorf("error messages sent %d (want 2), %d events", n, len(rec.events(SecEventMaxErrorMessages)))
	}
	// Max authentication failures: the failures above (4 so far) and more
	// pass 5, and the master's TCP connection is dropped.
	for i := range 3 {
		req := Fragment{Control: AppFIR | AppFIN | byte(i), Func: FCWrite, Objects: w}
		oa.gate(ctx, req, req.Encode())
	}
	select {
	case <-m.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the connection was not dropped after max authentication failures")
	}
	if len(rec.events(SecEventMaxAuthFailures)) == 0 {
		t.Error("no security event for max authentication failures")
	}
}

// The master's statistic limits (Table 7-6, Table 7-8): past Max Reply
// Timeouts it changes the session keys; past Max Authentication Failures
// it rekeys until Rekeys Due to Authentication Failure passes Max
// Authentication Rekeys, then closes the connection (ErrAuthLimit) and
// rekeys for failures no more until a scheduled key change; restarts
// rekey until Max Rekeys Due to Restarts. Each is a security event.
//
// Covers: SIG-IPE-2678
func TestMasterStatisticLimits(t *testing.T) {
	rec := useRecorder(t)
	a, err := NewAuth(&AuthConfig{UpdateKey: mustKey(bcKey), KeyChangeCount: 1000})
	if err != nil {
		t.Fatal(err)
	}
	keys := func() { a.mu.Lock(); a.ctrl, a.mon = []byte{1}, []byte{2}; a.mu.Unlock() }
	has := func() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.ctrl != nil }
	keys()
	for range 3 {
		a.replyTimeout()
	}
	if !has() {
		t.Fatal("keys dropped before Max Reply Timeouts was passed")
	}
	a.replyTimeout()
	if has() || len(rec.events(SecEventMaxReplyTimeouts)) != 1 {
		t.Fatal("Max Reply Timeouts did not change the keys")
	}
	// Authentication failures: five are tolerated, the sixth rekeys.
	for rekeys := 1; rekeys <= 3; rekeys++ {
		keys()
		for range 5 {
			a.authFailed()
			if err := a.limitAction(); err != nil || !has() {
				t.Fatalf("rekey %d: acted before the limit (%v)", rekeys, err)
			}
		}
		a.authFailed()
		if err := a.limitAction(); err != nil || has() {
			t.Fatalf("rekey %d: %v", rekeys, err)
		}
	}
	keys()
	for range 6 {
		a.authFailed()
	}
	if err := a.limitAction(); err != ErrAuthLimit {
		t.Fatalf("after Max Authentication Rekeys: %v, want ErrAuthLimit", err)
	}
	if !has() || len(rec.events(SecEventMaxAuthRekeys)) != 1 {
		t.Fatal("keys changed or no event after Max Authentication Rekeys")
	}
	if err := a.rekeyForAuthFailure(); err != ErrAuthLimit {
		t.Fatalf("rekeys for failures resumed early: %v", err)
	}
	a.ScheduledKeyChange()
	if err := a.rekeyForAuthFailure(); err != nil {
		t.Fatalf("after a scheduled key change: %v", err)
	}
	// Restarts.
	for i := range 3 {
		if !a.RestartRekey() {
			t.Fatalf("restart %d not rekeyed", i+1)
		}
	}
	if a.RestartRekey() || a.RestartRekey() {
		t.Fatal("rekeyed past Max Rekeys Due to Restarts")
	}
	if len(rec.events(SecEventMaxRekeysDueRestarts)) != 1 {
		t.Error("no single event for Max Rekeys Due to Restarts")
	}
	a.ScheduledKeyChange()
	if !a.RestartRekey() {
		t.Error("restart rekeys did not resume after the key change timeout")
	}
	st := a.Statistics()
	if st["rekeys-due-to-authentication-failure"] != 4 || st["reply-timeouts"] != 4 || st["rekeys-due-to-restarts"] != 5 {
		t.Errorf("statistics %v", st)
	}
}
