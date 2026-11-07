package dnp3_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// testHandler records what the outstation asks of its application.
type testHandler struct {
	mu        sync.Mutex
	controls  []dnp3.ControlRequest
	dsCtl     []dnp3.DataSetControl
	status    uint8
	restart   time.Duration
	activated [][]byte
	apps      []byte
	timeSet   time.Time
	written   []dnp3.DataSet
	unknown   func(dnp3.ControlRequest) bool // controls answered NOT_SUPPORTED
}

func (h *testHandler) Control(_ context.Context, c dnp3.ControlRequest) uint8 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.controls = append(h.controls, c)
	if h.unknown != nil && h.unknown(c) {
		return 4
	}
	return h.status
}
func (h *testHandler) DataSetControl(_ context.Context, c dnp3.DataSetControl) uint8 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dsCtl = append(h.dsCtl, c)
	return 0
}
func (h *testHandler) Restart(context.Context, bool) time.Duration { return h.restart }
func (h *testHandler) Activate(_ context.Context, names [][]byte) dnp3.ActivateStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activated = append(h.activated, names...)
	st := dnp3.ActivateStatus{Delay: 1500 * time.Millisecond}
	for _, n := range names {
		if string(n) == "missing.cfg" {
			st.Elements = append(st.Elements, dnp3.StatusElement{Code: dnp3.ActivateBadObject, Text: "File not found"})
		} else {
			st.Elements = append(st.Elements, dnp3.StatusElement{Code: dnp3.ActivateOK})
		}
	}
	return st
}
func (h *testHandler) Application(_ context.Context, fc byte, names [][]byte) dnp3.IIN {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.apps = append(h.apps, fc)
	return 0
}
func (h *testHandler) TimeSet(t time.Time) { h.mu.Lock(); h.timeSet = t; h.mu.Unlock() }
func (h *testHandler) DataSetWritten(_ context.Context, ds dnp3.DataSet) {
	h.mu.Lock()
	h.written = append(h.written, ds)
	h.mu.Unlock()
}

type testOutstation struct {
	db    *dnp3.PointDB
	h     *testHandler
	assoc *dnp3.Association
	url   string
	net   *dnp3.OutstationNet
}

func startOutstation(t *testing.T, tune func(*dnp3.OutstationConfig)) *testOutstation {
	t.Helper()
	db := dnp3.NewPointDB()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.Define(dnp3.DBPoint{Type: "binary", Index: 0, Class0: true, Class: 1}))
	must(db.Define(dnp3.DBPoint{Type: "binary", Index: 1, Class0: true, Class: 1}))
	must(db.Define(dnp3.DBPoint{Type: "analog", Index: 0, Class0: true, Class: 2, Deadband: 1}))
	must(db.Define(dnp3.DBPoint{Type: "counter", Index: 0, Class0: true, Class: 3}))
	must(db.Define(dnp3.DBPoint{Type: "frozen-counter", Index: 0, Class0: true}))
	must(db.Define(dnp3.DBPoint{Type: "binary-output", Index: 0, Class0: true}))
	must(db.Define(dnp3.DBPoint{Type: "analog-output", Index: 0, Class0: true}))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, u := range []struct {
		typ string
		v   float64
	}{{"binary", 1}, {"binary", 0}, {"analog", 230.5}, {"counter", 42}, {"frozen-counter", 0}, {"binary-output", 0}, {"analog-output", 0}} {
		idx := uint32(0)
		if u.typ == "binary" && u.v == 0 {
			idx = 1
		}
		_, _ = db.Update(ctx, u.typ, idx, u.v, nil, 0x01, time.Now())
	}
	h := &testHandler{}
	cfg := dnp3.OutstationConfig{Address: 10, Master: 1, DB: db, Handler: h, ConfirmTimeout: 300 * time.Millisecond,
		SelectTimeout: 300 * time.Millisecond, Broadcast: true,
		Attributes: map[uint8]any{252: "SigmaM2M", 250: "dnp3-server", 240: 2048.0, 241: 2048.0}, Writable: map[uint8]bool{240: true}}
	if tune != nil {
		tune(&cfg)
	}
	a := dnp3.NewAssociation(cfg)
	n := &dnp3.OutstationNet{KeepAlive: time.Minute}
	n.Add(a)
	go a.Run(ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
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
	return &testOutstation{db: db, h: h, assoc: a, url: "tcp://" + ln.Addr().String(), net: n}
}

func (o *testOutstation) master(t *testing.T, auth *dnp3.Auth, onUnsol func(dnp3.Fragment)) *dnp3.Master {
	t.Helper()
	m, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: o.url, MasterAddress: 1, OutstationAddress: 10,
		Timeout: 500 * time.Millisecond, Auth: auth, OnUnsolicited: onUnsol})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func pointsOf(t *testing.T, frags []dnp3.Fragment) map[[2]uint32]dnp3.Point {
	t.Helper()
	out := map[[2]uint32]dnp3.Point{}
	for _, f := range frags {
		bl, err := dnp3.ParseObjects(f.Objects, true)
		if err != nil {
			t.Fatalf("% X: %v", f.Objects, err)
		}
		for _, b := range bl {
			for _, p := range b.Points {
				out[[2]uint32{uint32(p.Group), p.Index}] = p
			}
		}
	}
	return out
}

// Covers: SIG-IPE-1605
func TestOutstationPollsAndEvents(t *testing.T) {
	o := startOutstation(t, nil)
	m := o.master(t, nil, nil)
	ctx := context.Background()
	// Integrity poll: class 0 static data with ONLINE flags; IIN1.7 set.
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0))
	if err != nil {
		t.Fatal(err)
	}
	pts := pointsOf(t, frags)
	if pts[[2]uint32{1, 0}].Value != true || pts[[2]uint32{1, 1}].Value != false || pts[[2]uint32{30, 0}].Value != 230.5 || pts[[2]uint32{20, 0}].Value != 42.0 {
		t.Fatalf("class 0: %+v", pts)
	}
	if m.IIN()&dnp3.IINDeviceRestart == 0 {
		t.Error("IIN1.7 not set after start")
	}
	// Clear restart (write g80v1 index 7).
	objs, _ := dnp3.EncodeBlock(80, 1, dnp3.Q8StartStop, []dnp3.Point{{Index: 7, Value: false}})
	if _, err := m.Request(ctx, dnp3.FCWrite, objs); err != nil || m.IIN()&dnp3.IINDeviceRestart != 0 {
		t.Fatalf("clear restart: %v %v", err, m.IIN())
	}
	// Events: a binary change (class 1) and an analog change within the
	// deadband (none) then beyond it (class 2).
	_, _ = o.db.Update(ctx, "binary", 1, 1, nil, 0x01, time.Now())
	_, _ = o.db.Update(ctx, "analog", 0, 231.0, nil, 0x01, time.Now())
	_, _ = o.db.Update(ctx, "analog", 0, 232.0, nil, 0x01, time.Now())
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
	if err != nil || m.IIN()&dnp3.IINClass2Events == 0 || m.IIN()&dnp3.IINClass1Events != 0 {
		t.Fatalf("class 1 poll: %v, IIN %v", err, m.IIN())
	}
	pts = pointsOf(t, frags)
	if pts[[2]uint32{2, 1}].Value != true || pts[[2]uint32{2, 1}].Time.IsZero() {
		t.Fatalf("binary event %+v", pts)
	}
	frags, _ = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(2))
	if p := pointsOf(t, frags)[[2]uint32{32, 0}]; p.Value != 232.0 {
		t.Fatalf("analog event %+v", p)
	}
	eventually(t, 2*time.Second, "the confirmed events dropped", func() bool { return o.assoc.Status()["events"] == 0 })
	// Read a range: missing index 5 gives IIN2.2; a type with qualifier 06.
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 30, 0, dnp3.Q8StartStop, 0, 5)); err == nil {
		t.Error("a range with undefined points was not rejected")
	}
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 30, 1, dnp3.QAll, 0, 0))
	if err != nil || pointsOf(t, frags)[[2]uint32{30, 0}].Value != 232.0 {
		t.Fatalf("g30v1 all: %v", err)
	}
	// An unknown object: IIN2.1; an unsupported function: IIN2.0.
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 70, 7, dnp3.QAll, 0, 0)); err == nil {
		t.Error("an unknown object was accepted")
	}
	if _, err := m.Request(ctx, dnp3.FCSaveConfig, nil); err == nil {
		t.Error("SAVE_CONFIG was accepted")
	}
	// Device attributes: the list (g0v255, as EX 5-11 with 0x17 and a
	// type 254 list) and a single one (as EX 5-10).
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 0, 255, dnp3.Q8StartStop, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x00, 0xFF, 0x17, 0x01, 0x00, 0xFE, 0x08, 0xFC, 0x00, 0xFA, 0x00, 0xF1, 0x00, 0xF0, 0x01}; !bytes.Equal(frags[0].Objects, want) {
		t.Fatalf("g0v255 % X", frags[0].Objects)
	}
	frags, _ = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 0, 241, dnp3.Q8StartStop, 0, 0))
	if pointsOf(t, frags)[[2]uint32{0, 0}].Value != 2048.0 {
		t.Fatalf("g0v241 % X", frags[0].Objects)
	}
	// Identical retry: the same response, not executed twice.
	_, _ = o.db.Update(ctx, "binary", 0, 0, nil, 0x01, time.Now())
	n := o.assoc.Status()["events"]
	if n != 1 {
		t.Fatalf("events %v", n)
	}
}

// Covers: SIG-IPE-1606
func TestOutstationUnsolicited(t *testing.T) {
	o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.Unsolicited, c.UnsolRetries = true, 2 })
	var mu sync.Mutex
	var got []dnp3.Fragment
	m := o.master(t, nil, func(f dnp3.Fragment) { mu.Lock(); got = append(got, f); mu.Unlock() })
	ctx := context.Background()
	// The start-up null unsolicited response with IIN1.7, confirmed.
	eventually(t, 3*time.Second, "the null unsolicited response", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 1 && len(got[0].Objects) == 0 && got[0].IIN&dnp3.IINDeviceRestart != 0
	})
	// Events are not sent before ENABLE_UNSOLICITED (5.1.1.1.1 rule 3).
	_, _ = o.db.Update(ctx, "binary", 1, 1, nil, 0x01, time.Now())
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	if len(got) != 1 {
		t.Fatalf("%d unsolicited responses before enabling", len(got))
	}
	mu.Unlock()
	if _, err := m.Request(ctx, dnp3.FCEnableUnsolicited, dnp3.ClassRequest(1, 2, 3)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "the event unsolicited", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 2 && len(got[1].Objects) > 0 && got[1].Control&dnp3.AppUNS != 0 && got[1].Control&dnp3.AppCON != 0
	})
	eventually(t, 2*time.Second, "the confirmed events dropped", func() bool { return o.assoc.Status()["events"] == 0 })
	// Disabled again: events wait for a poll.
	if _, err := m.Request(ctx, dnp3.FCDisableUnsolicited, dnp3.ClassRequest(1, 2, 3)); err != nil {
		t.Fatal(err)
	}
	_, _ = o.db.Update(ctx, "binary", 1, 0, nil, 0x01, time.Now())
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 2 || o.assoc.Status()["events"] != 1 {
		t.Fatalf("unsolicited after disable: %d, events %v", n, o.assoc.Status())
	}
}

// unconfirmingLink drops every master confirm: a raw client.
func rawClient(t *testing.T, url string) (net.Conn, *dnp3.LinkParser) {
	t.Helper()
	c, err := net.Dial("tcp", url[len("tcp://"):])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, &dnp3.LinkParser{}
}

func sendFrag(t *testing.T, c net.Conn, dest uint16, f dnp3.Fragment) {
	t.Helper()
	var seq uint8
	for _, s := range dnp3.Segment(f.Encode(), &seq) {
		b, _ := dnp3.Frame{Ctrl: dnp3.CtrlDIR | dnp3.CtrlPRM | dnp3.LinkUnconfirmedUserData, Dest: dest, Src: 1, Data: s}.Encode()
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
	}
}

func readFrags(t *testing.T, c net.Conn, lp *dnp3.LinkParser, within time.Duration) []dnp3.Fragment {
	t.Helper()
	var out []dnp3.Fragment
	var ra dnp3.Reassembler
	buf := make([]byte, 4096)
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		for _, f := range lp.Feed(buf[:n]) {
			if !f.Primary() || f.Func() != dnp3.LinkUnconfirmedUserData {
				continue
			}
			if apdu, _ := ra.Add(f.Data); apdu != nil {
				fr, _ := dnp3.ParseFragment(apdu)
				out = append(out, fr)
			}
		}
	}
	return out
}

// A READ changes nothing, so one repeated with the same sequence is
// answered with the current values rather than the previous response; and
// a request on a new connection is never the repeat of one on the old.
func TestOutstationRepeatedReadAndNewConnection(t *testing.T) {
	o := startOutstation(t, nil)
	ctx := context.Background()
	read := dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | 0x03, Func: dnp3.FCRead, Objects: dnp3.AppendHeader(nil, 20, 1, dnp3.Q8StartStop, 0, 0)}
	counter := func(c net.Conn, lp *dnp3.LinkParser) any {
		t.Helper()
		sendFrag(t, c, 10, read)
		return pointsOf(t, readFrags(t, c, lp, 300*time.Millisecond))[[2]uint32{20, 0}].Value
	}
	c, lp := rawClient(t, o.url)
	if v := counter(c, lp); v != 42.0 {
		t.Fatalf("counter %v", v)
	}
	_, _ = o.db.Update(ctx, "counter", 0, 43, nil, 0x01, time.Now())
	if v := counter(c, lp); v != 43.0 {
		t.Fatalf("repeated READ answered %v, not the current 43", v)
	}
	_ = c.Close()
	_, _ = o.db.Update(ctx, "counter", 0, 44, nil, 0x01, time.Now())
	c, lp = rawClient(t, o.url)
	if v := counter(c, lp); v != 44.0 {
		t.Fatalf("READ on a new connection answered %v, not the current 44", v)
	}
	// A repeated control is not executed twice on one connection, but the
	// same octets on the next connection are a new request.
	operate := dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | 0x04, Func: dnp3.FCDirectOperate, Objects: crobObjs(t, 0)}
	controls := func() int { o.h.mu.Lock(); defer o.h.mu.Unlock(); return len(o.h.controls) }
	for range 2 {
		sendFrag(t, c, 10, operate)
		if frs := readFrags(t, c, lp, 300*time.Millisecond); len(frs) != 1 {
			t.Fatalf("%d responses to DIRECT_OPERATE", len(frs))
		}
	}
	if n := controls(); n != 1 {
		t.Fatalf("a repeated control executed %d times", n)
	}
	_ = c.Close()
	c, lp = rawClient(t, o.url)
	sendFrag(t, c, 10, operate)
	if frs := readFrags(t, c, lp, 300*time.Millisecond); len(frs) != 1 || controls() != 2 {
		t.Fatalf("control on a new connection: %d responses, %d executed", len(frs), controls())
	}
}

// Covers: SIG-IPE-1606
func TestOutstationUnsolicitedRetriesAndBroadcast(t *testing.T) {
	o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.Unsolicited, c.UnsolRetries = true, 1 })
	c, lp := rawClient(t, o.url)
	// Say nothing but a link status: the null response is retried
	// indefinitely with the same sequence (5.1.1.1.1 rule 2).
	b, _ := dnp3.Frame{Ctrl: dnp3.CtrlDIR | dnp3.CtrlPRM | dnp3.LinkRequestLinkStatus, Dest: 10, Src: 1}.Encode()
	_, _ = c.Write(b)
	frs := readFrags(t, c, lp, 1100*time.Millisecond)
	if len(frs) < 3 {
		t.Fatalf("%d null unsolicited responses", len(frs))
	}
	for _, f := range frs {
		if f.Func != dnp3.FCUnsolicited || f.Seq() != frs[0].Seq() || len(f.Objects) != 0 {
			t.Fatalf("retry %+v", f)
		}
	}
	sendFrag(t, c, 10, dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | dnp3.AppUNS | frs[0].Seq(), Func: dnp3.FCConfirm})
	// A broadcast (0xFFFD) write of IIN1.7 clear: no response; the next
	// response carries IIN1.0, then it is cleared (Table 4-13).
	objs, _ := dnp3.EncodeBlock(80, 1, dnp3.Q8StartStop, []dnp3.Point{{Index: 7, Value: false}})
	sendFrag(t, c, dnp3.AddrBroadcastNoConfirm, dnp3.Fragment{Control: 0xC5, Func: dnp3.FCWrite, Objects: objs})
	if frs := readFrags(t, c, lp, 300*time.Millisecond); len(frs) != 0 {
		t.Fatalf("a broadcast was answered: %+v", frs)
	}
	sendFrag(t, c, 10, dnp3.Fragment{Control: 0xC6, Func: dnp3.FCRead, Objects: dnp3.ClassRequest(0)})
	frs = readFrags(t, c, lp, 300*time.Millisecond)
	if len(frs) != 1 || frs[0].IIN&dnp3.IINBroadcast == 0 || frs[0].IIN&dnp3.IINDeviceRestart != 0 {
		t.Fatalf("after broadcast %+v", frs)
	}
	sendFrag(t, c, 10, dnp3.Fragment{Control: 0xC7, Func: dnp3.FCRead, Objects: dnp3.ClassRequest(0)})
	if frs = readFrags(t, c, lp, 300*time.Millisecond); len(frs) != 1 || frs[0].IIN&dnp3.IINBroadcast != 0 {
		t.Fatalf("IIN1.0 not cleared %+v", frs)
	}
}

// Covers: SIG-IPE-1607
func TestOutstationControls(t *testing.T) {
	o := startOutstation(t, nil)
	m := o.master(t, nil, nil)
	ctx := context.Background()
	objs := crobObjs(t, 0)
	check := func(fc byte, frags []dnp3.Fragment) error { return nil }
	if err := m.SelectOperate(ctx, objs, time.Second, check); err != nil {
		t.Fatal(err)
	}
	o.h.mu.Lock()
	if len(o.h.controls) != 2 || !o.h.controls[0].Select || o.h.controls[1].Select || o.h.controls[1].CROB.Code != dnp3.OpLatchOn {
		t.Fatalf("controls %+v", o.h.controls)
	}
	o.h.mu.Unlock()
	status := func(frags []dnp3.Fragment) uint8 {
		for _, p := range pointsOf(t, frags) {
			return p.Status
		}
		return 255
	}
	// Operate without select: NO_SELECT (2); after the select timeout: 1.
	frags, _ := m.Request(ctx, dnp3.FCOperate, objs)
	if status(frags) != 2 {
		t.Errorf("operate without select: %d", status(frags))
	}
	_, _ = m.Request(ctx, dnp3.FCSelect, objs)
	time.Sleep(400 * time.Millisecond)
	if frags, _ = m.Request(ctx, dnp3.FCOperate, objs); status(frags) != 1 {
		t.Errorf("operate after timeout: %d", status(frags))
	}
	// Direct operate of an analog output block; the handler refuses: echo
	// with its status.
	o.h.status = 7
	ao, _ := dnp3.EncodeBlock(41, 3, dnp3.Q16Index16, []dnp3.Point{{Index: 0, Value: 12.5}})
	frags, err := m.Request(ctx, dnp3.FCDirectOperate, ao)
	if err != nil || status(frags) != 7 || pointsOf(t, frags)[[2]uint32{41, 0}].Value != 12.5 {
		t.Fatalf("AO: %v %+v", err, pointsOf(t, frags))
	}
	// A pattern control block without a pattern mask is malformed.
	pcb, _ := dnp3.EncodeBlock(12, 2, dnp3.Q8Count, []dnp3.Point{{CROB: dnp3.CROB{Code: 1, Count: 1}}})
	if _, err := m.Request(ctx, dnp3.FCSelect, pcb); err == nil {
		t.Error("PCB accepted")
	}
}

// Covers: SIG-IPE-1608
func TestOutstationTimeFreezeAssign(t *testing.T) {
	o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.NeedTime = time.Hour })
	m := o.master(t, nil, nil)
	ctx := context.Background()
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0)); err != nil || m.IIN()&dnp3.IINNeedTime == 0 {
		t.Fatalf("need time: %v %v", err, m.IIN())
	}
	// LAN procedure: record current time then g50v3.
	sent := time.Now()
	if _, err := m.Request(ctx, dnp3.FCRecordCurrentTime, nil); err != nil {
		t.Fatal(err)
	}
	objs, _ := dnp3.EncodeBlock(50, 3, dnp3.Q8Count, []dnp3.Point{{Value: sent}})
	if _, err := m.Request(ctx, dnp3.FCWrite, objs); err != nil || m.IIN()&dnp3.IINNeedTime != 0 {
		t.Fatalf("time write: %v %v", err, m.IIN())
	}
	o.h.mu.Lock()
	if d := o.h.timeSet.Sub(time.Now()); d > time.Second || d < -time.Second {
		t.Errorf("time set %v", o.h.timeSet)
	}
	o.h.mu.Unlock()
	// Delay measurement: g52v2.
	frags, err := m.Request(ctx, dnp3.FCDelayMeasure, nil)
	if err != nil || pointsOf(t, frags)[[2]uint32{52, 0}].Var != 2 {
		t.Fatalf("delay: %v", err)
	}
	// Freeze and clear: the frozen counter takes 42, the counter 0.
	if _, err := m.Request(ctx, dnp3.FCFreezeClear, dnp3.AppendHeader(nil, 20, 0, dnp3.QAll, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if p, _ := o.db.Point("frozen-counter", 0); p.Value != 42 {
		t.Errorf("frozen %v", p.Value)
	}
	if p, _ := o.db.Point("counter", 0); p.Value != 0 {
		t.Errorf("cleared %v", p.Value)
	}
	// Freeze at time: once in 200 ms.
	_, _ = o.db.Update(ctx, "counter", 0, 7, nil, 1, time.Now())
	at, _ := dnp3.EncodeBlock(50, 2, dnp3.Q8Count, []dnp3.Point{{Value: time.Now().Add(200 * time.Millisecond)}})
	if _, err := m.Request(ctx, dnp3.FCFreezeAtTime, append(at, dnp3.AppendHeader(nil, 20, 0, dnp3.QAll, 0, 0)...)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, "the scheduled freeze", func() bool { p, _ := o.db.Point("frozen-counter", 0); return p.Value == 7 })
	// Assign class: analog events to class 3, binaries off.
	req := dnp3.AssignClass([]dnp3.ClassAssignment{{Class: 3, Headers: [][]byte{dnp3.AppendHeader(nil, 30, 0, dnp3.QAll, 0, 0)}},
		{Class: 0, Headers: [][]byte{dnp3.AppendHeader(nil, 1, 0, dnp3.Q8StartStop, 0, 1)}}})
	if _, err := m.Request(ctx, dnp3.FCAssignClass, req); err != nil {
		t.Fatal(err)
	}
	if p, _ := o.db.Point("analog", 0); p.Class != 3 {
		t.Errorf("class %d", p.Class)
	}
	if _, err := m.Request(ctx, dnp3.FCAssignClass, dnp3.AssignClass([]dnp3.ClassAssignment{{Class: 0, Headers: [][]byte{dnp3.AppendHeader(nil, 122, 0, dnp3.QAll, 0, 0)}}})); err == nil {
		t.Error("security statistic events assigned to no class")
	}
	// Deadband write (g34v3): a change of 2 no longer makes an event.
	db, _ := dnp3.EncodeBlock(34, 3, dnp3.Q8Index8, []dnp3.Point{{Index: 0, Value: 5.0}})
	if _, err := m.Request(ctx, dnp3.FCWrite, db); err != nil {
		t.Fatal(err)
	}
	if ev, _ := o.db.Update(ctx, "analog", 0, 232.5, nil, 1, time.Now()); ev {
		t.Error("an event within the written deadband")
	}
	// Cold restart: g52v1 with the delay, IIN1.7 set again.
	o.h.restart = 2 * time.Second
	frags, err = m.Request(ctx, dnp3.FCColdRestart, nil)
	if p := pointsOf(t, frags)[[2]uint32{52, 0}]; err != nil || p.Var != 1 || p.Value != 2.0 {
		t.Fatalf("restart %+v %v", p, err)
	}
}

// Covers: SIG-IPE-1609, SIG-IPE-1594
func TestOutstationDataSetsAndActivation(t *testing.T) {
	o := startOutstation(t, nil)
	desc := dnp3.Descriptor{ID: 0, Name: "Fdr 11-A Fault", Elements: []dnp3.DescElement{
		{Code: dnp3.DescDAEL, Type: dnp3.DSFLT, MaxLen: 8, Ancillary: []byte("Current Phs A")},
		{Code: dnp3.DescDAEL, Type: dnp3.DSFLT, MaxLen: 8, Ancillary: []byte("Current Phs B")},
		{Code: dnp3.DescDAEL, Type: dnp3.DSFLT, MaxLen: 8, Ancillary: []byte("Current Phs C")},
		{Code: dnp3.DescDAEL, Type: dnp3.DSFLT, MaxLen: 8, Ancillary: []byte("Current Gnd")},
		{Code: dnp3.DescDAEL, Type: dnp3.DSBSTR, MaxLen: 2, Ancillary: []byte("Triggers")},
		{Code: dnp3.DescDAEL, Type: dnp3.DSVSTR, MaxLen: 8, Ancillary: []byte("Fault Class")},
		{Code: dnp3.DescDAEL, Type: dnp3.DSUINT, MaxLen: 4, Ancillary: []byte("Dist")},
	}}
	if err := o.db.DefineDataSet(dnp3.DataSetDef{Desc: desc, Chars: dnp3.DSReadable | dnp3.DSEvent, Class: 1}); err != nil {
		t.Fatal(err)
	}
	ctl := dnp3.Descriptor{ID: 1, Name: "Camera", Elements: []dnp3.DescElement{
		{Code: dnp3.DescCTLS, Type: dnp3.DSUINT, MaxLen: 1, Ancillary: []byte("zoom st")},
		{Code: dnp3.DescCTLV, Type: dnp3.DSUINT, MaxLen: 2, Ancillary: []byte("zoom")},
		{Code: dnp3.DescCTLS, Type: dnp3.DSUINT, MaxLen: 1, Ancillary: []byte("pan st")},
		{Code: dnp3.DescCTLV, Type: dnp3.DSINT, MaxLen: 2, Ancillary: []byte("pan")},
	}}
	if err := o.db.DefineDataSet(dnp3.DataSetDef{Desc: ctl, Chars: dnp3.DSReadable | dnp3.DSWritable | dnp3.DSStatic}); err != nil {
		t.Fatal(err)
	}
	m := o.master(t, nil, nil)
	ctx := context.Background()
	// EX 5-8: reading every descriptor returns Table 5-12 (size 0x7D).
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 86, 1, dnp3.Q8StartStop, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	want := hx(t, "56 01 5B 01 7D 00 05 01 00 00 00 00 11 04 00 00 46 64 72 20 31 31 2D 41 20 46 61 75 6C 74 10 05 04 08 43 75 72 72 65 6E 74 20 50 68 73 20 41 10 05 04 08 43 75 72 72 65 6E 74 20 50 68 73 20 42 10 05 04 08 43 75 72 72 65 6E 74 20 50 68 73 20 43 0E 05 04 08 43 75 72 72 65 6E 74 20 47 6E 64 0B 05 06 02 54 72 69 67 67 65 72 73 0E 05 01 08 46 61 75 6C 74 20 43 6C 61 73 73 07 05 02 04 44 69 73 74")
	if !bytes.Equal(frags[0].Objects, want) {
		t.Fatalf("descriptor\n% X\n% X", frags[0].Objects, want)
	}
	// EX 5-9 / Table 5-15: a fault event data set in a class 1 poll.
	f32 := func(v float32) []byte { return binary.LittleEndian.AppendUint32(nil, math.Float32bits(v)) }
	at := dnp3.Time48(hx(t, "F5 7C 38 01 F7 00"))
	vals := [][]byte{f32(1328.98), f32(420.17), f32(1048.43), f32(342.95), {0x0B}, []byte("ACG"), {141}}
	if err := o.db.SetDataSet(ctx, 0, vals, at, true); err != nil {
		t.Fatal(err)
	}
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3))
	if err != nil {
		t.Fatal(err)
	}
	ev := append(hx(t, "58 01 5B 01 26 00 02 00 00 06 F5 7C 38 01 F7 00"), 4)
	ev = append(ev, f32(1328.98)...)
	ev = append(append(ev, 4), f32(420.17)...)
	ev = append(append(ev, 4), f32(1048.43)...)
	ev = append(append(ev, 4), f32(342.95)...)
	ev = append(ev, hx(t, "01 0B 03 41 43 47 01 8D")...)
	if !bytes.Equal(frags[0].Objects, ev) {
		t.Fatalf("event\n% X\n% X", frags[0].Objects, ev)
	}
	ds, _ := dnp3.ParseDataSet(frags[0].Objects[6:])
	flat, _ := desc.Flatten(nil)
	if v, _ := dnp3.DataSetValue(flat[6].Type, ds.Values[6]); v != 141.0 {
		t.Fatalf("distance %v", v)
	}
	// Characteristics (g86v2) of data set 0: readable and events.
	frags, _ = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 86, 2, dnp3.Q8StartStop, 0, 0))
	if !bytes.Equal(frags[0].Objects, hx(t, "56 02 01 00 00 00 00 09")) {
		t.Fatalf("g86v2 % X", frags[0].Objects)
	}
	// Data set control: pan participates, zoom does not (126).
	ctlDS := dnp3.DataSet{ID: 1, Time: time.Now(), Values: [][]byte{{126}, {5, 0}, {0}, {0xF6, 0xFF}}}
	cobj, _ := dnp3.EncodeBlock(87, 1, dnp3.QFreeFormat, []dnp3.Point{{Raw: ctlDS.Encode()}})
	frags, err = m.Request(ctx, dnp3.FCDirectOperate, cobj)
	if err != nil {
		t.Fatal(err)
	}
	o.h.mu.Lock()
	if len(o.h.dsCtl) != 1 || o.h.dsCtl[0].Names[0] != "pan" || o.h.dsCtl[0].Values[0] != -10.0 {
		t.Fatalf("data set control %+v", o.h.dsCtl)
	}
	o.h.mu.Unlock()
	// Master-defined descriptor and data set write (5.4.2.6.2).
	md := dnp3.Descriptor{ID: 2, Elements: []dnp3.DescElement{{Code: dnp3.DescDAEL, Type: dnp3.DSINT, MaxLen: 4, Ancillary: []byte("Kp")}}}
	wobj, _ := dnp3.EncodeBlock(86, 1, dnp3.QFreeFormat, []dnp3.Point{{Raw: md.EncodeDescriptor()}})
	if _, err := m.Request(ctx, dnp3.FCWrite, wobj); err != nil {
		t.Fatal(err)
	}
	wds, _ := dnp3.EncodeBlock(87, 1, dnp3.QFreeFormat, []dnp3.Point{{Raw: dnp3.DataSet{ID: 2, Time: time.Now(), Values: [][]byte{{3}}}.Encode()}})
	if _, err := m.Request(ctx, dnp3.FCWrite, wds); err != nil {
		t.Fatal(err)
	}
	bad, _ := dnp3.EncodeBlock(87, 1, dnp3.QFreeFormat, []dnp3.Point{{Raw: dnp3.DataSet{ID: 2, Time: time.Now(), Values: [][]byte{{3}, {4}}}.Encode()}})
	if _, err := m.Request(ctx, dnp3.FCWrite, bad); err == nil {
		t.Error("a data set not matching its descriptor was accepted")
	}
	// Activate configuration (4.4.20): g70v8 names answered with g91v1.
	spec, _ := dnp3.EncodeBlock(70, 8, dnp3.QFreeFormat, []dnp3.Point{{Raw: []byte("AnalogDeadbands.tmp")}, {Raw: []byte("missing.cfg")}})
	frags, err = m.Request(ctx, dnp3.FCActivateConfig, spec)
	if err != nil {
		t.Fatal(err)
	}
	bl, _ := dnp3.ParseObjects(frags[0].Objects, true)
	st, err := dnp3.ParseActivateStatus(bl[0].Points[0].Raw)
	if err != nil || st.Delay != 1500*time.Millisecond || len(st.Elements) != 2 || st.Elements[1].Code != 1 || st.Elements[1].Text != "File not found" {
		t.Fatalf("g91 %+v %v", st, err)
	}
	// Application control (4.4.11, EX 4-23): initialise, start, stop "CL6".
	app, _ := dnp3.EncodeBlock(90, 1, dnp3.QFreeFormat, []dnp3.Point{{Raw: []byte("CL6")}})
	if !bytes.Equal(app, hx(t, "5A 01 5B 01 03 00 43 4C 36")) {
		t.Fatalf("% X", app)
	}
	for _, fc := range []byte{dnp3.FCInitializeAppl, dnp3.FCStartAppl, dnp3.FCStopAppl} {
		if _, err := m.Request(ctx, fc, app); err != nil {
			t.Fatal(err)
		}
	}
	if len(o.h.apps) != 3 {
		t.Fatalf("applications %v", o.h.apps)
	}
}
