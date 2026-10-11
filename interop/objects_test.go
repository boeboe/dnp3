// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// opendnp3Outstation starts opendnp3's outstation on TCP and connects
// this module's master to it.
func opendnp3Outstation(t *testing.T, opts ...string) (*peer, *dnp3.Master) {
	t.Helper()
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, append([]string{"-p", fmt.Sprintf("127.0.0.1:%d:20000", port), image, "dnp3-outstation", "tcp", "20000"}, opts...)...)
	p.expect(60*time.Second, "READY")
	m := dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", port), MasterAddress: 1, OutstationAddress: 10,
		Timeout: 3 * time.Second})
	ctx := context.Background()
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0)); err != nil {
		t.Fatal(err)
	}
	return p, m
}

func read(t *testing.T, m *dnp3.Master, objs ...byte) map[[2]uint32]dnp3.Point {
	t.Helper()
	frags, err := m.Request(context.Background(), dnp3.FCRead, objs)
	if err != nil {
		t.Fatalf("read % X: %v", objs, err)
	}
	return points(t, frags)
}

func recent(t *testing.T, what string, at time.Time) {
	t.Helper()
	if d := time.Since(at); d < -5*time.Second || d > 5*time.Second {
		t.Errorf("%s time %s is not now", what, at.UTC())
	}
}

// TestMasterObjects: this module's master reads every object type
// opendnp3's outstation serves, with and without time (a common time of
// occurrence included), and uses its freeze, restart, assign class,
// time-and-interval and output functions.
func TestMasterObjects(t *testing.T) {
	p, m := opendnp3Outstation(t)
	ctx := context.Background()

	t.Run("output status events", func(t *testing.T) {
		p.send("bo 1 1")
		p.expect(5*time.Second, "APPLIED bo 1")
		pts := read(t, m, 60, 2, 0x06)
		v, ok := pts[[2]uint32{11, 1}]
		if !ok || v.Var != 2 || v.Value != true {
			t.Fatalf("binary output event: %+v (%v)", v, ok)
		}
		recent(t, "g11v2", v.Time)
		p.send("ao 1 3.5")
		p.expect(5*time.Second, "APPLIED ao 1")
		p.send("ao 3 4.5")
		p.expect(5*time.Second, "APPLIED ao 3")
		pts = read(t, m, 60, 3, 0x06)
		if v := pts[[2]uint32{42, 1}]; v.Var != 5 || v.Value != 3.5 {
			t.Errorf("analog output event 1: %+v", v)
		}
		v = pts[[2]uint32{42, 3}]
		if v.Var != 7 || v.Value != 4.5 {
			t.Errorf("analog output event 3: %+v", v)
		}
		recent(t, "g42v7", v.Time)
	})

	t.Run("double-bit and common time of occurrence", func(t *testing.T) {
		p.send("dbl 1 1")
		p.expect(5*time.Second, "APPLIED dbl 1")
		p.send("dbl 3 2")
		p.expect(5*time.Second, "APPLIED dbl 3")
		p.send("bin 3 1")
		p.expect(5*time.Second, "APPLIED bin 3")
		frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
		if err != nil {
			t.Fatal(err)
		}
		gs := strings.Join(groups(t, frags), " ")
		pts := points(t, frags)
		if v := pts[[2]uint32{4, 1}]; v.Var != 2 || v.Value != 1.0 {
			t.Errorf("double-bit event 1: %+v", v)
		}
		if v := pts[[2]uint32{4, 3}]; v.Var != 3 || v.Value != 2.0 {
			t.Errorf("double-bit event 3 (relative time): %+v", v)
		} else {
			recent(t, "g4v3", v.Time)
		}
		if v := pts[[2]uint32{2, 3}]; v.Var != 3 || v.Value != true {
			t.Errorf("binary event 3 (relative time): %+v", v)
		} else {
			recent(t, "g2v3", v.Time)
		}
		if !strings.Contains(gs, "g51v1") && !strings.Contains(gs, "g51v2") {
			t.Errorf("no common time of occurrence in %s", gs)
		}
		t.Logf("class 1: %s", gs)
	})

	t.Run("counter event with time", func(t *testing.T) {
		p.send("cnt 3 9")
		p.expect(5*time.Second, "APPLIED cnt 3")
		v := read(t, m, 60, 4, 0x06)[[2]uint32{22, 3}]
		if v.Var != 5 || v.Value != 9.0 {
			t.Fatalf("counter event: %+v", v)
		}
		recent(t, "g22v5", v.Time)
	})

	t.Run("freeze", func(t *testing.T) {
		if _, err := m.Request(ctx, dnp3.FCImmedFreeze, []byte{20, 0, dnp3.QAll}); err != nil {
			t.Fatal(err)
		}
		v := read(t, m, 21, 0, dnp3.QAll)[[2]uint32{21, 0}]
		if v.Var != 5 || v.Value != 42.0 {
			t.Fatalf("frozen counter 0 after freeze: %+v", v)
		}
		recent(t, "g21v5", v.Time)
		if v := read(t, m, 60, 4, 0x06)[[2]uint32{23, 0}]; v.Var != 5 || v.Value != 42.0 {
			t.Errorf("frozen counter event: %+v", v)
		}
		if _, err := m.Request(ctx, dnp3.FCFreezeClear, []byte{20, 0, dnp3.QAll}); err != nil {
			t.Fatal(err)
		}
		if v := read(t, m, 20, 0, dnp3.QAll)[[2]uint32{20, 0}]; v.Value != 0.0 {
			t.Errorf("counter 0 after freeze and clear: %+v", v)
		}
		p.send("cnt 0 5")
		p.expect(5*time.Second, "APPLIED cnt 0")
		if frags, err := m.Request(ctx, dnp3.FCImmedFreezeNR, []byte{20, 0, dnp3.QAll}); err != nil || len(frags) != 0 {
			t.Fatalf("freeze without response: %v %v", frags, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if v := read(t, m, 21, 0, dnp3.QAll)[[2]uint32{21, 0}]; v.Value == 5.0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("IMMED_FREEZE_NR was not carried out")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	t.Run("octet strings", func(t *testing.T) {
		if v := read(t, m, 110, 0, dnp3.QAll)[[2]uint32{110, 0}]; string(v.Raw) != "hello" || v.Var != 5 {
			t.Errorf("octet string 0: %+v", v)
		}
		p.send("oct 1 6869")
		p.expect(5*time.Second, "APPLIED oct 1")
		if v := read(t, m, 60, 4, 0x06)[[2]uint32{111, 1}]; string(v.Raw) != "hi" || v.Var != 2 {
			t.Errorf("octet string event: %+v", v)
		}
	})

	t.Run("time and interval", func(t *testing.T) {
		v := read(t, m, 50, 4, dnp3.QAll)[[2]uint32{50, 0}]
		if ts, _ := v.Value.(time.Time); ts.UnixMilli() != 1_700_000_000_000 || v.Interval != 15 || v.Units != dnp3.UnitsMinutes {
			t.Errorf("g50v4 0: %+v", v)
		}
		at := time.UnixMilli(1_800_000_000_000)
		w, _ := dnp3.EncodeBlock(50, 4, dnp3.Q16Index16, []dnp3.Point{{Index: 2, Value: at, Interval: 30, Units: dnp3.UnitsSeconds}})
		if _, err := m.Request(ctx, dnp3.FCWrite, w); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "WRITE ti 2 1800000000000 30 2")
	})

	t.Run("restarts", func(t *testing.T) {
		frags, err := m.Request(ctx, dnp3.FCColdRestart, nil)
		if err != nil {
			t.Fatal(err)
		}
		if v := points(t, frags)[[2]uint32{52, 0}]; v.Var != 2 || v.Value != 1500.0 {
			t.Errorf("cold restart delay: %+v %v", v, groups(t, frags))
		}
		p.expect(5*time.Second, "RESTART cold")
		frags, err = m.Request(ctx, dnp3.FCWarmRestart, nil)
		if err != nil {
			t.Fatal(err)
		}
		if v := points(t, frags)[[2]uint32{52, 0}]; v.Var != 1 || v.Value != 3.0 {
			t.Errorf("warm restart delay: %+v %v", v, groups(t, frags))
		}
		p.expect(5*time.Second, "RESTART warm")
	})

	t.Run("assign class", func(t *testing.T) {
		if _, err := m.Request(ctx, dnp3.FCAssignClass, []byte{60, 2, dnp3.QAll, 30, 0, dnp3.Q8StartStop, 0, 1}); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "ASSIGN")
		p.send("ana 0 99")
		p.expect(5*time.Second, "APPLIED ana 0")
		if v, ok := read(t, m, 60, 2, 0x06)[[2]uint32{32, 0}]; !ok || v.Value != 99.0 {
			t.Errorf("analog 0 not reported in class 1 after the assignment: %+v", v)
		}
	})

	t.Run("controls", func(t *testing.T) {
		p.drain()
		pulse, _ := dnp3.EncodeBlock(12, 1, dnp3.Q16Index16, []dnp3.Point{{Index: 5, CROB: dnp3.CROB{Code: dnp3.OpPulseOn, Count: 3, OnTime: 250, OffTime: 500}}})
		if _, err := m.Request(ctx, dnp3.FCDirectOperate, pulse); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "OPERATE crob 5 1 DirectOperate count=3 on=250 off=500")
		for _, c := range []struct {
			v    uint8
			val  float64
			want string
		}{{1, -70000, "OPERATE ao 0 -70000 DirectOperate g41v1"}, {2, 300, "OPERATE ao 0 300 DirectOperate g41v2"},
			{4, 1.25, "OPERATE ao 0 1.250000 DirectOperate g41v4"}} {
			objs, err := dnp3.EncodeBlock(41, c.v, dnp3.Q16Index16, []dnp3.Point{{Index: 0, Value: c.val}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Request(ctx, dnp3.FCDirectOperate, objs); err != nil {
				t.Fatal(err)
			}
			p.expect(5*time.Second, c.want)
		}
		// A CROB and an analog output block in one select-before-operate.
		ao, _ := dnp3.EncodeBlock(41, 3, dnp3.Q16Index16, []dnp3.Point{{Index: 1, Value: 12.5}})
		objs := append(crob(t, 0, dnp3.OpLatchOn), ao...)
		if err := m.SelectOperate(ctx, objs, 5*time.Second, nil); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "OPERATE crob 0 3 SelectBeforeOperate")
		p.expect(5*time.Second, "OPERATE ao 1 12.500000 SelectBeforeOperate")
	})
}

// TestMasterMultiFragment: opendnp3's outstation answers an integrity
// poll in fragments of at most 249 octets, each confirmed by this
// module's master.
func TestMasterMultiFragment(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20000", port), image, "dnp3-outstation", "tcp", "20000", "maxtx=249")
	p.expect(60*time.Second, "READY")
	m := dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", port), MasterAddress: 1, OutstationAddress: 10,
		Timeout: 3 * time.Second})
	frags, err := m.Request(context.Background(), dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) < 2 {
		t.Fatalf("%d fragment(s); the poll did not need several", len(frags))
	}
	pts := points(t, frags)
	for _, k := range [][2]uint32{{1, 9}, {3, 9}, {30, 9}, {20, 9}, {21, 9}, {10, 9}, {40, 9}, {50, 9}, {110, 9}} {
		if _, ok := pts[k]; !ok {
			t.Errorf("g%d index %d missing from %d fragments", k[0], k[1], len(frags))
		}
	}
	t.Logf("%d fragments", len(frags))
}

// TestMasterLinkLayer: link-layer services against opendnp3's
// outstation: confirmed user data (reset of link states, FCB alternation,
// acknowledgements), REQUEST_LINK_STATUS as keep-alive both ways.
func TestMasterLinkLayer(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20000", port), image, "dnp3-outstation", "tcp", "20000", "keepalive=700")
	p.expect(60*time.Second, "READY")
	time.Sleep(500 * time.Millisecond)
	px := startProxy(t, fmt.Sprintf("127.0.0.1:%d", port), nil)
	m := dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", px.port), MasterAddress: 1, OutstationAddress: 10,
		Timeout: 2 * time.Second, LinkConfirm: true, LinkRetries: 2, KeepAlive: 400 * time.Millisecond})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0)); err != nil {
			t.Fatalf("poll %d with confirmed user data: %v", i, err)
		}
	}
	// Idle: our keep-alive asks for the link status, opendnp3's asks ours.
	time.Sleep(2 * time.Second)
	select {
	case <-m.Done():
		t.Fatalf("connection ended: %v", m.Err())
	default:
	}
	p.expect(5*time.Second, "KEEPALIVE ok")
	var resets, confirmed, acks, statusReq, status, ourStatus int
	fcbs := map[bool]int{}
	for _, s := range px.seen() {
		fc := s.f.Func()
		if s.toTarget && s.f.Primary() {
			switch fc {
			case dnp3.LinkResetLinkStates:
				resets++
			case dnp3.LinkConfirmedUserData:
				confirmed++
				fcbs[s.f.Ctrl&0x20 != 0]++
			case dnp3.LinkRequestLinkStatus:
				statusReq++
			}
		}
		if !s.toTarget && !s.f.Primary() {
			switch fc {
			case dnp3.LinkAck:
				acks++
			case dnp3.LinkStatus:
				status++
			}
		}
		if s.toTarget && !s.f.Primary() && fc == dnp3.LinkStatus {
			ourStatus++
		}
	}
	t.Logf("resets %d, confirmed %d (FCB %v), acks %d, our status requests %d answered %d, our status answers %d",
		resets, confirmed, fcbs, acks, statusReq, status, ourStatus)
	if resets != 1 || confirmed < 3 || acks < confirmed+resets || fcbs[true] == 0 || fcbs[false] == 0 {
		t.Error("confirmed user data was not reset once, alternated and acknowledged")
	}
	if statusReq == 0 || status == 0 || ourStatus == 0 {
		t.Error("link status requests were not exchanged both ways")
	}
}

// TestMasterUnsolicitedLoss: opendnp3's outstation repeats an unsolicited
// response whose confirmation was lost, with the same sequence number;
// this module's master confirms the repeat and the events are cleared.
func TestMasterUnsolicitedLoss(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20000", port), image, "dnp3-outstation", "tcp", "20000", "unsolto=1000")
	p.expect(60*time.Second, "READY")
	time.Sleep(500 * time.Millisecond)
	withObjects, dropped := false, 0
	px := startProxy(t, fmt.Sprintf("127.0.0.1:%d", port), func(toTarget bool, f dnp3.Frame) bool {
		ctl, fc, ok := app(f)
		if !ok {
			return false
		}
		if !toTarget && fc == dnp3.FCUnsolicited && len(f.Data) > 5 {
			withObjects = true
		}
		if toTarget && fc == dnp3.FCConfirm && ctl&dnp3.AppUNS != 0 && withObjects && dropped == 0 {
			dropped++
			return true
		}
		return false
	})
	var mu sync.Mutex
	var unsol []dnp3.Fragment
	m := dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", px.port), MasterAddress: 1, OutstationAddress: 10,
		Timeout: 3 * time.Second, OnUnsolicited: func(f dnp3.Fragment) { mu.Lock(); unsol = append(unsol, f); mu.Unlock() }})
	ctx := context.Background()
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Request(ctx, dnp3.FCEnableUnsolicited, dnp3.ClassRequest(1, 2, 3)); err != nil {
		t.Fatal(err)
	}
	p.drain()
	p.send("bin 2 1")
	p.expect(5*time.Second, "APPLIED bin 2")
	p.expect(10*time.Second, "CONFIRM unsol=1 left=0,0,0")
	mu.Lock()
	var seqs []byte
	for _, f := range unsol {
		if _, ok := points(t, []dnp3.Fragment{f})[[2]uint32{2, 2}]; ok {
			seqs = append(seqs, f.Seq())
		}
	}
	mu.Unlock()
	if dropped != 1 || len(seqs) != 2 || seqs[0] != seqs[1] {
		t.Errorf("dropped %d confirmations; the event came in unsolicited responses with sequence numbers %v", dropped, seqs)
	}
	if pts := read(t, m, 60, 2, 0x06); len(pts) != 0 {
		t.Errorf("events left after the repeat was confirmed: %+v", pts)
	}
}

// TestOpendnp3MasterObjects: opendnp3's master reads every object type
// this module's outstation serves and uses its freeze, restart,
// time-and-interval and output functions.
func TestOpendnp3MasterObjects(t *testing.T) {
	needDocker(t)
	o := newOurOutstation(t, nil)
	port := o.serveTCP(t, nil)
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", image, "dnp3-master", "tcp", "host.docker.internal",
		strconv.Itoa(port), "mode=nonlan")
	p.expect(60*time.Second, "READY")
	p.expect(20*time.Second, "TASK ENABLE_UNSOLICITED SUCCESS")
	ctx := context.Background()
	at := time.Now()

	t.Run("events of every type", func(t *testing.T) {
		p.drain()
		for _, u := range []struct {
			typ   string
			index uint32
			v     float64
			want  []string
		}{
			{"binary-output", 1, 1, []string{"VAL bostatus 1 1", "gv=Group11Var2", "event=1"}},
			{"analog-output", 1, 3.5, []string{"VAL aostatus 1 3.5", "gv=Group42Var7", "event=1"}},
			{"double", 1, 2, []string{"VAL doublebit 1 2", "gv=Group4Var2", "event=1"}},
			{"counter", 2, 9, []string{"VAL counter 2 9", "gv=Group22Var5", "event=1"}},
		} {
			if _, err := o.db.Update(ctx, u.typ, u.index, u.v, nil, 0x01, at); err != nil {
				t.Fatal(err)
			}
			line := p.expect(10*time.Second, u.want...)
			ms, _ := strconv.ParseInt(line[strings.LastIndex(line, "time=")+5:], 10, 64)
			if ms != at.UnixMilli() {
				t.Errorf("%s: time %d, want %d", line, ms, at.UnixMilli())
			}
		}
		if _, err := o.db.Update(ctx, "octet-string", 1, 0, []byte("ok"), 0x01, at); err != nil {
			t.Fatal(err)
		}
		p.expect(10*time.Second, "VAL octets 1 6f6b", "gv=Group111Var0", "unsol=1") // opendnp3 marks g111 headers event=0
	})

	t.Run("static data", func(t *testing.T) {
		p.drain()
		p.send("integrity")
		lines := p.until(10*time.Second, "DONE integrity")
		if !has(lines, "DONE integrity SUCCESS") {
			t.Errorf("integrity poll: %v", lines)
		}
		for _, want := range [][]string{
			{"VAL doublebit 0", "gv=Group3Var2"}, {"VAL bostatus 0", "gv=Group10Var2"}, {"VAL aostatus 0", "gv=Group40Var3"},
			{"VAL frozencounter 0", "gv=Group21Var1"}, {"VAL octets 0 6869", "gv=Group110Var0"},
			{"VAL ti 0 1700000000000 15 3", "gv=Group50Var4"},
		} {
			if !has(lines, want...) {
				t.Errorf("integrity poll without %q", want)
			}
		}
	})

	t.Run("freeze", func(t *testing.T) {
		p.drain()
		p.send("freeze")
		p.expectAll(10*time.Second, []string{"DONE freeze SUCCESS"}, []string{"VAL frozencounter 0 42", "event=1"})
		p.send("freezeclear")
		p.expect(10*time.Second, "DONE freezeclear SUCCESS")
		if c, _ := o.db.Point("counter", 0); c.Value != 0 {
			t.Errorf("counter 0 after freeze and clear: %g", c.Value)
		}
		if _, err := o.db.Update(ctx, "counter", 1, 77, nil, 0x01, time.Now()); err != nil {
			t.Fatal(err)
		}
		p.send("freezenr")
		p.expect(10*time.Second, "VAL frozencounter 1 77", "event=1")
		p.send("read 21 0")
		p.expectAll(10*time.Second, []string{"VAL frozencounter 1 77", "event=0"}, []string{"DONE read SUCCESS"})
	})

	t.Run("time and interval", func(t *testing.T) {
		p.send("writeti 1 1800000000000 30 2")
		p.expect(10*time.Second, "DONE writeti SUCCESS")
		o.h.mu.Lock()
		tis := append([]dnp3.TimeAndInterval(nil), o.h.tis...)
		o.h.mu.Unlock()
		if len(tis) != 1 || tis[0].Index != 1 || tis[0].Time.UnixMilli() != 1_800_000_000_000 || tis[0].Interval != 30 || tis[0].Units != 2 {
			t.Errorf("time-and-interval writes %+v", tis)
		}
		p.send("range 50 4 1 1")
		p.expect(10*time.Second, "VAL ti 1 1800000000000 30 2")
	})

	t.Run("restarts", func(t *testing.T) {
		p.send("cold")
		p.expect(10*time.Second, "RESTART cold SUCCESS 1500")
		p.send("warm")
		// Our g52v1 carries 3 (seconds); opendnp3 3.1.2's master takes
		// both g52v1 and g52v2 as milliseconds (RestartOperationTask.cpp),
		// so it reports 3.
		p.expect(10*time.Second, "RESTART warm SUCCESS 3")
	})

	t.Run("controls", func(t *testing.T) {
		before, _ := o.h.snapshot()
		p.send("pulse 2 3 250 500")
		p.expect(10*time.Second, "CMD pulse SUCCESS 2:SUCCESS:SUCCESS")
		p.send("ao16 1 300")
		p.expect(10*time.Second, "CMD ao16 SUCCESS")
		p.send("ao32 1 -70000")
		p.expect(10*time.Second, "CMD ao32 SUCCESS")
		p.send("aodbl 1 1.25")
		p.expect(10*time.Second, "CMD aodbl SUCCESS")
		p.send("multi")
		line := p.expect(10*time.Second, "CMD multi")
		if !strings.Contains(line, "SUCCESS 0:SUCCESS:SUCCESS 1:SUCCESS:SUCCESS") {
			t.Errorf("peer result %q", line)
		}
		ctl, _ := o.h.snapshot()
		ctl = ctl[len(before):]
		want := []string{"g12 2 code 1 count 3 on 250 off 500", "g41v2 1 300", "g41v1 1 -70000", "g41v4 1 1.25",
			"g12 0 code 3", "g41v3 1 12.5"}
		var got []string
		for _, c := range ctl {
			if c.Select {
				continue
			}
			if c.Group == 12 {
				s := fmt.Sprintf("g12 %d code %d", c.Index, c.CROB.Code)
				if c.CROB.Code == dnp3.OpPulseOn {
					s += fmt.Sprintf(" count %d on %d off %d", c.CROB.Count, c.CROB.OnTime, c.CROB.OffTime)
				}
				got = append(got, s)
			} else {
				got = append(got, fmt.Sprintf("g41v%d %d %g", c.Var, c.Index, c.Value))
			}
		}
		if strings.Join(got, "; ") != strings.Join(want, "; ") {
			t.Errorf("operated:\n got %s\nwant %s", strings.Join(got, "; "), strings.Join(want, "; "))
		}
	})
}

// TestOpendnp3MasterLinkAndLoss: opendnp3's master keeps the link alive
// with REQUEST_LINK_STATUS, which this module's outstation answers, and
// this module's outstation repeats an unsolicited response whose
// confirmation was lost.
func TestOpendnp3MasterLinkAndLoss(t *testing.T) {
	needDocker(t)
	o := newOurOutstation(t, func(c *dnp3.OutstationConfig) { c.ConfirmTimeout, c.UnsolRetries = time.Second, 3 })
	port := o.serveTCP(t, nil)
	withObjects, dropped := false, 0
	px := startProxy(t, fmt.Sprintf("127.0.0.1:%d", port), func(toTarget bool, f dnp3.Frame) bool {
		ctl, fc, ok := app(f)
		if !ok {
			return false
		}
		if !toTarget && fc == dnp3.FCUnsolicited && len(f.Data) > 5 && bytes.Contains(f.Data, []byte{2, 2, 0x28}) {
			withObjects = true
		}
		if toTarget && fc == dnp3.FCConfirm && ctl&dnp3.AppUNS != 0 && withObjects && dropped == 0 {
			dropped++
			return true
		}
		return false
	})
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", image, "dnp3-master", "tcp", "host.docker.internal",
		strconv.Itoa(px.port), "mode=nonlan", "keepalive=500")
	p.expect(60*time.Second, "READY")
	p.expect(20*time.Second, "TASK ENABLE_UNSOLICITED SUCCESS")
	p.expect(10*time.Second, "KEEPALIVE ok")

	p.drain()
	if _, err := o.db.Update(o.ctx, "binary", 2, 1, nil, 0x01, time.Now()); err != nil {
		t.Fatal(err)
	}
	p.expect(10*time.Second, "VAL binary 2 1", "unsol=1")
	p.expect(10*time.Second, "VAL binary 2 1", "unsol=1") // the repeat
	time.Sleep(500 * time.Millisecond)
	var seqs []byte
	for _, s := range px.seen() {
		if ctl, fc, ok := app(s.f); ok && !s.toTarget && fc == dnp3.FCUnsolicited && bytes.Contains(s.f.Data, []byte{2, 2, 0x28}) {
			seqs = append(seqs, ctl&0x0F)
		}
	}
	if dropped != 1 || len(seqs) != 2 || seqs[0] != seqs[1] {
		t.Errorf("dropped %d; the event went out in unsolicited responses with sequence numbers %v", dropped, seqs)
	}
	p.drain()
	p.send("class1")
	for {
		l := p.expect(10*time.Second, "")
		if strings.HasPrefix(l, "VAL binary 2") {
			t.Errorf("event still buffered after the repeat was confirmed: %s", l)
		}
		if strings.HasPrefix(l, "DONE class1") {
			break
		}
	}
}

// TestMasterSessionAgainstOpendnp3: this module's polling session runs its
// start-up against opendnp3's outstation (disable unsolicited, clear
// restart, integrity poll, time synchronisation, enable unsolicited),
// then takes unsolicited events and runs a periodic class scan.
func TestMasterSessionAgainstOpendnp3(t *testing.T) {
	for _, mode := range []dnp3.TimeSyncMode{dnp3.TimeSyncNonLAN, dnp3.TimeSyncLAN} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			needDocker(t)
			port := freePort(t)
			p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20000", port), image, "dnp3-outstation", "tcp", "20000")
			p.expect(60*time.Second, "READY")
			var mu sync.Mutex
			var unsol, data []dnp3.Fragment
			tasks := map[string]int{}
			var errs []error
			m := dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", port), MasterAddress: 1, OutstationAddress: 10,
				Timeout: 3 * time.Second, OnUnsolicited: func(f dnp3.Fragment) { mu.Lock(); unsol = append(unsol, f); mu.Unlock() }})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				_ = m.RunSession(ctx, dnp3.SessionConfig{Unsolicited: []int{1, 2}, TimeSync: mode, RetryDelay: time.Second,
					Scans:  []dnp3.ClassScan{{Classes: []int{3}, Period: 300 * time.Millisecond}},
					OnData: func(f dnp3.Fragment) { mu.Lock(); data = append(data, f); mu.Unlock() },
					OnTask: func(n string, err error) {
						mu.Lock()
						tasks[n]++
						if err != nil {
							errs = append(errs, fmt.Errorf("%s: %w", n, err))
						}
						mu.Unlock()
					}})
			}()
			p.expect(10*time.Second, "TIME")
			wait := func(what string, f func() bool) {
				t.Helper()
				deadline := time.Now().Add(10 * time.Second)
				for {
					mu.Lock()
					ok := f()
					mu.Unlock()
					if ok {
						return
					}
					if time.Now().After(deadline) {
						t.Fatalf("timed out waiting for %s (tasks %v, errors %v)", what, tasks, errs)
					}
					time.Sleep(50 * time.Millisecond)
				}
			}
			wait("start-up", func() bool { return tasks["enable unsolicited"] == 1 })
			if m.IIN()&(dnp3.IINDeviceRestart|dnp3.IINNeedTime) != 0 {
				t.Errorf("IIN %v after start-up", m.IIN())
			}
			p.send("bin 1 1")
			wait("unsolicited event", func() bool {
				_, ok := points(t, unsol)[[2]uint32{2, 1}]
				return ok
			})
			p.send("cnt 1 5")
			wait("class 3 scan", func() bool {
				_, ok := points(t, data)[[2]uint32{22, 1}]
				return ok
			})
			mu.Lock()
			defer mu.Unlock()
			if len(errs) != 0 {
				t.Errorf("task errors: %v", errs)
			}
		})
	}
}
