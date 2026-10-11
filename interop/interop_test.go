// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop runs this module's master and outstation against
// opendnp3 3.1.2 (github.com/dnp3/opendnp3, Apache-2.0), built in a
// container from ./peer. The tests are skipped unless SIGMA_DNP3_INTEROP=1
// is set and Docker is running.
package interop

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// points indexes the points of response fragments by group and index.
func points(t *testing.T, frags []dnp3.Fragment) map[[2]uint32]dnp3.Point {
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

func groups(t *testing.T, frags []dnp3.Fragment) []string {
	t.Helper()
	var out []string
	for _, f := range frags {
		bl, err := dnp3.ParseObjects(f.Objects, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bl {
			out = append(out, b.Header.String())
		}
	}
	return out
}

func crob(t *testing.T, index uint32, code uint8) []byte {
	t.Helper()
	b, err := dnp3.EncodeBlock(12, 1, dnp3.Q16Index16, []dnp3.Point{{Index: index, CROB: dnp3.CROB{Code: code, Count: 1, OnTime: 100, OffTime: 100}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMasterAgainstOpendnp3Outstation: this module's master polls,
// commands and synchronises opendnp3's outstation, and takes its
// unsolicited responses.
func TestMasterAgainstOpendnp3Outstation(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20000", port), image, "dnp3-outstation")
	p.expect(60*time.Second, "READY")

	var mu sync.Mutex
	var unsol []dnp3.Fragment
	ctx := context.Background()
	var m *dnp3.Master
	var err error
	for i := 0; i < 50; i++ {
		m, err = dnp3.Dial(ctx, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", port), MasterAddress: 1, OutstationAddress: 10,
			Timeout: 3 * time.Second, OnUnsolicited: func(f dnp3.Fragment) { mu.Lock(); unsol = append(unsol, f); mu.Unlock() }})
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Start-up: the outstation reports a restart and asks for time.
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0))
	if err != nil {
		t.Fatalf("integrity poll: %v", err)
	}
	iin := frags[len(frags)-1].IIN
	if iin&dnp3.IINDeviceRestart == 0 || iin&dnp3.IINNeedTime == 0 {
		t.Errorf("start-up IIN %v, want device restart and need time", iin)
	}
	t.Run("integrity poll", func(t *testing.T) {
		pts := points(t, frags)
		if v := pts[[2]uint32{1, 0}]; v.Value != true || v.Var != 2 {
			t.Errorf("binary 0: %+v", v)
		}
		if v := pts[[2]uint32{30, 0}]; v.Value != 230.5 || v.Var != 5 {
			t.Errorf("analog 0: %+v", v)
		}
		if v := pts[[2]uint32{20, 0}]; v.Value != 42.0 || v.Var != 1 {
			t.Errorf("counter 0: %+v", v)
		}
		t.Logf("integrity poll objects: %v", groups(t, frags))
	})

	t.Run("clear restart", func(t *testing.T) {
		objs, _ := dnp3.EncodeBlock(80, 1, dnp3.Q8StartStop, []dnp3.Point{{Index: 7, Value: false}})
		frags, err := m.Request(ctx, dnp3.FCWrite, objs)
		if err != nil {
			t.Fatal(err)
		}
		if frags[0].IIN&dnp3.IINDeviceRestart != 0 {
			t.Errorf("IIN1.7 still set: %v", frags[0].IIN)
		}
	})

	t.Run("time sync non-LAN", func(t *testing.T) {
		t0 := time.Now()
		frags, err := m.Request(ctx, dnp3.FCDelayMeasure, nil)
		if err != nil {
			t.Fatal(err)
		}
		rtt := time.Since(t0)
		pts := points(t, frags)
		d, ok := pts[[2]uint32{52, 0}]
		if !ok || d.Var != 2 {
			t.Fatalf("delay measure answered %v", groups(t, frags))
		}
		rtu := time.Duration(d.Value.(float64)) * time.Millisecond
		at := time.Now().Add(max((rtt-rtu)/2, 0))
		objs, _ := dnp3.EncodeBlock(50, 1, dnp3.Q8Count, []dnp3.Point{{Value: at}})
		frags, err = m.Request(ctx, dnp3.FCWrite, objs)
		if err != nil {
			t.Fatal(err)
		}
		line := p.expect(5*time.Second, "TIME")
		ms, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
		if diff := time.UnixMilli(ms).Sub(at); diff < -time.Millisecond || diff > time.Millisecond {
			t.Errorf("outstation set %s, sent %s", time.UnixMilli(ms).UTC(), at.UTC())
		}
		if frags[0].IIN&dnp3.IINNeedTime != 0 {
			t.Errorf("IIN1.4 still set: %v", frags[0].IIN)
		}
	})

	t.Run("time sync LAN", func(t *testing.T) {
		t0 := time.Now()
		if _, err := m.Request(ctx, dnp3.FCRecordCurrentTime, nil); err != nil {
			t.Fatal(err)
		}
		objs, _ := dnp3.EncodeBlock(50, 3, dnp3.Q8Count, []dnp3.Point{{Value: t0}})
		if _, err := m.Request(ctx, dnp3.FCWrite, objs); err != nil {
			t.Fatal(err)
		}
		line := p.expect(5*time.Second, "TIME")
		ms, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
		// The outstation adds the time since it recorded its own clock.
		if diff := time.UnixMilli(ms).Sub(t0); diff < -time.Millisecond || diff > 2*time.Second {
			t.Errorf("outstation set %s, recorded at %s", time.UnixMilli(ms).UTC(), t0.UTC())
		}
	})

	t.Run("class polls", func(t *testing.T) {
		p.send("bin 1 1")
		p.expect(5*time.Second, "APPLIED bin 1")
		p.send("ana 1 12.5")
		p.expect(5*time.Second, "APPLIED ana 1")
		p.send("cnt 1 7")
		p.expect(5*time.Second, "APPLIED cnt 1")
		want := map[int][3]any{1: {uint8(2), uint32(1), true}, 2: {uint8(32), uint32(1), 12.5}, 3: {uint8(22), uint32(1), 7.0}}
		for class := 1; class <= 3; class++ {
			frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(class))
			if err != nil {
				t.Fatalf("class %d: %v", class, err)
			}
			pts := points(t, frags)
			w := want[class]
			if len(pts) != 1 || pts[[2]uint32{uint32(w[0].(uint8)), w[1].(uint32)}].Value != w[2] {
				t.Errorf("class %d poll: %v %+v", class, groups(t, frags), pts)
			}
		}
		// The events were confirmed: a second class 1 poll is empty.
		frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
		if err != nil || len(points(t, frags)) != 0 {
			t.Errorf("events not cleared by the confirmation: %v %v", err, groups(t, frags))
		}
	})

	t.Run("unsolicited", func(t *testing.T) {
		if _, err := m.Request(ctx, dnp3.FCEnableUnsolicited, dnp3.ClassRequest(1, 2, 3)); err != nil {
			t.Fatal(err)
		}
		p.send("bin 2 1")
		p.expect(5*time.Second, "APPLIED bin 2")
		deadline := time.Now().Add(10 * time.Second)
		for {
			mu.Lock()
			var got bool
			for _, f := range unsol {
				if v, ok := points(t, []dnp3.Fragment{f})[[2]uint32{2, 2}]; ok && v.Value == true {
					got = true
				}
			}
			n := len(unsol)
			mu.Unlock()
			if got {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no unsolicited event for binary 2 (%d unsolicited fragments)", n)
			}
			time.Sleep(50 * time.Millisecond)
		}
		// Confirmed: nothing is left for a class 1 poll.
		time.Sleep(300 * time.Millisecond)
		frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
		if err != nil || len(points(t, frags)) != 0 {
			t.Errorf("unsolicited event not confirmed: %v %v", err, groups(t, frags))
		}
		if _, err := m.Request(ctx, dnp3.FCDisableUnsolicited, dnp3.ClassRequest(1, 2, 3)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("select before operate", func(t *testing.T) {
		p.drain()
		if err := m.SelectOperate(ctx, crob(t, 3, dnp3.OpLatchOn), 5*time.Second, nil); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "SELECT crob 3 3")
		p.expect(5*time.Second, "OPERATE crob 3 3 SelectBeforeOperate")
	})

	t.Run("direct operate", func(t *testing.T) {
		frags, err := m.Request(ctx, dnp3.FCDirectOperate, crob(t, 4, dnp3.OpLatchOff))
		if err != nil {
			t.Fatal(err)
		}
		if st := points(t, frags)[[2]uint32{12, 4}].Status; st != 0 {
			t.Errorf("status %d", st)
		}
		p.expect(5*time.Second, "OPERATE crob 4 4 DirectOperate")
	})

	t.Run("analog output select before operate", func(t *testing.T) {
		objs, err := dnp3.EncodeBlock(41, 3, dnp3.Q16Index16, []dnp3.Point{{Index: 0, Value: 12.5}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.SelectOperate(ctx, objs, 5*time.Second, nil); err != nil {
			t.Fatal(err)
		}
		line := p.expect(5*time.Second, "OPERATE ao 0")
		if f := strings.Fields(line); len(f) < 4 || f[3] != "12.500000" {
			t.Errorf("peer operated %q", line)
		}
	})
}

// handler records the controls and time settings of the outstation.
type handler struct {
	mu       sync.Mutex
	controls []dnp3.ControlRequest
	times    []time.Time
}

func (h *handler) Control(_ context.Context, c dnp3.ControlRequest) uint8 {
	h.mu.Lock()
	h.controls = append(h.controls, c)
	h.mu.Unlock()
	return 0
}
func (*handler) DataSetControl(context.Context, dnp3.DataSetControl) uint8 { return 4 }
func (*handler) Restart(context.Context, bool) time.Duration               { return 0 }
func (*handler) Activate(context.Context, [][]byte) dnp3.ActivateStatus {
	return dnp3.ActivateStatus{}
}
func (*handler) Application(context.Context, byte, [][]byte) dnp3.IIN {
	return dnp3.IINNoFuncCodeSupport
}
func (h *handler) TimeSet(t time.Time) {
	h.mu.Lock()
	h.times = append(h.times, t)
	h.mu.Unlock()
}
func (*handler) DataSetWritten(context.Context, dnp3.DataSet) {}

func (h *handler) snapshot() ([]dnp3.ControlRequest, []time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]dnp3.ControlRequest(nil), h.controls...), append([]time.Time(nil), h.times...)
}

// outstation serves this module's outstation on a loopback port.
func outstation(t *testing.T) (*dnp3.PointDB, *handler, int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	db := dnp3.NewPointDB()
	for i := uint32(0); i < 3; i++ {
		for _, p := range []dnp3.DBPoint{
			{Type: "binary", Index: i, Class0: true, Class: 1, Flags: 0x01},
			{Type: "analog", Index: i, Class0: true, Class: 2, Flags: 0x01},
			{Type: "counter", Index: i, Class0: true, Class: 3, Flags: 0x01},
			{Type: "binary-output", Index: i, Class0: true, Flags: 0x01},
			{Type: "analog-output", Index: i, Class0: true, Flags: 0x01},
		} {
			if err := db.Define(p); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, _ = db.Update(ctx, "binary", 0, 1, nil, 0x01, time.Now())
	_, _ = db.Update(ctx, "analog", 0, 230.5, nil, 0x01, time.Now())
	_, _ = db.Update(ctx, "counter", 0, 42, nil, 0x01, time.Now())
	h := &handler{}
	a := dnp3.NewAssociation(dnp3.OutstationConfig{Address: 10, Master: 1, DB: db, Handler: h, Unsolicited: true, NeedTime: time.Hour})
	n := &dnp3.OutstationNet{}
	n.Add(a)
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
	return db, h, ln.Addr().(*net.TCPAddr).Port
}

// TestOpendnp3MasterAgainstOutstation: opendnp3's master runs its start-up
// sequence (disable unsolicited, integrity poll, clear restart, time
// synchronisation, enable unsolicited) against this module's outstation,
// then polls each class, takes unsolicited events and sends controls.
func TestOpendnp3MasterAgainstOutstation(t *testing.T) {
	needDocker(t)
	for _, mode := range []string{"nonlan", "lan"} {
		t.Run(mode, func(t *testing.T) {
			db, h, port := outstation(t)
			ctx := context.Background()
			p := startPeer(t, "--add-host=host.docker.internal:host-gateway", image, "dnp3-master", "host.docker.internal", strconv.Itoa(port), mode)
			p.expect(60*time.Second, "READY")

			t.Run("start-up", func(t *testing.T) {
				p.expect(15*time.Second, "VAL analog 0 230.5", "event=0")
				p.expect(15*time.Second, "TASK ENABLE_UNSOLICITED SUCCESS")
				_, times := h.snapshot()
				if len(times) == 0 {
					p.expect(10*time.Second, "TASK", "SYNC", "SUCCESS")
					_, times = h.snapshot()
				}
				if len(times) != 1 || math.Abs(time.Since(times[0]).Seconds()) > 5 {
					t.Errorf("time settings %v", times)
				}
			})

			t.Run("unsolicited", func(t *testing.T) {
				p.drain()
				if _, err := db.Update(ctx, "binary", 1, 1, nil, 0x01, time.Now()); err != nil {
					t.Fatal(err)
				}
				p.expect(10*time.Second, "VAL binary 1 1", "event=1", "unsol=1")
			})

			t.Run("integrity and class polls", func(t *testing.T) {
				p.drain()
				p.send("integrity")
				p.expect(10*time.Second, "VAL counter 0 42")
				p.expect(10*time.Second, "DONE integrity SUCCESS")
				// With unsolicited reporting on, events go out unsolicited;
				// the class polls must still succeed (empty or not).
				for _, c := range []string{"class1", "class2", "class3"} {
					p.send(c)
					p.expect(10*time.Second, "DONE "+c+" SUCCESS")
				}
			})

			t.Run("select before operate", func(t *testing.T) {
				p.drain()
				p.send("sbo 2")
				line := p.expect(10*time.Second, "CMD sbo")
				if !strings.Contains(line, "SUCCESS 2:SUCCESS:SUCCESS") {
					t.Errorf("peer result %q", line)
				}
				ctl, _ := h.snapshot()
				var sel, op bool
				for _, c := range ctl {
					if c.Index == 2 && c.Group == 12 {
						sel = sel || (c.Select && c.Func == dnp3.FCSelect)
						op = op || (!c.Select && c.Func == dnp3.FCOperate && c.CROB.Code == dnp3.OpLatchOn)
					}
				}
				if !sel || !op {
					t.Errorf("controls %+v", ctl)
				}
			})

			t.Run("direct operate", func(t *testing.T) {
				p.send("do 1")
				line := p.expect(10*time.Second, "CMD do")
				if !strings.Contains(line, "SUCCESS 1:SUCCESS:SUCCESS") {
					t.Errorf("peer result %q", line)
				}
				ctl, _ := h.snapshot()
				last := ctl[len(ctl)-1]
				if last.Func != dnp3.FCDirectOperate || last.Index != 1 || last.CROB.Code != dnp3.OpLatchOff {
					t.Errorf("last control %+v", last)
				}
			})

			t.Run("analog output", func(t *testing.T) {
				p.send("aosbo 0 12.5")
				line := p.expect(10*time.Second, "CMD aosbo")
				if !strings.Contains(line, "SUCCESS 0:SUCCESS:SUCCESS") {
					t.Errorf("peer result %q", line)
				}
				ctl, _ := h.snapshot()
				last := ctl[len(ctl)-1]
				if last.Group != 41 || last.Value != 12.5 || last.Func != dnp3.FCOperate {
					t.Errorf("last control %+v", last)
				}
			})
		})
	}
}
