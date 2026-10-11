// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3/gateway"
)

// recorder accepts every control and keeps them.
type recorder struct {
	mu       sync.Mutex
	controls []dnp3.ControlRequest
	status   uint8
}

func (r *recorder) Control(_ context.Context, c dnp3.ControlRequest) uint8 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.controls = append(r.controls, c)
	return r.status
}
func (r *recorder) DataSetControl(context.Context, dnp3.DataSetControl) uint8 { return 4 }
func (r *recorder) Restart(context.Context, bool) time.Duration               { return 0 }
func (r *recorder) Activate(context.Context, [][]byte) dnp3.ActivateStatus {
	return dnp3.ActivateStatus{}
}
func (r *recorder) Application(context.Context, byte, [][]byte) dnp3.IIN {
	return dnp3.IINNoFuncCodeSupport
}
func (r *recorder) TimeSet(time.Time)                            {}
func (r *recorder) DataSetWritten(context.Context, dnp3.DataSet) {}

func (r *recorder) all() []dnp3.ControlRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]dnp3.ControlRequest(nil), r.controls...)
}

// serve runs an outstation (address 10, master 1) over TCP.
func serve(t *testing.T, ctx context.Context, db *dnp3.PointDB, h dnp3.Handler, unsol bool) string {
	t.Helper()
	a := dnp3.NewAssociation(dnp3.OutstationConfig{Address: 10, Master: 1, DB: db, Handler: h, Unsolicited: unsol,
		ConfirmTimeout: time.Second})
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
	return ln.Addr().String()
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// pointsOf parses responses into (group, index) -> point.
func pointsOf(t *testing.T, frags []dnp3.Fragment) map[[2]uint32]dnp3.Point {
	t.Helper()
	out := map[[2]uint32]dnp3.Point{}
	for _, f := range frags {
		blocks, err := dnp3.ParseObjects(f.Objects, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range blocks {
			for _, p := range b.Points {
				out[[2]uint32{uint32(b.Header.Group), p.Index}] = p
			}
		}
	}
	return out
}

// A data concentrator: an outstation below polled by the gateway's
// master, its points republished at other indexes on the gateway's
// outstation; events arrive upward as events; controls go down and their
// status comes back; a lost source turns its points COMM_LOST.
//
// Covers: SIG-IPE-6901
func TestGateway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now()

	// The outstation below.
	down := dnp3.NewPointDB()
	for _, p := range []dnp3.DBPoint{{Type: "binary", Index: 3, Class0: true, Class: 1}, {Type: "analog", Index: 7, Class0: true, Class: 2},
		{Type: "counter", Index: 1, Class0: true, Class: 3}, {Type: "double", Index: 0, Class0: true, Class: 1}} {
		if err := down.Define(p); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = down.Update(ctx, "binary", 3, 1, nil, 0x01, now)
	_, _ = down.Update(ctx, "analog", 7, 230.5, nil, 0x01, now)
	_, _ = down.Update(ctx, "counter", 1, 1000, nil, 0x01, now)
	_, _ = down.Update(ctx, "double", 0, 2, nil, 0x01, now)
	rtu := &recorder{}
	downAddr := serve(t, ctx, down, rtu, true)

	// The gateway.
	gdb := dnp3.NewPointDB()
	g := gateway.New(gdb, nil)
	src := &gateway.Source{Name: "rtu", Timeout: 3 * time.Second,
		Points: []gateway.Map{{Type: "binary", From: 3, To: 100, Class: 1}, {Type: "analog", From: 7, To: 200, Class: 2},
			{Type: "counter", From: 1, To: 300, Class: 3}, {Type: "double", From: 0, To: 400, Class: 1}},
		Controls: []gateway.Control{{Group: 12, From: 5, To: 50}, {Group: 41, From: 6, To: 60}}}
	if err := g.Add(src); err != nil {
		t.Fatal(err)
	}
	if err := g.Add(&gateway.Source{Name: "other", Points: []gateway.Map{{Type: "binary", From: 0, To: 100}}}); err == nil {
		t.Error("a gateway index mapped twice was accepted")
	}
	m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: "tcp://" + downAddr, MasterAddress: 1, OutstationAddress: 10,
		Timeout: 2 * time.Second, OnUnsolicited: src.Data})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	src.Master = m
	go func() {
		_ = m.RunSession(ctx, dnp3.SessionConfig{Unsolicited: []int{1, 2, 3}, OnData: src.Data, RetryDelay: 200 * time.Millisecond})
	}()
	eventually(t, "the mirrored analog", func() bool { p, _ := gdb.Point("analog", 200); return p.Value == 230.5 })

	// The master above.
	upAddr := serve(t, ctx, gdb, g.Handler(), false)
	up, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: "tcp://" + upAddr, MasterAddress: 1, OutstationAddress: 10, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	frags, err := up.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil {
		t.Fatal(err)
	}
	pts := pointsOf(t, frags)
	if p := pts[[2]uint32{1, 100}]; p.Value != true || p.Flags&gateway.FlagOnline == 0 {
		t.Errorf("binary 100: %+v", p)
	}
	if p := pts[[2]uint32{30, 200}]; p.Value != 230.5 {
		t.Errorf("analog 200: %+v", p)
	}
	if p := pts[[2]uint32{20, 300}]; p.Value != 1000.0 {
		t.Errorf("counter 300: %+v", p)
	}
	if p := pts[[2]uint32{3, 400}]; p.Value != 2.0 {
		t.Errorf("double 400: %+v", p)
	}
	_, _ = up.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3)) // take the start-up events

	// An event below, with its own time, becomes an event above; a
	// momentary change back is still an event.
	at := now.Add(-time.Minute).Truncate(time.Millisecond)
	_, _ = down.Update(ctx, "analog", 7, 231.25, nil, 0x01, at)
	_, _ = down.UpdateWith(ctx, "binary", 3, 1, nil, 0x01, at, dnp3.EventForce)
	eventually(t, "the mirrored change", func() bool { p, _ := gdb.Point("analog", 200); return p.Value == 231.25 })
	frags, err = up.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	ev := pointsOf(t, frags)
	if p, ok := ev[[2]uint32{32, 200}]; !ok || p.Value != 231.25 || !p.Time.Equal(at) {
		t.Errorf("analog event 200: %+v (time %s want %s)", p, p.Time, at)
	}
	if _, ok := ev[[2]uint32{2, 100}]; !ok {
		t.Error("the binary event below did not become an event above")
	}

	// Controls: select-before-operate and direct operate go down to the
	// source's indexes; the source's status comes back.
	crob, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 50, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	if err := up.SelectOperate(ctx, crob, 5*time.Second, nil); err != nil {
		t.Fatal(err)
	}
	ao, _ := dnp3.EncodeBlock(41, 3, dnp3.Q8Index8, []dnp3.Point{{Index: 60, Value: 12.5}})
	if _, err := up.Request(ctx, dnp3.FCDirectOperate, ao); err != nil {
		t.Fatal(err)
	}
	var sawSel, sawOp, sawAO bool
	for _, c := range rtu.all() {
		switch {
		case c.Group == 12 && c.Index == 5 && c.Select:
			sawSel = true
		case c.Group == 12 && c.Index == 5 && c.Func == dnp3.FCOperate && c.CROB.Code == dnp3.OpLatchOn:
			sawOp = true
		case c.Group == 41 && c.Index == 6 && c.Value == 12.5 && c.Func == dnp3.FCDirectOperate:
			sawAO = true
		}
	}
	if !sawSel || !sawOp || !sawAO {
		t.Errorf("controls below: %+v", rtu.all())
	}
	rtu.mu.Lock()
	rtu.status = 7 // a refusal code of the source
	rtu.mu.Unlock()
	frags, err = up.Request(ctx, dnp3.FCDirectOperate, crob)
	if err != nil {
		t.Fatal(err)
	}
	if p := pointsOf(t, frags)[[2]uint32{12, 50}]; p.Status != 7 {
		t.Errorf("status passed back %d, want 7", p.Status)
	}
	unmapped, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 99, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	frags, _ = up.Request(ctx, dnp3.FCDirectOperate, unmapped)
	if p := pointsOf(t, frags)[[2]uint32{12, 99}]; p.Status != 4 {
		t.Errorf("an unmapped control answered %d, want 4", p.Status)
	}

	// The source is lost: its points turn COMM_LOST (events above).
	src.SetOnline(ctx, false)
	p, _ := gdb.Point("analog", 200)
	if p.Flags&gateway.FlagCommLost == 0 || p.Flags&gateway.FlagOnline != 0 || p.Value != 231.25 {
		t.Errorf("offline analog %+v", p)
	}
	frags, _ = up.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(2))
	if p := pointsOf(t, frags)[[2]uint32{32, 200}]; p.Flags&gateway.FlagCommLost == 0 {
		t.Errorf("no COMM_LOST event: %+v", p)
	}
	frags, _ = up.Request(ctx, dnp3.FCDirectOperate, crob)
	if p := pointsOf(t, frags)[[2]uint32{12, 50}]; p.Status != 6 {
		t.Errorf("a control to a lost source answered %d, want 6", p.Status)
	}
}
