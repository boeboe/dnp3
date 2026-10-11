// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// tiHandler is testHandler that also takes time-and-interval writes.
type tiHandler struct {
	testHandler
	mu      sync.Mutex
	written []dnp3.TimeAndInterval
}

func (h *tiHandler) TimeAndIntervalWritten(_ context.Context, ti dnp3.TimeAndInterval) {
	h.mu.Lock()
	h.written = append(h.written, ti)
	h.mu.Unlock()
}

// Covers: SIG-IPE-6490
// TestTimeAndIntervalPoints: g50v4 points are served in class 0 and by
// range, written by the master (index by index, reported to a handler that
// takes them) and refused for undefined indexes; they have no events.
func TestTimeAndIntervalPoints(t *testing.T) {
	h := &tiHandler{}
	o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.Handler = h })
	if err := o.db.Define(dnp3.DBPoint{Type: "time-and-interval", Index: 0, Class: 1}); err == nil {
		t.Error("a time-and-interval point with an event class was defined")
	}
	for i := uint32(0); i < 2; i++ {
		if err := o.db.Define(dnp3.DBPoint{Type: "time-and-interval", Index: i, Class0: true}); err != nil {
			t.Fatal(err)
		}
	}
	at := time.UnixMilli(1_700_000_000_000).UTC()
	if err := o.db.SetTimeAndInterval(0, dnp3.TimeAndInterval{Time: at, Interval: 15, Units: dnp3.UnitsMinutes}); err != nil {
		t.Fatal(err)
	}
	if err := o.db.SetTimeAndInterval(5, dnp3.TimeAndInterval{Time: at}); err == nil {
		t.Error("an undefined time-and-interval point was set")
	}
	m := o.master(t, nil, nil)
	ctx := context.Background()

	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range frags {
		bl, _ := dnp3.ParseObjects(f.Objects, true)
		for _, b := range bl {
			if b.Header.Group == 50 && b.Header.Var == 4 {
				for _, p := range b.Points {
					if p.Index == 0 {
						found = p.Value.(time.Time).Equal(at) && p.Interval == 15 && p.Units == dnp3.UnitsMinutes
					}
				}
			}
		}
	}
	if !found {
		t.Errorf("class 0 poll without g50v4 index 0 = (%s, 15 minutes)", at)
	}

	frags, err = m.Request(ctx, dnp3.FCRead, []byte{50, 4, dnp3.Q8StartStop, 0, 1})
	if err != nil {
		t.Fatalf("range read: %v", err)
	}
	bl, _ := dnp3.ParseObjects(frags[0].Objects, true)
	if len(bl) != 1 || bl[0].Header.Group != 50 || bl[0].Header.Var != 4 || len(bl[0].Points) != 2 {
		t.Fatalf("range read answered %+v", bl)
	}
	if _, err := m.Request(ctx, dnp3.FCRead, []byte{50, 2, dnp3.Q8StartStop, 0, 0}); err == nil {
		t.Error("a read of g50v2 points was answered")
	}

	then := at.Add(time.Hour)
	w, _ := dnp3.EncodeBlock(50, 4, dnp3.Q16Index16, []dnp3.Point{{Index: 1, Value: then, Interval: 2, Units: dnp3.UnitsHours}})
	if _, err := m.Request(ctx, dnp3.FCWrite, w); err != nil {
		t.Fatalf("write: %v", err)
	}
	p, _ := o.db.Point("time-and-interval", 1)
	if got, _ := o.db.TimeAndInterval(1); !got.Time.Equal(then) || got.Interval != 2 || got.Units != dnp3.UnitsHours {
		t.Errorf("point 1 is %+v (%+v) after the write", got, p)
	}
	h.mu.Lock()
	if len(h.written) != 1 || h.written[0].Index != 1 || !h.written[0].Time.Equal(then) {
		t.Errorf("handler saw %+v", h.written)
	}
	h.mu.Unlock()

	w, _ = dnp3.EncodeBlock(50, 4, dnp3.Q16Index16, []dnp3.Point{{Index: 9, Value: then}})
	_, err = m.Request(ctx, dnp3.FCWrite, w)
	var rej *dnp3.RejectedError
	if !errors.As(err, &rej) || rej.IIN&dnp3.IINParameterError == 0 {
		t.Errorf("write to an undefined point: %v", err)
	}
}

// Covers: SIG-IPE-6492
// TestTime48BeforeEpoch: a time that was never set (the zero time.Time)
// or lies before 1970 goes out as 0, not as a wrapped 48-bit value.
func TestTime48BeforeEpoch(t *testing.T) {
	for _, at := range []time.Time{{}, time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC)} {
		if b := dnp3.AppendTime48(nil, at); string(b) != "\x00\x00\x00\x00\x00\x00" {
			t.Errorf("%s encoded % X", at, b)
		}
	}
	at := time.UnixMilli(0x0123456789AB)
	if b := dnp3.AppendTime48(nil, at); !dnp3.Time48(b).Equal(at) {
		t.Errorf("%s did not survive the round trip: % X", at, b)
	}
}

// Covers: SIG-IPE-6493
// TestLinkConfirmWhileFramesArrive: with link-layer confirmation, frames
// the read loop must answer (an unsolicited response to confirm, a link
// status request) arrive while the master waits for its link
// acknowledgement; the read loop must not wait for the sender, or the
// acknowledgement is never read.
func TestLinkConfirmWhileFramesArrive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		var tseq uint8
		send := func(f dnp3.Frame) {
			b, _ := f.Encode()
			_, _ = c.Write(b)
		}
		var lp dnp3.LinkParser
		buf := make([]byte, 1024)
		for {
			n, err := c.Read(buf)
			if err != nil {
				served <- nil
				return
			}
			for _, f := range lp.Feed(buf[:n]) {
				if !f.Primary() {
					continue
				}
				switch f.Func() {
				case dnp3.LinkResetLinkStates:
					// Before the acknowledgement: a link status request and
					// an unsolicited response asking for confirmation.
					send(dnp3.Frame{Ctrl: dnp3.CtrlPRM | dnp3.LinkRequestLinkStatus, Dest: 1, Src: 10})
					uns := dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | dnp3.AppCON | dnp3.AppUNS, Func: dnp3.FCUnsolicited}
					for _, s := range dnp3.Segment(uns.Encode(), &tseq) {
						send(dnp3.Frame{Ctrl: dnp3.CtrlPRM | dnp3.LinkUnconfirmedUserData, Dest: 1, Src: 10, Data: s})
					}
					send(dnp3.Frame{Ctrl: dnp3.LinkAck, Dest: 1, Src: 10})
				case dnp3.LinkConfirmedUserData:
					send(dnp3.Frame{Ctrl: dnp3.LinkAck, Dest: 1, Src: 10})
					if len(f.Data) > 2 && f.Data[2] == dnp3.FCRead {
						resp := dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | f.Data[1]&0x0F, Func: dnp3.FCResponse}
						for _, s := range dnp3.Segment(resp.Encode(), &tseq) {
							send(dnp3.Frame{Ctrl: dnp3.CtrlPRM | dnp3.LinkUnconfirmedUserData, Dest: 1, Src: 10, Data: s})
						}
					}
				}
			}
		}
	}()
	m, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: "tcp://" + ln.Addr().String(), MasterAddress: 1,
		OutstationAddress: 10, Timeout: 500 * time.Millisecond, LinkConfirm: true})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := m.Request(context.Background(), dnp3.FCRead, dnp3.ClassRequest(0)); err != nil {
		t.Fatalf("request: %v", err)
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Errorf("the request took %s: a link acknowledgement waited for a timeout", d)
	}
	_ = m.Close()
	<-served
}

// rawMaster is a master written frame by frame, to leave confirmations
// out on purpose.
type rawMaster struct {
	t    *testing.T
	c    net.Conn
	tseq uint8
	lp   dnp3.LinkParser
	ra   dnp3.Reassembler
	q    []dnp3.Fragment
}

func (r *rawMaster) send(f dnp3.Fragment) {
	r.t.Helper()
	for _, s := range dnp3.Segment(f.Encode(), &r.tseq) {
		b, _ := dnp3.Frame{Ctrl: dnp3.CtrlDIR | dnp3.CtrlPRM | dnp3.LinkUnconfirmedUserData, Dest: 10, Src: 1, Data: s}.Encode()
		if _, err := r.c.Write(b); err != nil {
			r.t.Fatal(err)
		}
	}
}

// next returns the next fragment from the outstation (ok false after d).
func (r *rawMaster) next(d time.Duration) (dnp3.Fragment, bool) {
	deadline := time.Now().Add(d)
	buf := make([]byte, 4096)
	for len(r.q) == 0 {
		_ = r.c.SetReadDeadline(deadline)
		n, err := r.c.Read(buf)
		if err != nil {
			return dnp3.Fragment{}, false
		}
		for _, f := range r.lp.Feed(buf[:n]) {
			if !f.Primary() {
				continue
			}
			apdu, err := r.ra.Add(f.Data)
			if err != nil || apdu == nil {
				continue
			}
			if fr, err := dnp3.ParseFragment(apdu); err == nil {
				r.q = append(r.q, fr)
			}
		}
	}
	f := r.q[0]
	r.q = r.q[1:]
	return f, true
}

func (r *rawMaster) confirm(f dnp3.Fragment) {
	r.send(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | f.Control&(dnp3.AppUNS|0x0F), Func: dnp3.FCConfirm})
}

// Covers: SIG-IPE-6494
// TestUnsolicitedSeriesRestarts: when an unsolicited series ends without
// a confirmation (no retries left), its events stay buffered and a new
// series (the next sequence number) carries them after UnsolOffline,
// without waiting for another event.
func TestUnsolicitedSeriesRestarts(t *testing.T) {
	o := startOutstation(t, func(c *dnp3.OutstationConfig) {
		c.Unsolicited, c.ConfirmTimeout, c.UnsolOffline = true, 200*time.Millisecond, 300*time.Millisecond
	})
	c, err := net.Dial("tcp", strings.TrimPrefix(o.url, "tcp://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := &rawMaster{t: t, c: c}
	f, ok := r.next(2 * time.Second)
	if !ok || f.Func != dnp3.FCUnsolicited {
		t.Fatalf("no null unsolicited response: %+v", f)
	}
	r.confirm(f)
	r.send(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN, Func: dnp3.FCEnableUnsolicited, Objects: dnp3.ClassRequest(1, 2, 3)})
	for {
		f, ok = r.next(2 * time.Second)
		if !ok {
			t.Fatal("no answer to ENABLE_UNSOLICITED")
		}
		if f.Func == dnp3.FCResponse {
			break
		}
	}
	if _, err := o.db.Update(context.Background(), "binary", 0, 0, nil, 0x01, time.Now()); err != nil {
		t.Fatal(err)
	}
	first, ok := r.next(2 * time.Second)
	if !ok || first.Func != dnp3.FCUnsolicited || len(first.Objects) == 0 {
		t.Fatalf("no unsolicited event: %+v", first)
	}
	// Not confirmed: the series ends; a new one follows.
	start := time.Now()
	second, ok := r.next(3 * time.Second)
	if !ok || second.Func != dnp3.FCUnsolicited || string(second.Objects) != string(first.Objects) {
		t.Fatalf("the event was not sent again: %+v", second)
	}
	if second.Seq() != (first.Seq()+1)&0x0F {
		t.Errorf("new series sequence %d after %d", second.Seq(), first.Seq())
	}
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Errorf("the new series came %s after the first, before the timeout and offline interval", d)
	}
	r.confirm(second)
	if f, ok := r.next(time.Second); ok && f.Func == dnp3.FCUnsolicited && len(f.Objects) > 0 {
		t.Errorf("events sent again after the confirmation: %+v", f)
	}
}

// Covers: SIG-IPE-6491
// TestCounterDeadband: a counter or frozen counter with a deadband makes
// an event only when it moved by more than the deadband since the last
// event; without one every change is an event.
func TestCounterDeadband(t *testing.T) {
	db := dnp3.NewPointDB()
	buf := dnp3.NewEventBuffer(nil, nil)
	db.Attach(buf)
	for _, p := range []dnp3.DBPoint{
		{Type: "counter", Index: 0, Class: 3, Deadband: 10},
		{Type: "counter", Index: 1, Class: 3},
		{Type: "frozen-counter", Index: 0, Class: 3, Deadband: 5},
	} {
		if err := db.Define(p); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	now := time.Now()
	steps := []struct {
		typ   string
		index uint32
		v     float64
		event bool
	}{
		{"counter", 0, 100, true}, // first value
		{"counter", 0, 105, false},
		{"counter", 0, 110, false}, // exactly the deadband
		{"counter", 0, 111, true},
		{"counter", 0, 115, false},
		{"counter", 1, 1, true},
		{"counter", 1, 2, true},
		{"frozen-counter", 0, 50, true},
		{"frozen-counter", 0, 54, false},
		{"frozen-counter", 0, 56, true},
	}
	for i, s := range steps {
		ev, err := db.Update(ctx, s.typ, s.index, s.v, nil, 0x01, now)
		if err != nil {
			t.Fatal(err)
		}
		if ev != s.event {
			t.Errorf("step %d (%s %d = %g): event %v, want %v", i, s.typ, s.index, s.v, ev, s.event)
		}
	}
	if p, _ := db.Point("counter", 0); p.Value != 115 {
		t.Errorf("the static value is %g, want the latest 115", p.Value)
	}
}

// vtHandler is testHandler that also takes virtual terminal input.
type vtHandler struct {
	testHandler
	mu sync.Mutex
	in map[uint32][]string
}

func (h *vtHandler) VirtualTerminalWritten(_ context.Context, port uint32, data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.in == nil {
		h.in = map[uint32][]string{}
	}
	h.in[port] = append(h.in[port], string(data))
}

// Covers: SIG-IPE-6497
// TestVirtualTerminal: the master writes virtual terminal output blocks
// (g112) to an outstation port, which hands them to its handler; what the
// port answers goes to the master as virtual terminal events (g113), one
// per output even when repeated; g112 is never read or in class 0.
func TestVirtualTerminal(t *testing.T) {
	h := &vtHandler{}
	o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.Handler = h })
	if err := o.db.Define(dnp3.DBPoint{Type: "virtual-terminal", Index: 1, Class: 1}); err != nil {
		t.Fatal(err)
	}
	m := o.master(t, nil, nil)
	ctx := context.Background()
	w, err := dnp3.EncodeBlock(112, 5, dnp3.Q16Index16, []dnp3.Point{{Index: 1, Raw: []byte("help\r")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Request(ctx, dnp3.FCWrite, w); err != nil {
		t.Fatalf("write g112: %v", err)
	}
	h.mu.Lock()
	if got := h.in[1]; len(got) != 1 || got[0] != "help\r" {
		t.Errorf("port 1 received %q", got)
	}
	h.mu.Unlock()
	w, _ = dnp3.EncodeBlock(112, 1, dnp3.Q16Index16, []dnp3.Point{{Index: 7, Raw: []byte("x")}})
	if _, err := m.Request(ctx, dnp3.FCWrite, w); err == nil {
		t.Error("a write to an undefined port was taken")
	}
	for range 2 {
		if err := o.db.VirtualTerminalOutput(ctx, 1, []byte("ok>")); err != nil {
			t.Fatal(err)
		}
	}
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range frags {
		bl, _ := dnp3.ParseObjects(f.Objects, true)
		for _, b := range bl {
			for _, p := range b.Points {
				if p.Group == 113 && p.Var == 3 && p.Index == 1 && string(p.Raw) == "ok>" {
					n++
				}
			}
		}
	}
	if n != 2 {
		t.Errorf("%d virtual terminal events, want 2", n)
	}
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frags {
		bl, _ := dnp3.ParseObjects(f.Objects, true)
		for _, b := range bl {
			if b.Header.Group == 112 {
				t.Error("class 0 carries g112")
			}
		}
	}
	if _, err := m.Request(ctx, dnp3.FCRead, []byte{112, 0, dnp3.QAll}); err == nil {
		t.Error("a read of g112 was answered")
	}
}
