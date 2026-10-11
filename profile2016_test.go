package dnp3_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// Behaviour the device profile declares for the items the 2016 template
// added (1.5.9, 1.7.9, 1.13).

// Covers: SIG-IPE-2670
func TestControlStatusCodes(t *testing.T) {
	// The master names every code 1 to 18, 126 and 127 (1.5.9).
	codes := []uint8{126, 127}
	for c := uint8(1); c <= 18; c++ {
		codes = append(codes, c)
	}
	for _, c := range codes {
		if strings.HasPrefix(dnp3.StatusName(c), "status-") {
			t.Errorf("status %d has no name", c)
		}
	}
	if dnp3.StatusName(19) != "status-19" {
		t.Errorf("status 19: %s", dnp3.StatusName(19))
	}
	o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.MaxControls = 1 })
	m := o.master(t, nil, nil)
	ctx := context.Background()
	crob := dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}
	statuses := func(frags []dnp3.Fragment) []uint8 {
		var out []uint8
		for _, f := range frags {
			for _, b := range blocks(t, f, true) {
				for _, p := range b.Points {
					out = append(out, p.Status)
				}
			}
		}
		return out
	}
	// Two outputs above maxControls 1: TOO_MANY_OBJS (8), none operated.
	two, _ := dnp3.EncodeBlock(12, 1, dnp3.Q16Index16, []dnp3.Point{{Index: 0, CROB: crob}, {Index: 1, CROB: crob}})
	frags, err := m.Request(ctx, dnp3.FCDirectOperate, two)
	if st := statuses(frags); err != nil || len(st) != 2 || st[0] != 8 || st[1] != 8 {
		t.Fatalf("too many: %v %v", err, st)
	}
	o.h.mu.Lock()
	if len(o.h.controls) != 0 {
		t.Fatalf("operated %+v", o.h.controls)
	}
	o.h.mu.Unlock()
	// A pattern control block whose mask selects nothing: FORMAT_ERROR (3).
	pcb, _ := dnp3.EncodeBlock(12, 2, dnp3.Q8Count, []dnp3.Point{{CROB: crob}})
	mask, _ := dnp3.EncodeBlock(12, 3, dnp3.Q8StartStop, []dnp3.Point{{Index: 0, Value: false}})
	frags, err = m.Request(ctx, dnp3.FCDirectOperate, append(pcb, mask...))
	if st := statuses(frags); err != nil || len(st) == 0 || st[0] != 3 {
		t.Fatalf("empty pattern: %v %v", err, st)
	}
	// The application's refusal is echoed: HARDWARE_ERROR (6) and
	// NOT_AUTHORIZED (9), the codes the dnp3-server kind maps CSE
	// refusals to.
	for _, want := range []uint8{6, 9} {
		o.h.mu.Lock()
		o.h.status = want
		o.h.mu.Unlock()
		frags, err = m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0))
		if st := statuses(frags); err != nil || len(st) != 1 || st[0] != want {
			t.Fatalf("status %d: %v %v", want, err, st)
		}
	}
}

// Covers: SIG-IPE-2671
func TestOutstationBroadcastFunctions(t *testing.T) {
	for _, on := range []bool{true, false} {
		o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.Broadcast = on })
		c, lp := rawClient(t, o.url)
		// A link status first, so that the association is up.
		b, _ := dnp3.Frame{Ctrl: dnp3.CtrlDIR | dnp3.CtrlPRM | dnp3.LinkRequestLinkStatus, Dest: 10, Src: 1}.Encode()
		_, _ = c.Write(b)
		_ = readFrags(t, c, lp, 200*time.Millisecond)
		at := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
		clock, _ := dnp3.EncodeBlock(50, 1, dnp3.Q8Count, []dnp3.Point{{Value: at}})
		freeze := dnp3.AppendHeader(nil, 20, 0, dnp3.QAll, 0, 0)
		assign := dnp3.AssignClass([]dnp3.ClassAssignment{{Class: 3, Headers: [][]byte{dnp3.AppendHeader(nil, 30, 0, dnp3.QAll, 0, 0)}}})
		reqs := []dnp3.Fragment{
			{Func: dnp3.FCWrite, Objects: clock},
			{Func: dnp3.FCDirectOperate, Objects: crobObjs(t, 0)},
			{Func: dnp3.FCDirectOperateNR, Objects: crobObjs(t, 0)},
			{Func: dnp3.FCImmedFreeze, Objects: freeze},
			{Func: dnp3.FCAssignClass, Objects: assign},
		}
		for i, dest := range []uint16{dnp3.AddrBroadcastNoConfirm, dnp3.AddrBroadcastMandatory, dnp3.AddrBroadcastOptional, dnp3.AddrBroadcastOptional, dnp3.AddrBroadcastNoConfirm} {
			f := reqs[i]
			f.Control = dnp3.AppFIR | dnp3.AppFIN | uint8(i)
			sendFrag(t, c, dest, f)
			if frs := readFrags(t, c, lp, 200*time.Millisecond); len(frs) != 0 {
				t.Fatalf("broadcast %s was answered: %+v", dnp3.FuncName(f.Func), frs)
			}
		}
		o.h.mu.Lock()
		timeSet, controls := o.h.timeSet, len(o.h.controls)
		o.h.mu.Unlock()
		fc, _ := o.db.Point("frozen-counter", 0)
		an, _ := o.db.Point("analog", 0)
		executed := timeSet.Equal(at) && controls == 2 && fc.Value == 42 && an.Class == 3
		none := timeSet.IsZero() && controls == 0 && fc.Value != 42 && an.Class == 2
		if on && !executed || !on && !none {
			t.Errorf("broadcast %v: time %v, controls %d, frozen %v, analog class %d", on, timeSet, controls, fc.Value, an.Class)
		}
	}
}

// Covers: SIG-IPE-2673
func TestOutstationSettingsKeptThroughRestart(t *testing.T) {
	o := startOutstation(t, nil)
	m := o.master(t, nil, nil)
	ctx := context.Background()
	assign := dnp3.AssignClass([]dnp3.ClassAssignment{{Class: 3, Headers: [][]byte{dnp3.AppendHeader(nil, 30, 0, dnp3.QAll, 0, 0)}}})
	if _, err := m.Request(ctx, dnp3.FCAssignClass, assign); err != nil {
		t.Fatal(err)
	}
	db, _ := dnp3.EncodeBlock(34, 1, dnp3.Q8StartStop, []dnp3.Point{{Index: 0, Value: 7.0}})
	if _, err := m.Request(ctx, dnp3.FCWrite, db); err != nil {
		t.Fatal(err)
	}
	for _, fc := range []byte{dnp3.FCColdRestart, dnp3.FCWarmRestart} {
		if _, err := m.Request(ctx, fc, nil); err != nil {
			t.Fatalf("%s: %v", dnp3.FuncName(fc), err)
		}
		if p, _ := o.db.Point("analog", 0); p.Class != 3 || p.Deadband != 7 {
			t.Fatalf("after %s: class %d, deadband %v", dnp3.FuncName(fc), p.Class, p.Deadband)
		}
	}
}

// Covers: SIG-IPE-2674
func TestOutstationAttributesNotServed(t *testing.T) {
	o := startOutstation(t, nil)
	m := o.master(t, nil, nil)
	for _, v := range []uint8{200, 201, 206, 207, 208, 244} {
		frags, _ := m.Request(context.Background(), dnp3.FCRead, dnp3.AppendHeader(nil, 0, v, dnp3.Q8StartStop, 0, 0))
		if len(frags) != 1 || frags[0].IIN&dnp3.IINObjectUnknown == 0 || len(frags[0].Objects) != 0 {
			t.Errorf("g0v%d: %+v", v, frags)
		}
	}
}
