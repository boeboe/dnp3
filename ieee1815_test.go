package dnp3_test

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// Vectors from IEEE Std 1815-2012: the octet examples of clauses 4, 8 and
// 9 and Annex E are rebuilt here from their field values and compared
// octet for octet (facts only; the standard's text is not reproduced).

// hx decodes space-separated hex octets.
func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func frag(t *testing.T, s string) dnp3.Fragment {
	t.Helper()
	f, err := dnp3.ParseFragment(hx(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func blocks(t *testing.T, f dnp3.Fragment, withData bool) []dnp3.Block {
	t.Helper()
	b, err := dnp3.ParseObjects(f.Objects, withData)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-1580
func TestIEEE1815LinkFrameVector(t *testing.T) {
	// 9.2.4.3: TEST_LINK_STATES from 65519 to 1, DIR, PRM, FCB and FCV set.
	f := dnp3.Frame{Ctrl: dnp3.CtrlDIR | dnp3.CtrlPRM | dnp3.CtrlFCB | dnp3.CtrlFCV | dnp3.LinkTestLinkStates, Dest: 1, Src: 65519}
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := hx(t, "05 64 05 F2 01 00 EF FF BF B5"); !bytes.Equal(b, want) {
		t.Fatalf("frame % X, want % X", b, want)
	}
	g, err := dnp3.DecodeFrame(b)
	if err != nil || g.Func() != dnp3.LinkTestLinkStates || !g.FCB() || !g.FCV() || !g.FromMaster() || !g.Primary() {
		t.Fatalf("decoded %+v %v", g, err)
	}
	// A frame with the largest user data: 250 octets, 16-octet blocks.
	data := bytes.Repeat([]byte{0xA5}, dnp3.MaxLinkData)
	b, err = dnp3.Frame{Ctrl: dnp3.CtrlPRM | dnp3.LinkUnconfirmedUserData, Dest: 1, Src: 2, Data: data}.Encode()
	if err != nil || len(b) != 292 || b[2] != 255 {
		t.Fatalf("largest frame is %d octets (length %d), want 292 and 255: %v", len(b), b[2], err)
	}
	if _, err := (dnp3.Frame{Data: make([]byte, 251)}).Encode(); err == nil {
		t.Fatal("251 octets of user data were accepted")
	}
}

// Covers: SIG-IPE-1580
func TestIEEE1815AnnexECRCTable(t *testing.T) {
	// Annex E table look-up values (first row, entry 128 and the last).
	want := map[int]uint16{0: 0x0000, 1: 0x365E, 2: 0x6CBC, 3: 0x5AE2, 4: 0xD978, 5: 0xEF26, 6: 0xB5C4, 7: 0x839A, 128: 0xA6BC, 255: 0x1235}
	for i, w := range want {
		if got := dnp3.CRCTableEntry(byte(i)); got != w {
			t.Errorf("table[%d] = %04X, want %04X", i, got, w)
		}
	}
	// The result is inverted and sent low octet first (Figure 9-7).
	if got := dnp3.CRC([]byte("123456789")); got != 0xEA82 {
		t.Errorf("check value %04X", got)
	}
}

// Covers: SIG-IPE-1581
func TestIEEE1815LinkSecondaryStation(t *testing.T) {
	prim := func(fc byte, fcb, fcv bool) dnp3.Frame {
		c := dnp3.CtrlDIR | dnp3.CtrlPRM | fc
		if fcb {
			c |= dnp3.CtrlFCB
		}
		if fcv {
			c |= dnp3.CtrlFCV
		}
		return dnp3.Frame{Ctrl: c, Dest: 10, Src: 1, Data: []byte{0xC0}}
	}
	var s dnp3.Secondary
	type step struct {
		f       dnp3.Frame
		respond bool
		fc      byte
		deliver bool
	}
	steps := []step{
		// Not reset: confirmed data and test link states are NACKed and not passed up (9.2.7.2).
		{prim(dnp3.LinkConfirmedUserData, true, true), true, dnp3.LinkNack, false},
		{prim(dnp3.LinkTestLinkStates, true, true), true, dnp3.LinkNack, false},
		// Unconfirmed data: no response, passed up; request link status: LINK_STATUS.
		{prim(dnp3.LinkUnconfirmedUserData, false, false), false, 0, true},
		{prim(dnp3.LinkRequestLinkStatus, false, false), true, dnp3.LinkStatus, false},
		// Reset: ACK; the next FCV frame must carry FCB 1 (9.2.6.1).
		{prim(dnp3.LinkResetLinkStates, false, false), true, dnp3.LinkAck, false},
		{prim(dnp3.LinkConfirmedUserData, true, true), true, dnp3.LinkAck, true},
		// A repeat (same FCB) is acknowledged but not passed up (9.2.6.3).
		{prim(dnp3.LinkConfirmedUserData, true, true), true, dnp3.LinkAck, false},
		{prim(dnp3.LinkConfirmedUserData, false, true), true, dnp3.LinkAck, true},
		// TEST_LINK_STATES with the expected FCB: ACK and toggle; repeated: the same answer.
		{prim(dnp3.LinkTestLinkStates, true, true), true, dnp3.LinkAck, false},
		{prim(dnp3.LinkTestLinkStates, true, true), true, dnp3.LinkAck, false},
		// Wrong FCV for the function code: discarded (9.2.9).
		{prim(dnp3.LinkUnconfirmedUserData, false, true), false, 0, false},
		{prim(dnp3.LinkConfirmedUserData, false, false), false, 0, false},
		{prim(dnp3.LinkResetLinkStates, false, true), false, 0, false},
		// Reserved and obsolete codes: NOT_SUPPORTED (Table 9-1).
		{prim(1, false, false), true, dnp3.LinkNotSupported, false},
		{prim(14, false, false), true, dnp3.LinkNotSupported, false},
	}
	for i, st := range steps {
		a := s.Handle(st.f)
		if a.Respond != st.respond || (st.respond && a.Func != st.fc) || a.Deliver != st.deliver {
			t.Errorf("step %d (fc %d): got %+v, want respond %v fc %d deliver %v", i, st.f.Func(), a, st.respond, st.fc, st.deliver)
		}
	}
	// Codes 0, 2, 3, 4 and 9 are never answered with NOT_SUPPORTED.
	for _, fc := range []byte{0, 2, 3, 4, 9} {
		fcv := fc == 2 || fc == 3
		var fresh dnp3.Secondary
		if a := fresh.Handle(prim(fc, fcv, fcv)); a.Func == dnp3.LinkNotSupported && a.Respond {
			t.Errorf("function %d answered NOT_SUPPORTED", fc)
		}
	}
}

// Covers: SIG-IPE-1582
func TestIEEE1815LinkAddresses(t *testing.T) {
	for _, a := range []uint16{0xFFFD, 0xFFFE, 0xFFFF} {
		if !dnp3.IsBroadcast(a) {
			t.Errorf("%04X is a broadcast address", a)
		}
		var s dnp3.Secondary
		// Nothing is answered to a broadcast, whatever the function code.
		for _, fc := range []byte{0, 2, 3, 4, 9, 7} {
			fcv := fc == 2 || fc == 3
			c := dnp3.CtrlDIR | dnp3.CtrlPRM | fc
			if fcv {
				c |= dnp3.CtrlFCV | dnp3.CtrlFCB
			}
			act := s.Handle(dnp3.Frame{Ctrl: c, Dest: a, Src: 1})
			if act.Respond {
				t.Errorf("broadcast %04X function %d was answered", a, fc)
			}
			if act.Deliver != (fc == dnp3.LinkUnconfirmedUserData) {
				t.Errorf("broadcast %04X function %d delivered %v", a, fc, act.Deliver)
			}
		}
	}
	for a := uint16(0xFFF0); a <= 0xFFFB; a++ {
		if !dnp3.IsReservedAddress(a) || dnp3.IsBroadcast(a) {
			t.Errorf("%04X is reserved", a)
		}
	}
	if dnp3.IsReservedAddress(dnp3.AddrSelf) || dnp3.IsReservedAddress(0xFFEF) || dnp3.IsBroadcast(dnp3.AddrSelf) {
		t.Error("0xFFEF and the self-address are not reserved")
	}
}

// Covers: SIG-IPE-1580
func TestIEEE1815LinkPrimaryFCB(t *testing.T) {
	var p dnp3.Primary
	p.ResetDone()
	c := p.Control(dnp3.CtrlDIR)
	if c != dnp3.CtrlDIR|dnp3.CtrlPRM|dnp3.CtrlFCB|dnp3.CtrlFCV|dnp3.LinkConfirmedUserData {
		t.Fatalf("first confirmed frame after reset: %02X", c)
	}
	p.Acked()
	if p.Control(0)&dnp3.CtrlFCB != 0 {
		t.Fatal("FCB not toggled after ACK")
	}
}

// Covers: SIG-IPE-1585
func TestIEEE1815TransportRules(t *testing.T) {
	// EX 8-1: a 600-octet fragment in three segments, 249 + 249 + 102,
	// sequence n, n+1, n+2.
	apdu := make([]byte, 600)
	for i := range apdu {
		apdu[i] = byte(i)
	}
	seq := uint8(25)
	segs := dnp3.Segment(apdu, &seq)
	if len(segs) != 3 || segs[0][0] != dnp3.TransportFIR|25 || segs[1][0] != 26 || segs[2][0] != dnp3.TransportFIN|27 ||
		len(segs[0]) != 250 || len(segs[1]) != 250 || len(segs[2]) != 103 {
		t.Fatalf("segments: %d, headers %02X %02X %02X", len(segs), segs[0][0], segs[1][0], segs[2][0])
	}
	if segs[1][1] != 249 || segs[2][1] != apdu[498] {
		t.Fatal("octet order not preserved")
	}
	var r dnp3.Reassembler
	// Rule 3: no series in progress, no FIR: discarded.
	if out, err := r.Add(segs[1]); out != nil || err == nil {
		t.Fatal("segment without FIR accepted")
	}
	// Rule 5.3: an identical repeat is discarded without ending the series.
	if out, err := r.Add(segs[0]); out != nil || err != nil {
		t.Fatal(err)
	}
	if out, err := r.Add(segs[1]); out != nil || err != nil {
		t.Fatal(err)
	}
	if out, err := r.Add(segs[1]); out != nil || err != nil {
		t.Fatalf("identical repeat: %v", err)
	}
	out, err := r.Add(segs[2])
	if err != nil || !bytes.Equal(out, apdu) {
		t.Fatalf("reassembled %d octets: %v", len(out), err)
	}
	// Rule 5.2: a new FIR discards the series in progress.
	_, _ = r.Add(segs[0])
	single := []byte{dnp3.TransportFIR | dnp3.TransportFIN | 5, 0xC1, 0x00}
	if out, err := r.Add(single); err != nil || !bytes.Equal(out, []byte{0xC1, 0x00}) {
		t.Fatalf("FIR restart: % X %v", out, err)
	}
	// Rule 5.4: a different segment out of sequence ends the series.
	_, _ = r.Add(segs[0])
	bad := append([]byte{28}, segs[1][1:]...)
	if _, err := r.Add(bad); err == nil {
		t.Fatal("out-of-sequence segment accepted")
	}
	if out, _ := r.Add(segs[2]); out != nil {
		t.Fatal("series survived an out-of-sequence segment")
	}
	// Sequence numbers wrap after 63.
	seq = 63
	segs = dnp3.Segment(make([]byte, 300), &seq)
	if segs[0][0]&0x3F != 63 || segs[1][0]&0x3F != 0 {
		t.Fatalf("wrap: %02X %02X", segs[0][0], segs[1][0])
	}
}

// Covers: SIG-IPE-1586
func TestIEEE1815ApplicationHeader(t *testing.T) {
	names := map[byte]string{0: "CONFIRM", 8: "IMMED_FREEZE_NR", 11: "FREEZE_AT_TIME", 14: "WARM_RESTART", 22: "ASSIGN_CLASS",
		25: "OPEN_FILE", 28: "GET_FILE_INFO", 31: "ACTIVATE_CONFIG", 33: "AUTH_REQUEST_NO_ACK", 131: "AUTH_RESPONSE"}
	for fc, n := range names {
		if dnp3.FuncName(fc) != n {
			t.Errorf("function %d is %s, want %s", fc, dnp3.FuncName(fc), n)
		}
	}
	for fc := 34; fc <= 128; fc++ {
		if !strings.HasPrefix(dnp3.FuncName(byte(fc)), "function ") {
			t.Errorf("reserved function %d has a name", fc)
		}
	}
	for _, fc := range []byte{6, 8, 10, 12, 33} {
		if !dnp3.NoResponse(fc) {
			t.Errorf("function %d gets no response", fc)
		}
	}
	// Figure 4-8 / Table 4-3: every IIN bit named, in octet order.
	all := dnp3.IIN(0xFFFF).Names()
	want := []string{"broadcast", "class-1-events", "class-2-events", "class-3-events", "need-time", "local-control",
		"device-trouble", "device-restart", "no-func-code-support", "object-unknown", "parameter-error",
		"event-buffer-overflow", "already-executing", "config-corrupt", "reserved-2.6", "reserved-2.7"}
	if strings.Join(all, ",") != strings.Join(want, ",") {
		t.Fatalf("IIN names %v", all)
	}
	// EX 4-13: a null response with IIN1.2 set.
	f := frag(t, "C3 81 04 00")
	if f.Seq() != 3 || f.Control&dnp3.AppCON != 0 || f.IIN != dnp3.IINClass2Events || len(f.Objects) != 0 {
		t.Fatalf("%+v", f)
	}
}

// Covers: SIG-IPE-1587
func TestIEEE1815Qualifiers(t *testing.T) {
	valid := map[uint8]bool{}
	for _, q := range []uint8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x17, 0x18, 0x19, 0x27, 0x28, 0x29, 0x37, 0x38, 0x39, 0x4B, 0x5B, 0x6B} {
		valid[q] = true
	}
	for q := range 256 {
		if dnp3.ValidQualifier(uint8(q)) != valid[uint8(q)] {
			t.Errorf("qualifier %02X valid %v", q, !valid[uint8(q)])
		}
	}
	// Each range form round-trips through a header.
	for _, c := range []struct {
		q    uint8
		a, b uint32
		n    uint32
	}{{0x00, 4, 7, 4}, {0x01, 300, 301, 2}, {0x02, 70000, 70002, 3}, {0x07, 20, 0, 20}, {0x08, 300, 0, 300}, {0x09, 70000, 0, 70000}} {
		raw := dnp3.AppendHeader(nil, 30, 0, c.q, c.a, c.b)
		bl, err := dnp3.ParseObjects(raw, false)
		if err != nil || len(bl) != 1 || bl[0].Header.Count != c.n {
			t.Errorf("qualifier %02X: %+v %v", c.q, bl, err)
		}
	}
	// 4-octet index prefix (0x39) and 1-octet size prefix (0x4B).
	raw, err := dnp3.EncodeBlock(30, 1, dnp3.Q32Index32, []dnp3.Point{{Index: 70000, Value: 5.0, HasFlags: true, Flags: 1}})
	if err != nil {
		t.Fatal(err)
	}
	bl, err := dnp3.ParseObjects(raw, true)
	if err != nil || bl[0].Points[0].Index != 70000 || bl[0].Points[0].Value != 5.0 {
		t.Fatalf("%+v %v", bl, err)
	}
	raw, err = dnp3.EncodeBlock(70, 8, dnp3.QSize8, []dnp3.Point{{Raw: []byte("Config.bin")}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, append(hx(t, "46 08 4B 01 0A"), "Config.bin"...)) {
		t.Fatalf("% X", raw)
	}
	if _, err := dnp3.ParseObjects([]byte{30, 1, 0x80, 0, 0}, true); err == nil {
		t.Fatal("reserved bit 7 accepted")
	}
	if _, err := dnp3.ParseObjects([]byte{70, 3, 0x07, 1, 0}, true); err == nil {
		t.Fatal("a free-format object without a size prefix was accepted")
	}
}

// Covers: SIG-IPE-1588
func TestIEEE1815ReadExamples(t *testing.T) {
	// EX 4-9: analog inputs 4 to 7 as 16-bit with flags.
	req, _ := dnp3.EncodeBlock(30, 2, dnp3.Q8StartStop, nil)
	_ = req
	if got := append([]byte{0xC3, dnp3.FCRead}, dnp3.AppendHeader(nil, 30, 2, dnp3.Q8StartStop, 4, 7)...); !bytes.Equal(got, hx(t, "C3 01 1E 02 00 04 07")) {
		t.Fatalf("% X", got)
	}
	resp := "C3 81 00 00 1E 02 00 04 07 01 88 13 01 20 4E 01 50 FB 01 60 00"
	bl := blocks(t, frag(t, resp), true)
	wantV := []float64{5000, 20000, -1200, 96}
	var pts []dnp3.Point
	for i, p := range bl[0].Points {
		if p.Index != uint32(4+i) || p.Value != wantV[i] || p.Quality() != "good" {
			t.Errorf("point %d: %+v", i, p)
		}
		pts = append(pts, dnp3.Point{Index: p.Index, Value: p.Value, Flags: p.Flags, HasFlags: true})
	}
	enc, err := dnp3.EncodeBlock(30, 2, dnp3.Q8StartStop, pts)
	if err != nil || !bytes.Equal(dnp3.Fragment{Control: 0xC3, Func: dnp3.FCResponse, Objects: enc}.Encode(), hx(t, resp)) {
		t.Fatalf("re-encoded % X %v", enc, err)
	}
	// The same without flags (variation 4).
	bl = blocks(t, frag(t, "C3 81 00 00 1E 04 00 04 07 88 13 20 4E 50 FB 60 00"), true)
	if bl[0].Points[3].Value != 96.0 || bl[0].Points[2].Value != -1200.0 {
		t.Fatalf("%+v", bl[0].Points)
	}
	// EX 4-10: 18 packed binary inputs.
	bl = blocks(t, frag(t, "C3 81 00 00 01 01 00 00 11 0F AA 03"), true)
	if len(bl[0].Points) != 18 {
		t.Fatalf("%d points", len(bl[0].Points))
	}
	for i, p := range bl[0].Points {
		want := i < 4 || (i >= 8 && i < 16 && i%2 == 1) || i >= 16
		if p.Value != want {
			t.Errorf("binary %d = %v", i, p.Value)
		}
	}
	// EX 4-11: class 1 and 2 request; the response's events in their order.
	if got := dnp3.ClassRequest(1, 2); !bytes.Equal(got, hx(t, "3C 02 06 3C 03 06")) {
		t.Fatalf("% X", got)
	}
	f := frag(t, "E3 81 06 00 02 01 17 01 14 81 02 01 17 01 05 01 20 02 17 01 0B 20 FF FF 02 01 17 01 03 81")
	if f.Control&dnp3.AppCON == 0 || f.IIN != dnp3.IINClass1Events|dnp3.IINClass2Events {
		t.Fatalf("%+v", f)
	}
	bl = blocks(t, f, true)
	type ev struct {
		g   uint8
		idx uint32
		v   any
	}
	var got []ev
	for _, b := range bl {
		for _, p := range b.Points {
			got = append(got, ev{p.Group, p.Index, p.Value})
		}
	}
	want := []ev{{2, 20, true}, {2, 5, false}, {32, 11, -1.0}, {2, 3, true}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	// The analog event's flag octet is 0x20: over-range, ONLINE clear.
	if q := bl[2].Points[0].Quality(); q != "offline,over-range" {
		t.Errorf("quality %q", q)
	}
	// Its confirmation echoes the sequence number: C3 00.
	if c := (dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | f.Seq(), Func: dnp3.FCConfirm}).Encode(); !bytes.Equal(c, hx(t, "C3 00")) {
		t.Fatalf("% X", c)
	}
	// EX 4-12: up to 20 binary input events, any variation.
	if got := dnp3.AppendHeader(nil, 2, 0, dnp3.Q8Count, 20, 0); !bytes.Equal(got, hx(t, "02 00 07 14")) {
		t.Fatalf("% X", got)
	}
	bl = blocks(t, frag(t, "E3 81 06 00 02 01 17 03 14 81 05 01 03 81"), true)
	if len(bl[0].Points) != 3 || bl[0].Points[1].Index != 5 || bl[0].Points[1].Value != false {
		t.Fatalf("%+v", bl[0].Points)
	}
}

// Covers: SIG-IPE-1588
func TestIEEE1815WriteAndControlExamples(t *testing.T) {
	// EX 4-14: clear IIN1.7.
	objs, _ := dnp3.EncodeBlock(80, 1, dnp3.Q8StartStop, []dnp3.Point{{Index: 7, Value: false}})
	if !bytes.Equal(objs, hx(t, "50 01 00 07 07 00")) {
		t.Fatalf("% X", objs)
	}
	// EX 4-15: analog deadbands for 6, 8 and 20 (g34v1, 1-octet index).
	objs, err := dnp3.EncodeBlock(34, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 6, Value: 18.0}, {Index: 8, Value: 74.0}, {Index: 20, Value: 65535.0}})
	if err != nil || !bytes.Equal(objs, hx(t, "22 01 17 03 06 12 00 08 4A 00 14 FF FF")) {
		t.Fatalf("% X %v", objs, err)
	}
	// EX 4-16: write the time (g50v1, count 1).
	ms := int64(0x01084000E9AC)
	objs, _ = dnp3.EncodeBlock(50, 1, dnp3.Q8Count, []dnp3.Point{{Value: time.UnixMilli(ms)}})
	if !bytes.Equal(objs, hx(t, "32 01 07 01 AC E9 00 40 08 01")) {
		t.Fatalf("% X", objs)
	}
	// EX 4-17: select and operate of a CROB at index 10: close, pulse on, once, 250 ms.
	crob := dnp3.CROB{Code: dnp3.TCCClose | dnp3.OpPulseOn, Count: 1, OnTime: 250}
	objs, _ = dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 10, CROB: crob}})
	sel := dnp3.Fragment{Control: 0xC3, Func: dnp3.FCSelect, Objects: objs}.Encode()
	if !bytes.Equal(sel, hx(t, "C3 03 0C 01 17 01 0A 41 01 FA 00 00 00 00 00 00 00 00")) {
		t.Fatalf("% X", sel)
	}
	bl := blocks(t, frag(t, "C4 81 00 00 0C 01 17 01 0A 41 01 FA 00 00 00 00 00 00 00 00"), true)
	if bl[0].Points[0].CROB != crob || bl[0].Points[0].Status != 0 {
		t.Fatalf("%+v", bl[0].Points[0])
	}
	// EX 4-18: pattern control block and mask for points 5, 10 and 15; the
	// response's PCB status 4 with IIN2.2.
	pcb, _ := dnp3.EncodeBlock(12, 2, dnp3.Q8Count, []dnp3.Point{{CROB: dnp3.CROB{Code: 0x41, Count: 3, OnTime: 500, OffTime: 2000}}})
	var mask []dnp3.Point
	for i := uint32(5); i <= 15; i++ {
		mask = append(mask, dnp3.Point{Index: i, Value: i == 5 || i == 10 || i == 15})
	}
	pcm, _ := dnp3.EncodeBlock(12, 3, dnp3.Q8StartStop, mask)
	if got := append(pcb, pcm...); !bytes.Equal(got, hx(t, "0C 02 07 01 41 03 F4 01 00 00 D0 07 00 00 00 0C 03 00 05 0F 21 04")) {
		t.Fatalf("% X", got)
	}
	f := frag(t, "C3 81 00 04 0C 02 07 01 41 03 F4 01 00 00 D0 07 00 00 04 0C 03 00 05 0F 21 04")
	bl = blocks(t, f, true)
	if f.IIN != dnp3.IINParameterError || bl[0].Points[0].Status != 4 || len(bl[1].Points) != 11 || bl[1].Points[5].Value != true {
		t.Fatalf("%+v %+v", f, bl)
	}
	// EX 4-20: freeze all counters.
	if got := dnp3.AppendHeader(nil, 20, 0, dnp3.QAll, 0, 0); !bytes.Equal(got, hx(t, "14 00 06")) {
		t.Fatalf("% X", got)
	}
	// EX 4-21: freeze at time, 15 June 2001 14:02:00 UTC every 15 minutes.
	at := time.Date(2001, 6, 15, 14, 2, 0, 0, time.UTC)
	objs, _ = dnp3.EncodeBlock(50, 2, dnp3.Q8Count, []dnp3.Point{{Value: at, Interval: 900000}})
	if got := append(objs, dnp3.AppendHeader(nil, 20, 0, dnp3.QAll, 0, 0)...); !bytes.Equal(got, hx(t, "32 02 07 01 C0 5F 63 1C E7 00 A0 BB 0D 00 14 00 06")) {
		t.Fatalf("% X", got)
	}
	bl = blocks(t, dnp3.Fragment{Func: dnp3.FCFreezeAtTime, Objects: objs}, true)
	if bl[0].Points[0].Interval != 900000 || !bl[0].Points[0].Value.(time.Time).Equal(at) {
		t.Fatalf("%+v", bl[0].Points[0])
	}
	// EX 4-22 and 4-26: cold restart delay 45 s (g52v1), delay measurement 18 ms (g52v2).
	bl = blocks(t, frag(t, "C3 81 00 00 34 01 07 01 2D 00"), true)
	if bl[0].Points[0].Value != 45.0 {
		t.Fatalf("%+v", bl[0].Points[0])
	}
	bl = blocks(t, frag(t, "C3 81 00 00 34 02 07 01 12 00"), true)
	if bl[0].Points[0].Value != 18.0 || bl[0].Header.Var != 2 {
		t.Fatalf("%+v", bl[0].Points[0])
	}
	// EX 4-24: enable unsolicited responses for classes 1 to 3.
	if got := dnp3.ClassRequest(1, 2, 3); !bytes.Equal(got, hx(t, "3C 02 06 3C 03 06 3C 04 06")) {
		t.Fatalf("% X", got)
	}
	// EX 4-25: assign class (sets of a class header and point headers).
	asg := dnp3.AssignClass([]dnp3.ClassAssignment{
		{Class: 1, Headers: [][]byte{dnp3.AppendHeader(nil, 1, 0, dnp3.QAll, 0, 0)}},
		{Class: 2, Headers: [][]byte{dnp3.AppendHeader(nil, 30, 0, dnp3.QAll, 0, 0), dnp3.AppendHeader(nil, 21, 0, dnp3.Q8StartStop, 0, 2)}},
		{Class: 0, Headers: [][]byte{dnp3.AppendHeader(nil, 21, 0, dnp3.Q8StartStop, 3, 10)}},
	})
	if !bytes.Equal(asg, hx(t, "3C 02 06 01 00 06 3C 03 06 1E 00 06 15 00 00 00 02 3C 01 06 15 00 00 03 0A")) {
		t.Fatalf("% X", asg)
	}
}

// Covers: SIG-IPE-1595
func TestIEEE1815FileObjectExamples(t *testing.T) {
	// EX 4-28: open "ABC" for reading, block size 192, request ID 311.
	open := dnp3.FileCommand{Permissions: 0x01FF, Mode: dnp3.FileModeRead, MaxBlock: 192, RequestID: 311, Name: "ABC"}
	objs, err := dnp3.EncodeBlock(70, 3, dnp3.QFreeFormat, []dnp3.Point{{Raw: open.Encode()}})
	if err != nil {
		t.Fatal(err)
	}
	want := hx(t, "46 03 5B 01 1D 00 1A 00 03 00 00 00 00 00 00 00 FF 01 00 00 00 00 00 00 00 00 01 00 C0 00 37 01 41 42 43")
	if !bytes.Equal(objs, want) {
		t.Fatalf("% X\n% X", objs, want)
	}
	bl := blocks(t, dnp3.Fragment{Func: dnp3.FCOpenFile, Objects: objs}, true)
	back, err := dnp3.ParseFileCommand(bl[0].Points[0].Raw)
	if err != nil || back != open {
		t.Fatalf("%+v %v", back, err)
	}
	// EX 4-29: open for writing, 2048 octets, created at the given time.
	wr := dnp3.FileCommand{Created: time.UnixMilli(0x00EB1F8F4E80), Permissions: 0x01FF, Size: 2048, Mode: dnp3.FileModeWrite, MaxBlock: 2048, RequestID: 311, Name: "ABC"}
	if got := wr.Encode(); !bytes.Equal(got, hx(t, "1A 00 03 00 80 4E 8F 1F EB 00 FF 01 00 00 00 00 00 08 00 00 02 00 00 08 37 01 41 42 43")) {
		t.Fatalf("% X", got)
	}
	// The status answer: handle 0x99887766, 2048 octets, block 192.
	bl = blocks(t, frag(t, "EE 81 00 00 46 04 5B 01 0D 00 66 77 88 99 00 08 00 00 C0 00 37 01 00"), true)
	st, err := dnp3.ParseFileStatus(bl[0].Points[0].Raw)
	if err != nil || st.Handle != 0x99887766 || st.Size != 2048 || st.MaxBlock != 192 || st.RequestID != 311 || st.Status != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	// EX 4-30: close with that handle.
	cl := dnp3.FileStatus{Handle: 0x99887766, RequestID: 311}
	if got := cl.Encode(); !bytes.Equal(got, hx(t, "66 77 88 99 00 00 00 00 00 00 37 01 00")) {
		t.Fatalf("% X", got)
	}
	// EX 4-33: file information answer.
	bl = blocks(t, frag(t, "EE 81 00 00 46 07 5B 01 17 00 14 00 03 00 01 00 00 08 00 00 80 4E 8F 1F EB 00 FF 01 37 01 41 42 43"), true)
	d, err := dnp3.ParseFileDescriptor(bl[0].Points[0].Raw)
	if err != nil || d.Name != "ABC" || d.Type != 1 || d.Size != 2048 || d.Permissions != 0x01FF || d.RequestID != 311 || d.Created.UnixMilli() != 0x00EB1F8F4E80 {
		t.Fatalf("%+v %v", d, err)
	}
	// EX 4-34: authentication object with user SCADA and password ZEBRA;
	// the answer carries key 0xDDCCBBAA.
	a := dnp3.FileAuth{User: "SCADA", Password: "ZEBRA"}
	if got := a.Encode(); !bytes.Equal(got, hx(t, "0C 00 05 00 11 00 05 00 00 00 00 00 53 43 41 44 41 5A 45 42 52 41")) {
		t.Fatalf("% X", got)
	}
	ar, err := dnp3.ParseFileAuth(hx(t, "00 00 00 00 00 00 00 00 AA BB CC DD"))
	if err != nil || ar.Key != 0xDDCCBBAA {
		t.Fatalf("%+v %v", ar, err)
	}
	// File transport (g70v5) with the last bit; transport status (g70v6).
	tr := dnp3.FileTransport{Handle: 7, Block: 2, Last: true, Data: []byte("xyz")}
	if got := tr.Encode(); !bytes.Equal(got, hx(t, "07 00 00 00 02 00 00 80 78 79 7A")) {
		t.Fatalf("% X", got)
	}
	if back, err := dnp3.ParseFileTransport(tr.Encode()); err != nil || back.Block != 2 || !back.Last || string(back.Data) != "xyz" {
		t.Fatalf("%+v %v", back, err)
	}
}

// Covers: SIG-IPE-1589
func TestIEEE1815ObjectSizes(t *testing.T) {
	// Octets per object of each fixed-size variation (Annex A).
	sizes := map[[2]uint8]int{
		{1, 2}: 1, {2, 1}: 1, {2, 2}: 7, {2, 3}: 3, {3, 2}: 1, {4, 1}: 1, {4, 2}: 7, {4, 3}: 3,
		{10, 2}: 1, {11, 1}: 1, {11, 2}: 7, {12, 1}: 11, {12, 2}: 11, {13, 1}: 1, {13, 2}: 7,
		{20, 1}: 5, {20, 2}: 3, {20, 3}: 5, {20, 4}: 3, {20, 5}: 4, {20, 6}: 2, {20, 7}: 4, {20, 8}: 2,
		{21, 1}: 5, {21, 2}: 3, {21, 3}: 5, {21, 4}: 3, {21, 5}: 11, {21, 6}: 9, {21, 7}: 11, {21, 8}: 9, {21, 9}: 4, {21, 10}: 2, {21, 11}: 4, {21, 12}: 2,
		{22, 1}: 5, {22, 2}: 3, {22, 3}: 5, {22, 4}: 3, {22, 5}: 11, {22, 6}: 9, {22, 7}: 11, {22, 8}: 9,
		{23, 1}: 5, {23, 2}: 3, {23, 3}: 5, {23, 4}: 3, {23, 5}: 11, {23, 6}: 9, {23, 7}: 11, {23, 8}: 9,
		{30, 1}: 5, {30, 2}: 3, {30, 3}: 4, {30, 4}: 2, {30, 5}: 5, {30, 6}: 9,
		{31, 1}: 5, {31, 2}: 3, {31, 3}: 11, {31, 4}: 9, {31, 5}: 4, {31, 6}: 2, {31, 7}: 5, {31, 8}: 9,
		{32, 1}: 5, {32, 2}: 3, {32, 3}: 11, {32, 4}: 9, {32, 5}: 5, {32, 6}: 9, {32, 7}: 11, {32, 8}: 15,
		{33, 1}: 5, {33, 2}: 3, {33, 3}: 11, {33, 4}: 9, {33, 5}: 5, {33, 6}: 9, {33, 7}: 11, {33, 8}: 15,
		{34, 1}: 2, {34, 2}: 4, {34, 3}: 4,
		{40, 1}: 5, {40, 2}: 3, {40, 3}: 5, {40, 4}: 9, {41, 1}: 5, {41, 2}: 3, {41, 3}: 5, {41, 4}: 9,
		{42, 1}: 5, {42, 2}: 3, {42, 3}: 11, {42, 4}: 9, {42, 5}: 5, {42, 6}: 9, {42, 7}: 11, {42, 8}: 15,
		{43, 1}: 5, {43, 2}: 3, {43, 3}: 11, {43, 4}: 9, {43, 5}: 5, {43, 6}: 9, {43, 7}: 11, {43, 8}: 15,
		{50, 1}: 6, {50, 2}: 10, {50, 3}: 6, {50, 4}: 11, {51, 1}: 6, {51, 2}: 6, {52, 1}: 2, {52, 2}: 2,
		{81, 1}: 3, {101, 1}: 2, {101, 2}: 4, {101, 3}: 8, {102, 1}: 1, {120, 3}: 6, {120, 4}: 2,
		{121, 1}: 7, {122, 1}: 7, {122, 2}: 13,
	}
	for gvar, n := range sizes {
		if got := dnp3.ObjectSize(gvar[0], gvar[1]); got != n {
			t.Errorf("g%dv%d is %d octets, want %d", gvar[0], gvar[1], got, n)
		}
		// Decoding exactly n octets per object (two objects) succeeds, one
		// octet fewer fails.
		raw := append(dnp3.AppendHeader(nil, gvar[0], gvar[1], dnp3.Q8StartStop, 0, 1), make([]byte, 2*n)...)
		if gvar[0] == 2 || gvar[0] == 4 {
			if gvar[1] == 3 {
				raw = append(append(dnp3.AppendHeader(nil, 51, 1, dnp3.Q8Count, 1, 0), make([]byte, 6)...), raw...)
			}
		}
		if _, err := dnp3.ParseObjects(raw, true); err != nil {
			t.Errorf("g%dv%d: %v", gvar[0], gvar[1], err)
		}
		if _, err := dnp3.ParseObjects(raw[:len(raw)-1], true); err == nil {
			t.Errorf("g%dv%d: a truncated object was accepted", gvar[0], gvar[1])
		}
	}
	// Packed: g1v1, g3v1 (2 bits), g10v1, g12v3, g80v1.
	for _, g := range [][3]int{{1, 1, 1}, {3, 1, 2}, {10, 1, 1}, {12, 3, 1}, {80, 1, 1}} {
		if dnp3.PackedBits(uint8(g[0]), uint8(g[1])) != g[2] {
			t.Errorf("g%dv%d packs %d bits", g[0], g[1], g[2])
		}
	}
}

// Covers: SIG-IPE-1590
func TestIEEE1815MoreObjects(t *testing.T) {
	// g13v2: commanded state 1, status 4, with time; g43v1: status 7, value -5.
	at := time.UnixMilli(1_600_000_000_123).UTC()
	raw, err := dnp3.EncodeBlock(13, 2, dnp3.Q16Index16, []dnp3.Point{{Index: 3, Value: true, Status: 4, Time: at}})
	if err != nil {
		t.Fatal(err)
	}
	bl, err := dnp3.ParseObjects(raw, true)
	if err != nil || bl[0].Points[0].Value != true || bl[0].Points[0].Status != 4 || !bl[0].Points[0].Time.Equal(at) || raw[7] != 0x84 {
		t.Fatalf("% X %+v %v", raw, bl, err)
	}
	raw, _ = dnp3.EncodeBlock(43, 1, dnp3.Q16Index16, []dnp3.Point{{Index: 1, Value: -5.0, Status: 7}})
	bl, _ = dnp3.ParseObjects(raw, true)
	if bl[0].Points[0].Value != -5.0 || bl[0].Points[0].Status != 7 || raw[7] != 7 {
		t.Fatalf("% X %+v", raw, bl)
	}
	// g50v4: indexed time, interval 15 of unit 3 (minutes).
	raw, _ = dnp3.EncodeBlock(50, 4, dnp3.Q8StartStop, []dnp3.Point{{Index: 0, Value: at, Interval: 15, Units: 3}})
	bl, _ = dnp3.ParseObjects(raw, true)
	if p := bl[0].Points[0]; p.Interval != 15 || p.Units != 3 || !p.Value.(time.Time).Equal(at) {
		t.Fatalf("%+v", p)
	}
	// g81v1: 75 % full with overflow, for g32v0.
	bl, _ = dnp3.ParseObjects(hx(t, "51 01 07 01 CB 20 00"), true)
	if p := bl[0].Points[0]; p.Value != 75.0 || p.Flags != 0x80 || p.Ref != [2]uint8{32, 0} {
		t.Fatalf("%+v", p)
	}
	// g101: 0173 (BCD4), -57 (padded, sign in the top character), g102v1.
	bl, _ = dnp3.ParseObjects(hx(t, "65 01 00 00 01 73 01 57 F0"), true)
	if bl[0].Points[0].Value != 173.0 || bl[0].Points[1].Value != -57.0 {
		t.Fatalf("%+v", bl[0].Points)
	}
	bl, _ = dnp3.ParseObjects(hx(t, "66 01 00 00 00 FE"), true)
	if bl[0].Points[0].Value != 254.0 {
		t.Fatalf("%+v", bl[0].Points)
	}
	// g110 and g112: the variation is the length (EX 11-3 octet string).
	raw, err = dnp3.EncodeBlock(110, 3, dnp3.Q8StartStop, []dnp3.Point{{Index: 4, Raw: []byte{0x0A, 0x3F, 0xC7}}})
	if err != nil || !bytes.Equal(raw, hx(t, "6E 03 00 04 04 0A 3F C7")) {
		t.Fatalf("% X %v", raw, err)
	}
	bl, _ = dnp3.ParseObjects(hx(t, "71 02 17 02 01 68 69 02 6F 6B"), true)
	if string(bl[0].Points[0].Raw) != "hi" || bl[0].Points[1].Index != 2 {
		t.Fatalf("%+v", bl[0].Points)
	}
	if _, err := dnp3.EncodeBlock(110, 3, dnp3.Q8StartStop, []dnp3.Point{{Raw: []byte{1}}}); err == nil {
		t.Fatal("an octet string shorter than its variation was accepted")
	}
	// g121v1 and g122v2: security statistic with association and count.
	raw, _ = dnp3.EncodeBlock(122, 2, dnp3.Q16Index16, []dnp3.Point{{Index: 5, Flags: 1, HasFlags: true, Assoc: 2, Value: 40.0, Time: at}})
	bl, _ = dnp3.ParseObjects(raw, true)
	if p := bl[0].Points[0]; p.Assoc != 2 || p.Value != 40.0 || !p.Time.Equal(at) || p.Index != 5 {
		t.Fatalf("%+v", p)
	}
	// g34v3 deadband float; g31v7 frozen analog float with flags.
	raw, _ = dnp3.EncodeBlock(34, 3, dnp3.Q8StartStop, []dnp3.Point{{Index: 0, Value: 0.5}})
	bl, _ = dnp3.ParseObjects(raw, true)
	if bl[0].Points[0].Value != 0.5 {
		t.Fatalf("%+v", bl[0].Points)
	}
	if dnp3.Family(31) != "frozen-analog" || dnp3.Family(33) != "frozen-analog" || dnp3.Family(13) != "" {
		t.Fatal("families")
	}
	if math.IsNaN(0) {
		t.Fatal()
	}
}

// Covers: SIG-IPE-1591
func TestIEEE1815DeviceAttributeTypes(t *testing.T) {
	// Table 5-16: a list of UINT8-BSTR8 pairs (254) and an extended list
	// whose length is 256 plus the length octet (255).
	raw := append(dnp3.AppendHeader(nil, 0, 255, dnp3.Q8StartStop, 0, 0), dnp3.AttrList, 4, 240, 0, 247, 1)
	bl, err := dnp3.ParseObjects(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := bl[0].Points[0].Value.([]any)
	if len(list) != 2 || list[1].(map[string]any)["variation"] != 247.0 || list[1].(map[string]any)["properties"] != 1.0 {
		t.Fatalf("%+v", bl[0].Points[0].Value)
	}
	ext := append(dnp3.AppendHeader(nil, 0, 255, dnp3.Q8StartStop, 0, 0), dnp3.AttrExtList, 2)
	ext = append(ext, make([]byte, 258)...)
	bl, err = dnp3.ParseObjects(ext, true)
	if err != nil || len(bl[0].Points[0].Value.([]any)) != 129 {
		t.Fatalf("extended list: %v", err)
	}
	for v, n := range map[uint8]string{209: "secure-auth-version", 210: "security-statistics-count", 236: "double-bit-inputs", 239: "binary-inputs", 241: "max-rx-fragment"} {
		if dnp3.AttributeName(v) != n {
			t.Errorf("attribute %d is %s", v, dnp3.AttributeName(v))
		}
	}
}
