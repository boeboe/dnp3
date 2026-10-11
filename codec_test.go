package dnp3_test

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/bits"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// refCRC is an independent bit-by-bit DNP3 CRC: polynomial 0x3D65 shifted
// most significant bit first, with reflected input and output and a
// complemented result.
func refCRC(b []byte) uint16 {
	var crc uint16
	for _, x := range b {
		crc ^= uint16(bits.Reverse8(x)) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x3D65
			} else {
				crc <<= 1
			}
		}
	}
	return ^bits.Reverse16(crc)
}

// crcCheck is the catalogue check value of CRC-16/DNP over "123456789".
var crcCheck uint16 = 0xEA82

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }

func withCRC(b []byte) []byte { return append(append([]byte(nil), b...), le16(refCRC(b))...) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// Covers: SIG-IPE-150
func TestDNP3LinkAndTransport(t *testing.T) {
	// The catalogue check value of CRC-16/DNP.
	if got := refCRC([]byte("123456789")); got != crcCheck {
		t.Fatalf("reference CRC check value = %04x, want %04x", got, crcCheck)
	}
	for _, in := range [][]byte{[]byte("123456789"), {}, {0x05, 0x64, 0x05, 0xC9, 0x0A, 0x00, 0x01, 0x00}, bytes.Repeat([]byte{0xA5, 0x3C}, 40)} {
		if got, want := dnp3.CRC(in), refCRC(in); got != want {
			t.Errorf("CRC(% x) = %04x, want %04x", in, got, want)
		}
	}

	// REQUEST_LINK_STATUS from master 1 to outstation 10, by hand.
	hand := withCRC([]byte{0x05, 0x64, 0x05, 0xC9, 0x0A, 0x00, 0x01, 0x00})
	enc, err := dnp3.Frame{Ctrl: dnp3.CtrlDIR | dnp3.CtrlPRM | dnp3.LinkRequestLinkStatus, Dest: 10, Src: 1}.Encode()
	if err != nil || !bytes.Equal(enc, hand) {
		t.Fatalf("link status request = % x, %v; want % x", enc, err, hand)
	}

	// 20 octets of user data: a 16-octet block and a 4-octet block, each
	// with its own CRC.
	data := make([]byte, 20)
	for i := range data {
		data[i] = byte(i * 7)
	}
	want := cat(withCRC([]byte{0x05, 0x64, 25, 0x44, 0x01, 0x00, 0x0A, 0x00}), withCRC(data[:16]), withCRC(data[16:]))
	f := dnp3.Frame{Ctrl: dnp3.CtrlPRM | dnp3.LinkUnconfirmedUserData, Dest: 1, Src: 10, Data: data}
	enc, _ = f.Encode()
	if !bytes.Equal(enc, want) || len(enc) != 34 {
		t.Fatalf("data frame = % x\nwant           % x", enc, want)
	}
	back, err := dnp3.DecodeFrame(enc)
	if err != nil || !reflect.DeepEqual(back, f) {
		t.Fatalf("decode = %+v, %v", back, err)
	}
	if _, err := (dnp3.Frame{Data: make([]byte, 251)}).Encode(); err == nil {
		t.Error("a 251-octet frame was encoded")
	}

	// A stream with garbage, a frame, a frame with a corrupted block and
	// another frame, fed whole and one octet at a time.
	bad := append([]byte(nil), enc...)
	bad[12] ^= 0xFF
	f2 := dnp3.Frame{Ctrl: 0x44, Dest: 1, Src: 10, Data: []byte{0xC0, 0x81, 0x00, 0x00}}
	enc2, _ := f2.Encode()
	stream := cat([]byte{0x05, 0x00, 0xFF, 0x64, 0x05}, enc, bad, []byte{0x05}, enc2)
	for _, step := range []int{len(stream), 1, 3, 17} {
		var p dnp3.LinkParser
		var got []dnp3.Frame
		for i := 0; i < len(stream); i += step {
			got = append(got, p.Feed(stream[i:min(i+step, len(stream))])...)
		}
		if len(got) != 2 || !reflect.DeepEqual(got[0], f) || !reflect.DeepEqual(got[1], f2) {
			t.Fatalf("step %d: parsed %d frames: %+v", step, len(got), got)
		}
		if p.Errors == 0 {
			t.Errorf("step %d: garbage and the bad CRC were not counted", step)
		}
	}

	// Transport: 600 octets become segments of 249, 249 and 102 with
	// FIR/FIN and a running sequence that wraps at 64.
	apdu := make([]byte, 600)
	for i := range apdu {
		apdu[i] = byte(i)
	}
	seq := uint8(62)
	segs := dnp3.Segment(apdu, &seq)
	if len(segs) != 3 || len(segs[0]) != 250 || len(segs[1]) != 250 || len(segs[2]) != 103 {
		t.Fatalf("segments: %d", len(segs))
	}
	if segs[0][0] != 0x40|62 || segs[1][0] != 63 || segs[2][0] != 0x80|0 || seq != 1 {
		t.Errorf("segment headers %02x %02x %02x, next seq %d", segs[0][0], segs[1][0], segs[2][0], seq)
	}
	var ra dnp3.Reassembler
	for i, s := range segs {
		out, err := ra.Add(s)
		if err != nil || (i < 2) != (out == nil) {
			t.Fatalf("segment %d: %v %v", i, out == nil, err)
		}
		if i == 2 && !bytes.Equal(out, apdu) {
			t.Error("reassembled fragment differs")
		}
	}
	if _, err := ra.Add(segs[1]); err == nil {
		t.Error("a middle segment without a first was accepted")
	}
	_, _ = ra.Add(segs[0])
	if _, err := ra.Add(segs[2]); err == nil {
		t.Error("a segment out of sequence was accepted")
	}
	one := dnp3.Segment([]byte{1, 2}, &seq)
	if len(one) != 1 || one[0][0] != 0xC0|1 {
		t.Errorf("single segment header %02x", one[0][0])
	}
}

func t48(t time.Time) []byte { return dnp3.AppendTime48(nil, t) }

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func f32(v float32) []byte { return le32(math.Float32bits(v)) }

func f64(v float64) []byte { return binary.LittleEndian.AppendUint64(nil, math.Float64bits(v)) }

type want struct {
	g, v  uint8
	idx   uint32
	value any
	q     string
	tm    time.Time
}

// Covers: SIG-IPE-151
func TestDNP3ObjectDecoding(t *testing.T) {
	T := time.Date(2026, 9, 24, 10, 11, 12, 345e6, time.UTC)
	T0 := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		in   []byte
		want []want
	}{
		{"g1v1 packed, 0x00", cat([]byte{1, 1, 0x00, 0, 9}, []byte{0x05, 0x02}), []want{
			{1, 1, 0, true, "good", time.Time{}}, {1, 1, 1, false, "good", time.Time{}}, {1, 1, 2, true, "good", time.Time{}},
			{1, 1, 3, false, "", time.Time{}}, {1, 1, 4, false, "", time.Time{}}, {1, 1, 5, false, "", time.Time{}},
			{1, 1, 6, false, "", time.Time{}}, {1, 1, 7, false, "", time.Time{}}, {1, 1, 8, false, "", time.Time{}}, {1, 1, 9, true, "", time.Time{}}}},
		{"g1v2 flags, 0x01", cat([]byte{1, 2, 0x01}, le16(3), le16(4), []byte{0x81, 0x04}), []want{
			{1, 2, 3, true, "good", time.Time{}}, {1, 2, 4, false, "offline,comm-lost", time.Time{}}}},
		{"g2v1 0x28", cat([]byte{2, 1, 0x28}, le16(1), le16(300), []byte{0x81}), []want{{2, 1, 300, true, "good", time.Time{}}}},
		{"g2v2 0x17 time", cat([]byte{2, 2, 0x17, 1, 5, 0x01}, t48(T)), []want{{2, 2, 5, false, "good", T}}},
		{"g51v1 CTO + g2v3", cat([]byte{51, 1, 0x07, 1}, t48(T0), []byte{2, 3, 0x28}, le16(2), le16(1), []byte{0x81}, le16(250), le16(2), []byte{0x21}, le16(1000)), []want{
			{51, 1, 0, T0, "", time.Time{}}, {2, 3, 1, true, "good", T0.Add(250 * time.Millisecond)}, {2, 3, 2, false, "chatter-filter", T0.Add(time.Second)}}},
		{"g51v2 CTO + g4v3", cat([]byte{51, 2, 0x07, 1}, t48(T0), []byte{4, 3, 0x17, 1, 9, 0x81}, le16(65535)), []want{
			{51, 2, 0, T0, "", time.Time{}}, {4, 3, 9, 2.0, "good", T0.Add(65535 * time.Millisecond)}}},
		{"g3v1 packed double", []byte{3, 1, 0x00, 0, 3, 0xE4}, []want{{3, 1, 0, 0.0, "good", time.Time{}}, {3, 1, 1, 1.0, "", time.Time{}}, {3, 1, 2, 2.0, "", time.Time{}}, {3, 1, 3, 3.0, "", time.Time{}}}},
		{"g3v2", []byte{3, 2, 0x00, 4, 4, 0x81}, []want{{3, 2, 4, 2.0, "good", time.Time{}}}},
		{"g4v1", cat([]byte{4, 1, 0x28}, le16(1), le16(7), []byte{0x41}), []want{{4, 1, 7, 1.0, "good", time.Time{}}}},
		{"g4v2", cat([]byte{4, 2, 0x28}, le16(1), le16(7), []byte{0xC1}, t48(T)), []want{{4, 2, 7, 3.0, "good", T}}},
		{"g10v1", []byte{10, 1, 0x00, 0, 1, 0x02}, []want{{10, 1, 0, false, "good", time.Time{}}, {10, 1, 1, true, "good", time.Time{}}}},
		{"g10v2", []byte{10, 2, 0x00, 2, 2, 0x83}, []want{{10, 2, 2, true, "restart", time.Time{}}}},
		{"g20v1", cat([]byte{20, 1, 0x00, 0, 0, 0x61}, le32(123456)), []want{{20, 1, 0, 123456.0, "rollover,discontinuity", time.Time{}}}},
		{"g20v2", cat([]byte{20, 2, 0x00, 0, 0, 0x01}, le16(65535)), []want{{20, 2, 0, 65535.0, "good", time.Time{}}}},
		{"g20v5", cat([]byte{20, 5, 0x00, 1, 1}, le32(4000000000)), []want{{20, 5, 1, 4e9, "good", time.Time{}}}},
		{"g20v6", cat([]byte{20, 6, 0x00, 1, 1}, le16(7)), []want{{20, 6, 1, 7.0, "good", time.Time{}}}},
		{"g21v1", cat([]byte{21, 1, 0x00, 0, 0, 0x01}, le32(9)), []want{{21, 1, 0, 9.0, "good", time.Time{}}}},
		{"g21v9", cat([]byte{21, 9, 0x00, 0, 0}, le32(10)), []want{{21, 9, 0, 10.0, "good", time.Time{}}}},
		{"g22v1", cat([]byte{22, 1, 0x28}, le16(1), le16(3), []byte{0x01}, le32(11)), []want{{22, 1, 3, 11.0, "good", time.Time{}}}},
		{"g22v2", cat([]byte{22, 2, 0x17, 1, 3, 0x01}, le16(12)), []want{{22, 2, 3, 12.0, "good", time.Time{}}}},
		{"g22v5", cat([]byte{22, 5, 0x17, 1, 3, 0x01}, le32(13), t48(T)), []want{{22, 5, 3, 13.0, "good", T}}},
		{"g22v6", cat([]byte{22, 6, 0x17, 1, 3, 0x01}, le16(14), t48(T)), []want{{22, 6, 3, 14.0, "good", T}}},
		{"g30v1", cat([]byte{30, 1, 0x00, 0, 0, 0x01}, le32(uint32(0xFFFFFFFB))), []want{{30, 1, 0, -5.0, "good", time.Time{}}}},
		{"g30v2", cat([]byte{30, 2, 0x00, 0, 0, 0x21}, le16(0xFFFE)), []want{{30, 2, 0, -2.0, "over-range", time.Time{}}}},
		{"g30v3", cat([]byte{30, 3, 0x00, 0, 0}, le32(100000)), []want{{30, 3, 0, 100000.0, "good", time.Time{}}}},
		{"g30v4", cat([]byte{30, 4, 0x00, 0, 0}, le16(0x8000)), []want{{30, 4, 0, -32768.0, "good", time.Time{}}}},
		{"g30v5", cat([]byte{30, 5, 0x00, 0, 0, 0x41}, f32(1.5)), []want{{30, 5, 0, 1.5, "reference-error", time.Time{}}}},
		{"g30v6", cat([]byte{30, 6, 0x00, 0, 0, 0x1E}, f64(-2.25)), []want{{30, 6, 0, -2.25, "offline,restart,comm-lost,remote-forced,local-forced", time.Time{}}}},
		{"g32v1", cat([]byte{32, 1, 0x28}, le16(1), le16(2), []byte{0x01}, le32(42)), []want{{32, 1, 2, 42.0, "good", time.Time{}}}},
		{"g32v2", cat([]byte{32, 2, 0x28}, le16(1), le16(2), []byte{0x01}, le16(43)), []want{{32, 2, 2, 43.0, "good", time.Time{}}}},
		{"g32v3", cat([]byte{32, 3, 0x28}, le16(1), le16(2), []byte{0x01}, le32(44), t48(T)), []want{{32, 3, 2, 44.0, "good", T}}},
		{"g32v4", cat([]byte{32, 4, 0x28}, le16(1), le16(2), []byte{0x01}, le16(45), t48(T)), []want{{32, 4, 2, 45.0, "good", T}}},
		{"g32v5", cat([]byte{32, 5, 0x28}, le16(1), le16(2), []byte{0x01}, f32(4.5)), []want{{32, 5, 2, 4.5, "good", time.Time{}}}},
		{"g32v6", cat([]byte{32, 6, 0x28}, le16(1), le16(2), []byte{0x01}, f64(4.75)), []want{{32, 6, 2, 4.75, "good", time.Time{}}}},
		{"g32v7", cat([]byte{32, 7, 0x28}, le16(1), le16(2), []byte{0x01}, f32(5.5), t48(T)), []want{{32, 7, 2, 5.5, "good", T}}},
		{"g32v8", cat([]byte{32, 8, 0x28}, le16(1), le16(2), []byte{0x05}, f64(5.75), t48(T)), []want{{32, 8, 2, 5.75, "comm-lost", T}}},
		{"g40v1", cat([]byte{40, 1, 0x00, 0, 0, 0x01}, le32(7)), []want{{40, 1, 0, 7.0, "good", time.Time{}}}},
		{"g40v2", cat([]byte{40, 2, 0x00, 0, 0, 0x01}, le16(8)), []want{{40, 2, 0, 8.0, "good", time.Time{}}}},
		{"g40v3", cat([]byte{40, 3, 0x00, 0, 0, 0x01}, f32(9.5)), []want{{40, 3, 0, 9.5, "good", time.Time{}}}},
		{"g40v4", cat([]byte{40, 4, 0x00, 0, 0, 0x01}, f64(10.25)), []want{{40, 4, 0, 10.25, "good", time.Time{}}}},
		{"g50v1", cat([]byte{50, 1, 0x07, 1}, t48(T)), []want{{50, 1, 0, T, "", time.Time{}}}},
		{"g50v3", cat([]byte{50, 3, 0x07, 1}, t48(T)), []want{{50, 3, 0, T, "", time.Time{}}}},
		{"g52v1", cat([]byte{52, 1, 0x07, 1}, le16(2)), []want{{52, 1, 0, 2.0, "", time.Time{}}}},
		{"g52v2", cat([]byte{52, 2, 0x07, 1}, le16(150)), []want{{52, 2, 0, 150.0, "", time.Time{}}}},
		{"g80v1", []byte{80, 1, 0x00, 7, 7, 0x01}, []want{{80, 1, 7, true, "", time.Time{}}}},
	}
	for _, tc := range cases {
		blocks, err := dnp3.ParseObjects(tc.in, true)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		var pts []dnp3.Point
		for _, b := range blocks {
			pts = append(pts, b.Points...)
		}
		if len(pts) != len(tc.want) {
			t.Errorf("%s: %d points, want %d", tc.name, len(pts), len(tc.want))
			continue
		}
		for i, w := range tc.want {
			p := pts[i]
			if p.Group != w.g || p.Var != w.v || p.Index != w.idx {
				t.Errorf("%s[%d]: g%dv%d #%d, want g%dv%d #%d", tc.name, i, p.Group, p.Var, p.Index, w.g, w.v, w.idx)
			}
			if tm, ok := w.value.(time.Time); ok {
				if got, _ := p.Value.(time.Time); !got.Equal(tm) {
					t.Errorf("%s[%d]: time value %v, want %v", tc.name, i, p.Value, tm)
				}
			} else if p.Value != w.value {
				t.Errorf("%s[%d]: value %v (%T), want %v", tc.name, i, p.Value, p.Value, w.value)
			}
			if w.q != "" && p.Quality() != w.q {
				t.Errorf("%s[%d]: quality %q, want %q", tc.name, i, p.Quality(), w.q)
			}
			if !p.Time.Equal(w.tm) {
				t.Errorf("%s[%d]: time %v, want %v", tc.name, i, p.Time, w.tm)
			}
		}
	}

	// Control objects with their status.
	crob := cat([]byte{12, 1, 0x28}, le16(1), le16(3), []byte{0x41, 1}, le32(100), le32(200), []byte{4})
	blocks, err := dnp3.ParseObjects(crob, true)
	if err != nil || blocks[0].Points[0].CROB != (dnp3.CROB{Code: 0x41, Count: 1, OnTime: 100, OffTime: 200}) || blocks[0].Points[0].Status != 4 || blocks[0].Points[0].Index != 3 {
		t.Errorf("g12v1 = %+v, %v", blocks, err)
	}
	for v, obj := range map[uint8][]byte{1: le32(uint32(0xFFFFFFF6)), 2: le16(0xFFF6), 3: f32(-10), 4: f64(-10)} {
		in := cat([]byte{41, v, 0x17, 1, 2}, obj, []byte{12})
		blocks, err := dnp3.ParseObjects(in, true)
		if err != nil || blocks[0].Points[0].Value != -10.0 || blocks[0].Points[0].Status != 12 || dnp3.StatusName(12) != "out-of-range" {
			t.Errorf("g41v%d = %+v, %v", v, blocks, err)
		}
	}

	// An unknown object stops parsing but keeps what came before.
	in := cat([]byte{30, 4, 0x00, 0, 0}, le16(1), []byte{99, 1, 0x00, 0, 0, 1, 2, 3})
	blocks, err = dnp3.ParseObjects(in, true)
	if err == nil || len(blocks) != 1 || !strings.Contains(err.Error(), "g99v1") {
		t.Errorf("unknown object: %d blocks, %v", len(blocks), err)
	}
	// Relative time needs a CTO.
	if _, err := dnp3.ParseObjects(cat([]byte{2, 3, 0x17, 1, 0, 0x01}, le16(1)), true); err == nil {
		t.Error("g2v3 without a CTO was accepted")
	}
	// Truncated data.
	if _, err := dnp3.ParseObjects([]byte{30, 1, 0x00, 0, 1, 0x01, 0, 0}, true); err == nil {
		t.Error("truncated objects were accepted")
	}

	// Response header and internal indications.
	frag, err := dnp3.ParseFragment([]byte{0xE3, 0x81, 0x92, 0x0A, 60, 1, 0x06})
	if err != nil || frag.Seq() != 3 || frag.Control&dnp3.AppCON == 0 || frag.Func != dnp3.FCResponse ||
		frag.IIN.String() != "class-1-events,need-time,device-restart,object-unknown,event-buffer-overflow" {
		t.Errorf("response header = %+v (%s), %v", frag, frag.IIN, err)
	}

	// Request encoding.
	integrity := dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | 5, Func: dnp3.FCRead, Objects: dnp3.ClassRequest(1, 2, 3, 0)}.Encode()
	if w := []byte{0xC5, 0x01, 60, 2, 6, 60, 3, 6, 60, 4, 6, 60, 1, 6}; !bytes.Equal(integrity, w) {
		t.Errorf("integrity poll = % x, want % x", integrity, w)
	}
	enc, _ := dnp3.EncodeBlock(12, 1, dnp3.Q16Index16, []dnp3.Point{{Index: 3, CROB: dnp3.CROB{Code: 0x41, Count: 1, OnTime: 100, OffTime: 200}}})
	if w := cat([]byte{12, 1, 0x28}, le16(1), le16(3), []byte{0x41, 1}, le32(100), le32(200), []byte{0}); !bytes.Equal(enc, w) {
		t.Errorf("CROB = % x, want % x", enc, w)
	}
	enc, _ = dnp3.EncodeBlock(41, 3, dnp3.Q16Index16, []dnp3.Point{{Index: 1, Value: 42.5}})
	if w := cat([]byte{41, 3, 0x28}, le16(1), le16(1), f32(42.5), []byte{0}); !bytes.Equal(enc, w) {
		t.Errorf("g41v3 = % x, want % x", enc, w)
	}
	enc, _ = dnp3.EncodeBlock(41, 2, dnp3.Q8Index8, []dnp3.Point{{Index: 1, Value: -3.0}})
	if w := cat([]byte{41, 2, 0x17, 1, 1}, le16(0xFFFD), []byte{0}); !bytes.Equal(enc, w) {
		t.Errorf("g41v2 = % x, want % x", enc, w)
	}
	enc, _ = dnp3.EncodeBlock(80, 1, dnp3.Q8StartStop, []dnp3.Point{{Index: 7, Value: false}})
	if w := []byte{80, 1, 0x00, 7, 7, 0x00}; !bytes.Equal(enc, w) {
		t.Errorf("clear restart = % x, want % x", enc, w)
	}
	enc, _ = dnp3.EncodeBlock(50, 1, dnp3.Q8Count, []dnp3.Point{{Value: T}})
	if w := cat([]byte{50, 1, 0x07, 1}, t48(T)); !bytes.Equal(enc, w) {
		t.Errorf("write time = % x, want % x", enc, w)
	}
	// time48 is milliseconds since the epoch, little-endian.
	if w := []byte{0x39, 0x30, 0, 0, 0, 0}; !bytes.Equal(t48(time.UnixMilli(12345)), w) {
		t.Errorf("time48(12345 ms) = % x", t48(time.UnixMilli(12345)))
	}
	// Encoding and decoding events with a CTO round-trips.
	enc, err = dnp3.EncodeBlock(2, 3, dnp3.Q16Index16, []dnp3.Point{{Index: 4, Value: true, Time: T0.Add(1234 * time.Millisecond)}}, T0)
	cto, _ := dnp3.EncodeBlock(51, 1, dnp3.Q8Count, []dnp3.Point{{Value: T0}})
	blocks, err2 := dnp3.ParseObjects(cat(cto, enc), true)
	if err != nil || err2 != nil || !blocks[1].Points[0].Time.Equal(T0.Add(1234*time.Millisecond)) || blocks[1].Points[0].Value != true {
		t.Errorf("CTO round trip: %+v %v %v", blocks, err, err2)
	}
	// READ requests carry headers only.
	blocks, err = dnp3.ParseObjects(cat(dnp3.ClassRequest(0), []byte{30, 0, 0x01}, le16(0), le16(9)), false)
	if err != nil || len(blocks) != 2 || blocks[1].Header.Count != 10 || len(blocks[1].Points) != 0 {
		t.Errorf("READ request objects = %+v, %v", blocks, err)
	}
}
