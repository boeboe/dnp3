package dnp3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Object groups and variations (IEEE 1815 Annex A) this implementation
// encodes and decodes. Layouts are little-endian; a "time48" is
// milliseconds since 1970-01-01 UTC in six octets.

// CROB operation types (low nibble of the control code) and trip/close
// codes (top two bits).
const (
	OpNul      = 0
	OpPulseOn  = 1
	OpPulseOff = 2
	OpLatchOn  = 3
	OpLatchOff = 4

	TCCClose = 0x40
	TCCTrip  = 0x80
)

// CROB is a control relay output block (g12v1).
type CROB struct {
	Code    uint8
	Count   uint8
	OnTime  uint32 // ms
	OffTime uint32 // ms
}

// Point is one decoded object.
type Point struct {
	Group, Var uint8
	Index      uint32
	// Value is a bool (binary, binary output, g80), a float64 (double-bit
	// state 0–3, counters, analogs, delays) or a time.Time (g50, g51).
	Value    any
	Flags    uint8
	HasFlags bool
	Time     time.Time // event time, when the object carries one
	Status   uint8     // command status (g12, g13, g41, g43)
	CROB     CROB      // g12v1, g12v2
	// Interval and Units are the interval of g50v2 (ms) and g50v4 (count
	// and units code); Assoc is the association ID of g121 and g122; Ref
	// is the group and variation a g81 fill status refers to.
	Interval uint32
	Units    uint8
	Assoc    uint16
	Ref      [2]uint8
	// Raw is the object data of variable-size objects: those with an
	// object size prefix (g70, g91, g120, ...) and those whose variation
	// is their length (g110 to g113).
	Raw []byte
}

// Block is an object header and its decoded objects.
type Block struct {
	Header Header
	Points []Point
}

type objDef struct {
	bits   int  // packed: bits per point
	flags  bool // leading flags octet
	num    byte // numeric layout: h i H I f d, or 0
	time   bool // time48 after the value
	rel    bool // 16-bit time relative to a CTO
	status bool // trailing control status
	lead   bool // leading status octet (g13, g43)
	extra  int  // trailing octets decoded per group (g50v2, g50v4, g121, g122, g81)
	fixed  int  // special layouts (g12v1, g12v2)
}

func (d objDef) size() int {
	if d.fixed > 0 {
		return d.fixed
	}
	n := 0
	if d.flags {
		n++
	}
	switch d.num {
	case 'h', 'H':
		n += 2
	case 'i', 'I', 'f':
		n += 4
	case 'd':
		n += 8
	}
	if d.time {
		n += 6
	}
	if d.rel {
		n += 2
	}
	if d.status || d.lead {
		n++
	}
	return n + d.extra
}

func gv(g, v uint8) uint16 { return uint16(g)<<8 | uint16(v) }

// objDefs are the fixed-size objects of Annex A. Variations marked
// obsolete there (delta counters) are decoded like their non-delta
// counterparts.
var objDefs = map[uint16]objDef{
	gv(1, 1): {bits: 1}, gv(1, 2): {flags: true},
	gv(2, 1): {flags: true}, gv(2, 2): {flags: true, time: true}, gv(2, 3): {flags: true, rel: true},
	gv(3, 1): {bits: 2}, gv(3, 2): {flags: true},
	gv(4, 1): {flags: true}, gv(4, 2): {flags: true, time: true}, gv(4, 3): {flags: true, rel: true},
	gv(10, 1): {bits: 1}, gv(10, 2): {flags: true},
	gv(11, 1): {flags: true}, gv(11, 2): {flags: true, time: true},
	gv(12, 1): {fixed: 11}, gv(12, 2): {fixed: 11}, gv(12, 3): {bits: 1},
	gv(13, 1): {lead: true}, gv(13, 2): {lead: true, time: true},
	gv(20, 1): {flags: true, num: 'I'}, gv(20, 2): {flags: true, num: 'H'}, gv(20, 3): {flags: true, num: 'I'}, gv(20, 4): {flags: true, num: 'H'},
	gv(20, 5): {num: 'I'}, gv(20, 6): {num: 'H'}, gv(20, 7): {num: 'I'}, gv(20, 8): {num: 'H'},
	gv(21, 1): {flags: true, num: 'I'}, gv(21, 2): {flags: true, num: 'H'}, gv(21, 3): {flags: true, num: 'I'}, gv(21, 4): {flags: true, num: 'H'},
	gv(21, 5): {flags: true, num: 'I', time: true}, gv(21, 6): {flags: true, num: 'H', time: true},
	gv(21, 7): {flags: true, num: 'I', time: true}, gv(21, 8): {flags: true, num: 'H', time: true},
	gv(21, 9): {num: 'I'}, gv(21, 10): {num: 'H'}, gv(21, 11): {num: 'I'}, gv(21, 12): {num: 'H'},
	gv(22, 1): {flags: true, num: 'I'}, gv(22, 2): {flags: true, num: 'H'}, gv(22, 3): {flags: true, num: 'I'}, gv(22, 4): {flags: true, num: 'H'},
	gv(22, 5): {flags: true, num: 'I', time: true}, gv(22, 6): {flags: true, num: 'H', time: true},
	gv(22, 7): {flags: true, num: 'I', time: true}, gv(22, 8): {flags: true, num: 'H', time: true},
	gv(23, 1): {flags: true, num: 'I'}, gv(23, 2): {flags: true, num: 'H'}, gv(23, 3): {flags: true, num: 'I'}, gv(23, 4): {flags: true, num: 'H'},
	gv(23, 5): {flags: true, num: 'I', time: true}, gv(23, 6): {flags: true, num: 'H', time: true},
	gv(23, 7): {flags: true, num: 'I', time: true}, gv(23, 8): {flags: true, num: 'H', time: true},
	gv(30, 1): {flags: true, num: 'i'}, gv(30, 2): {flags: true, num: 'h'}, gv(30, 3): {num: 'i'}, gv(30, 4): {num: 'h'},
	gv(30, 5): {flags: true, num: 'f'}, gv(30, 6): {flags: true, num: 'd'},
	gv(31, 1): {flags: true, num: 'i'}, gv(31, 2): {flags: true, num: 'h'},
	gv(31, 3): {flags: true, num: 'i', time: true}, gv(31, 4): {flags: true, num: 'h', time: true},
	gv(31, 5): {num: 'i'}, gv(31, 6): {num: 'h'}, gv(31, 7): {flags: true, num: 'f'}, gv(31, 8): {flags: true, num: 'd'},
	gv(32, 1): {flags: true, num: 'i'}, gv(32, 2): {flags: true, num: 'h'},
	gv(32, 3): {flags: true, num: 'i', time: true}, gv(32, 4): {flags: true, num: 'h', time: true},
	gv(32, 5): {flags: true, num: 'f'}, gv(32, 6): {flags: true, num: 'd'},
	gv(32, 7): {flags: true, num: 'f', time: true}, gv(32, 8): {flags: true, num: 'd', time: true},
	gv(33, 1): {flags: true, num: 'i'}, gv(33, 2): {flags: true, num: 'h'},
	gv(33, 3): {flags: true, num: 'i', time: true}, gv(33, 4): {flags: true, num: 'h', time: true},
	gv(33, 5): {flags: true, num: 'f'}, gv(33, 6): {flags: true, num: 'd'},
	gv(33, 7): {flags: true, num: 'f', time: true}, gv(33, 8): {flags: true, num: 'd', time: true},
	gv(34, 1): {num: 'H'}, gv(34, 2): {num: 'I'}, gv(34, 3): {num: 'f'},
	gv(40, 1): {flags: true, num: 'i'}, gv(40, 2): {flags: true, num: 'h'}, gv(40, 3): {flags: true, num: 'f'}, gv(40, 4): {flags: true, num: 'd'},
	gv(41, 1): {num: 'i', status: true}, gv(41, 2): {num: 'h', status: true}, gv(41, 3): {num: 'f', status: true}, gv(41, 4): {num: 'd', status: true},
	gv(42, 1): {flags: true, num: 'i'}, gv(42, 2): {flags: true, num: 'h'},
	gv(42, 3): {flags: true, num: 'i', time: true}, gv(42, 4): {flags: true, num: 'h', time: true},
	gv(42, 5): {flags: true, num: 'f'}, gv(42, 6): {flags: true, num: 'd'},
	gv(42, 7): {flags: true, num: 'f', time: true}, gv(42, 8): {flags: true, num: 'd', time: true},
	gv(43, 1): {lead: true, num: 'i'}, gv(43, 2): {lead: true, num: 'h'},
	gv(43, 3): {lead: true, num: 'i', time: true}, gv(43, 4): {lead: true, num: 'h', time: true},
	gv(43, 5): {lead: true, num: 'f'}, gv(43, 6): {lead: true, num: 'd'},
	gv(43, 7): {lead: true, num: 'f', time: true}, gv(43, 8): {lead: true, num: 'd', time: true},
	gv(50, 1): {time: true}, gv(50, 2): {time: true, extra: 4}, gv(50, 3): {time: true}, gv(50, 4): {time: true, extra: 5},
	gv(51, 1): {time: true}, gv(51, 2): {time: true},
	gv(52, 1): {num: 'H'}, gv(52, 2): {num: 'H'},
	gv(80, 1):  {bits: 1},
	gv(81, 1):  {extra: 3},
	gv(101, 1): {extra: 2}, gv(101, 2): {extra: 4}, gv(101, 3): {extra: 8},
	gv(102, 1): {extra: 1},
	gv(120, 3): {extra: 6}, gv(120, 4): {extra: 2},
	gv(121, 1): {flags: true, extra: 6},
	gv(122, 1): {flags: true, extra: 6}, gv(122, 2): {flags: true, extra: 6, time: true},
}

// freeFormat lists the objects that are carried with an object size
// prefix (qualifier 0x5B and the like): file control, status of requested
// operation, authentication and data set objects, whose layout is decoded
// by their own functions from Point.Raw.
func freeFormat(group, variation uint8) bool {
	switch group {
	case 70:
		return variation >= 2 && variation <= 8
	case 82, 85, 87, 88, 90, 91:
		return variation == 1
	case 83:
		return variation == 1 || variation == 2
	case 86:
		return variation >= 1 && variation <= 3
	case 120:
		return variation != 3 && variation != 4 && variation >= 1 && variation <= 15
	}
	return false
}

// lengthVariation reports groups whose variation is the object length
// (octet strings g110/g111, virtual terminal g112/g113).
func lengthVariation(group uint8) bool { return group >= 110 && group <= 113 }

// Known reports whether a group/variation can be decoded.
func Known(group, variation uint8) bool {
	_, ok := objDefs[gv(group, variation)]
	return ok || freeFormat(group, variation) || (lengthVariation(group) && variation > 0)
}

// Family is the point type a group reports: binary, double,
// binary-output, counter, frozen-counter, analog or analog-output; empty
// for groups that are not data points.
func Family(group uint8) string {
	switch group {
	case 1, 2:
		return "binary"
	case 3, 4:
		return "double"
	case 10, 11:
		return "binary-output"
	case 20, 22:
		return "counter"
	case 21, 23:
		return "frozen-counter"
	case 30, 32:
		return "analog"
	case 31, 33:
		return "frozen-analog"
	case 40, 42:
		return "analog-output"
	}
	return ""
}

// Quality turns a point's flags into "good" or a comma-separated list of
// flag names. The online bit reads as "offline" when clear.
func (p Point) Quality() string {
	if !p.HasFlags {
		return "good"
	}
	f := p.Flags
	var out []string
	if f&0x01 == 0 {
		out = append(out, "offline")
	}
	for i, n := range []string{"restart", "comm-lost", "remote-forced", "local-forced"} {
		if f&(0x02<<i) != 0 {
			out = append(out, n)
		}
	}
	switch p.Group {
	case 1, 2, 3, 4:
		if f&0x20 != 0 {
			out = append(out, "chatter-filter")
		}
	case 20, 21, 22, 23:
		if f&0x20 != 0 {
			out = append(out, "rollover")
		}
		if f&0x40 != 0 {
			out = append(out, "discontinuity")
		}
	case 30, 31, 32, 33, 40, 42:
		if f&0x20 != 0 {
			out = append(out, "over-range")
		}
		if f&0x40 != 0 {
			out = append(out, "reference-error")
		}
	}
	if len(out) == 0 {
		return "good"
	}
	return strings.Join(out, ",")
}

// Time48 decodes six octets of milliseconds since the epoch.
func Time48(b []byte) time.Time {
	ms := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40
	return time.UnixMilli(int64(ms)).UTC()
}

// AppendTime48 appends t as a time48.
func AppendTime48(out []byte, t time.Time) []byte {
	// DNP3 time counts from 1970: a time never set (the zero time.Time)
	// or before 1970 goes out as 0 rather than wrapped around.
	var ms uint64
	if v := t.UnixMilli(); v > 0 {
		ms = uint64(v)
	}
	for i := range 6 {
		out = append(out, byte(ms>>(8*i)))
	}
	return out
}

// ParseObjects decodes the object headers and objects of a fragment. With
// withData false (READ requests and unsolicited enable/disable) headers
// carry no objects. An unknown group/variation stops parsing, since its
// size is unknown; the blocks decoded so far are returned with the error.
func ParseObjects(b []byte, withData bool) ([]Block, error) {
	var out []Block
	var cto time.Time
	for len(b) > 0 {
		h, rest, err := parseHeader(b)
		if err != nil {
			return out, err
		}
		b = rest
		blk := Block{Header: h}
		// Objects with a size prefix are carried even in READ requests
		// (a g70v5 read names its file handle and block).
		if (!withData && sizePrefixLen(h.Qual) == 0) || h.Group == 60 || h.Qual == QAll || h.Var == 0 {
			out = append(out, blk)
			continue
		}
		if h.Group == 0 {
			var err error
			if b, err = parseAttributes(h, b, &blk); err != nil {
				return out, err
			}
			out = append(out, blk)
			continue
		}
		pl := prefixLen(h.Qual)
		index := func(i uint32) uint32 {
			switch {
			case pl > 0:
				return readUint(b, pl)
			case h.Qual&0x0F >= 7:
				return i // count qualifiers carry no index
			}
			return h.Start + i
		}
		if spl := sizePrefixLen(h.Qual); spl > 0 {
			for i := range h.Count {
				if len(b) < spl {
					return out, fmt.Errorf("%s: truncated object size", h)
				}
				n := int(readUint(b, spl))
				if len(b) < spl+n {
					return out, fmt.Errorf("%s: truncated objects", h)
				}
				blk.Points = append(blk.Points, Point{Group: h.Group, Var: h.Var, Index: i, Raw: append([]byte(nil), b[spl:spl+n]...)})
				b = b[spl+n:]
			}
			out = append(out, blk)
			continue
		}
		if lengthVariation(h.Group) {
			n := int(h.Var)
			for i := range h.Count {
				if len(b) < pl+n {
					return out, fmt.Errorf("%s: truncated objects", h)
				}
				blk.Points = append(blk.Points, Point{Group: h.Group, Var: h.Var, Index: index(i), Raw: append([]byte(nil), b[pl:pl+n]...)})
				b = b[pl+n:]
			}
			out = append(out, blk)
			continue
		}
		def, ok := objDefs[gv(h.Group, h.Var)]
		if !ok {
			if freeFormat(h.Group, h.Var) {
				return out, fmt.Errorf("%s: qualifier 0x%02x has no object size prefix", h, h.Qual)
			}
			return out, fmt.Errorf("%s is not a known object; the rest of the fragment is skipped", h)
		}
		if def.bits > 0 {
			if pl != 0 {
				return out, fmt.Errorf("%s: packed objects cannot carry index prefixes", h)
			}
			n := (int(h.Count)*def.bits + 7) / 8
			if len(b) < n {
				return out, fmt.Errorf("%s: truncated objects", h)
			}
			for i := range h.Count {
				bit := int(i) * def.bits
				v := (b[bit/8] >> (bit % 8)) & (1<<def.bits - 1)
				p := Point{Group: h.Group, Var: h.Var, Index: h.Start + i}
				if def.bits == 1 {
					p.Value = v != 0
				} else {
					p.Value = float64(v)
				}
				blk.Points = append(blk.Points, p)
			}
			b = b[n:]
			out = append(out, blk)
			continue
		}
		size := def.size()
		for i := range h.Count {
			if len(b) < pl+size {
				return out, fmt.Errorf("%s: truncated objects", h)
			}
			idx := index(i)
			p, err := decodeObject(h, def, b[pl:pl+size], cto)
			if err != nil {
				return out, err
			}
			p.Index = idx
			blk.Points = append(blk.Points, p)
			b = b[pl+size:]
			if h.Group == 51 {
				cto = p.Value.(time.Time)
			}
		}
		out = append(out, blk)
	}
	return out, nil
}

func decodeObject(h Header, d objDef, b []byte, cto time.Time) (Point, error) {
	p := Point{Group: h.Group, Var: h.Var}
	if h.Group == 12 {
		p.CROB = CROB{Code: b[0], Count: b[1], OnTime: binary.LittleEndian.Uint32(b[2:]), OffTime: binary.LittleEndian.Uint32(b[6:])}
		p.Status = b[10] & 0x7F
		return p, nil
	}
	if d.lead {
		// g13: commanded state in bit 7; g43: bit 7 reserved.
		p.Status = b[0] & 0x7F
		if h.Group == 13 {
			p.Value = b[0]&0x80 != 0
		}
		b = b[1:]
	}
	if d.flags {
		p.Flags, p.HasFlags = b[0], true
		b = b[1:]
		switch h.Group {
		case 1, 2, 10, 11:
			p.Value = p.Flags&0x80 != 0
		case 3, 4:
			p.Value = float64(p.Flags >> 6)
		}
	}
	switch d.num {
	case 'h':
		p.Value = float64(int16(binary.LittleEndian.Uint16(b)))
		b = b[2:]
	case 'H':
		p.Value = float64(binary.LittleEndian.Uint16(b))
		b = b[2:]
	case 'i':
		p.Value = float64(int32(binary.LittleEndian.Uint32(b)))
		b = b[4:]
	case 'I':
		p.Value = float64(binary.LittleEndian.Uint32(b))
		b = b[4:]
	case 'f':
		p.Value = float64(math.Float32frombits(binary.LittleEndian.Uint32(b)))
		b = b[4:]
	case 'd':
		p.Value = math.Float64frombits(binary.LittleEndian.Uint64(b))
		b = b[8:]
	}
	if h.Group == 121 || h.Group == 122 {
		p.Assoc = binary.LittleEndian.Uint16(b)
		p.Value = float64(binary.LittleEndian.Uint32(b[2:]))
		b = b[6:]
	}
	if d.time {
		t := Time48(b)
		b = b[6:]
		if d.num == 0 && !d.flags && !d.lead {
			p.Value = t // g50, g51
		} else {
			p.Time = t
		}
	}
	switch h.Group {
	case 50:
		if h.Var == 2 || h.Var == 4 {
			p.Interval = binary.LittleEndian.Uint32(b)
			if h.Var == 4 {
				p.Units = b[4]
			}
		}
	case 81:
		p.Value, p.Flags, p.Ref = float64(b[0]&0x7F), b[0]&0x80, [2]uint8{b[1], b[2]}
	case 101:
		p.Value = bcd(b[:d.extra])
	case 102:
		p.Value = float64(b[0])
	case 120:
		p.Raw = append([]byte(nil), b[:d.extra]...)
	}
	if d.rel {
		if cto.IsZero() {
			return p, fmt.Errorf("%s: relative time without a preceding common time-of-occurrence (g51)", h)
		}
		p.Time = cto.Add(time.Duration(binary.LittleEndian.Uint16(b)) * time.Millisecond)
		b = b[2:]
	}
	if d.status {
		p.Status = b[0] & 0x7F
	}
	return p, nil
}

// bcd decodes packed binary-coded decimal characters (11.3.6): least
// significant character first, starting at bit 0; a most significant
// character of 0xA to 0xF marks a negative value. An illegal character
// elsewhere yields NaN.
func bcd(b []byte) float64 {
	var v float64
	neg := false
	for i := 2*len(b) - 1; i >= 0; i-- {
		c := b[i/2] >> (4 * (i % 2)) & 0x0F
		if c > 9 {
			if i != 2*len(b)-1 {
				return math.NaN()
			}
			neg = true
			continue
		}
		v = v*10 + float64(c)
	}
	if neg {
		return -v
	}
	return v
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint32:
		return float64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// appendObject encodes one non-packed object.
func appendObject(out []byte, d objDef, p Point) ([]byte, error) {
	if p.Group == 12 {
		out = append(out, p.CROB.Code, p.CROB.Count)
		out = binary.LittleEndian.AppendUint32(out, p.CROB.OnTime)
		out = binary.LittleEndian.AppendUint32(out, p.CROB.OffTime)
		return append(out, p.Status), nil
	}
	switch p.Group {
	case 50, 51:
		t, ok := p.Value.(time.Time)
		if !ok {
			return nil, fmt.Errorf("g%dv%d needs a time", p.Group, p.Var)
		}
		out = AppendTime48(out, t)
		if p.Group == 50 && (p.Var == 2 || p.Var == 4) {
			out = binary.LittleEndian.AppendUint32(out, p.Interval)
			if p.Var == 4 {
				out = append(out, p.Units)
			}
		}
		return out, nil
	case 81:
		v, _ := number(p.Value)
		return append(out, byte(int(v)&0x7F)|p.Flags&0x80, p.Ref[0], p.Ref[1]), nil
	case 102:
		v, _ := number(p.Value)
		return append(out, byte(v)), nil
	case 101, 120:
		if len(p.Raw) != d.extra {
			return nil, fmt.Errorf("g%dv%d needs %d octets", p.Group, p.Var, d.extra)
		}
		return append(out, p.Raw...), nil
	}
	v, _ := number(p.Value)
	if d.lead {
		st := p.Status & 0x7F
		if p.Group == 13 && v != 0 {
			st |= 0x80
		}
		out = append(out, st)
	}
	if d.flags {
		f := byte(0x01)
		if p.HasFlags {
			f = p.Flags
		}
		switch p.Group {
		case 1, 2, 10, 11:
			f &= 0x7F
			if v != 0 {
				f |= 0x80
			}
		case 3, 4:
			f = f&0x3F | byte(int(v)&3)<<6
		}
		out = append(out, f)
	}
	switch d.num {
	case 'h':
		out = binary.LittleEndian.AppendUint16(out, uint16(int16(clamp(v, math.MinInt16, math.MaxInt16))))
	case 'H':
		out = binary.LittleEndian.AppendUint16(out, uint16(clamp(v, 0, math.MaxUint16)))
	case 'i':
		out = binary.LittleEndian.AppendUint32(out, uint32(int32(clamp(v, math.MinInt32, math.MaxInt32))))
	case 'I':
		out = binary.LittleEndian.AppendUint32(out, uint32(clamp(v, 0, math.MaxUint32)))
	case 'f':
		out = binary.LittleEndian.AppendUint32(out, math.Float32bits(float32(v)))
	case 'd':
		out = binary.LittleEndian.AppendUint64(out, math.Float64bits(v))
	}
	if p.Group == 121 || p.Group == 122 {
		out = binary.LittleEndian.AppendUint16(out, p.Assoc)
		out = binary.LittleEndian.AppendUint32(out, uint32(clamp(v, 0, math.MaxUint32)))
	}
	if d.time {
		out = AppendTime48(out, p.Time)
	}
	if d.status {
		out = append(out, p.Status)
	}
	return out, nil
}

func clamp(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, math.Round(v)))
}

// EncodeBlock encodes an object header and its objects. Start-stop
// qualifiers need consecutive indices; relative-time objects (g2v3, g4v3)
// take their offset from the preceding CTO given as cto.
func EncodeBlock(group, variation, qual uint8, pts []Point, cto ...time.Time) ([]byte, error) {
	d, ok := objDefs[gv(group, variation)]
	if !ok && group != 60 && !freeFormat(group, variation) && !lengthVariation(group) {
		return nil, fmt.Errorf("g%dv%d is not a known object", group, variation)
	}
	n := uint32(len(pts))
	var out []byte
	switch qual {
	case QAll:
		return AppendHeader(nil, group, variation, qual, 0, 0), nil
	case Q8StartStop, Q16StartStop, Q32StartStop:
		if n == 0 {
			return nil, errors.New("a start-stop range needs at least one object")
		}
		start := pts[0].Index
		for i, p := range pts {
			if p.Index != start+uint32(i) {
				return nil, errors.New("a start-stop range needs consecutive indices")
			}
		}
		out = AppendHeader(out, group, variation, qual, start, start+n-1)
	default:
		if !ValidQualifier(qual) || qual&0x0F < 7 {
			return nil, fmt.Errorf("qualifier 0x%02x is not supported", qual)
		}
		out = AppendHeader(out, group, variation, qual, n, 0)
	}
	if spl := sizePrefixLen(qual); spl > 0 {
		for _, p := range pts {
			for i := range spl {
				out = append(out, byte(len(p.Raw)>>(8*i)))
			}
			out = append(out, p.Raw...)
		}
		return out, nil
	}
	if freeFormat(group, variation) {
		return nil, fmt.Errorf("g%dv%d needs an object size prefix qualifier", group, variation)
	}
	if d.bits > 0 {
		if prefixLen(qual) != 0 {
			return nil, errors.New("packed objects cannot carry index prefixes")
		}
		packed := make([]byte, (int(n)*d.bits+7)/8)
		for i, p := range pts {
			v, _ := number(p.Value)
			bit := i * d.bits
			packed[bit/8] |= byte(int(v)&(1<<d.bits-1)) << (bit % 8)
		}
		return append(out, packed...), nil
	}
	var base time.Time
	if len(cto) > 0 {
		base = cto[0]
	}
	for _, p := range pts {
		p.Group, p.Var = group, variation
		for i := range prefixLen(qual) {
			out = append(out, byte(p.Index>>(8*i)))
		}
		if lengthVariation(group) {
			if len(p.Raw) != int(variation) {
				return nil, fmt.Errorf("g%dv%d carries exactly %d octets", group, variation, variation)
			}
			out = append(out, p.Raw...)
			continue
		}
		if d.rel {
			rel := p.Time.Sub(base).Milliseconds()
			if base.IsZero() || rel < 0 || rel > math.MaxUint16 {
				return nil, fmt.Errorf("g%dv%d: event time is not within 65535 ms after the CTO", group, variation)
			}
			d2 := d
			d2.rel = false
			var err error
			if out, err = appendObject(out, d2, p); err != nil {
				return nil, err
			}
			out = binary.LittleEndian.AppendUint16(out, uint16(rel))
			continue
		}
		var err error
		if out, err = appendObject(out, d, p); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ObjectSize is the octets per object of a fixed-size, non-packed
// variation (0 for packed, free-format and unknown ones).
func ObjectSize(group, variation uint8) int {
	d, ok := objDefs[gv(group, variation)]
	if !ok || d.bits > 0 {
		return 0
	}
	return d.size()
}

// PackedBits is the bits per point of a packed variation (0 otherwise).
func PackedBits(group, variation uint8) int { return objDefs[gv(group, variation)].bits }
