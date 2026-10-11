package dnp3

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf16"
)

// Data sets (IEEE 1815-2012 5.4; objects g85 prototypes, g86 descriptors,
// g87 present value, g88 events, A.32 to A.35). A descriptor or
// prototype is a list of descriptor elements (length, code, data type,
// maximum length, ancillary value); a data set is a list of values, each
// preceded by its length, the first two being the identifier and the
// time. All travel with qualifier 0x5B.

// Descriptor element codes (Table 5-7).
const (
	DescID   = 1
	DescUUID = 2
	DescNSPC = 3
	DescNAME = 4
	DescDAEL = 5
	DescPTYP = 6
	DescCTLV = 7
	DescCTLS = 8
)

// Data set data type codes (Table 5-6).
const (
	DSNone = 0
	DSVSTR = 1
	DSUINT = 2
	DSINT  = 3
	DSFLT  = 4
	DSOSTR = 5
	DSBSTR = 6
	DSTIME = 7
	DSUNCD = 8
)

var dsTypeNames = map[uint8]string{DSNone: "none", DSVSTR: "vstr", DSUINT: "uint", DSINT: "int", DSFLT: "flt", DSOSTR: "ostr", DSBSTR: "bstr", DSTIME: "time", DSUNCD: "uncd"}

// DataSetType maps a data type name (vstr, uint, ...) to its code.
func DataSetType(name string) (uint8, bool) {
	for c, n := range dsTypeNames {
		if n == name {
			return c, true
		}
	}
	return 0, false
}

// DescElement is one descriptor element.
type DescElement struct {
	Code      uint8
	Type      uint8
	MaxLen    uint8
	Ancillary []byte
}

// Name is the element's name (the ancillary VSTR of DAEL, CTLV, CTLS and
// NAME; the instance name after the UUID of a PTYP).
func (e DescElement) Name() string {
	if e.Code == DescPTYP {
		if len(e.Ancillary) > 16 {
			return string(e.Ancillary[16:])
		}
		return ""
	}
	return string(e.Ancillary)
}

// AppendElements encodes descriptor elements.
func AppendElements(out []byte, els []DescElement) []byte {
	for _, e := range els {
		out = append(out, byte(3+len(e.Ancillary)), e.Code, e.Type, e.MaxLen)
		out = append(out, e.Ancillary...)
	}
	return out
}

// ParseElements decodes descriptor elements.
func ParseElements(b []byte) ([]DescElement, error) {
	var out []DescElement
	for len(b) > 0 {
		n := int(b[0])
		if n < 3 || len(b) < 1+n {
			return nil, errors.New("descriptor element length does not fit the object")
		}
		out = append(out, DescElement{Code: b[1], Type: b[2], MaxLen: b[3], Ancillary: append([]byte(nil), b[4:1+n]...)})
		b = b[1+n:]
	}
	return out, nil
}

// uintBytes is v in the fewest octets (at least min).
func uintBytes(v uint64, min int) []byte {
	var out []byte
	for i := 0; i < 8 && (v>>(8*i) != 0 || i < min); i++ {
		out = append(out, byte(v>>(8*i)))
	}
	return out
}

func readUintN(b []byte) uint64 {
	var v uint64
	for i, x := range b {
		if i < 8 {
			v |= uint64(x) << (8 * i)
		}
	}
	return v
}

// IDElement is the mandatory first element carrying the identifier (a
// 2-octet UINT up to 65535, as in EX 5-5).
func IDElement(id uint32) DescElement {
	return DescElement{Code: DescID, Ancillary: uintBytes(uint64(id), 2)}
}

// Descriptor is a data set descriptor (g86v1) or prototype (g85v1).
type Descriptor struct {
	ID        uint32
	UUID      [16]byte // prototypes only
	Namespace string   // prototypes only
	Name      string
	Elements  []DescElement // after the ID (and UUID, NSPC, NAME)
}

// EncodeDescriptor is a g86v1 object's data.
func (d Descriptor) EncodeDescriptor() []byte {
	els := []DescElement{IDElement(d.ID)}
	if d.Name != "" {
		els = append(els, DescElement{Code: DescNAME, Ancillary: []byte(d.Name)})
	}
	return AppendElements(nil, append(els, d.Elements...))
}

// EncodePrototype is a g85v1 object's data.
func (d Descriptor) EncodePrototype() []byte {
	els := []DescElement{IDElement(d.ID), {Code: DescUUID, Ancillary: d.UUID[:]}}
	if d.Name != "" || d.Namespace != "" {
		els = append(els, DescElement{Code: DescNSPC, Ancillary: []byte(d.Namespace)}, DescElement{Code: DescNAME, Ancillary: []byte(d.Name)})
	}
	return AppendElements(nil, append(els, d.Elements...))
}

// ParseDescriptor decodes a g86v1 (proto false) or g85v1 (proto true)
// and checks the element order rules (5.4.6.2, 5.4.7.2).
func ParseDescriptor(b []byte, proto bool) (Descriptor, error) {
	els, err := ParseElements(b)
	if err != nil {
		return Descriptor{}, err
	}
	if len(els) == 0 || els[0].Code != DescID {
		return Descriptor{}, errors.New("the first descriptor element is not an ID")
	}
	d := Descriptor{ID: uint32(readUintN(els[0].Ancillary))}
	rest := els[1:]
	if proto {
		if len(rest) == 0 || rest[0].Code != DescUUID || len(rest[0].Ancillary) != 16 {
			return d, errors.New("the second prototype element is not a 16-octet UUID")
		}
		copy(d.UUID[:], rest[0].Ancillary)
		rest = rest[1:]
		if len(rest) > 0 && (rest[0].Code == DescNSPC || rest[0].Code == DescNAME) {
			if len(rest) < 2 || rest[0].Code != DescNSPC || rest[1].Code != DescNAME {
				return d, errors.New("a prototype has both a namespace and a name, or neither")
			}
			d.Namespace, d.Name = string(rest[0].Ancillary), string(rest[1].Ancillary)
			rest = rest[2:]
		}
	} else if len(rest) > 0 && rest[0].Code == DescNAME {
		d.Name = string(rest[0].Ancillary)
		rest = rest[1:]
	}
	for _, e := range rest {
		switch e.Code {
		case DescDAEL, DescCTLV, DescCTLS:
		case DescPTYP:
			if proto {
				return d, errors.New("a prototype cannot reference a prototype")
			}
			if len(e.Ancillary) < 16 {
				return d, errors.New("a prototype reference needs a 16-octet UUID")
			}
		default:
			return d, fmt.Errorf("descriptor element code %d is not permitted here", e.Code)
		}
	}
	d.Elements = rest
	return d, nil
}

// Flatten resolves the data elements of a descriptor, substituting each
// prototype reference with the prototype's elements (5.4.6.2.5).
func (d Descriptor) Flatten(protos map[[16]byte]Descriptor) ([]DescElement, error) {
	var out []DescElement
	for _, e := range d.Elements {
		if e.Code != DescPTYP {
			out = append(out, e)
			continue
		}
		var u [16]byte
		copy(u[:], e.Ancillary)
		p, ok := protos[u]
		if !ok {
			return nil, fmt.Errorf("prototype %s is not known", hex.EncodeToString(u[:]))
		}
		out = append(out, p.Elements...)
	}
	return out, nil
}

// Characteristics of a data set (g86v2): RD, WR, ST, EV, DF.
const (
	DSReadable   = 0x01
	DSWritable   = 0x02
	DSStatic     = 0x04
	DSEvent      = 0x08
	DSByMaster   = 0x10
	dsCharsValid = 0x1F
)

// PointRef is one element of a g86v3 point index attribute object.
type PointRef struct {
	Group uint8
	Index uint32
}

// EncodePointRefs is a g86v3 object's data.
func EncodePointRefs(id uint32, refs []PointRef) []byte {
	idb := uintBytes(uint64(id), 1)
	out := append([]byte{byte(len(idb))}, idb...)
	for _, r := range refs {
		ib := uintBytes(uint64(r.Index), 1)
		out = append(out, byte(1+len(ib)), r.Group)
		out = append(out, ib...)
	}
	return out
}

// ParsePointRefs decodes a g86v3.
func ParsePointRefs(b []byte) (uint32, []PointRef, error) {
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return 0, nil, errors.New("g86v3 identifier truncated")
	}
	id := uint32(readUintN(b[1 : 1+b[0]]))
	b = b[1+b[0]:]
	var out []PointRef
	for len(b) > 0 {
		n := int(b[0])
		if n < 1 || len(b) < 1+n {
			return 0, nil, errors.New("g86v3 element truncated")
		}
		out = append(out, PointRef{Group: b[1], Index: uint32(readUintN(b[2 : 1+n]))})
		b = b[1+n:]
	}
	return id, out, nil
}

// DataSet is a g87v1 (present value) or g88v1 (event) object: identifier,
// evaluation or event time and the raw element values.
type DataSet struct {
	ID     uint32
	Time   time.Time
	Values [][]byte
}

// Encode is the object data.
func (d DataSet) Encode() []byte {
	idb := uintBytes(uint64(d.ID), 2)
	out := append([]byte{byte(len(idb))}, idb...)
	out = append(out, 6)
	out = AppendTime48(out, d.Time)
	for _, v := range d.Values {
		out = append(append(out, byte(len(v))), v...)
	}
	return out
}

// ParseDataSet decodes a g87v1 or g88v1.
func ParseDataSet(b []byte) (DataSet, error) {
	var vals [][]byte
	for len(b) > 0 {
		n := int(b[0])
		if len(b) < 1+n {
			return DataSet{}, errors.New("data set element truncated")
		}
		vals = append(vals, b[1:1+n])
		b = b[1+n:]
	}
	if len(vals) < 2 || len(vals[1]) != 6 {
		return DataSet{}, errors.New("a data set needs an identifier and a 6-octet time")
	}
	return DataSet{ID: uint32(readUintN(vals[0])), Time: Time48(vals[1]), Values: vals[2:]}, nil
}

// DataSetValue decodes one element value by its data type.
func DataSetValue(typ uint8, v []byte) (any, error) {
	switch typ {
	case DSVSTR:
		return string(v), nil
	case DSUINT:
		if len(v) > 8 {
			return nil, errors.New("unsigned integer longer than 8 octets")
		}
		return float64(readUintN(v)), nil
	case DSINT:
		if len(v) == 0 || len(v) > 8 {
			return nil, errors.New("integer of 0 or more than 8 octets")
		}
		u := readUintN(v)
		shift := 64 - 8*len(v)
		return float64(int64(u<<shift) >> shift), nil
	case DSFLT:
		switch len(v) {
		case 4:
			return float64(math.Float32frombits(binary.LittleEndian.Uint32(v))), nil
		case 8:
			return math.Float64frombits(binary.LittleEndian.Uint64(v)), nil
		}
		return nil, fmt.Errorf("floating-point value of %d octets", len(v))
	case DSTIME:
		if len(v) != 6 {
			return nil, errors.New("a time value is 6 octets")
		}
		return Time48(v), nil
	case DSUNCD:
		if len(v)%2 != 0 {
			return nil, errors.New("a Unicode value has two octets per character")
		}
		u := make([]uint16, len(v)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(v[2*i:])
		}
		return string(utf16.Decode(u)), nil
	}
	return hex.EncodeToString(v), nil
}

// EncodeDataSetValue encodes a value for an element (maximum length and
// type from the descriptor): strings for VSTR/UNCD, hex strings for OSTR
// and BSTR, numbers for UINT/INT/FLT, time.Time or RFC 3339 for TIME.
func EncodeDataSetValue(e DescElement, v any) ([]byte, error) {
	var out []byte
	switch e.Type {
	case DSVSTR:
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("a text value is needed")
		}
		out = []byte(s)
	case DSUNCD:
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("a text value is needed")
		}
		for _, u := range utf16.Encode([]rune(s)) {
			out = binary.LittleEndian.AppendUint16(out, u)
		}
	case DSOSTR, DSBSTR:
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("a hex string is needed")
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("a hex string is needed")
		}
		out = b
	case DSUINT, DSINT, DSFLT:
		f, ok := number(v)
		if !ok {
			return nil, errors.New("a number is needed")
		}
		switch {
		case e.Type == DSFLT && e.MaxLen >= 8:
			out = binary.LittleEndian.AppendUint64(nil, math.Float64bits(f))
		case e.Type == DSFLT:
			out = binary.LittleEndian.AppendUint32(nil, math.Float32bits(float32(f)))
		case f != math.Trunc(f):
			return nil, errors.New("an integer is needed")
		case e.Type == DSUINT:
			if f < 0 {
				return nil, errors.New("a non-negative integer is needed")
			}
			out = uintBytes(uint64(f), 1)
		default:
			i := int64(f)
			n := 1
			for n < 8 && (i < -(1<<(8*n-1)) || i >= 1<<(8*n-1)) {
				n++
			}
			out = uintBytes(uint64(i), n)[:n]
		}
	case DSTIME:
		switch t := v.(type) {
		case time.Time:
			out = AppendTime48(nil, t)
		case string:
			tt, err := time.Parse(time.RFC3339Nano, t)
			if err != nil {
				return nil, errors.New("an RFC 3339 time is needed")
			}
			out = AppendTime48(nil, tt)
		default:
			return nil, errors.New("a time is needed")
		}
	default:
		out = nil
	}
	if e.MaxLen != 0 && len(out) > int(e.MaxLen) {
		return nil, fmt.Errorf("value of %d octets exceeds the maximum %d", len(out), e.MaxLen)
	}
	return out, nil
}

// CTLSStatus is the status code of a CTLS element (as in g12v1).
func CTLSStatus(v []byte) uint8 {
	if len(v) == 0 {
		return 0
	}
	return v[0]
}
