package dnp3

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
)

// Device attributes (IEEE 1815 group 0): each object is a data type code,
// a length octet and the value. The object header's index is the
// attribute set (0 is the standard set); the variation names the
// attribute. Variation 254 in a READ asks for every attribute.

// Attribute data type codes decoded here.
const (
	AttrVSTR = 1 // visible string
	AttrUINT = 2 // unsigned integer, 1–4 octets
	AttrINT  = 3 // signed integer, 1–4 octets
	AttrFLT  = 4 // IEEE-754 float, 4 or 8 octets
	AttrOSTR = 5 // octet string
	AttrBSTR = 6 // bit string
	// AttrList and AttrExtList are lists of UINT8-BSTR8 pairs (the list of
	// attribute variations, g0v255); an extended list is 256 octets plus
	// its length octet long (5.5.4.3, Table 5-16).
	AttrList    = 254
	AttrExtList = 255
)

// AttrAll is the group 0 variation that reads every attribute.
const AttrAll = 254

// attributeNames names the standard attributes this master reports by
// name; any other variation is reported as "attribute-<variation>".
var attributeNames = map[uint8]string{
	209: "secure-auth-version", 210: "security-statistics-count", 211: "user-specific-attribute-sets",
	212: "master-data-set-prototypes", 213: "outstation-data-set-prototypes", 214: "master-data-sets",
	215: "outstation-data-sets", 216: "max-binary-outputs-per-request", 217: "local-timing-accuracy",
	218: "time-accuracy-duration", 219: "analog-output-events", 220: "max-analog-output-index",
	221: "analog-outputs", 222: "binary-output-events", 223: "max-binary-output-index", 224: "binary-outputs",
	225: "frozen-counter-events", 226: "frozen-counters", 227: "counter-events", 228: "max-counter-index",
	229: "counters", 230: "frozen-analog-inputs", 231: "analog-input-events", 232: "max-analog-input-index",
	233: "analog-inputs", 234: "double-bit-input-events", 235: "max-double-bit-input-index",
	236: "double-bit-inputs", 237: "binary-input-events", 238: "max-binary-input-index", 239: "binary-inputs",
	240: "max-tx-fragment", 241: "max-rx-fragment",
	242: "software-version", 243: "hardware-version",
	245: "location", 246: "id-code", 247: "device-name", 248: "serial-number",
	249: "subset-conformance", 250: "product-model", 252: "manufacturer", 255: "attribute-variations",
}

// AttributeName is the key a group 0 variation is reported under.
func AttributeName(variation uint8) string {
	if n, ok := attributeNames[variation]; ok {
		return n
	}
	return fmt.Sprintf("attribute-%d", variation)
}

// parseAttributes decodes the group 0 objects of one header into blk.
func parseAttributes(h Header, b []byte, blk *Block) ([]byte, error) {
	pl := prefixLen(h.Qual)
	for i := range h.Count {
		if len(b) < pl+2 {
			return nil, fmt.Errorf("%s: truncated attribute", h)
		}
		idx := h.Start + i
		if pl > 0 {
			idx = readUint(b, pl)
		}
		typ, n := b[pl], int(b[pl+1])
		if typ == AttrExtList {
			n += 256
		}
		if len(b) < pl+2+n {
			return nil, fmt.Errorf("%s: truncated attribute", h)
		}
		v, err := attributeValue(typ, b[pl+2:pl+2+n])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", h, err)
		}
		blk.Points = append(blk.Points, Point{Group: 0, Var: h.Var, Index: idx, Value: v, Status: typ})
		b = b[pl+2+n:]
	}
	return b, nil
}

func attributeValue(typ uint8, v []byte) (any, error) {
	switch typ {
	case AttrVSTR:
		return string(v), nil
	case AttrUINT, AttrINT:
		if len(v) == 0 || len(v) > 4 {
			return nil, fmt.Errorf("integer attribute of %d octets", len(v))
		}
		var u uint32
		for i, x := range v {
			u |= uint32(x) << (8 * i)
		}
		if typ == AttrUINT {
			return float64(u), nil
		}
		shift := 32 - 8*len(v)
		return float64(int32(u<<shift) >> shift), nil
	case AttrFLT:
		switch len(v) {
		case 4:
			return float64(math.Float32frombits(binary.LittleEndian.Uint32(v))), nil
		case 8:
			return math.Float64frombits(binary.LittleEndian.Uint64(v)), nil
		}
		return nil, fmt.Errorf("float attribute of %d octets", len(v))
	case AttrList, AttrExtList:
		if len(v)%2 != 0 {
			return nil, fmt.Errorf("attribute list of %d octets", len(v))
		}
		out := make([]any, 0, len(v)/2)
		for i := 0; i < len(v); i += 2 {
			out = append(out, map[string]any{"variation": float64(v[i]), "properties": float64(v[i+1])})
		}
		return out, nil
	}
	return hex.EncodeToString(v), nil // octet and bit strings and other types
}

// AppendAttribute appends one group 0 object (header with the attribute
// set as a one-octet start-stop range, then type, length and value). A
// string value is sent as VSTR, a float64 with a fraction or outside the
// 32-bit range as FLT (8 octets), other numbers as UINT or INT in 4
// octets, and []byte as OSTR.
func AppendAttribute(out []byte, variation uint8, set uint8, value any) []byte {
	out = AppendHeader(out, 0, variation, Q8StartStop, uint32(set), uint32(set))
	switch v := value.(type) {
	case string:
		return append(append(out, AttrVSTR, byte(len(v))), v...)
	case []byte:
		return append(append(out, AttrOSTR, byte(len(v))), v...)
	case float64:
		switch {
		case v == math.Trunc(v) && v >= 0 && v <= math.MaxUint32:
			return binary.LittleEndian.AppendUint32(append(out, AttrUINT, 4), uint32(v))
		case v == math.Trunc(v) && v < 0 && v >= math.MinInt32:
			return binary.LittleEndian.AppendUint32(append(out, AttrINT, 4), uint32(int32(v)))
		default:
			return binary.LittleEndian.AppendUint64(append(out, AttrFLT, 8), math.Float64bits(v))
		}
	}
	return out
}
