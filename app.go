package dnp3

import (
	"errors"
	"fmt"
	"strings"
)

// Application layer (IEEE 1815 clause 4): a control octet and function
// code, plus two internal indication octets in responses, followed by
// object headers and objects.

// Application control bits; the low four bits are the sequence number.
const (
	AppFIR = 0x80
	AppFIN = 0x40
	AppCON = 0x20
	AppUNS = 0x10
)

// Application function codes (4.2.2.5, Table 4-2). Requests use 0 to
// 128 (34 to 128 reserved), responses 129 to 255 (132 to 255 reserved).
const (
	FCConfirm            = 0
	FCRead               = 1
	FCWrite              = 2
	FCSelect             = 3
	FCOperate            = 4
	FCDirectOperate      = 5
	FCDirectOperateNR    = 6
	FCImmedFreeze        = 7
	FCImmedFreezeNR      = 8
	FCFreezeClear        = 9
	FCFreezeClearNR      = 10
	FCFreezeAtTime       = 11
	FCFreezeAtTimeNR     = 12
	FCColdRestart        = 13
	FCWarmRestart        = 14
	FCInitializeData     = 15 // obsolete
	FCInitializeAppl     = 16
	FCStartAppl          = 17
	FCStopAppl           = 18
	FCSaveConfig         = 19 // deprecated
	FCEnableUnsolicited  = 20
	FCDisableUnsolicited = 21
	FCAssignClass        = 22
	FCDelayMeasure       = 23
	FCRecordCurrentTime  = 24
	FCOpenFile           = 25
	FCCloseFile          = 26
	FCDeleteFile         = 27
	FCGetFileInfo        = 28
	FCAuthenticateFile   = 29
	FCAbortFile          = 30
	FCActivateConfig     = 31
	FCAuthRequest        = 32
	FCAuthRequestNoAck   = 33
	FCResponse           = 129
	FCUnsolicited        = 130
	FCAuthResponse       = 131
)

var funcNames = map[byte]string{
	FCConfirm: "CONFIRM", FCRead: "READ", FCWrite: "WRITE", FCSelect: "SELECT", FCOperate: "OPERATE",
	FCDirectOperate: "DIRECT_OPERATE", FCDirectOperateNR: "DIRECT_OPERATE_NR",
	FCImmedFreeze: "IMMED_FREEZE", FCImmedFreezeNR: "IMMED_FREEZE_NR",
	FCFreezeClear: "FREEZE_CLEAR", FCFreezeClearNR: "FREEZE_CLEAR_NR",
	FCFreezeAtTime: "FREEZE_AT_TIME", FCFreezeAtTimeNR: "FREEZE_AT_TIME_NR",
	FCColdRestart: "COLD_RESTART", FCWarmRestart: "WARM_RESTART", FCInitializeData: "INITIALIZE_DATA",
	FCInitializeAppl: "INITIALIZE_APPL", FCStartAppl: "START_APPL", FCStopAppl: "STOP_APPL",
	FCSaveConfig: "SAVE_CONFIG", FCEnableUnsolicited: "ENABLE_UNSOLICITED", FCDisableUnsolicited: "DISABLE_UNSOLICITED",
	FCAssignClass: "ASSIGN_CLASS", FCDelayMeasure: "DELAY_MEASURE", FCRecordCurrentTime: "RECORD_CURRENT_TIME",
	FCOpenFile: "OPEN_FILE", FCCloseFile: "CLOSE_FILE", FCDeleteFile: "DELETE_FILE", FCGetFileInfo: "GET_FILE_INFO",
	FCAuthenticateFile: "AUTHENTICATE_FILE", FCAbortFile: "ABORT_FILE", FCActivateConfig: "ACTIVATE_CONFIG",
	FCAuthRequest: "AUTH_REQUEST", FCAuthRequestNoAck: "AUTH_REQUEST_NO_ACK",
	FCResponse: "RESPONSE", FCUnsolicited: "UNSOLICITED_RESPONSE", FCAuthResponse: "AUTH_RESPONSE",
}

// FuncName is a readable name for a function code.
func FuncName(fc byte) string {
	if n, ok := funcNames[fc]; ok {
		return n
	}
	return fmt.Sprintf("function %d", fc)
}

// NoResponse reports the request function codes the outstation never
// answers (the _NR variants and AUTH_REQUEST_NO_ACK), plus CONFIRM.
func NoResponse(fc byte) bool {
	switch fc {
	case FCConfirm, FCDirectOperateNR, FCImmedFreezeNR, FCFreezeClearNR, FCFreezeAtTimeNR, FCAuthRequestNoAck:
		return true
	}
	return false
}

// IIN is the internal indications of a response: IIN1 in the low octet,
// IIN2 in the high octet.
type IIN uint16

// Internal indication bits.
const (
	IINBroadcast           IIN = 1 << 0
	IINClass1Events        IIN = 1 << 1
	IINClass2Events        IIN = 1 << 2
	IINClass3Events        IIN = 1 << 3
	IINNeedTime            IIN = 1 << 4
	IINLocalControl        IIN = 1 << 5
	IINDeviceTrouble       IIN = 1 << 6
	IINDeviceRestart       IIN = 1 << 7
	IINNoFuncCodeSupport   IIN = 1 << 8
	IINObjectUnknown       IIN = 1 << 9
	IINParameterError      IIN = 1 << 10
	IINEventBufferOverflow IIN = 1 << 11
	IINAlreadyExecuting    IIN = 1 << 12
	IINConfigCorrupt       IIN = 1 << 13
	IINReserved2           IIN = 1 << 14 // IIN2.6, always 0
	IINReserved1           IIN = 1 << 15 // IIN2.7, always 0

	IINClassEvents = IINClass1Events | IINClass2Events | IINClass3Events
	iinRequestErr  = IINNoFuncCodeSupport | IINObjectUnknown | IINParameterError
)

var iinNames = []string{
	"broadcast", "class-1-events", "class-2-events", "class-3-events",
	"need-time", "local-control", "device-trouble", "device-restart",
	"no-func-code-support", "object-unknown", "parameter-error", "event-buffer-overflow",
	"already-executing", "config-corrupt", "reserved-2.6", "reserved-2.7",
}

// Names lists the set indications.
func (i IIN) Names() []string {
	out := []string{}
	for b := range 16 {
		if i&(1<<b) != 0 {
			out = append(out, iinNames[b])
		}
	}
	return out
}

// String lists the indications set, by name.
func (i IIN) String() string { return strings.Join(i.Names(), ",") }

// Fragment is one application fragment (request or response).
type Fragment struct {
	Control byte
	Func    byte
	IIN     IIN // responses only
	Objects []byte
}

// Seq is the fragment's sequence number.
func (f Fragment) Seq() uint8 { return f.Control & 0x0F }

// IsResponse reports a solicited or unsolicited response.
func (f Fragment) IsResponse() bool {
	return f.Func == FCResponse || f.Func == FCUnsolicited || f.Func == FCAuthResponse
}

// Encode serialises the fragment.
func (f Fragment) Encode() []byte {
	out := make([]byte, 0, 4+len(f.Objects))
	out = append(out, f.Control, f.Func)
	if f.IsResponse() {
		out = append(out, byte(f.IIN), byte(f.IIN>>8))
	}
	return append(out, f.Objects...)
}

// ParseFragment decodes an application fragment's header.
func ParseFragment(b []byte) (Fragment, error) {
	if len(b) < 2 {
		return Fragment{}, errors.New("application fragment shorter than its header")
	}
	f := Fragment{Control: b[0], Func: b[1]}
	b = b[2:]
	if f.IsResponse() {
		if len(b) < 2 {
			return Fragment{}, errors.New("response without internal indications")
		}
		f.IIN = IIN(b[0]) | IIN(b[1])<<8
		b = b[2:]
	}
	f.Objects = b
	return f, nil
}

// Object header qualifiers (4.2.2.7.3): bit 7 reserved (0), bits 6-4 the
// object prefix code, bits 3-0 the range specifier code. Every code of
// Table 4-6 is parsed.
const (
	Q8StartStop  = 0x00
	Q16StartStop = 0x01
	Q32StartStop = 0x02
	QVAddr8      = 0x03 // virtual address ranges (group 102)
	QVAddr16     = 0x04
	QVAddr32     = 0x05
	QAll         = 0x06
	Q8Count      = 0x07
	Q16Count     = 0x08
	Q32Count     = 0x09
	Q8Index8     = 0x17 // 1-octet count, 1-octet index prefix
	Q8Index16    = 0x18 // 2-octet count, 1-octet index prefix
	Q8Index32    = 0x19
	Q16Index8    = 0x27
	Q16Index16   = 0x28 // 2-octet count, 2-octet index prefix
	Q16Index32   = 0x29
	Q32Index8    = 0x37
	Q32Index16   = 0x38
	Q32Index32   = 0x39
	QSize8       = 0x4B // 1-octet count, 1-octet object size prefix
	QFreeFormat  = 0x5B // 1-octet count, 2-octet object size prefix
	QSize32      = 0x6B
)

// ValidQualifier reports the codes of Table 4-6.
func ValidQualifier(q uint8) bool {
	pre, rng := q>>4, q&0x0F
	switch {
	case q&0x80 != 0:
		return false
	case pre == 0:
		return rng <= 9
	case pre <= 3:
		return rng >= 7 && rng <= 9
	case pre <= 6:
		return rng == 0x0B
	}
	return false
}

// Header is one object header.
type Header struct {
	Group, Var, Qual uint8
	Start, Stop      uint32 // start-stop and virtual address qualifiers
	Count            uint32 // number of objects that follow
}

// String is the object type as gNvM.
func (h Header) String() string { return fmt.Sprintf("g%dv%d", h.Group, h.Var) }

// prefixLen is the index prefix size of a qualifier (prefix codes 1-3).
func prefixLen(q uint8) int {
	switch q >> 4 {
	case 1:
		return 1
	case 2:
		return 2
	case 3:
		return 4
	}
	return 0
}

// sizePrefixLen is the object size prefix of a qualifier (codes 4-6).
func sizePrefixLen(q uint8) int {
	switch q >> 4 {
	case 4:
		return 1
	case 5:
		return 2
	case 6:
		return 4
	}
	return 0
}

// readUint reads an n-octet little-endian unsigned integer.
func readUint(b []byte, n int) uint32 {
	var v uint32
	for i := range n {
		v |= uint32(b[i]) << (8 * i)
	}
	return v
}

// parseHeader reads an object header and returns the remaining octets.
func parseHeader(b []byte) (Header, []byte, error) {
	if len(b) < 3 {
		return Header{}, nil, errors.New("truncated object header")
	}
	h := Header{Group: b[0], Var: b[1], Qual: b[2]}
	b = b[3:]
	if !ValidQualifier(h.Qual) {
		return h, nil, fmt.Errorf("%s: qualifier 0x%02x is not valid", h, h.Qual)
	}
	rng := h.Qual & 0x0F
	var n int
	switch rng {
	case 0, 3:
		n = 1
	case 1, 4:
		n = 2
	case 2, 5:
		n = 4
	case 6:
		return h, b, nil
	case 7, 0x0B:
		n = 1
	case 8:
		n = 2
	case 9:
		n = 4
	}
	if rng >= 7 {
		if len(b) < n {
			return h, nil, fmt.Errorf("%s: truncated range", h)
		}
		h.Count = readUint(b, n)
		return h, b[n:], nil
	}
	if len(b) < 2*n {
		return h, nil, fmt.Errorf("%s: truncated range", h)
	}
	h.Start, h.Stop = readUint(b, n), readUint(b[n:], n)
	b = b[2*n:]
	if h.Stop < h.Start {
		return h, nil, fmt.Errorf("%s: range stop %d before start %d", h, h.Stop, h.Start)
	}
	h.Count = h.Stop - h.Start + 1
	return h, b, nil
}

// AppendHeader appends an object header. For start-stop and virtual
// address qualifiers a and b are the start and stop; for count, index-
// and size-prefix qualifiers a is the count; QAll takes neither.
func AppendHeader(out []byte, group, variation, qual uint8, a, b uint32) []byte {
	out = append(out, group, variation, qual)
	put := func(v uint32, n int) {
		for i := range n {
			out = append(out, byte(v>>(8*i)))
		}
	}
	switch qual & 0x0F {
	case 0, 3:
		put(a, 1)
		put(b, 1)
	case 1, 4:
		put(a, 2)
		put(b, 2)
	case 2, 5:
		put(a, 4)
		put(b, 4)
	case 7, 0x0B:
		put(a, 1)
	case 8:
		put(a, 2)
	case 9:
		put(a, 4)
	}
	return out
}

// ClassRequest is the object part of a READ (or unsolicited enable or
// disable) of the given classes, 0 to 3, with qualifier "all".
func ClassRequest(classes ...int) []byte {
	var out []byte
	for _, c := range classes {
		out = AppendHeader(out, 60, uint8(c+1), QAll, 0, 0)
	}
	return out
}

// Command status codes carried by control objects (g12, g41).
var commandStatus = map[uint8]string{
	0: "success", 1: "timeout", 2: "no-select", 3: "format-error", 4: "not-supported",
	5: "already-active", 6: "hardware-error", 7: "local", 8: "too-many-objs",
	9: "not-authorized", 10: "automation-inhibit", 11: "processing-limited",
	12: "out-of-range", 13: "downstream-local", 14: "already-complete", 15: "blocked",
	16: "cancelled", 17: "blocked-other-master", 18: "downstream-fail",
	126: "non-participating", 127: "undefined",
}

// StatusName is the readable name of a command status code.
func StatusName(s uint8) string {
	if n, ok := commandStatus[s]; ok {
		return n
	}
	return fmt.Sprintf("status-%d", s)
}

// ClassAssignment is one assignment set of an ASSIGN_CLASS request
// (4.4.14): the class (0 disables events, 1 to 3) and the object headers
// of the points whose events it takes.
type ClassAssignment struct {
	Class   int
	Headers [][]byte
}

// AssignClass builds the objects of an ASSIGN_CLASS request: per set a
// group 60 header with qualifier 0x06 (variation 1 for class 0, 2 to 4 for
// classes 1 to 3) followed by its point headers.
func AssignClass(sets []ClassAssignment) []byte {
	var out []byte
	for _, s := range sets {
		out = AppendHeader(out, 60, uint8(s.Class+1), QAll, 0, 0)
		for _, h := range s.Headers {
			out = append(out, h...)
		}
	}
	return out
}
