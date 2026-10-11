package dnp3

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Data link layer (IEEE 1815 clause 9): a 10-octet header (two start
// octets, length, control, destination, source, CRC) followed by the user
// data in blocks of at most 16 octets, each block followed by its own CRC.

// Link control octet bits.
const (
	CtrlDIR = 0x80 // set on frames sent by a master
	CtrlPRM = 0x40 // set on primary (initiating) frames
	CtrlFCB = 0x20
	CtrlFCV = 0x10 // DFC on secondary frames
)

// Link function codes. Primary codes are used with CtrlPRM, secondary codes
// without it.
const (
	LinkResetLinkStates     = 0
	LinkTestLinkStates      = 2
	LinkConfirmedUserData   = 3
	LinkUnconfirmedUserData = 4
	LinkRequestLinkStatus   = 9

	LinkAck          = 0
	LinkNack         = 1
	LinkStatus       = 11
	LinkNotSupported = 15
)

// MaxLinkData is the most user data one link frame carries.
const MaxLinkData = 250

const (
	start1   = 0x05
	start2   = 0x64
	blockLen = 16
)

var crcTable = func() (t [256]uint16) {
	// The DNP CRC polynomial 0x3D65, bit-reversed (0xA6BC) because the
	// computation runs least significant bit first.
	for i := range 256 {
		c := uint16(i)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ 0xA6BC
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return t
}()

// CRC is the DNP3 link-layer CRC of b (initial value 0, complemented
// result). It is sent least significant octet first.
func CRC(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c = c>>8 ^ crcTable[byte(c)^x]
	}
	return ^c
}

// Frame is one link-layer frame.
type Frame struct {
	Ctrl byte
	Dest uint16
	Src  uint16
	Data []byte
}

// Func is the frame's link function code.
func (f Frame) Func() byte { return f.Ctrl & 0x0F }

// Primary reports a primary (initiating) frame.
func (f Frame) Primary() bool { return f.Ctrl&CtrlPRM != 0 }

// FromMaster reports the DIR bit.
func (f Frame) FromMaster() bool { return f.Ctrl&CtrlDIR != 0 }

// Encode serialises the frame with its header and block CRCs.
func (f Frame) Encode() ([]byte, error) {
	if len(f.Data) > MaxLinkData {
		return nil, fmt.Errorf("link frame user data is %d octets; at most %d fit", len(f.Data), MaxLinkData)
	}
	n := len(f.Data)
	out := make([]byte, 0, 10+n+2*((n+blockLen-1)/blockLen))
	out = append(out, start1, start2, byte(5+n), f.Ctrl)
	out = binary.LittleEndian.AppendUint16(out, f.Dest)
	out = binary.LittleEndian.AppendUint16(out, f.Src)
	out = binary.LittleEndian.AppendUint16(out, CRC(out))
	for i := 0; i < n; i += blockLen {
		blk := f.Data[i:min(i+blockLen, n)]
		out = append(out, blk...)
		out = binary.LittleEndian.AppendUint16(out, CRC(blk))
	}
	return out, nil
}

// frameLen is the encoded size of a frame whose length octet is l.
func frameLen(l byte) int {
	n := int(l) - 5
	return 10 + n + 2*((n+blockLen-1)/blockLen)
}

// LinkParser extracts frames from a byte stream. It tolerates reads split
// anywhere and resynchronises on the start octets after garbage or a CRC
// error.
type LinkParser struct {
	buf []byte
	// Errors counts discarded octets runs (garbage, bad CRC, bad length).
	Errors int
}

// ErrLinkCRC is reported through LinkParser.Errors; it is exported for
// callers that decode single frames with DecodeFrame.
var ErrLinkCRC = errors.New("link frame CRC mismatch")

// Feed adds received octets and returns every complete frame.
func (p *LinkParser) Feed(b []byte) []Frame {
	p.buf = append(p.buf, b...)
	var out []Frame
	for {
		i := indexStart(p.buf)
		if i < 0 {
			// Keep a trailing first start octet; drop the rest.
			if n := len(p.buf); n > 0 && p.buf[n-1] == start1 {
				if n > 1 {
					p.Errors++
				}
				p.buf = append(p.buf[:0], start1)
			} else {
				if n > 0 {
					p.Errors++
				}
				p.buf = p.buf[:0]
			}
			break
		}
		if i > 0 {
			p.Errors++
			p.buf = p.buf[i:]
		}
		if len(p.buf) < 10 {
			break
		}
		if p.buf[2] < 5 || binary.LittleEndian.Uint16(p.buf[8:]) != CRC(p.buf[:8]) {
			p.Errors++
			p.buf = p.buf[1:]
			continue
		}
		total := frameLen(p.buf[2])
		if len(p.buf) < total {
			break
		}
		f, err := DecodeFrame(p.buf[:total])
		if err != nil {
			p.Errors++
			p.buf = p.buf[1:]
			continue
		}
		out = append(out, f)
		p.buf = p.buf[total:]
	}
	if len(p.buf) == 0 {
		p.buf = nil
	}
	return out
}

func indexStart(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == start1 && b[i+1] == start2 {
			return i
		}
	}
	return -1
}

// DecodeFrame decodes exactly one encoded frame.
func DecodeFrame(b []byte) (Frame, error) {
	if len(b) < 10 || b[0] != start1 || b[1] != start2 {
		return Frame{}, errors.New("not a link frame")
	}
	if b[2] < 5 || len(b) != frameLen(b[2]) {
		return Frame{}, fmt.Errorf("link frame length octet %d does not match %d octets", b[2], len(b))
	}
	if binary.LittleEndian.Uint16(b[8:]) != CRC(b[:8]) {
		return Frame{}, ErrLinkCRC
	}
	f := Frame{Ctrl: b[3], Dest: binary.LittleEndian.Uint16(b[4:]), Src: binary.LittleEndian.Uint16(b[6:])}
	n := int(b[2]) - 5
	f.Data = make([]byte, 0, n)
	rest := b[10:]
	for n > 0 {
		k := min(n, blockLen)
		blk := rest[:k]
		if binary.LittleEndian.Uint16(rest[k:]) != CRC(blk) {
			return Frame{}, ErrLinkCRC
		}
		f.Data = append(f.Data, blk...)
		rest = rest[k+2:]
		n -= k
	}
	return f, nil
}

// Special addresses (9.2.5.2, Table 9-3). Individual addresses are
// 0x0000 to 0xFFEF; 0xFFF0 to 0xFFFB are reserved and frames sent to
// them are discarded.
const (
	AddrMaxIndividual      = 0xFFEF
	AddrSelf               = 0xFFFC  // self-address: optional, only as a destination
	AddrBroadcastNoConfirm = 0xFFFD  // application confirmation not required to clear IIN1.0
	AddrBroadcastMandatory = 0xFFFE  // application confirmation mandatory to clear IIN1.0
	AddrBroadcastOptional  = 0xFFFF  // application confirmation optional to clear IIN1.0
	CtrlDFC                = CtrlFCV // data flow control, secondary frames
	linkReservedFirst      = 0xFFF0
	linkReservedLast       = 0xFFFB
)

// IsBroadcast reports the three broadcast addresses (9.2.5.2.1).
func IsBroadcast(a uint16) bool { return a >= AddrBroadcastNoConfirm }

// IsReservedAddress reports 0xFFF0 to 0xFFFB, which no frame may be
// passed up for (9.2.5.2.3).
func IsReservedAddress(a uint16) bool { return a >= linkReservedFirst && a <= linkReservedLast }

// FCB reports the frame count bit and FCV the frame count valid bit of a
// primary frame.
func (f Frame) FCB() bool { return f.Ctrl&CtrlFCB != 0 }

// FCV reports the frame count valid bit (DFC on secondary frames).
func (f Frame) FCV() bool { return f.Ctrl&CtrlFCV != 0 }

// primaryFCV is the FCV each primary function code must carry (Table
// 9-1); ok is false for codes that are reserved or obsolete.
func primaryFCV(fc byte) (fcv, ok bool) {
	switch fc {
	case LinkResetLinkStates, LinkUnconfirmedUserData, LinkRequestLinkStatus:
		return false, true
	case LinkTestLinkStates, LinkConfirmedUserData:
		return true, true
	}
	return false, false
}

// Secondary is the secondary-station half of the data link layer for one
// primary peer (9.2.6, 9.2.8 Table 9-5): link reset state, the expected
// frame count bit and the last ACK or NACK sent, so a repeated TEST_LINK_STATES
// gets the same answer.
type Secondary struct {
	reset   bool
	efcb    bool
	last    byte
	hasLast bool
}

// LinkAction is what a secondary station does with a received primary
// frame: the secondary function code to answer with (when Respond), and
// whether the user data goes to the transport function (Deliver).
type LinkAction struct {
	Respond bool
	Func    byte
	Deliver bool
}

// Handle applies the secondary station rules to a primary frame addressed
// to this station (individually or by broadcast). Frames whose FCV does
// not match their function code are discarded (9.2.9). Nothing is ever
// answered to a broadcast destination, and confirmed user data sent to a
// broadcast address is discarded (9.2.4.1.3.6, 9.2.5.2.1).
func (s *Secondary) Handle(f Frame) LinkAction {
	fc := f.Func()
	fcv, known := primaryFCV(fc)
	bc := IsBroadcast(f.Dest)
	if !known {
		if bc {
			return LinkAction{}
		}
		return LinkAction{Respond: true, Func: LinkNotSupported}
	}
	if f.FCV() != fcv {
		return LinkAction{}
	}
	if bc {
		return LinkAction{Deliver: fc == LinkUnconfirmedUserData}
	}
	ack := func(fc byte) LinkAction {
		s.last, s.hasLast = fc, true
		return LinkAction{Respond: true, Func: fc}
	}
	switch fc {
	case LinkResetLinkStates:
		s.reset, s.efcb = true, true
		return ack(LinkAck)
	case LinkTestLinkStates:
		if !s.reset {
			return ack(LinkNack)
		}
		if f.FCB() == s.efcb {
			s.efcb = !s.efcb
			return ack(LinkAck)
		}
		if s.hasLast {
			return LinkAction{Respond: true, Func: s.last}
		}
		return ack(LinkAck)
	case LinkConfirmedUserData:
		if !s.reset {
			return ack(LinkNack)
		}
		if f.FCB() == s.efcb {
			s.efcb = !s.efcb
			a := ack(LinkAck)
			a.Deliver = true
			return a
		}
		return ack(LinkAck) // a repeat: acknowledged, not passed up
	case LinkUnconfirmedUserData:
		return LinkAction{Deliver: true}
	default: // LinkRequestLinkStatus
		return LinkAction{Respond: true, Func: LinkStatus}
	}
}

// Primary is the primary-station state for confirmed user data towards one
// secondary peer (9.2.6.1, Table 9-4): whether its link states were reset
// and the next frame count bit.
type Primary struct {
	Reset bool
	NFCB  bool
}

// Control is the control octet of the next confirmed user data frame
// (dir is CtrlDIR for a master, 0 for an outstation).
func (p *Primary) Control(dir byte) byte {
	c := dir | CtrlPRM | CtrlFCV | LinkConfirmedUserData
	if p.NFCB {
		c |= CtrlFCB
	}
	return c
}

// Acked records an ACK of the last confirmed frame: the next one toggles
// the frame count bit.
func (p *Primary) Acked() { p.NFCB = !p.NFCB }

// ResetDone records an ACK of RESET_LINK_STATES: the next confirmed frame
// carries FCB 1.
func (p *Primary) ResetDone() { p.Reset, p.NFCB = true, true }

// CRCTableEntry is entry i of the CRC look-up table (Annex E).
func CRCTableEntry(i byte) uint16 { return crcTable[i] }
