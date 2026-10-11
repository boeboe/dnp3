package dnp3

import (
	"bytes"
	"errors"
	"fmt"
)

// Transport function (IEEE 1815 clause 8): one header octet (FIN, FIR and a
// 6-bit sequence number) in front of each link frame's user data, so an
// application fragment can span several frames.

// Transport header bits.
const (
	TransportFIN = 0x80
	TransportFIR = 0x40
)

// MaxSegment is the most application octets one transport segment carries.
const MaxSegment = MaxLinkData - 1

// maxFragment bounds reassembly so a broken peer cannot grow memory.
const maxFragment = 1 << 16

// Segment splits an application fragment into transport segments of 1 to
// 249 application octets (8.2.2). seq is the sender's running sequence
// number and is advanced per segment.
func Segment(apdu []byte, seq *uint8) [][]byte {
	var out [][]byte
	for i := 0; i == 0 || i < len(apdu); i += MaxSegment {
		end := min(i+MaxSegment, len(apdu))
		h := *seq & 0x3F
		if i == 0 {
			h |= TransportFIR
		}
		if end == len(apdu) {
			h |= TransportFIN
		}
		seg := make([]byte, 0, 1+end-i)
		seg = append(seg, h)
		seg = append(seg, apdu[i:end]...)
		out = append(out, seg)
		*seq = (*seq + 1) & 0x3F
	}
	return out
}

// Reassembler rebuilds application fragments from transport segments.
type Reassembler struct {
	buf    []byte
	active bool
	next   uint8
	prev   []byte // the preceding segment, to drop an identical repeat
}

// Add takes one segment. It returns the fragment when the segment carried
// FIN, nil while more are expected, and an error for a segment that does
// not continue the current fragment (the partial fragment is discarded).
func (r *Reassembler) Add(seg []byte) ([]byte, error) {
	if len(seg) == 0 {
		return nil, errors.New("empty transport segment")
	}
	h := seg[0]
	seq := h & 0x3F
	// Rule 5.3 (8.2.1.4): a segment octet-for-octet identical to the
	// preceding one is discarded without ending the series.
	if r.active && h&TransportFIR == 0 && bytes.Equal(seg, r.prev) {
		return nil, nil
	}
	r.prev = append(r.prev[:0], seg...)
	if h&TransportFIR != 0 {
		r.buf = r.buf[:0]
		r.active = true
	} else if !r.active {
		return nil, fmt.Errorf("transport segment %d without a first segment", seq)
	} else if seq != r.next {
		r.active = false
		r.buf = r.buf[:0]
		return nil, fmt.Errorf("transport segment %d out of sequence (expected %d)", seq, r.next)
	}
	if len(r.buf)+len(seg)-1 > maxFragment {
		r.active = false
		r.buf = r.buf[:0]
		return nil, errors.New("application fragment too large")
	}
	r.buf = append(r.buf, seg[1:]...)
	r.next = (seq + 1) & 0x3F
	if h&TransportFIN == 0 {
		return nil, nil
	}
	r.active = false
	out := append([]byte(nil), r.buf...)
	r.buf = r.buf[:0]
	return out, nil
}
