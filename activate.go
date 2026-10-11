package dnp3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Status of requested operation (g91v1, A.37) answering ACTIVATE_CONFIG
// (function code 31, 4.4.20): a busy time and one status element per
// request object.

// Activate configuration status codes.
const (
	ActivateOK          = 0
	ActivateBadObject   = 1
	ActivateBadConfig   = 2
	ActivateOtherError  = 3
	ActivateNotChecked  = 4
	activateStatusCount = 5
)

var activateNames = [activateStatusCount]string{"ok", "object-error", "configuration-error", "other-error", "not-checked"}

// ActivateStatusName names an activate configuration status code.
func ActivateStatusName(c uint8) string {
	if int(c) < len(activateNames) {
		return activateNames[c]
	}
	return fmt.Sprintf("status-%d", c)
}

// StatusElement is one status element of a g91v1.
type StatusElement struct {
	Code uint8
	Text string
}

// ActivateStatus is a g91v1.
type ActivateStatus struct {
	Delay    time.Duration
	Elements []StatusElement
}

// Encode is the object data.
func (a ActivateStatus) Encode() []byte {
	out := binary.LittleEndian.AppendUint32(nil, uint32(a.Delay.Milliseconds()))
	out = append(out, byte(len(a.Elements)))
	for _, e := range a.Elements {
		out = append(out, byte(1+len(e.Text)), e.Code)
		out = append(out, e.Text...)
	}
	return out
}

// ParseActivateStatus decodes a g91v1.
func ParseActivateStatus(b []byte) (ActivateStatus, error) {
	if len(b) < 5 {
		return ActivateStatus{}, errors.New("g91v1 too short")
	}
	a := ActivateStatus{Delay: time.Duration(binary.LittleEndian.Uint32(b)) * time.Millisecond}
	n := int(b[4])
	b = b[5:]
	for range n {
		if len(b) < 2 || b[0] < 1 || len(b) < 1+int(b[0]) {
			return a, errors.New("g91v1 status element truncated")
		}
		a.Elements = append(a.Elements, StatusElement{Code: b[1], Text: string(b[2 : 1+b[0]])})
		b = b[1+b[0]:]
	}
	if len(b) != 0 {
		return a, errors.New("g91v1 has octets after its status elements")
	}
	return a, nil
}
