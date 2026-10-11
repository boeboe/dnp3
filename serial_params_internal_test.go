package dnp3

import (
	"net/url"
	"testing"
)

// The parity of a serial:// URL is written as a letter (N, E, O) or a
// word (none, even, odd) in any case; both reach the serial port as the
// letter, no parity is the default, and anything else is refused.
// Covers: SIG-IPE-3065
func TestSerialParity(t *testing.T) {
	for in, want := range map[string]string{
		"": "N", "N": "N", "n": "N", "none": "N", "NONE": "N",
		"E": "E", "e": "E", "even": "E", "Even": "E",
		"O": "O", "o": "O", "odd": "O", "ODD": "O",
	} {
		u, _ := url.Parse("serial:///dev/ttyS1?baud=19200&parity=" + in)
		dev, baud, p, err := SerialParams(u)
		if err != nil || dev != "/dev/ttyS1" || baud != 19200 || p != want {
			t.Errorf("parity=%q: %q %d %q %v, want %q", in, dev, baud, p, err, want)
		}
	}
	for _, in := range []string{"M", "mark", "space", "x", "evens"} {
		u, _ := url.Parse("serial:///dev/ttyS1?parity=" + in)
		if _, _, _, err := SerialParams(u); err == nil {
			t.Errorf("parity=%q was accepted", in)
		}
	}
}
