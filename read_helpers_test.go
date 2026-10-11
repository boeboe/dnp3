package dnp3_test

import (
	"github.com/cB-Sigma/dnp3"
)

// readHeader builds a READ header for index 0 (or all, or a count of 1).
func readHeader(g, v, q uint8) []byte {
	switch q {
	case dnp3.Q8StartStop, dnp3.Q16StartStop, dnp3.QAll:
		return dnp3.AppendHeader(nil, g, v, q, 0, 0)
	case dnp3.Q8Count, dnp3.Q16Count:
		return dnp3.AppendHeader(nil, g, v, q, 1, 0)
	case dnp3.Q8Index8:
		return append(dnp3.AppendHeader(nil, g, v, q, 1, 0), 0)
	case dnp3.Q16Index16:
		return append(dnp3.AppendHeader(nil, g, v, q, 1, 0), 0, 0)
	}
	return nil
}
