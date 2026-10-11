// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3

import (
	"context"
	"fmt"
	"time"
)

// Virtual terminal ports on the outstation: the master writes output
// blocks (g112, variation = length) to a port, which the handler takes;
// what the port answers goes to the master as virtual terminal events
// (g113) of the port's class, one per output even when it repeats. A
// port is a "virtual-terminal" point; g112 is never read or reported in
// class 0.

// VirtualTerminalHandler is implemented by a Handler that serves virtual
// terminal ports.
type VirtualTerminalHandler interface {
	VirtualTerminalWritten(ctx context.Context, port uint32, data []byte)
}

// VirtualTerminalOutput queues data from a port as a virtual terminal
// event (1 to 255 octets).
func (db *PointDB) VirtualTerminalOutput(ctx context.Context, port uint32, data []byte) error {
	if len(data) == 0 || len(data) > 255 {
		return fmt.Errorf("virtual terminal data is 1 to 255 octets, not %d", len(data))
	}
	_, err := db.Update(ctx, "virtual-terminal", port, 0, append([]byte(nil), data...), 0x01, time.Now())
	return err
}

// writeVirtualTerminal takes a master's g112 objects.
func (a *Association) writeVirtualTerminal(ctx context.Context, b Block) IIN {
	h, ok := a.cfg.Handler.(VirtualTerminalHandler)
	var iin IIN
	for _, p := range b.Points {
		if _, defined := a.cfg.DB.Point("virtual-terminal", p.Index); !defined || !ok {
			iin |= IINParameterError
			continue
		}
		h.VirtualTerminalWritten(ctx, p.Index, p.Raw)
	}
	return iin
}
