// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// collector keeps the points of fragments handed to a callback.
type collector struct {
	mu    sync.Mutex
	pts   []dnp3.Point
	tasks map[string]int
	errs  []error
}

func (c *collector) data(f dnp3.Fragment) {
	bl, _ := dnp3.ParseObjects(f.Objects, true)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range bl {
		c.pts = append(c.pts, b.Points...)
	}
}

func (c *collector) task(name string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tasks == nil {
		c.tasks = map[string]int{}
	}
	c.tasks[name]++
	if err != nil {
		c.errs = append(c.errs, err)
	}
}

func (c *collector) has(group uint8, index uint32, v any) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.pts {
		if p.Group == group && p.Index == index && p.Value == v {
			return true
		}
	}
	return false
}

func (c *collector) count(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tasks[name]
}

// Covers: SIG-IPE-6495
// TestSessionStartup: a session runs the start-up sequence (disable
// unsolicited, clear the restart indication, integrity poll, time
// synchronisation when asked, enable unsolicited), then takes unsolicited
// events, and runs it again when the outstation restarts.
func TestSessionStartup(t *testing.T) {
	for _, mode := range []dnp3.TimeSyncMode{dnp3.TimeSyncNonLAN, dnp3.TimeSyncLAN} {
		t.Run(map[dnp3.TimeSyncMode]string{dnp3.TimeSyncNonLAN: "non-LAN", dnp3.TimeSyncLAN: "LAN"}[mode], func(t *testing.T) {
			o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.Unsolicited, c.NeedTime = true, time.Hour })
			var unsol collector
			m := o.master(t, nil, unsol.data)
			var c collector
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- m.RunSession(ctx, dnp3.SessionConfig{Unsolicited: []int{1, 2, 3}, TimeSync: mode,
					OnData: c.data, OnTask: c.task, RetryDelay: 200 * time.Millisecond})
			}()
			eventually(t, 5*time.Second, "start-up", func() bool { return c.count("enable unsolicited") == 1 })
			if !c.has(30, 0, 230.5) || !c.has(20, 0, 42.0) {
				t.Error("the integrity poll did not deliver the static data")
			}
			for _, name := range []string{"disable unsolicited", "clear restart", "integrity", "time sync"} {
				if c.count(name) != 1 {
					t.Errorf("task %q ran %d times", name, c.count(name))
				}
			}
			o.h.mu.Lock()
			set := o.h.timeSet
			o.h.mu.Unlock()
			if d := time.Since(set); d < 0 || d > 5*time.Second {
				t.Errorf("time set to %s", set)
			}
			if iin := m.IIN(); iin&(dnp3.IINDeviceRestart|dnp3.IINNeedTime) != 0 {
				t.Errorf("IIN %v after start-up", iin)
			}
			if _, err := o.db.Update(context.Background(), "binary", 0, 0, nil, 0x01, time.Now()); err != nil {
				t.Fatal(err)
			}
			eventually(t, 3*time.Second, "unsolicited event", func() bool { return unsol.has(2, 0, false) })

			// A cold restart sets IIN1.7: the start-up runs again.
			if _, err := m.Request(context.Background(), dnp3.FCColdRestart, nil); err != nil {
				t.Fatal(err)
			}
			eventually(t, 5*time.Second, "second start-up", func() bool { return c.count("enable unsolicited") == 2 })
			c.mu.Lock()
			errs := c.errs
			c.mu.Unlock()
			if len(errs) != 0 {
				t.Errorf("task errors: %v", errs)
			}
			cancel()
			if err := <-done; err != context.Canceled {
				t.Errorf("RunSession returned %v", err)
			}
		})
	}
}

// Covers: SIG-IPE-6496
// TestSessionScans: without unsolicited reporting, periodic class scans
// and polls for the classes the outstation flags (IIN1.1 to 1.3) bring
// the events in; a periodic integrity poll repeats.
func TestSessionScans(t *testing.T) {
	o := startOutstation(t, nil)
	m := o.master(t, nil, nil)
	var c collector
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = m.RunSession(ctx, dnp3.SessionConfig{Integrity: 700 * time.Millisecond, EventPoll: true,
			Scans: []dnp3.ClassScan{{Classes: []int{2}, Period: 300 * time.Millisecond}}, OnData: c.data, OnTask: c.task})
	}()
	eventually(t, 3*time.Second, "start-up integrity poll", func() bool { return c.count("integrity") >= 1 })
	if _, err := o.db.Update(context.Background(), "analog", 0, 300, nil, 0x01, time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "class 2 scan", func() bool { return c.has(32, 0, 300.0) })
	if _, err := o.db.Update(context.Background(), "binary", 1, 1, nil, 0x01, time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "event poll", func() bool { return c.has(2, 1, true) })
	eventually(t, 3*time.Second, "periodic integrity poll", func() bool { return c.count("integrity") >= 3 })
	if c.count("class 2 scan") < 2 {
		t.Errorf("class 2 scan ran %d times", c.count("class 2 scan"))
	}
}
