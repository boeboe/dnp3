// Copyright 2026 Bart Van Bos
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// The keep-alive interval runs from the latest frame received, the answer
// to the previous REQUEST_LINK_STATUS included; it does not wait for the
// response timeout first (13.2.3.3).
func TestMasterKeepAliveInterval(t *testing.T) {
	const keepAlive, timeout = 200 * time.Millisecond, 600 * time.Millisecond
	for _, answer := range []bool{true, false} {
		probes, m := keepAlivePeer(t, answer, keepAlive, timeout)
		if !answer {
			// Unanswered: the connection ends at the timeout after the
			// first keep-alive.
			start := time.Now()
			select {
			case <-m.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("the connection outlived an unanswered keep-alive")
			}
			if d := time.Since(start); d < keepAlive+timeout-50*time.Millisecond {
				t.Errorf("the connection ended %v after it opened, before the timeout", d)
			}
			continue
		}
		eventually(t, 3*time.Second, "four keep-alives", func() bool { return len(probes()) >= 4 })
		ps := probes()
		for i := 1; i < len(ps); i++ {
			if d := ps[i].Sub(ps[i-1]); d < keepAlive-20*time.Millisecond || d > keepAlive+timeout/2 {
				t.Errorf("keep-alive %d came %v after the previous one; want about %v", i, d, keepAlive)
			}
		}
	}
}

// keepAlivePeer is an outstation that only sees REQUEST_LINK_STATUS,
// answering it with answer, and a master connected to it.
func keepAlivePeer(t *testing.T, answer bool, keepAlive, timeout time.Duration) (func() []time.Time, *dnp3.Master) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var probes []time.Time
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var lp dnp3.LinkParser
		buf := make([]byte, 1024)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			for _, f := range lp.Feed(buf[:n]) {
				if f.Primary() && f.Func() == dnp3.LinkRequestLinkStatus {
					mu.Lock()
					probes = append(probes, time.Now())
					mu.Unlock()
					if answer {
						b, _ := dnp3.Frame{Ctrl: dnp3.LinkStatus, Dest: f.Src, Src: f.Dest}.Encode()
						_, _ = c.Write(b)
					}
				}
			}
		}
	}()
	m, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: "tcp://" + ln.Addr().String(), MasterAddress: 1, OutstationAddress: 10,
		Timeout: timeout, KeepAlive: keepAlive})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return func() []time.Time { mu.Lock(); defer mu.Unlock(); return append([]time.Time(nil), probes...) }, m
}
