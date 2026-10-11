// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// eventually polls f every 20 ms until it holds or timeout passes.
func eventually(t *testing.T, timeout time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// crobObjs is a latch-on CROB (g12v1) for one index.
func crobObjs(t *testing.T, idx uint32) []byte {
	t.Helper()
	b, err := dnp3.EncodeBlock(12, 1, dnp3.Q16Index16, []dnp3.Point{{Index: idx, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
