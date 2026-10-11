// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3/gateway"
)

// TestOpendnp3ThroughGateway: opendnp3's outstation below the gateway
// (polled by this module's master), opendnp3's master above it (against
// the gateway's outstation, this module's): start-up and integrity poll
// of the mapped points at the gateway's indexes, an event below arriving
// above as an unsolicited event, select-before-operate of a CROB and of an
// analog output passed down to opendnp3's outstation at the source's
// indexes with SUCCESS back, and a lost source seen above as COMM_LOST.
func TestOpendnp3ThroughGateway(t *testing.T) {
	needDocker(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Below: opendnp3's outstation.
	port := freePort(t)
	below := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20000", port), image, "dnp3-outstation")
	below.expect(60*time.Second, "READY")

	gdb := dnp3.NewPointDB()
	g := gateway.New(gdb, nil)
	src := &gateway.Source{Name: "opendnp3", Timeout: 5 * time.Second,
		Points: []gateway.Map{{Type: "binary", From: 0, To: 100, Class: 1}, {Type: "binary", From: 1, To: 101, Class: 1},
			{Type: "analog", From: 0, To: 200, Class: 2}, {Type: "counter", From: 0, To: 300, Class: 3}},
		Controls: []gateway.Control{{Group: 12, From: 0, To: 2}, {Group: 41, From: 1, To: 0}}}
	if err := g.Add(src); err != nil {
		t.Fatal(err)
	}
	m := dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", port), MasterAddress: 1, OutstationAddress: 10,
		Timeout: 3 * time.Second, OnUnsolicited: src.Data})
	src.Master = m
	go func() {
		_ = m.RunSession(ctx, dnp3.SessionConfig{Unsolicited: []int{1, 2, 3}, TimeSync: dnp3.TimeSyncLAN, OnData: src.Data,
			RetryDelay: time.Second})
	}()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if p, _ := gdb.Point("analog", 200); p.Value == 230.5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the gateway did not mirror opendnp3's analog 0")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Above: opendnp3's master against the gateway's outstation.
	o := &ourOutstation{db: gdb, net: &dnp3.OutstationNet{}, ctx: ctx}
	a := dnp3.NewAssociation(dnp3.OutstationConfig{Address: 10, Master: 1, DB: gdb, Handler: g.Handler(), Unsolicited: true})
	o.net.Add(a)
	o.a = a
	go a.Run(ctx)
	up := startPeer(t, "--add-host=host.docker.internal:host-gateway", image, "dnp3-master", "host.docker.internal",
		strconv.Itoa(o.serveTCP(t, nil)), "nonlan")
	up.expect(60*time.Second, "READY")

	t.Run("integrity", func(t *testing.T) {
		up.expect(15*time.Second, "VAL analog 200 230.5")
		up.expect(15*time.Second, "TASK ENABLE_UNSOLICITED SUCCESS")
		up.send("integrity")
		up.expect(10*time.Second, "VAL counter 300 42")
		up.expect(10*time.Second, "DONE integrity SUCCESS")
	})
	t.Run("event", func(t *testing.T) {
		up.drain()
		below.send("bin 1 1")
		below.expect(5*time.Second, "APPLIED bin 1")
		up.expect(15*time.Second, "VAL binary 101 1", "event=1", "unsol=1")
	})
	t.Run("select before operate", func(t *testing.T) {
		up.drain()
		up.send("sbo 2")
		below.expect(10*time.Second, "SELECT crob 0")
		below.expect(10*time.Second, "OPERATE crob 0")
		if line := up.expect(15*time.Second, "CMD sbo"); !strings.Contains(line, "SUCCESS 2:SUCCESS:SUCCESS") {
			t.Errorf("opendnp3 master: %q", line)
		}
		up.send("aosbo 0 12.5")
		below.expect(10*time.Second, "OPERATE ao 1 12.5")
		if line := up.expect(15*time.Second, "CMD aosbo"); !strings.Contains(line, "SUCCESS 0:SUCCESS:SUCCESS") {
			t.Errorf("opendnp3 master: %q", line)
		}
	})
	t.Run("source lost", func(t *testing.T) {
		up.drain()
		src.SetOnline(ctx, false)
		line := up.expect(15*time.Second, "VAL analog 200", "event=1")
		f := line[strings.Index(line, "flags=")+len("flags="):]
		flags, _ := strconv.Atoi(strings.Fields(f)[0])
		if flags&gateway.FlagCommLost == 0 || flags&gateway.FlagOnline != 0 {
			t.Errorf("opendnp3 read flags %d, want COMM_LOST without ONLINE", flags)
		}
	})
}

// TestOpendnp3MasterEventModes: opendnp3's master reads events of this
// module's outstation made with the v0.3.0 database features: a forced
// event of an unchanged value and a flags-only change.
func TestOpendnp3MasterEventModes(t *testing.T) {
	needDocker(t)
	db, _, port := outstation(t)
	ctx := context.Background()
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", image, "dnp3-master", "host.docker.internal", strconv.Itoa(port), "nonlan")
	p.expect(60*time.Second, "READY")
	p.expect(15*time.Second, "TASK ENABLE_UNSOLICITED SUCCESS")
	p.drain()
	if ok, err := db.UpdateWith(ctx, "analog", 0, 230.5, nil, 0x01, time.Now(), dnp3.EventForce); !ok || err != nil {
		t.Fatalf("forced event: %v %v", ok, err)
	}
	p.expect(10*time.Second, "VAL analog 0 230.5", "event=1", "unsol=1")
	if ok, err := db.UpdateFlags(ctx, "analog", 0, 0x04, time.Now()); !ok || err != nil {
		t.Fatalf("flags update: %v %v", ok, err)
	}
	p.expect(10*time.Second, "VAL analog 0 230.5 flags=4", "event=1")
}
