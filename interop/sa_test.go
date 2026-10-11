// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// Secure Authentication v5 against opendnp3 2.1.0-RC5, the last opendnp3
// tag with its experimental SAv5 module (Apache-2.0), built from ./peer-sa.

func updateKey(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// saOutstation starts opendnp3's SAv5 outstation behind a recording proxy.
func saOutstation(t *testing.T, opts ...string) (*peer, *proxy) {
	t.Helper()
	needImage(t, saImage, "peer-sa")
	port := freePort(t)
	p := startPeer(t, append([]string{"-p", fmt.Sprintf("127.0.0.1:%d:20000", port), saImage, "dnp3-sa", "outstation"}, opts...)...)
	p.expect(60*time.Second, "READY")
	time.Sleep(300 * time.Millisecond)
	return p, startProxy(t, fmt.Sprintf("127.0.0.1:%d", port), nil)
}

func saMaster(t *testing.T, px *proxy, cfg dnp3.AuthConfig) *dnp3.Master {
	t.Helper()
	auth, err := dnp3.NewAuth(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", px.port), MasterAddress: 1, OutstationAddress: 10,
		Timeout: 3 * time.Second, Auth: auth})
}

// requestsWith counts this module's requests of fc whose objects start
// with group 120 variation v.
func requestsWith(px *proxy, fc byte, v byte) int {
	n := 0
	for _, s := range px.seen() {
		if !s.toTarget || len(s.f.Data) < 5 {
			continue
		}
		if _, f, ok := app(s.f); ok && f == fc && s.f.Data[3] == 120 && s.f.Data[4] == v {
			n++
		}
	}
	return n
}

// TestMasterSAv5: this module's master changes the session keys of
// opendnp3's SAv5 outstation, answers its challenges of critical requests
// with each MAC algorithm opendnp3 offers, with AES-128 and AES-256 key
// wrap, uses aggressive mode, and is refused with a wrong update key.
func TestMasterSAv5(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		mac, key string
		n        int
	}{{"sha256-16", "128", 16}, {"sha256-8", "128", 16}, {"sha1-10", "128", 16}, {"sha1-8", "128", 16}, {"sha256-16", "256", 32}} {
		t.Run("MAC "+c.mac+" key AES-"+c.key, func(t *testing.T) {
			p, px := saOutstation(t, "mac="+c.mac, "key="+c.key)
			m := saMaster(t, px, dnp3.AuthConfig{UpdateKey: updateKey(0x5a, c.n)})
			if err := m.ChangeSessionKeys(ctx); err != nil {
				t.Fatalf("session key change: %v", err)
			}
			frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0))
			if err != nil {
				t.Fatalf("integrity poll: %v", err)
			}
			if v := points(t, frags)[[2]uint32{30, 0}]; v.Value != 230.0 { // 2.x default static variation g30v1 (32-bit integer)
				t.Errorf("analog 0: %+v", v)
			}
			if _, err := m.Request(ctx, dnp3.FCDirectOperate, crob(t, 2, dnp3.OpLatchOn)); err != nil {
				t.Fatalf("challenged direct operate: %v", err)
			}
			p.expect(5*time.Second, "OPERATE crob 2 3")
			if requestsWith(px, dnp3.FCAuthRequest, 2) == 0 {
				t.Error("no challenge reply (g120v2) was sent")
			}
			if err := m.SelectOperate(ctx, crob(t, 3, dnp3.OpLatchOn), 5*time.Second, nil); err != nil {
				t.Fatalf("challenged select-before-operate: %v", err)
			}
			p.expect(5*time.Second, "OPERATE crob 3 3")
		})
	}

	t.Run("aggressive mode refused", func(t *testing.T) {
		// opendnp3 2.1.0-RC5's outstation does not take aggressive mode:
		// it challenges the request and then refuses its g120v3 object
		// with IIN2.2 instead of the "aggressive mode not supported"
		// error. The master falls back to challenges at once and the
		// operation is carried out, exactly once.
		p, px := saOutstation(t)
		m := saMaster(t, px, dnp3.AuthConfig{UpdateKey: updateKey(0x5a, 16), AggressiveMode: true})
		if err := m.ChangeSessionKeys(ctx); err != nil {
			t.Fatal(err)
		}
		for i := uint32(0); i < 3; i++ {
			if _, err := m.Request(ctx, dnp3.FCDirectOperate, crob(t, i, dnp3.OpLatchOn)); err != nil {
				t.Fatalf("direct operate %d: %v", i, err)
			}
			p.expect(5*time.Second, fmt.Sprintf("OPERATE crob %d 3", i))
		}
		if n := requestsWith(px, dnp3.FCDirectOperate, 3); n != 1 {
			t.Errorf("%d aggressive-mode requests; want one, then none", n)
		}
		time.Sleep(200 * time.Millisecond)
		if c := strings.Count(p.output(), "PEER OPERATE crob 1 3"); c != 1 {
			t.Errorf("CROB 1 operated %d times", c)
		}
	})

	t.Run("challenging every request", func(t *testing.T) {
		_, px := saOutstation(t, "challenge=all")
		m := saMaster(t, px, dnp3.AuthConfig{UpdateKey: updateKey(0x5a, 16)})
		if err := m.ChangeSessionKeys(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0)); err != nil {
			t.Fatalf("challenged read: %v", err)
		}
		if requestsWith(px, dnp3.FCAuthRequest, 2) == 0 {
			t.Error("the read was not challenged")
		}
	})

	t.Run("wrong update key", func(t *testing.T) {
		_, px := saOutstation(t)
		m := saMaster(t, px, dnp3.AuthConfig{UpdateKey: updateKey(0x11, 16)})
		if err := m.ChangeSessionKeys(ctx); err == nil {
			t.Fatal("session keys changed with a wrong update key")
		} else {
			t.Logf("refused as expected: %v", err)
		}
	})
}

// TestOpendnp3SAv5MasterAgainstOutstation: opendnp3's SAv5 master changes
// the session keys of this module's outstation, answers its challenges of
// critical requests (each MAC algorithm the outstation may choose) and has
// its controls carried out for the authenticated user.
func TestOpendnp3SAv5MasterAgainstOutstation(t *testing.T) {
	needImage(t, saImage, "peer-sa")
	for _, c := range []struct {
		name string
		mal  uint8
		key  string
		n    int
	}{{"sha256-16", dnp3.MACSHA256Trunc16, "128", 16}, {"sha1-10", dnp3.MACSHA1Trunc10, "128", 16}, {"sha256-8 AES-256", dnp3.MACSHA256Trunc8, "256", 32}} {
		t.Run(c.name, func(t *testing.T) {
			oa, err := dnp3.NewOutstationAuth(dnp3.OutstationAuthConfig{MAL: c.mal,
				Users: []dnp3.OutstationUser{{Number: 1, Name: "default", UpdateKey: updateKey(0x5a, c.n)}}})
			if err != nil {
				t.Fatal(err)
			}
			o := newOurOutstation(t, func(cfg *dnp3.OutstationConfig) { cfg.Auth = oa })
			port := o.serveTCP(t, nil)
			p := startPeer(t, "--add-host=host.docker.internal:host-gateway", saImage, "dnp3-sa", "master", "host.docker.internal",
				strconv.Itoa(port), "key="+c.key)
			p.expect(60*time.Second, "READY")
			p.expect(20*time.Second, "TASK", "ENABLE_UNSOLICITED", "SUCCESS")
			p.send("integrity")
			p.expect(10*time.Second, "VAL analog 0 230.5")
			p.send("do 1")
			if line := p.expect(10*time.Second, "CMD do"); !strings.Contains(line, "SUCCESS") {
				t.Errorf("peer result %q", line)
			}
			ctl, _ := o.h.snapshot()
			var ok bool
			for _, x := range ctl {
				if x.Index == 1 && x.Group == 12 && x.User == 1 && !x.Select {
					ok = true
				}
			}
			if !ok {
				t.Errorf("controls %+v: no operate of CROB 1 by user 1", ctl)
			}
			p.send("ao 0 12.5")
			if line := p.expect(10*time.Second, "CMD ao"); !strings.Contains(line, "SUCCESS") {
				t.Errorf("peer result %q", line)
			}
		})
	}
}
