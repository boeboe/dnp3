// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/iotsec"
)

// exercise polls, clears the restart indication, operates a CROB and
// takes a class 1 event from opendnp3's outstation through m.
func exercise(t *testing.T, m *dnp3.Master, p *peer) {
	t.Helper()
	ctx := context.Background()
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0))
	if err != nil {
		t.Fatalf("integrity poll: %v", err)
	}
	pts := points(t, frags)
	if v := pts[[2]uint32{1, 0}]; v.Value != true {
		t.Errorf("binary 0: %+v", v)
	}
	if v := pts[[2]uint32{30, 0}]; v.Value != 230.5 {
		t.Errorf("analog 0: %+v", v)
	}
	objs, _ := dnp3.EncodeBlock(80, 1, dnp3.Q8StartStop, []dnp3.Point{{Index: 7, Value: false}})
	if _, err := m.Request(ctx, dnp3.FCWrite, objs); err != nil {
		t.Fatalf("clear restart: %v", err)
	}
	if _, err := m.Request(ctx, dnp3.FCDirectOperate, crob(t, 4, dnp3.OpLatchOff)); err != nil {
		t.Fatalf("direct operate: %v", err)
	}
	p.expect(5*time.Second, "OPERATE crob 4 4 DirectOperate")
	p.send("bin 1 1")
	p.expect(5*time.Second, "APPLIED bin 1")
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
	if err != nil {
		t.Fatalf("class 1 poll: %v", err)
	}
	if v, ok := points(t, frags)[[2]uint32{2, 1}]; !ok || v.Value != true {
		t.Errorf("class 1 poll: %v", groups(t, frags))
	}
}

// Covers: SIG-SEC-637
// TestMasterTLS: this module's master over TLS 1.2 and 1.3 (crypto/tls,
// mutual certificates) against opendnp3's TLS outstation (OpenSSL), and
// refused when its certificate comes from a CA the outstation does not
// trust.
func TestMasterTLS(t *testing.T) {
	needDocker(t)
	k := newPKI(t)
	for _, v := range []struct {
		name string
		ver  uint16
	}{{"1.2", tls.VersionTLS12}, {"1.3", tls.VersionTLS13}} {
		t.Run("TLS "+v.name, func(t *testing.T) {
			port := freePort(t)
			p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20001", port), "-v", k.dir+":/certs:ro", image,
				"dnp3-outstation", "tls", "20001", "tls="+v.name)
			p.expect(60*time.Second, "READY")
			cfg := &tls.Config{RootCAs: k.pool, Certificates: []tls.Certificate{k.ours}, ServerName: "peer",
				MinVersion: v.ver, MaxVersion: v.ver}
			m := dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", port), MasterAddress: 1,
				OutstationAddress: 10, Timeout: 3 * time.Second, TLS: iotsec.StdTLS{Config: cfg}})
			exercise(t, m, p)
			if st := m.Done(); st != nil {
				select {
				case <-st:
					t.Errorf("connection ended: %v", m.Err())
				default:
				}
			}
		})
	}
	t.Run("untrusted client certificate", func(t *testing.T) {
		port := freePort(t)
		p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20001", port), "-v", k.dir+":/certs:ro", image,
			"dnp3-outstation", "tls", "20001")
		p.expect(60*time.Second, "READY")
		cfg := &tls.Config{RootCAs: k.pool, Certificates: []tls.Certificate{k.stranger}, ServerName: "peer"}
		var err error
		for i := 0; i < 20; i++ {
			var m *dnp3.Master
			m, err = dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", port),
				MasterAddress: 1, OutstationAddress: 10, Timeout: 2 * time.Second, TLS: iotsec.StdTLS{Config: cfg}})
			if err == nil {
				_, err = m.Request(context.Background(), dnp3.FCRead, dnp3.ClassRequest(0))
				_ = m.Close()
			}
			if err != nil && !strings.Contains(err.Error(), "connection refused") {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err == nil {
			t.Fatal("the outstation served a master whose certificate it cannot verify")
		}
		t.Logf("refused as expected: %v", err)
	})
}

// Covers: SIG-SEC-637
// TestOpendnp3MasterTLS: opendnp3's TLS master (OpenSSL) against this
// module's outstation behind crypto/tls with client certificates required,
// in TLS 1.2 and 1.3.
func TestOpendnp3MasterTLS(t *testing.T) {
	needDocker(t)
	k := newPKI(t)
	for _, v := range []struct {
		name string
		ver  uint16
	}{{"1.2", tls.VersionTLS12}, {"1.3", tls.VersionTLS13}} {
		t.Run("TLS "+v.name, func(t *testing.T) {
			o := newOurOutstation(t, nil)
			port := o.serveTCP(t, &tls.Config{Certificates: []tls.Certificate{k.ours}, ClientCAs: k.pool,
				ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: v.ver, MaxVersion: v.ver})
			p := startPeer(t, "--add-host=host.docker.internal:host-gateway", "-v", k.dir+":/certs:ro", image,
				"dnp3-master", "tls", "host.docker.internal", strconv.Itoa(port), "mode=nonlan", "tls="+v.name)
			p.expect(60*time.Second, "READY")
			p.expect(20*time.Second, "TASK ENABLE_UNSOLICITED SUCCESS")
			p.send("integrity")
			p.expect(10*time.Second, "VAL analog 0 230.5")
			p.expect(10*time.Second, "DONE integrity SUCCESS")
			p.send("do 1")
			if line := p.expect(10*time.Second, "CMD do"); !strings.Contains(line, "SUCCESS 1:SUCCESS:SUCCESS") {
				t.Errorf("peer result %q", line)
			}
		})
	}
}

// Covers: SIG-IPE-641, SIG-CMD-212
// TestMasterUDP: this module's master over UDP, from a fixed local port,
// against opendnp3's UDP outstation. The outstation's socket is bound to
// fixed ports inside the container and socat relays the datagrams of the
// published port to it (Docker's port forwarding changes the source
// address, which opendnp3's connected UDP socket would drop).
func TestMasterUDP(t *testing.T) {
	needDocker(t)
	port, local := freeUDPPort(t), freeUDPPort(t)
	m := dialRetry(t, dnp3.MasterConfig{URL: fmt.Sprintf("udp://127.0.0.1:%d", port), LocalPort: local, MasterAddress: 1,
		OutstationAddress: 10, Timeout: 3 * time.Second})
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:21000/udp", port), "--entrypoint", "udp.sh", image)
	p.expect(60*time.Second, "READY")
	// The outstation's first datagrams (its start-up unsolicited response)
	// go nowhere until the master's first request opens the relay; poll
	// until it answers.
	var err error
	for i := 0; i < 10; i++ {
		if _, err = m.Request(context.Background(), dnp3.FCRead, dnp3.ClassRequest(0)); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("no answer over UDP: %v", err)
	}
	exercise(t, m, p)
}

// Covers: SIG-IPE-641
// TestOpendnp3MasterUDP: opendnp3's UDP master against this module's
// outstation serving datagrams.
func TestOpendnp3MasterUDP(t *testing.T) {
	needDocker(t)
	o := newOurOutstation(t, nil)
	port := o.serveUDP(t)
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", image,
		"dnp3-master", "udp", "20000", "host.docker.internal", strconv.Itoa(port), "mode=nonlan")
	p.expect(60*time.Second, "READY")
	p.expect(20*time.Second, "TASK ENABLE_UNSOLICITED SUCCESS")
	p.send("integrity")
	p.expect(10*time.Second, "VAL analog 0 230.5")
	p.expect(10*time.Second, "DONE integrity SUCCESS")
	if _, err := o.db.Update(o.ctx, "binary", 1, 1, nil, 0x01, time.Now()); err != nil {
		t.Fatal(err)
	}
	p.expect(10*time.Second, "VAL binary 1 1", "event=1", "unsol=1")
	p.send("do 2")
	if line := p.expect(10*time.Second, "CMD do"); !strings.Contains(line, "SUCCESS 2:SUCCESS:SUCCESS") {
		t.Errorf("peer result %q", line)
	}
}

// Covers: SIG-IPE-1620
// TestMasterSerial: this module's master opens a real serial device (a
// pty) whose bytes reach opendnp3's serial outstation on its own pty
// through socat.
func TestMasterSerial(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:2410", port), "--entrypoint", "serial.sh", image, "outstation", "9600")
	p.expect(60*time.Second, "READY")
	dev := ptyBridge(t, port)
	m := dialRetry(t, dnp3.MasterConfig{URL: "serial://" + dev + "?baud=9600", MasterAddress: 1, OutstationAddress: 10,
		Timeout: 3 * time.Second})
	exercise(t, m, p)
}

// Covers: SIG-IPE-1620
// TestOpendnp3MasterSerial: opendnp3's serial master against this
// module's outstation on a real serial device (a pty) here.
func TestOpendnp3MasterSerial(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:2410", port), "--entrypoint", "serial.sh", image, "master", "9600", "mode=nonlan")
	p.expect(60*time.Second, "READY")
	dev := ptyBridge(t, port)
	o := newOurOutstation(t, nil)
	o.serveSerial(t, dev, 9600)
	p.expect(20*time.Second, "TASK ENABLE_UNSOLICITED SUCCESS")
	p.send("integrity")
	p.expect(10*time.Second, "VAL counter 0 42")
	p.expect(10*time.Second, "DONE integrity SUCCESS")
	if _, err := o.db.Update(o.ctx, "analog", 1, 12.5, nil, 0x01, time.Now()); err != nil {
		t.Fatal(err)
	}
	p.expect(10*time.Second, "VAL analog 1 12.5", "event=1", "unsol=1")
	p.send("aosbo 0 7.5")
	if line := p.expect(10*time.Second, "CMD aosbo"); !strings.Contains(line, "SUCCESS 0:SUCCESS:SUCCESS") {
		t.Errorf("peer result %q", line)
	}
}
