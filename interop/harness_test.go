// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/creack/pty"
	"golang.org/x/term"
)

// ourOutstation is this module's outstation (address 10, master 1) with
// points 0 to 2 of every type, served on whichever channels a test opens.
type ourOutstation struct {
	db  *dnp3.PointDB
	h   *handler
	net *dnp3.OutstationNet
	a   *dnp3.Association
	ctx context.Context
}

// newOurOutstation builds the outstation; mod adjusts its configuration.
func newOurOutstation(t *testing.T, mod func(*dnp3.OutstationConfig)) *ourOutstation {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	db := dnp3.NewPointDB()
	for i := uint32(0); i < 3; i++ {
		for _, p := range []dnp3.DBPoint{
			{Type: "binary", Index: i, Class0: true, Class: 1, Flags: 0x01},
			{Type: "double", Index: i, Class0: true, Class: 1, Flags: 0x01},
			{Type: "analog", Index: i, Class0: true, Class: 2, Flags: 0x01},
			{Type: "counter", Index: i, Class0: true, Class: 3, Flags: 0x01},
			{Type: "frozen-counter", Index: i, Class0: true, Class: 3, Flags: 0x01},
			{Type: "binary-output", Index: i, Class0: true, Class: 1, Flags: 0x01},
			{Type: "analog-output", Index: i, Class0: true, Class: 2, Flags: 0x01},
			{Type: "octet-string", Index: i, Class0: true, Class: 3, Raw: []byte("hi")},
			{Type: "time-and-interval", Index: i, Class0: true},
		} {
			if err := db.Define(p); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, _ = db.Update(ctx, "binary", 0, 1, nil, 0x01, time.Now())
	_, _ = db.Update(ctx, "analog", 0, 230.5, nil, 0x01, time.Now())
	_, _ = db.Update(ctx, "counter", 0, 42, nil, 0x01, time.Now())
	_, _ = db.Update(ctx, "octet-string", 0, 0, []byte("hi"), 0x01, time.Now())
	_ = db.SetTimeAndInterval(0, dnp3.TimeAndInterval{Time: time.UnixMilli(1_700_000_000_000), Interval: 15, Units: dnp3.UnitsMinutes})
	h := &handler{}
	cfg := dnp3.OutstationConfig{Address: 10, Master: 1, DB: db, Handler: h, Unsolicited: true, NeedTime: time.Hour}
	if mod != nil {
		mod(&cfg)
	}
	a := dnp3.NewAssociation(cfg)
	n := &dnp3.OutstationNet{}
	n.Add(a)
	go a.Run(ctx)
	return &ourOutstation{db: db, h: h, net: n, a: a, ctx: ctx}
}

// serveTCP listens on a loopback port (with TLS when cfg is set) and
// returns it.
func (o *ourOutstation) serveTCP(t *testing.T, cfg *tls.Config) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if cfg != nil {
				tc := tls.Server(c, cfg)
				go func() {
					hctx, cancel := context.WithTimeout(o.ctx, 10*time.Second)
					defer cancel()
					if err := tc.HandshakeContext(hctx); err != nil {
						t.Logf("TLS handshake with the peer master: %v", err)
						_ = c.Close()
						return
					}
					o.net.ServeStream(o.ctx, tc)
				}()
				continue
			}
			go o.net.ServeStream(o.ctx, c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// serveUDP serves datagrams on a loopback port and returns it.
func (o *ourOutstation) serveUDP(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go o.net.ServeUDP(o.ctx, pc, nil)
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// serveSerial serves a serial device (8N1).
func (o *ourOutstation) serveSerial(t *testing.T, dev string, baud int) {
	t.Helper()
	rw, err := dnp3.OpenSerial(dev, baud, "N")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rw.Close() })
	go o.net.ServeStream(o.ctx, rw)
}

// outstation serves this module's outstation on a loopback TCP port.
func outstation(t *testing.T) (*dnp3.PointDB, *handler, int) {
	t.Helper()
	o := newOurOutstation(t, nil)
	return o.db, o.h, o.serveTCP(t, nil)
}

// freeUDPPort returns a UDP port free on the loopback interface.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// ptyBridge opens a pty pair here and copies between its controlling
// side and the container's socat at 127.0.0.1:port (TCP), so that this
// module opens a real serial device while the peer opens its own pty. It
// returns the device name to open.
func ptyBridge(t *testing.T, port int) string {
	t.Helper()
	ptm, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("pty: %v", err)
	}
	t.Cleanup(func() { _ = ptm.Close(); _ = pts.Close() })
	// A new pty is a terminal (echo, line editing) until a serial port
	// configuration makes it raw; make it raw before any byte arrives.
	if _, err := term.MakeRaw(int(pts.Fd())); err != nil {
		t.Fatalf("pty raw mode: %v", err)
	}
	var c net.Conn
	for i := 0; i < 100; i++ {
		c, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if c == nil {
		t.Fatalf("connecting to the peer's serial bridge: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() { _, _ = io.Copy(c, ptm) }()
	go func() { _, _ = io.Copy(ptm, c) }()
	return pts.Name()
}

// pki is a test CA with a certificate for the peer (written to dir as
// ca.pem, peer.pem and peer.key for the container) and one for us, and a
// second CA the peer does not trust.
type pki struct {
	dir      string
	pool     *x509.CertPool
	ours     tls.Certificate
	stranger tls.Certificate
}

func newPKI(t *testing.T) pki {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	newCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k, der
	}
	ca, caKey, caDER := newCA("interop test CA")
	other, otherKey, _ := newCA("untrusted CA")
	leaf := func(serial int64, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			DNSNames:    []string{name, "localhost", "host.docker.internal"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, k
	}
	write := func(name, typ string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.pem", "CERTIFICATE", caDER)
	peerDER, peerKey := leaf(2, "peer", ca, caKey)
	write("peer.pem", "CERTIFICATE", peerDER)
	kb, _ := x509.MarshalECPrivateKey(peerKey)
	write("peer.key", "EC PRIVATE KEY", kb)
	ourDER, ourKey := leaf(3, "sigma", ca, caKey)
	strangerDER, strangerKey := leaf(4, "sigma", other, otherKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pki{dir: dir, pool: pool,
		ours:     tls.Certificate{Certificate: [][]byte{ourDER}, PrivateKey: ourKey},
		stranger: tls.Certificate{Certificate: [][]byte{strangerDER}, PrivateKey: strangerKey}}
}

// proxy relays one TCP connection at a time between a loopback listener
// and target, parsing the link frames both ways: it records them and
// drops those drop selects (toTarget: travelling towards target). Frames
// passed on are encoded again by this module, which reproduces valid
// frames octet for octet.
type proxy struct {
	mu     sync.Mutex
	frames []seenFrame
	port   int
}

type seenFrame struct {
	toTarget bool
	dropped  bool
	f        dnp3.Frame
}

func startProxy(t *testing.T, target string, drop func(toTarget bool, f dnp3.Frame) bool) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &proxy{port: ln.Addr().(*net.TCPAddr).Port}
	var dmu sync.Mutex
	pipe := func(dst, src net.Conn, toTarget bool) {
		var lp dnp3.LinkParser
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if err != nil {
				_ = dst.Close()
				return
			}
			for _, f := range lp.Feed(buf[:n]) {
				dmu.Lock()
				d := drop != nil && drop(toTarget, f)
				dmu.Unlock()
				p.mu.Lock()
				p.frames = append(p.frames, seenFrame{toTarget: toTarget, dropped: d, f: f})
				p.mu.Unlock()
				if d {
					continue
				}
				b, err := f.Encode()
				if err != nil {
					t.Errorf("proxy: %v", err)
					continue
				}
				if _, err := dst.Write(b); err != nil {
					_ = src.Close()
					return
				}
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			t.Cleanup(func() { _ = c.Close(); _ = u.Close() })
			go pipe(u, c, true)
			go pipe(c, u, false)
		}
	}()
	return p
}

// seen returns the frames recorded so far.
func (p *proxy) seen() []seenFrame {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]seenFrame(nil), p.frames...)
}

// app returns the application control and function code of a frame
// carrying a whole fragment's first segment (ok false otherwise).
func app(f dnp3.Frame) (control, fc byte, ok bool) {
	if len(f.Data) < 3 || f.Data[0]&0x40 == 0 {
		return 0, 0, false
	}
	return f.Data[1], f.Data[2], true
}

// dialRetry dials the master until the peer accepts (it starts in a
// container).
func dialRetry(t *testing.T, cfg dnp3.MasterConfig) *dnp3.Master {
	t.Helper()
	var m *dnp3.Master
	var err error
	for i := 0; i < 50; i++ {
		m, err = dnp3.Dial(context.Background(), cfg)
		if err == nil {
			t.Cleanup(func() { _ = m.Close() })
			return m
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}
