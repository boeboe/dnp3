package dnp3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goburrow/serial"
)

// Several outstations on one connection (multi-drop, IEEE 1815-2012
// 9.2.5.1): a Channel owns the connection (a TCP link to a terminal
// server, a serial line) and routes each frame to the Master of its source
// address; every Master keeps its own link, transport and application
// state, and writes are serialised.

// Channel is one shared connection.
type Channel struct {
	conn net.Conn
	cfg  MasterConfig

	wmu     sync.Mutex
	mu      sync.Mutex
	members map[uint16]*member
	done    chan struct{}
	once    sync.Once
	err     error
}

type member struct {
	m  *Master
	ra Reassembler
}

// OpenChannel opens the connection of cfg (URL, TLS, Timeout) for
// several masters.
func OpenChannel(ctx context.Context, cfg MasterConfig) (*Channel, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	conn, err := dialConn(ctx, cfg)
	if err != nil {
		return nil, err
	}
	c := &Channel{conn: conn, cfg: cfg, members: map[uint16]*member{}, done: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

// Done is closed when the connection ends.
func (c *Channel) Done() <-chan struct{} { return c.done }

// Err is why the connection ended.
func (c *Channel) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Channel) fail(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		ms := c.members
		c.members = map[uint16]*member{}
		c.mu.Unlock()
		_ = c.conn.Close()
		close(c.done)
		for _, mb := range ms {
			mb.m.fail(err)
		}
	})
}

// Close ends the connection and every association on it.
func (c *Channel) Close() error {
	c.fail(errors.New("closed"))
	return nil
}

// Attach adds an association for cfg.OutstationAddress (its own
// addresses, timeouts, authentication; the URL and TLS are the channel's).
func (c *Channel) Attach(cfg MasterConfig) (*Master, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = c.cfg.Timeout
	}
	if cfg.OutstationAddress == AddrSelf || IsBroadcast(cfg.OutstationAddress) {
		return nil, errors.New("a shared channel needs individual outstation addresses")
	}
	cfg.URL = c.cfg.URL
	cfg.KeepAlive = 0 // the channel is shared: one keep-alive per member would multiply
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return nil, c.err
	default:
	}
	if c.members[cfg.OutstationAddress] != nil {
		return nil, fmt.Errorf("outstation %d is already on this channel", cfg.OutstationAddress)
	}
	m := newMaster(cfg, &memberConn{c: c, addr: cfg.OutstationAddress})
	m.lastRx.Store(time.Now().UnixNano())
	c.members[cfg.OutstationAddress] = &member{m: m}
	return m, nil
}

func (c *Channel) detach(addr uint16) {
	c.mu.Lock()
	delete(c.members, addr) // the channel stays open for the next attach; Close ends it
	c.mu.Unlock()
}

// Members counts the attached associations.
func (c *Channel) Members() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.members)
}

func (c *Channel) readLoop() {
	var lp LinkParser
	buf := make([]byte, 4096)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			c.fail(fmt.Errorf("connection lost: %w", err))
			return
		}
		for _, f := range lp.Feed(buf[:n]) {
			c.mu.Lock()
			mb := c.members[f.Src]
			c.mu.Unlock()
			if mb != nil {
				mb.m.frame(f, &mb.ra)
			}
		}
	}
}

func (c *Channel) write(b []byte, deadline time.Time) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !deadline.IsZero() {
		_ = c.conn.SetWriteDeadline(deadline)
	}
	n, err := c.conn.Write(b)
	if err != nil {
		c.fail(fmt.Errorf("connection lost: %w", err))
	}
	return n, err
}

// memberConn is a Master's view of the shared connection: writes go to
// the channel, reads never happen (the channel reads), Close detaches.
type memberConn struct {
	c        *Channel
	addr     uint16
	mu       sync.Mutex
	deadline time.Time
	closed   bool
}

func (m *memberConn) Read([]byte) (int, error) { <-m.c.done; return 0, io.EOF }
func (m *memberConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	d, closed := m.deadline, m.closed
	m.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	return m.c.write(b, d)
}
func (m *memberConn) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.c.detach(m.addr)
	return nil
}
func (m *memberConn) LocalAddr() net.Addr             { return m.c.conn.LocalAddr() }
func (m *memberConn) RemoteAddr() net.Addr            { return m.c.conn.RemoteAddr() }
func (m *memberConn) SetDeadline(t time.Time) error   { return m.SetWriteDeadline(t) }
func (m *memberConn) SetReadDeadline(time.Time) error { return nil }
func (m *memberConn) SetWriteDeadline(t time.Time) error {
	m.mu.Lock()
	m.deadline = t
	m.mu.Unlock()
	return nil
}

// Serial lines: serial:///dev/ttyS1?baud=9600&parity=N (8 data bits, 1
// stop bit; baud 50 to 921600, default 9600; parity none, even or odd,
// also written N, E or O, in any case; default none).

// OpenSerial opens a serial line (8 data bits, 1 stop bit; parity "N", "E"
// or "O"). The master and the outstation's serial channel use it; tests,
// or an application that reaches its ports another way, replace it.
var OpenSerial = func(dev string, baud int, parity string) (io.ReadWriteCloser, error) {
	return serial.Open(&serial.Config{Address: dev, BaudRate: baud, DataBits: 8, StopBits: 1, Parity: parity, Timeout: 200 * time.Millisecond})
}

// SerialParams reads a serial URL (serial:///dev/ttyS1?baud=9600&parity=N):
// the device, the baud rate and the parity letter.
func SerialParams(u *url.URL) (dev string, baud int, parity string, err error) {
	q := u.Query()
	baud = 9600
	if b := q.Get("baud"); b != "" {
		n, err := strconv.Atoi(b)
		if err != nil || n < 50 || n > 921600 {
			return "", 0, "", fmt.Errorf("baud %q is out of range", b)
		}
		baud = n
	}
	// Parity as a letter or a word, in any case; the port takes the letter.
	parity, ok := map[string]string{"": "N", "n": "N", "none": "N", "e": "E", "even": "E", "o": "O", "odd": "O"}[strings.ToLower(q.Get("parity"))]
	if !ok {
		return "", 0, "", fmt.Errorf("parity %q is not none, even or odd (or N, E, O)", q.Get("parity"))
	}
	return u.Path, baud, parity, nil
}

type serialConn struct {
	rw     io.ReadWriteCloser
	dev    string
	closed chan struct{}
	once   sync.Once
}

func openSerialConn(u *url.URL) (net.Conn, error) {
	dev, baud, parity, err := SerialParams(u)
	if err != nil {
		return nil, err
	}
	rw, err := OpenSerial(dev, baud, parity)
	if err != nil {
		return nil, fmt.Errorf("serial %s: %w", dev, err)
	}
	return &serialConn{rw: rw, dev: dev, closed: make(chan struct{})}, nil
}

func (s *serialConn) Read(b []byte) (int, error) {
	for {
		n, err := s.rw.Read(b)
		if n > 0 || err == nil {
			return n, nil
		}
		select {
		case <-s.closed:
			return 0, net.ErrClosed
		default:
		}
		if strings.Contains(err.Error(), "timeout") || isTimeout(err) {
			continue // the port's read timeout: keep waiting
		}
		return 0, err
	}
}
func (s *serialConn) Write(b []byte) (int, error) { return s.rw.Write(b) }
func (s *serialConn) Close() error {
	s.once.Do(func() { close(s.closed) })
	return s.rw.Close()
}

type serialAddr string

func (a serialAddr) Network() string { return "serial" }
func (a serialAddr) String() string  { return string(a) }

func (s *serialConn) LocalAddr() net.Addr              { return serialAddr(s.dev) }
func (s *serialConn) RemoteAddr() net.Addr             { return serialAddr(s.dev) }
func (s *serialConn) SetDeadline(time.Time) error      { return nil }
func (s *serialConn) SetReadDeadline(time.Time) error  { return nil }
func (s *serialConn) SetWriteDeadline(time.Time) error { return nil }
