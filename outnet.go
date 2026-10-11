package dnp3

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// Serving associations over a byte stream (a TCP connection, a serial
// line) or a UDP socket (IEEE 1815-2012 clause 13): frames are routed to
// the association of their source (master) address; a master already
// connected keeps its connection when it still answers a link status
// request (13.2.3.3, NOTE 2), otherwise the new connection replaces it;
// idle connections are tested with REQUEST_LINK_STATUS (13.2.3.3.1).

// OutstationNet routes frames to associations.
type OutstationNet struct {
	Log       *slog.Logger
	KeepAlive time.Duration // default 30 s
	Timeout   time.Duration // link status answer; default 5 s

	mu     sync.Mutex
	assocs map[uint16]*Association
}

// Add registers an association.
func (n *OutstationNet) Add(a *Association) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.assocs == nil {
		n.assocs = map[uint16]*Association{}
	}
	n.assocs[a.cfg.Master] = a
}

func (n *OutstationNet) assoc(master uint16) *Association {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.assocs[master]
}

func (n *OutstationNet) log() *slog.Logger {
	if n.Log == nil {
		return slog.Default()
	}
	return n.Log
}

type streamLink struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
	once   sync.Once
	done   chan struct{}
}

func (l *streamLink) WriteFrame(f Frame) error {
	b, err := f.Encode()
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if d, ok := l.w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = d.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}
	_, err = l.w.Write(b)
	return err
}

func (l *streamLink) Close() error {
	l.once.Do(func() {
		_ = l.closer.Close()
		close(l.done)
	})
	return nil
}

// ServeStream serves one connection until it ends or ctx is done.
func (n *OutstationNet) ServeStream(ctx context.Context, rw io.ReadWriteCloser) {
	link := &streamLink{w: rw, closer: rw, done: make(chan struct{})}
	defer link.Close()
	stop := context.AfterFunc(ctx, func() { _ = link.Close() })
	defer stop()
	ka := n.KeepAlive
	if ka <= 0 {
		ka = 30 * time.Second
	}
	to := n.Timeout
	if to <= 0 {
		to = 5 * time.Second
	}
	var lastRx sync.Mutex
	last := time.Now()
	attached := map[*Association]bool{}
	// Under a TLS profile that needs traffic before a timed key update on
	// an idle link (IEC 62351-3; iotsec.KeepaliveConn), the keepalive is
	// REQUEST_LINK_STATUS to an attached master (13.2.3.3.1).
	var kaMu sync.Mutex
	var kaAssoc *Association
	attach := func(a *Association) {
		attached[a] = true
		kaMu.Lock()
		if kaAssoc == nil {
			kaAssoc = a
		}
		kaMu.Unlock()
	}
	iotsec.SetKeepalive(rw, func() error {
		kaMu.Lock()
		a := kaAssoc
		kaMu.Unlock()
		if a == nil {
			return errors.New("no master association on the connection yet")
		}
		return link.WriteFrame(Frame{Ctrl: CtrlPRM | LinkRequestLinkStatus, Dest: a.cfg.Master, Src: a.cfg.Address})
	})
	go func() {
		t := time.NewTicker(ka / 4)
		defer t.Stop()
		probed := time.Time{}
		for {
			select {
			case <-link.done:
				return
			case <-t.C:
			}
			lastRx.Lock()
			idle := time.Since(last)
			lastRx.Unlock()
			if !probed.IsZero() {
				if idle >= time.Since(probed) {
					if time.Since(probed) > to {
						n.log().Info("DNP3 master connection silent after a keep-alive; closing")
						_ = link.Close()
						return
					}
					continue
				}
				probed = time.Time{}
			}
			if idle > ka {
				for a := range attached {
					_ = link.WriteFrame(Frame{Ctrl: CtrlPRM | LinkRequestLinkStatus, Dest: a.cfg.Master, Src: a.cfg.Address})
					break
				}
				probed = time.Now()
			}
		}
	}()
	// With a single association the connection is the master's at once,
	// so the start-up unsolicited response can go out before a request.
	n.mu.Lock()
	var only *Association
	if len(n.assocs) == 1 {
		for _, a := range n.assocs {
			only = a
		}
	}
	n.mu.Unlock()
	if only != nil {
		if !n.take(only, link, to) {
			return
		}
		attach(only)
	}
	var lp LinkParser
	buf := make([]byte, 4096)
	for {
		k, err := rw.Read(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			break
		}
		lastRx.Lock()
		last = time.Now()
		lastRx.Unlock()
		for _, f := range lp.Feed(buf[:k]) {
			if IsReservedAddress(f.Dest) {
				continue
			}
			a := n.assoc(f.Src)
			if a == nil || !a.Accepts(f.Dest) {
				continue
			}
			if !attached[a] {
				if !n.take(a, link, to) {
					n.log().Warn("DNP3 master already connected and answering; new connection refused", "master", f.Src)
					return
				}
				attach(a)
			}
			a.Deliver(f)
		}
	}
	for a := range attached {
		a.Detach(link)
	}
}

// take attaches link to a, testing a link it already has first.
func (n *OutstationNet) take(a *Association, link OutLink, to time.Duration) bool {
	a.mu.Lock()
	old := a.link
	a.mu.Unlock()
	if old != nil && old != link {
		before := time.Now()
		a.KeepAlive()
		deadline := time.Now().Add(to)
		for time.Now().Before(deadline) {
			a.mu.Lock()
			answered := a.lastRx.After(before)
			a.mu.Unlock()
			if answered {
				return false
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	a.Attach(link)
	return true
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() && !errors.Is(err, net.ErrClosed)
}

// udpLink answers the address a master's latest datagram came from.
type udpLink struct {
	pc   net.PacketConn
	mu   sync.Mutex
	addr net.Addr
}

func (l *udpLink) WriteFrame(f Frame) error {
	b, err := f.Encode()
	if err != nil {
		return err
	}
	l.mu.Lock()
	to := l.addr
	l.mu.Unlock()
	_, err = l.pc.WriteTo(b, to)
	return err
}

func (l *udpLink) Close() error { return nil }

// ServeUDP serves datagrams until ctx is done; allowed filters peers.
func (n *OutstationNet) ServeUDP(ctx context.Context, pc net.PacketConn, allowed func(net.Addr, uint16) bool) {
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()
	links := map[uint16]*udpLink{}
	parsers := map[string]*LinkParser{}
	buf := make([]byte, 65536)
	for {
		k, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		lp := parsers[from.String()]
		if lp == nil {
			lp = &LinkParser{}
			parsers[from.String()] = lp
		}
		for _, f := range lp.Feed(buf[:k]) {
			a := n.assoc(f.Src)
			if a == nil || !a.Accepts(f.Dest) || IsReservedAddress(f.Dest) || (allowed != nil && !allowed(from, f.Src)) {
				continue
			}
			l := links[f.Src]
			if l == nil {
				l = &udpLink{pc: pc}
				links[f.Src] = l
			}
			l.mu.Lock()
			l.addr = from
			l.mu.Unlock()
			if !a.Linked() {
				a.Attach(l)
			}
			a.Deliver(f)
		}
	}
}
