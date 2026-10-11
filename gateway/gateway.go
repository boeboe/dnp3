// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package gateway is a DNP3 data concentrator: points a master reads from
// downstream outstations are republished, under indexes of the gateway's
// choosing, in the PointDB of the gateway's own outstation, and controls
// the gateway's outstation receives for mapped outputs are passed down to
// the outstation that owns them, with its status passed back.
//
// Each downstream outstation is a Source: the master session to it and
// its point and control maps. The application polls the source the usual
// way (Master.RunSession with OnData, MasterConfig.OnUnsolicited) and
// hands every response to Source.Data. Static values update the gateway's
// points (an event where they changed); events from below become events
// of the gateway's points even when the value did not change, keeping
// their own time. A lost source marks its points COMM_LOST and not
// ONLINE; the next data from it clears that.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// Flags common to the point types (IEEE 1815-2012 Table 11-9 and the
// flags of the other static objects share these bits).
const (
	FlagOnline   = 0x01
	FlagRestart  = 0x02
	FlagCommLost = 0x04
)

// Map republishes one point of a source.
type Map struct {
	// Type is the point type ("binary", "double", "binary-output",
	// "counter", "frozen-counter", "analog", "frozen-analog",
	// "analog-output", "octet-string").
	Type string
	// From is the index at the source, To the index in the gateway's
	// database.
	From, To uint32
	// Class is the event class of the gateway's point when the gateway
	// defines it (0: no events); Static leaves it out of class 0. A point
	// the application defined already keeps its own settings.
	Class  int
	Static bool
}

// Control passes one of the gateway's outputs to a source.
type Control struct {
	// Group is 12 (CROB) or 41 (analog output); To is the index the
	// gateway's masters use, From the index at the source.
	Group    uint8
	From, To uint32
}

// Source is one downstream outstation.
type Source struct {
	Name string
	// Master is the session to the source; set it before controls are
	// passed down.
	Master   *dnp3.Master
	Points   []Map
	Controls []Control
	// Timeout bounds a control passed down (zero: 10 s).
	Timeout time.Duration

	g      *Gateway
	byFrom map[string]map[uint32]uint32 // type, source index -> gateway index
	online bool
	mu     sync.Mutex
}

// Gateway maps sources onto one outstation database.
type Gateway struct {
	DB *dnp3.PointDB

	mu       sync.Mutex
	sources  []*Source
	controls map[[2]uint32]route // group, gateway index
	next     dnp3.Handler
}

type route struct {
	s    *Source
	from uint32
}

// New makes a gateway over db; next answers what the gateway does not
// (controls of unmapped outputs, restarts, data sets...); nil refuses
// them.
func New(db *dnp3.PointDB, next dnp3.Handler) *Gateway {
	return &Gateway{DB: db, controls: map[[2]uint32]route{}, next: next}
}

// ErrMapped is returned for a gateway index mapped twice.
var ErrMapped = errors.New("the gateway point is already mapped")

// Add registers a source, defining the gateway's points it maps that the
// database does not hold yet.
func (g *Gateway) Add(s *Source) error {
	if s.Timeout <= 0 {
		s.Timeout = 10 * time.Second
	}
	s.g, s.byFrom, s.online = g, map[string]map[uint32]uint32{}, true
	for _, m := range s.Points {
		if _, ok := dnp3.PointGroup(m.Type); !ok {
			return fmt.Errorf("point type %q is not served", m.Type)
		}
		if s.byFrom[m.Type] == nil {
			s.byFrom[m.Type] = map[uint32]uint32{}
		}
		if _, dup := s.byFrom[m.Type][m.From]; dup {
			return fmt.Errorf("%s %d of %s is mapped twice", m.Type, m.From, s.Name)
		}
		s.byFrom[m.Type][m.From] = m.To
		if _, ok := g.DB.Point(m.Type, m.To); ok {
			if g.owner(m.Type, m.To) != nil {
				return fmt.Errorf("%w: %s %d", ErrMapped, m.Type, m.To)
			}
			continue
		}
		if err := g.DB.Define(dnp3.DBPoint{Type: m.Type, Index: m.To, Class0: !m.Static, Class: m.Class}); err != nil {
			return err
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range s.Controls {
		if c.Group != 12 && c.Group != 41 {
			return fmt.Errorf("control group %d is neither 12 nor 41", c.Group)
		}
		k := [2]uint32{uint32(c.Group), c.To}
		if _, dup := g.controls[k]; dup {
			return fmt.Errorf("%w: control g%d %d", ErrMapped, c.Group, c.To)
		}
		g.controls[k] = route{s, c.From}
	}
	g.sources = append(g.sources, s)
	return nil
}

func (g *Gateway) owner(typ string, to uint32) *Source {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.sources {
		for _, m := range s.Points {
			if m.Type == typ && m.To == to {
				return s
			}
		}
	}
	return nil
}

// Handler is the dnp3.Handler of the gateway's outstation associations:
// controls of mapped outputs go down, the rest to next.
func (g *Gateway) Handler() dnp3.Handler { return handler{g} }

// Data takes a response or unsolicited response from the source and
// updates the gateway's points. It is meant for SessionConfig.OnData and
// MasterConfig.OnUnsolicited.
func (s *Source) Data(f dnp3.Fragment) {
	blocks, err := dnp3.ParseObjects(f.Objects, true)
	if err != nil {
		return
	}
	ctx := context.Background()
	s.mu.Lock()
	s.online = true
	s.mu.Unlock()
	now := time.Now()
	for _, b := range blocks {
		typ := dnp3.PointTypeOf(b.Header.Group)
		idx := s.byFrom[typ]
		if idx == nil {
			continue
		}
		g, _ := dnp3.PointGroup(typ)
		event := b.Header.Group == g[1] && g[1] != g[0]
		for _, p := range b.Points {
			to, ok := idx[p.Index]
			if !ok {
				continue
			}
			v, raw := value(p)
			flags := p.Flags
			if !p.HasFlags {
				flags = FlagOnline
			}
			switch b.Header.Group {
			case 1, 2, 10, 11:
				flags &^= 0x80
			case 3, 4:
				flags &^= 0xC0
			}
			t := p.Time
			if t.IsZero() {
				t = now
			}
			mode := dnp3.EventDetect
			if event {
				mode = dnp3.EventForce
			}
			_, _ = s.g.DB.UpdateWith(ctx, typ, to, v, raw, flags, t, mode)
		}
	}
}

func value(p dnp3.Point) (float64, []byte) {
	switch v := p.Value.(type) {
	case bool:
		if v {
			return 1, nil
		}
		return 0, nil
	case float64:
		return v, nil
	}
	if p.Raw != nil {
		return 0, append([]byte(nil), p.Raw...)
	}
	return 0, nil
}

// SetOnline records whether the source is reachable. Offline, every
// point it maps loses ONLINE and gains COMM_LOST (an event where the
// point has a class); online again, the next data from the source sets
// the flags it reports.
func (s *Source) SetOnline(ctx context.Context, online bool) {
	s.mu.Lock()
	was := s.online
	s.online = online
	s.mu.Unlock()
	if was == online || online {
		return
	}
	now := time.Now()
	for _, m := range s.Points {
		p, ok := s.g.DB.Point(m.Type, m.To)
		if !ok {
			continue
		}
		f := p.Flags&^FlagOnline | FlagCommLost
		_, _ = s.g.DB.UpdateFlags(ctx, m.Type, m.To, f, now)
	}
}

// Online reports what SetOnline (or the last data) recorded.
func (s *Source) Online() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.online
}

type handler struct{ g *Gateway }

// Control passes a mapped control down: SELECT as SELECT, OPERATE as
// OPERATE (the select made by the earlier pass), DIRECT_OPERATE(_NR) as
// DIRECT_OPERATE, with the source's status returned (6 HARDWARE_ERROR
// when it did not answer, 4 NOT_SUPPORTED for an unmapped output without
// next).
func (h handler) Control(ctx context.Context, c dnp3.ControlRequest) uint8 {
	h.g.mu.Lock()
	r, ok := h.g.controls[[2]uint32{uint32(c.Group), c.Index}]
	h.g.mu.Unlock()
	if !ok {
		if h.g.next != nil {
			return h.g.next.Control(ctx, c)
		}
		return 4
	}
	m := r.s.Master
	if m == nil || !r.s.Online() {
		return 6
	}
	p := dnp3.Point{Index: r.from, CROB: c.CROB, Value: c.Value}
	q := uint8(dnp3.Q16Index16)
	if r.from < 256 {
		q = dnp3.Q8Index8
	}
	objs, err := dnp3.EncodeBlock(c.Group, c.Var, q, []dnp3.Point{p})
	if err != nil {
		return 3 // FORMAT_ERROR
	}
	ctx, cancel := context.WithTimeout(ctx, r.s.Timeout)
	defer cancel()
	status := func(frags []dnp3.Fragment) uint8 {
		if len(frags) == 0 {
			return 6
		}
		blocks, err := dnp3.ParseObjects(frags[len(frags)-1].Objects, true)
		if err != nil || len(blocks) == 0 || len(blocks[0].Points) == 0 {
			return 6
		}
		return blocks[0].Points[0].Status
	}
	switch c.Func {
	case dnp3.FCOperate:
		// The source's select and operate go as one pair, so the master's
		// polls cannot come between them (the operate must follow its
		// select directly, 4.4.4.3); the select passed down earlier
		// checked the control.
		st := uint8(6)
		_ = m.SelectOperate(ctx, objs, r.s.Timeout, func(_ byte, frags []dnp3.Fragment) error {
			st = status(frags)
			if st != 0 {
				return errors.New("refused")
			}
			return nil
		})
		return st
	case dnp3.FCDirectOperateNR:
		c.Func = dnp3.FCDirectOperate
	}
	frags, err := m.Request(ctx, c.Func, objs)
	if err != nil {
		return 6
	}
	return status(frags)
}

func (h handler) DataSetControl(ctx context.Context, c dnp3.DataSetControl) uint8 {
	if h.g.next != nil {
		return h.g.next.DataSetControl(ctx, c)
	}
	return 4
}

func (h handler) Restart(ctx context.Context, cold bool) time.Duration {
	if h.g.next != nil {
		return h.g.next.Restart(ctx, cold)
	}
	return 0
}

func (h handler) Activate(ctx context.Context, names [][]byte) dnp3.ActivateStatus {
	if h.g.next != nil {
		return h.g.next.Activate(ctx, names)
	}
	return dnp3.ActivateStatus{}
}

func (h handler) Application(ctx context.Context, fc byte, names [][]byte) dnp3.IIN {
	if h.g.next != nil {
		return h.g.next.Application(ctx, fc, names)
	}
	return dnp3.IINNoFuncCodeSupport
}

func (h handler) TimeSet(t time.Time) {
	if h.g.next != nil {
		h.g.next.TimeSet(t)
	}
}

func (h handler) DataSetWritten(ctx context.Context, ds dnp3.DataSet) {
	if h.g.next != nil {
		h.g.next.DataSetWritten(ctx, ds)
	}
}
