package dnp3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// The outstation application layer (IEEE 1815-2012 clauses 4 to 6): one
// Association per master address, answering requests from a PointDB and a
// Handler, keeping sequence numbers, confirmations, select-before-operate,
// unsolicited responses (4.6, 5.1.1.1), broadcasts (4.7, Table 4-13), time
// synchronisation, freezes, assign class, data sets, activate
// configuration and Secure Authentication (ostauth.go). Frames reach it
// through an OutLink (a TCP connection, a UDP socket or a serial line).

// ControlRequest is one control object of a SELECT, OPERATE or
// DIRECT_OPERATE(_NR): a CROB (g12v1) or an analog output block (g41).
type ControlRequest struct {
	Func   byte
	Group  uint8
	Var    uint8
	Index  uint32
	CROB   CROB
	Value  float64
	Select bool   // a SELECT: check only, do not operate
	User   uint16 // the authenticated user (Secure Authentication), 0 without
}

// DataSetControl is a control group of a data set in a control request
// (5.4.11): the values of the CTLV elements following one CTLS.
type DataSetControl struct {
	Func   byte
	Select bool
	ID     uint32
	Names  []string
	Values []any
	User   uint16
}

// Handler performs what the outstation cannot do from its database.
type Handler interface {
	// Control returns the control status (0 success; codes of Table 11-7).
	Control(ctx context.Context, c ControlRequest) uint8
	// DataSetControl issues one control group of a data set.
	DataSetControl(ctx context.Context, c DataSetControl) uint8
	// Restart returns the time the outstation will be busy (4.4.9).
	Restart(ctx context.Context, cold bool) time.Duration
	// Activate checks and activates the configurations named by the
	// request objects (g70v8 file specifications, g110 octet strings).
	Activate(ctx context.Context, names [][]byte) ActivateStatus
	// Application initialises, starts or stops applications (g90 names;
	// nil for all); a non-zero IIN (2.0, 2.1, 2.4) reports a refusal.
	Application(ctx context.Context, fc byte, names [][]byte) IIN
	// TimeSet reports a time synchronisation: the master's time now.
	TimeSet(masterNow time.Time)
	// DataSetWritten reports a data set written by the master.
	DataSetWritten(ctx context.Context, ds DataSet)
}

// OutLink sends frames towards a master.
type OutLink interface {
	WriteFrame(f Frame) error
	Close() error
}

// OutstationConfig configures one association.
type OutstationConfig struct {
	Address     uint16 // ours
	Master      uint16 // the master's
	SelfAddress bool   // accept frames to 0xFFFC (9.2.5.2.2)
	Log         *slog.Logger
	DB          *PointDB
	Events      *EventBuffer
	Handler     Handler
	// MaxFragment is the largest response fragment (default 2048).
	MaxFragment int
	// ConfirmTimeout waits for an application confirmation (default 5 s).
	ConfirmTimeout time.Duration
	// SelectTimeout is how long a select stays valid (default 5 s).
	SelectTimeout time.Duration
	// MaxControls is the most control objects in one request (default 16).
	MaxControls int
	// Unsolicited: the unsolicited response mode (4.6.2.1 b). UnsolRetries
	// is the retries per series (-1: indefinitely); UnsolHold delays a
	// response after the first new event, UnsolCount sends at once when
	// this many events are pending (4.6.2.2).
	Unsolicited  bool
	UnsolRetries int
	UnsolHold    time.Duration
	UnsolCount   int
	// UnsolOffline is the pause after a series that ended without a
	// confirmation (its retries used up) before a new series carries the
	// events still buffered (default: ConfirmTimeout).
	UnsolOffline time.Duration
	// NeedTime sets IIN1.4 at start and again this long after each
	// synchronisation; 0 never asks for time.
	NeedTime time.Duration
	// Attributes are the device attributes of set 0 by variation, and
	// Writable the variations the master may write.
	Attributes map[uint8]any
	Writable   map[uint8]bool
	// Auth enables Secure Authentication as outstation.
	Auth *OutstationAuth
	// Broadcast takes requests sent to the broadcast addresses (4.7;
	// never answered). BroadcastFuncs, when set, are the request function
	// codes carried out by broadcast (the device profile's 1.13 items);
	// others are discarded. Under Secure Authentication a critical
	// request by broadcast is carried out only in a verified Aggressive
	// Mode (OutstationAuth.gateBroadcast).
	Broadcast      bool
	BroadcastFuncs map[byte]bool
	// Files enables sequential file transfer (outfile.go); FileStore, when
	// set, is this association's store in place of Files.Store.
	Files     *OutstationFiles
	FileStore FileStore
	// Filter restricts the requests served to a declared device profile
	// (a simulator preset): a non-zero IIN refuses the request with it.
	Filter func(req Fragment) IIN
}

type chunk struct {
	data    []byte
	events  []int64
	confirm bool // event objects not from the buffer (file transfer)
}

type inbound struct {
	frag    Fragment
	raw     []byte
	dest    uint16
	arrived time.Time
	link    uint64 // the link it came on (Association.links)
}

// Association is the outstation's side of one master–outstation
// association.
type Association struct {
	cfg OutstationConfig

	mu       sync.Mutex
	link     OutLink
	sec      Secondary
	ra       Reassembler
	tseq     uint8
	lastRx   time.Time
	links    uint64 // links attached so far: a new connection is a new number
	attached chan struct{}

	in   chan inbound
	wake chan struct{}

	// Guarded by the run loop.
	restart    bool
	needTime   bool
	timeAt     time.Time
	recordedAt time.Time
	unsolOn    map[int]bool
	nullDone   bool // the start-up null unsolicited response was confirmed
	useq       uint8
	started    bool // first request after restart seen
	lastReq    []byte
	lastSeq    uint8
	lastLink   uint64
	lastResp   [][]byte
	sel        *selection
	bcast      uint16 // broadcast address received, 0 none
	// clockOffset is the master's time less the host clock at the last
	// synchronisation (g50v1 reads).
	clockOffset time.Duration
	bcastConf   bool // a response with IIN1.0 and CON awaits confirmation
	schedules   []*freezeSchedule
	lastSent    []byte // the latest response fragment sent (for SA challenges of responses)
	stats       struct{ requests, responses, unsol int }
}

type selection struct {
	objs []byte
	seq  uint8
	at   time.Time
}

type freezeSchedule struct {
	stop    chan struct{}
	headers []Block
	clear   bool
}

// NewAssociation makes an association (Run starts it).
func NewAssociation(cfg OutstationConfig) *Association {
	if cfg.MaxFragment <= 0 {
		cfg.MaxFragment = 2048
	}
	if cfg.ConfirmTimeout <= 0 {
		cfg.ConfirmTimeout = 5 * time.Second
	}
	if cfg.SelectTimeout <= 0 {
		cfg.SelectTimeout = 5 * time.Second
	}
	if cfg.UnsolOffline <= 0 {
		cfg.UnsolOffline = cfg.ConfirmTimeout
	}
	if cfg.MaxControls <= 0 {
		cfg.MaxControls = 16
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Events == nil {
		cfg.Events = NewEventBuffer(nil, nil)
	}
	a := &Association{cfg: cfg, in: make(chan inbound, 64), wake: make(chan struct{}, 1), attached: make(chan struct{}, 1),
		restart: true, unsolOn: map[int]bool{}}
	if cfg.DB != nil {
		cfg.DB.Attach(cfg.Events)
	}
	cfg.Events.notify = a.poke
	if cfg.Auth != nil {
		cfg.Auth.assoc = a
	}
	return a
}

// Master is the association's master address.
func (a *Association) Master() uint16 { return a.cfg.Master }

func (a *Association) poke() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// Attach makes l the link the association sends on (a new connection).
func (a *Association) Attach(l OutLink) {
	a.mu.Lock()
	old := a.link
	a.link = l
	if l != old {
		a.links++
	}
	a.sec = Secondary{}
	a.ra = Reassembler{}
	a.lastRx = time.Now()
	a.mu.Unlock()
	if old != nil && old != l {
		_ = old.Close()
	}
	select {
	case a.attached <- struct{}{}:
	default:
	}
}

// Detach forgets l when it is the current link.
func (a *Association) Detach(l OutLink) {
	a.mu.Lock()
	if a.link == l {
		a.link = nil
	}
	a.mu.Unlock()
}

// Linked reports whether a link is attached.
func (a *Association) Linked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.link != nil
}

// Idle is how long nothing was received.
func (a *Association) Idle() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.lastRx)
}

// Accepts reports whether the association takes a frame to dest.
func (a *Association) Accepts(dest uint16) bool {
	return dest == a.cfg.Address || (a.cfg.SelfAddress && dest == AddrSelf) || (IsBroadcast(dest) && a.cfg.Broadcast)
}

// Deliver takes a primary frame from the association's master: the
// secondary station rules, the transport function, then the request.
func (a *Association) Deliver(f Frame) {
	now := time.Now()
	a.mu.Lock()
	a.lastRx = now
	if !f.Primary() {
		a.mu.Unlock()
		return
	}
	act := a.sec.Handle(f)
	link, gen := a.link, a.links
	a.mu.Unlock()
	if act.Respond && link != nil {
		_ = link.WriteFrame(Frame{Ctrl: act.Func, Dest: a.cfg.Master, Src: a.cfg.Address})
	}
	if !act.Deliver {
		return
	}
	a.mu.Lock()
	apdu, err := a.ra.Add(f.Data)
	a.mu.Unlock()
	if err != nil || apdu == nil {
		return
	}
	frag, err := ParseFragment(apdu)
	if err != nil || frag.Func >= 129 {
		return
	}
	select {
	case a.in <- inbound{frag: frag, raw: apdu, dest: f.Dest, arrived: now, link: gen}:
	default:
		a.cfg.Log.Warn("DNP3 outstation request dropped: the association is busy")
	}
}

// send segments and sends one fragment.
func (a *Association) send(f Fragment) error {
	b := f.Encode()
	a.mu.Lock()
	link := a.link
	segs := Segment(b, &a.tseq)
	a.mu.Unlock()
	if link == nil {
		return errors.New("no link to the master")
	}
	for _, s := range segs {
		if err := link.WriteFrame(Frame{Ctrl: CtrlPRM | LinkUnconfirmedUserData, Dest: a.cfg.Master, Src: a.cfg.Address, Data: s}); err != nil {
			return err
		}
	}
	if f.Func == FCResponse || f.Func == FCUnsolicited {
		a.lastSent = b
	}
	if a.cfg.Auth != nil {
		a.cfg.Auth.stat(StatMessagesSent)
	}
	return nil
}

// KeepAlive sends REQUEST_LINK_STATUS on the link (13.2.3.3.1).
func (a *Association) KeepAlive() {
	a.mu.Lock()
	link := a.link
	a.mu.Unlock()
	if link != nil {
		_ = link.WriteFrame(Frame{Ctrl: CtrlPRM | LinkRequestLinkStatus, Dest: a.cfg.Master, Src: a.cfg.Address})
	}
}

// iin is the indications of a response (not counting events in skip).
func (a *Association) iin(skip map[int64]bool) IIN {
	var i IIN
	if a.restart {
		i |= IINDeviceRestart
	}
	if a.needTime {
		i |= IINNeedTime
	}
	for c := range a.cfg.Events.Classes(skip) {
		i |= IIN(1) << c
	}
	if a.cfg.Events.Overflow() {
		i |= IINEventBufferOverflow
	}
	if a.bcast != 0 {
		i |= IINBroadcast
	}
	return i
}

// Status is a summary for the status container.
func (a *Association) Status() map[string]any {
	a.mu.Lock()
	linked := a.link != nil
	a.mu.Unlock()
	st := map[string]any{"master": a.cfg.Master, "connected": linked, "events": a.cfg.Events.Len(), "overflow": a.cfg.Events.Overflow()}
	classes := map[string]any{}
	counts := a.cfg.Events.Counts()
	for c := 1; c <= 3; c++ {
		classes[fmt.Sprintf("class%d", c)] = map[string]any{"events": counts[c], "capacity": a.cfg.Events.Capacity(c)}
	}
	st["classes"] = classes
	if fs := a.cfg.Files; fs != nil {
		n := 0
		fs.mu.Lock()
		for _, of := range fs.open {
			if of.assoc == a {
				n++
			}
		}
		fs.mu.Unlock()
		st["filesOpen"] = n
	}
	if a.cfg.Auth != nil {
		st["auth"] = a.cfg.Auth.Summary()
		evs, refused := a.cfg.Auth.RecentSecurityEvents()
		list := make([]any, 0, len(evs))
		for _, e := range evs {
			d := map[string]any{}
			for k, v := range e.Detail {
				d[k] = v
			}
			list = append(list, map[string]any{"at": e.At.Format(time.RFC3339), "event": e.Event, "detail": d})
		}
		st["securityEvents"] = list
		st["broadcastRefused"] = int(refused)
		state, keysAt := a.cfg.Auth.SAState()
		sa := map[string]any{"state": state, "version": 5}
		if !keysAt.IsZero() {
			sa["sessionKeysAt"] = keysAt.UTC().Format(time.RFC3339)
		}
		st["sa"] = sa
	}
	return st
}

// Run serves the association until ctx ends.
func (a *Association) Run(ctx context.Context) {
	if a.cfg.NeedTime > 0 {
		a.needTime = true
	}
	var unsolTimer, offlineTimer <-chan time.Time
	var unsol *unsolState
	var deferred []inbound
	var sol *solState
	var holdTimer <-chan time.Time
	needTick := time.NewTicker(time.Second)
	defer needTick.Stop()
	defer func() {
		for _, s := range a.schedules {
			close(s.stop)
		}
	}()
	startUnsol := func(null bool) {
		if !a.cfg.Unsolicited || unsol != nil || !a.Linked() {
			return
		}
		if !null && !a.nullDone {
			return
		}
		var objs []byte
		var ids []int64
		if !null {
			classes := map[int]bool{}
			for c, on := range a.unsolOn {
				if on {
					classes[c] = true
				}
			}
			if len(classes) == 0 {
				return
			}
			evs := a.cfg.Events.Pending(classes, 0)
			if len(evs) == 0 {
				return
			}
			chs := a.eventChunks(evs)
			limit := a.cfg.MaxFragment - 4
			for _, c := range chs {
				if len(objs) > 0 && len(objs)+len(c.data) > limit {
					break
				}
				objs = append(objs, c.data...)
				ids = append(ids, c.events...)
			}
		}
		skip := map[int64]bool{}
		for _, id := range ids {
			skip[id] = true
		}
		f := Fragment{Control: AppFIR | AppFIN | AppCON | AppUNS | a.useq, Func: FCUnsolicited, IIN: a.iin(skip), Objects: objs}
		if a.cfg.Auth != nil {
			f = a.cfg.Auth.wrapResponse(f)
		}
		unsol = &unsolState{frag: f, events: ids, null: null, retries: a.cfg.UnsolRetries}
		if err := a.send(f); err != nil {
			unsol = nil
			return
		}
		a.stats.unsol++
		unsolTimer = time.After(a.cfg.ConfirmTimeout)
	}
	process := func(in inbound) {
		if sol != nil && in.frag.Func != FCConfirm && in.frag.Func != FCAuthRequest && in.frag.Func != FCAuthRequestNoAck {
			// A new request cancels the solicited response in progress; its
			// events stay buffered (4.4.2.1 rule 1).
			sol = nil
		}
		sol = a.handle(ctx, in, sol)
	}
	for {
		if unsol == nil && len(deferred) > 0 {
			d := deferred
			deferred = nil
			for _, in := range d {
				process(in)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-a.attached:
			if a.cfg.Unsolicited && !a.nullDone {
				startUnsol(true)
			} else if !a.nullDone && !a.cfg.Unsolicited {
				a.nullDone = true
			}
		case in := <-a.in:
			if in.frag.Func == FCConfirm {
				if in.frag.Control&AppUNS != 0 {
					if unsol != nil && in.frag.Seq() == unsol.frag.Seq() && a.confirmOK(in) {
						a.cfg.Events.Remove(ctx, unsol.events)
						if unsol.null {
							a.nullDone = true
						}
						a.useq = (a.useq + 1) & 0x0F
						unsol, unsolTimer = nil, nil
						a.poke()
					}
					continue
				}
				if sol != nil && in.frag.Seq() == sol.seq && a.confirmOK(in) {
					sol = a.confirmed(ctx, sol)
				}
				continue
			}
			if unsol != nil && in.frag.Func == FCRead {
				deferred = append(deferred, in) // 4.6.6 rule 16
				continue
			}
			process(in)
			a.poke()
		case <-unsolTimer:
			if unsol == nil {
				continue
			}
			if len(deferred) > 0 && !unsol.null {
				// Rule 16: a read waits; the series ends at the timeout.
				unsol, unsolTimer = nil, nil
				a.useq = (a.useq + 1) & 0x0F
				offlineTimer = time.After(a.cfg.UnsolOffline)
				continue
			}
			if unsol.null || unsol.retries != 0 {
				if unsol.retries > 0 {
					unsol.retries--
				}
				_ = a.send(unsol.frag) // identical retry
				unsolTimer = time.After(a.cfg.ConfirmTimeout)
				continue
			}
			// The series ends unconfirmed; its events stay buffered and a
			// new series carries them after the offline interval.
			unsol, unsolTimer = nil, nil
			a.useq = (a.useq + 1) & 0x0F
			offlineTimer = time.After(a.cfg.UnsolOffline)
		case <-offlineTimer:
			offlineTimer = nil
			if unsol == nil && sol == nil {
				startUnsol(false)
			} else {
				a.poke()
			}
		case <-a.wake:
			if unsol != nil || sol != nil {
				continue
			}
			if a.cfg.UnsolHold > 0 && holdTimer == nil {
				pending := len(a.cfg.Events.Pending(a.enabledClasses(), 0))
				if pending > 0 && (a.cfg.UnsolCount <= 0 || pending < a.cfg.UnsolCount) {
					holdTimer = time.After(a.cfg.UnsolHold)
					continue
				}
			}
			startUnsol(false)
		case <-holdTimer:
			holdTimer = nil
			if unsol == nil && sol == nil {
				startUnsol(false)
			}
		case <-needTick.C:
			if a.cfg.NeedTime > 0 && !a.needTime && !a.timeAt.IsZero() && time.Since(a.timeAt) > a.cfg.NeedTime {
				a.needTime = true
			}
			a.expireFiles(ctx)
			if sol != nil && time.Since(sol.sentAt) > a.cfg.ConfirmTimeout {
				sol = nil // confirmation not forthcoming: events stay buffered
			}
		}
	}
}

func (a *Association) enabledClasses() map[int]bool {
	out := map[int]bool{}
	for c, on := range a.unsolOn {
		if on {
			out[c] = true
		}
	}
	return out
}

// confirmOK checks a confirmation (in aggressive mode when one was
// asked for).
func (a *Association) confirmOK(in inbound) bool {
	if a.cfg.Auth == nil {
		return true
	}
	ok := a.cfg.Auth.checkConfirm(in.frag)
	a.cfg.Auth.limits(false)
	return ok
}

// dropLink closes the current link (a TCP connection; nothing for UDP).
func (a *Association) dropLink() {
	a.mu.Lock()
	l := a.link
	a.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
}

type unsolState struct {
	frag    Fragment
	events  []int64
	null    bool
	retries int
}

type solState struct {
	seq    uint8
	frags  []Fragment
	events [][]int64
	sentAt time.Time
}

// confirmed handles the confirmation of a solicited fragment: its events
// are dropped and the next fragment goes out.
func (a *Association) confirmed(ctx context.Context, s *solState) *solState {
	a.cfg.Events.Remove(ctx, s.events[0])
	if s.frags[0].IIN&IINBroadcast != 0 && a.bcastConf {
		a.bcast, a.bcastConf = 0, false
	}
	s.frags, s.events = s.frags[1:], s.events[1:]
	if len(s.frags) == 0 {
		return nil
	}
	s.seq = s.frags[0].Seq()
	s.sentAt = time.Now()
	_ = a.send(s.frags[0])
	return s
}

// respond packs chunks into fragments and sends the first; it returns the
// state waiting for confirmations (nil when none is needed).
func (a *Association) respond(seq uint8, chunks []chunk, iin2 IIN, fn byte) *solState {
	limit := a.cfg.MaxFragment - 4
	var groups [][]chunk
	var cur []chunk
	size := 0
	for _, c := range chunks {
		if len(cur) > 0 && size+len(c.data) > limit {
			groups = append(groups, cur)
			cur, size = nil, 0
		}
		cur = append(cur, c)
		size += len(c.data)
	}
	groups = append(groups, cur)
	s := &solState{seq: seq}
	all := map[int64]bool{}
	for _, g := range groups {
		for _, c := range g {
			for _, id := range c.events {
				all[id] = true
			}
		}
	}
	for i, g := range groups {
		ctl := (seq + uint8(i)) & 0x0F
		if i == 0 {
			ctl |= AppFIR
		}
		last := i == len(groups)-1
		if last {
			ctl |= AppFIN
		}
		var objs []byte
		var ids []int64
		confirm := false
		for _, c := range g {
			objs = append(objs, c.data...)
			ids = append(ids, c.events...)
			confirm = confirm || c.confirm
		}
		iin := a.iin(all) | iin2
		if !last || len(ids) > 0 || confirm {
			ctl |= AppCON
		}
		if a.bcast == AddrBroadcastMandatory {
			ctl |= AppCON
			a.bcastConf = true
		}
		f := Fragment{Control: ctl, Func: fn, IIN: iin, Objects: objs}
		if a.cfg.Auth != nil && fn == FCResponse {
			f = a.cfg.Auth.wrapResponse(f)
		}
		s.frags = append(s.frags, f)
		s.events = append(s.events, ids)
	}
	a.lastResp = nil
	for _, f := range s.frags {
		a.lastResp = append(a.lastResp, f.Encode())
	}
	s.sentAt = time.Now()
	_ = a.send(s.frags[0])
	a.stats.responses++
	if a.bcast == AddrBroadcastNoConfirm || a.bcast == AddrBroadcastOptional {
		// Cleared after the first response carrying IIN1.0 (Table 4-13).
		a.bcast = 0
	}
	if s.frags[0].Control&AppCON == 0 {
		return nil
	}
	return s
}

// handle processes one request (not a confirmation).
func (a *Association) handle(ctx context.Context, in inbound, sol *solState) *solState {
	req := in.frag
	bc := IsBroadcast(in.dest)
	if a.cfg.Auth != nil {
		a.cfg.Auth.stat(StatMessagesReceived)
	}
	// Identical retry of the previous request: repeat the response
	// without executing again (Table 6-1). A READ changes nothing and is
	// answered afresh, and a request on a new connection is never a retry
	// of one on the old.
	if !bc && a.started && req.Seq() == a.lastSeq && bytes.Equal(in.raw, a.lastReq) && len(a.lastResp) > 0 && req.Func != FCSelect && req.Func != FCRead && in.link == a.lastLink {
		for _, b := range a.lastResp[:1] {
			f, _ := ParseFragment(b)
			_ = a.send(f)
		}
		return sol
	}
	a.started = true
	a.lastReq, a.lastSeq, a.lastLink = in.raw, req.Seq(), in.link
	user := uint16(0)
	if bc {
		if a.cfg.BroadcastFuncs != nil && !a.cfg.BroadcastFuncs[req.Func] {
			a.cfg.Log.Debug("DNP3 broadcast discarded: function not enabled for broadcast", "function", FuncName(req.Func))
			return sol
		}
		if a.cfg.Auth != nil {
			r, u := a.cfg.Auth.gateBroadcast(ctx, req, in.dest)
			if r == nil {
				return sol
			}
			req, user = *r, u
		}
	}
	if a.cfg.Auth != nil && !bc {
		r, u, reply := a.cfg.Auth.gate(ctx, req, in.raw)
		if reply != nil {
			_ = a.send(*reply)
			a.lastResp = [][]byte{reply.Encode()}
			if r == nil {
				return sol
			}
		}
		if r == nil {
			return sol
		}
		req, user = *r, u
	}
	if a.cfg.Filter != nil {
		if iin := a.cfg.Filter(req); iin != 0 {
			if bc || NoResponse(req.Func) {
				return sol
			}
			return a.respond(req.Seq(), nil, iin, FCResponse)
		}
	}
	chunks, iin2, answer := a.execute(ctx, req, in, user)
	if bc {
		a.bcast = in.dest
		return sol
	}
	if !answer || NoResponse(req.Func) {
		return sol
	}
	return a.respond(req.Seq(), chunks, iin2, FCResponse)
}

// execute performs a request and returns the response objects.
func (a *Association) execute(ctx context.Context, req Fragment, in inbound, user uint16) ([]chunk, IIN, bool) {
	a.stats.requests++
	switch req.Func {
	case FCRead:
		if isFileTransport(req.Objects) {
			ch, iin := a.fileRequest(ctx, req.Func, req.Objects)
			return ch, iin, true
		}
		ch, iin := a.read(req.Objects)
		return ch, iin, true
	case FCWrite:
		if isFileTransport(req.Objects) {
			ch, iin := a.fileRequest(ctx, req.Func, req.Objects)
			return ch, iin, true
		}
		return nil, a.write(ctx, req.Objects, in), true
	case FCOpenFile, FCCloseFile, FCDeleteFile, FCGetFileInfo, FCAuthenticateFile, FCAbortFile:
		ch, iin := a.fileRequest(ctx, req.Func, req.Objects)
		return ch, iin, true
	case FCSelect, FCOperate, FCDirectOperate, FCDirectOperateNR:
		echo, iin := a.control(ctx, req, user)
		if iin&IINObjectUnknown != 0 || iin&IINNoFuncCodeSupport != 0 {
			return nil, iin, true
		}
		return []chunk{{data: echo}}, iin, true
	case FCImmedFreeze, FCImmedFreezeNR, FCFreezeClear, FCFreezeClearNR, FCFreezeAtTime, FCFreezeAtTimeNR:
		return nil, a.freeze(ctx, req), true
	case FCColdRestart, FCWarmRestart:
		d := a.cfg.Handler.Restart(ctx, req.Func == FCColdRestart)
		var obj []byte
		if d%time.Second == 0 && d/time.Second <= math.MaxUint16 {
			obj, _ = EncodeBlock(52, 1, Q8Count, []Point{{Value: float64(d / time.Second)}})
		} else {
			obj, _ = EncodeBlock(52, 2, Q8Count, []Point{{Value: float64(min(d/time.Millisecond, math.MaxUint16))}})
		}
		a.restart, a.nullDone, a.unsolOn = true, false, map[int]bool{}
		a.started = false
		go func() {
			time.Sleep(d)
			select {
			case a.attached <- struct{}{}:
			default:
			}
		}()
		return []chunk{{data: obj}}, 0, true
	case FCEnableUnsolicited, FCDisableUnsolicited:
		blocks, err := ParseObjects(req.Objects, false)
		if err != nil || len(blocks) == 0 {
			return nil, IINParameterError, true
		}
		for _, b := range blocks {
			if b.Header.Group != 60 || b.Header.Var < 2 || b.Header.Var > 4 || b.Header.Qual != QAll {
				return nil, IINObjectUnknown, true
			}
		}
		for _, b := range blocks {
			a.unsolOn[int(b.Header.Var)-1] = req.Func == FCEnableUnsolicited
		}
		return nil, 0, true
	case FCAssignClass:
		return nil, a.assign(req.Objects), true
	case FCDelayMeasure:
		d := time.Since(in.arrived).Milliseconds()
		obj, _ := EncodeBlock(52, 2, Q8Count, []Point{{Value: float64(min(d, math.MaxUint16))}})
		return []chunk{{data: obj}}, 0, true
	case FCRecordCurrentTime:
		a.recordedAt = in.arrived
		return nil, 0, true
	case FCActivateConfig:
		blocks, err := ParseObjects(req.Objects, true)
		if err != nil || len(blocks) == 0 {
			return nil, IINParameterError, true
		}
		var names [][]byte
		for _, b := range blocks {
			if !(b.Header.Group == 70 && b.Header.Var == 8) && b.Header.Group != 110 {
				return nil, IINObjectUnknown, true
			}
			for _, p := range b.Points {
				names = append(names, p.Raw)
			}
		}
		st := a.cfg.Handler.Activate(ctx, names)
		obj, _ := EncodeBlock(91, 1, QFreeFormat, []Point{{Raw: st.Encode()}})
		return []chunk{{data: obj}}, 0, true
	case FCInitializeAppl, FCStartAppl, FCStopAppl:
		blocks, err := ParseObjects(req.Objects, true)
		if err != nil || len(blocks) == 0 {
			return nil, IINParameterError, true
		}
		var names [][]byte
		for _, b := range blocks {
			if b.Header.Group != 90 {
				return nil, IINObjectUnknown, true
			}
			if b.Header.Qual == QAll {
				names = nil
				break
			}
			for _, p := range b.Points {
				names = append(names, p.Raw)
			}
		}
		return nil, a.cfg.Handler.Application(ctx, req.Func, names), true
	case FCAuthRequest, FCAuthRequestNoAck:
		return nil, IINNoFuncCodeSupport, true
	}
	return nil, IINNoFuncCodeSupport, true
}

// ParseRequest splits a request's objects into headers (a READ's headers
// carry no data; size-prefixed objects are kept whole), as the outstation
// reads them.
func ParseRequest(fc byte, objs []byte) ([]Block, error) {
	if fc == FCRead {
		return parseRequestHeaders(objs)
	}
	return ParseObjects(objs, true)
}

// isFileTransport reports whether a READ or WRITE carries a g70v5 file
// transport object.
func isFileTransport(objs []byte) bool {
	return len(objs) >= 3 && objs[0] == 70 && objs[1] == 5 && objs[2] == QFreeFormat
}

// ---- READ -------------------------------------------------------------------

// staticChunks encodes the points of a type (all, or those in idx),
// consecutive indexes of one variation per header.
func (a *Association) staticChunks(typ string, variation uint8, idx func(uint32) bool, class0 bool) []chunk {
	if typ == "virtual-terminal" {
		return nil // ports have no static value
	}
	g := pointGroups[typ][0]
	var pts []DBPoint
	for _, p := range a.cfg.DB.Points(typ) {
		if (class0 && !p.Class0) || (idx != nil && !idx(p.Index)) {
			continue
		}
		pts = append(pts, p)
	}
	if typ == "security-statistic" && a.cfg.Auth != nil {
		pts = a.cfg.Auth.statPoints(idx)
	}
	var out []chunk
	for i := 0; i < len(pts); {
		v := variation
		if v == 0 {
			v = pts[i].StaticVar
		}
		if v == 0 {
			v = defaultVars[typ][0]
		}
		if typ == "octet-string" {
			v = uint8(len(pts[i].Raw))
		}
		j := i + 1
		for j < len(pts) && j-i < 64 && pts[j].Index == pts[j-1].Index+1 {
			vj := variation
			if vj == 0 {
				vj = pts[j].StaticVar
			}
			if vj == 0 {
				vj = defaultVars[typ][0]
			}
			if typ == "octet-string" {
				vj = uint8(len(pts[j].Raw))
			}
			if vj != v {
				break
			}
			j++
		}
		var ps []Point
		for _, p := range pts[i:j] {
			pt := Point{Index: p.Index, Value: p.Value, Flags: p.Flags, HasFlags: true, Time: p.Time, Raw: p.Raw}
			if typ == "frozen-counter" || typ == "frozen-analog" {
				pt.Time = p.Time
			}
			if typ == "time-and-interval" {
				pt = Point{Index: p.Index, Value: p.Time, Interval: uint32(p.Value), Units: p.Units}
			}
			ps = append(ps, pt)
		}
		q := uint8(Q8StartStop)
		if pts[j-1].Index > 255 {
			q = Q16StartStop
		}
		b, err := EncodeBlock(g, v, q, ps)
		if err == nil {
			out = append(out, chunk{data: b})
		}
		i = j
	}
	return out
}

// eventChunks encodes events in their order, one header per run of the
// same object (relative-time variations after a common time of
// occurrence).
func (a *Association) eventChunks(evs []Event) []chunk {
	var out []chunk
	for i := 0; i < len(evs); {
		e := evs[i]
		j := i + 1
		for j < len(evs) && j-i < 64 && evs[j].Group == e.Group && evs[j].Var == e.Var {
			j++
		}
		run := evs[i:j]
		var ids []int64
		var ps []Point
		for _, x := range run {
			ids = append(ids, x.ID)
			ps = append(ps, Point{Index: x.Index, Value: x.Value, Flags: x.Flags, HasFlags: true, Time: x.Time, Raw: x.Raw, Assoc: x.Assoc})
		}
		var b []byte
		var err error
		switch {
		case e.Group == 70 || e.Group == 88 || e.Group == 120:
			b, err = EncodeBlock(e.Group, e.Var, QFreeFormat, ps)
		case (e.Group == 2 || e.Group == 4) && e.Var == 3:
			cto := run[0].Time
			for _, x := range run {
				if x.Time.Before(cto) {
					cto = x.Time
				}
			}
			var ok bool
			ok = true
			for _, x := range run {
				if x.Time.Sub(cto) > 65535*time.Millisecond {
					ok = false
				}
			}
			if !ok {
				b, err = EncodeBlock(e.Group, 2, Q16Index16, ps)
				break
			}
			head, _ := EncodeBlock(51, 1, Q8Count, []Point{{Value: cto}})
			b, err = EncodeBlock(e.Group, 3, Q16Index16, ps, cto)
			b = append(head, b...)
		default:
			b, err = EncodeBlock(e.Group, e.Var, Q16Index16, ps)
		}
		if err != nil {
			a.cfg.Log.Warn("DNP3 event not encoded", "group", e.Group, "variation", e.Var, "error", err)
		} else {
			out = append(out, chunk{data: b, events: ids})
		}
		i = j
	}
	return out
}

// indexFilter turns a request header into a point filter; missing reports
// requested indexes not defined (IIN2.2).
func (a *Association) indexFilter(h Header, b Block, typ string) (func(uint32) bool, bool) {
	switch {
	case h.Qual == QAll:
		return nil, false
	case h.Qual&0x0F <= 2:
		missing := false
		for i := h.Start; i <= h.Stop; i++ {
			if _, ok := a.cfg.DB.Point(typ, i); !ok {
				missing = true
			}
			if i == math.MaxUint32 {
				break
			}
		}
		return func(i uint32) bool { return i >= h.Start && i <= h.Stop }, missing
	case prefixLen(h.Qual) > 0:
		set := map[uint32]bool{}
		missing := false
		for _, p := range b.Points {
			set[p.Index] = true
			if _, ok := a.cfg.DB.Point(typ, p.Index); !ok {
				missing = true
			}
		}
		return func(i uint32) bool { return set[i] }, missing
	}
	return nil, false
}

// parseIndexList decodes a READ header with an index list (no objects).
func parseRequestHeaders(objs []byte) ([]Block, error) {
	var out []Block
	for len(objs) > 0 {
		h, rest, err := parseHeader(objs)
		if err != nil {
			return out, err
		}
		b := Block{Header: h}
		objs = rest
		if pl := prefixLen(h.Qual); pl > 0 {
			if len(objs) < pl*int(h.Count) {
				return out, errors.New("truncated index list")
			}
			for i := range h.Count {
				b.Points = append(b.Points, Point{Index: readUint(objs[int(i)*pl:], pl)})
			}
			objs = objs[pl*int(h.Count):]
		} else if spl := sizePrefixLen(h.Qual); spl > 0 {
			// Size-prefixed objects in a READ (g70v5 names a block).
			for range h.Count {
				if len(objs) < spl {
					return out, errors.New("truncated object size")
				}
				n := int(readUint(objs, spl))
				if len(objs) < spl+n {
					return out, errors.New("truncated object")
				}
				b.Points = append(b.Points, Point{Raw: objs[spl : spl+n]})
				objs = objs[spl+n:]
			}
		}
		out = append(out, b)
	}
	return out, nil
}

func (a *Association) read(objs []byte) ([]chunk, IIN) {
	blocks, err := parseRequestHeaders(objs)
	if err != nil {
		return nil, IINParameterError
	}
	var events, statics []chunk
	var iin IIN
	eventsTaken := map[int64]bool{}
	takeEvents := func(evs []Event) {
		var fresh []Event
		for _, e := range evs {
			if !eventsTaken[e.ID] {
				eventsTaken[e.ID] = true
				fresh = append(fresh, e)
			}
		}
		events = append(events, a.eventChunks(fresh)...)
	}
	for _, b := range blocks {
		h := b.Header
		limit := 0
		if h.Qual == Q8Count || h.Qual == Q16Count || h.Qual == Q32Count {
			limit = int(h.Count)
		}
		switch {
		case h.Group == 60:
			if h.Var == 1 {
				for _, t := range a.cfg.DB.Types() {
					statics = append(statics, a.staticChunks(t, 0, nil, true)...)
				}
				if a.cfg.Auth != nil {
					statics = append(statics, a.staticChunks("security-statistic", 0, nil, false)...)
				}
				statics = append(statics, a.dataSetChunks(87, nil, true)...)
				continue
			}
			if h.Var < 2 || h.Var > 4 {
				iin |= IINObjectUnknown
				continue
			}
			takeEvents(a.cfg.Events.Pending(map[int]bool{int(h.Var) - 1: true}, limit))
		case h.Group == 0:
			ch, e := a.attributes(h)
			statics = append(statics, ch...)
			iin |= e
		case h.Group == 50 && h.Var == 1:
			// The outstation's time (g50v1 read with qualifier 07 and a
			// count of 1): the host clock corrected by the offset
			// of the last synchronisation; the host clock is never set.
			if (h.Qual != Q8Count && h.Qual != Q16Count) || h.Count != 1 {
				iin |= IINParameterError
				continue
			}
			obj, err := EncodeBlock(50, 1, h.Qual, []Point{{Value: time.Now().Add(a.clockOffset)}})
			if err != nil {
				iin |= IINParameterError
				continue
			}
			statics = append(statics, chunk{data: obj})
		case h.Group == 80 && h.Var == 1:
			// The internal indications as a packed bit string, index n
			// being bit n of the IIN field (IIN1.0 to IIN2.7).
			lo, hi := uint32(0), uint32(15)
			switch h.Qual {
			case Q8StartStop, Q16StartStop:
				lo, hi = h.Start, h.Stop
			case QAll:
			default:
				iin |= IINParameterError
				continue
			}
			if lo > hi || hi > 15 {
				iin |= IINParameterError
				continue
			}
			cur := a.iin(nil)
			var pts []Point
			for i := lo; i <= hi; i++ {
				pts = append(pts, Point{Index: i, Value: cur&(IIN(1)<<i) != 0})
			}
			q := uint8(Q8StartStop)
			if h.Qual == Q16StartStop {
				q = Q16StartStop
			}
			obj, err := EncodeBlock(80, 1, q, pts)
			if err != nil {
				iin |= IINParameterError
				continue
			}
			statics = append(statics, chunk{data: obj})
		case h.Group >= 85 && h.Group <= 87:
			var ids []uint32
			if h.Qual&0x0F <= 2 && h.Qual != QAll {
				for i := h.Start; i <= h.Stop; i++ {
					ids = append(ids, i)
				}
			}
			ch := a.dataSetChunks(h.Group, ids, false)
			if h.Group == 86 && h.Var >= 2 {
				ch = a.descriptorVariant(h.Var, ids)
			}
			if len(ch) == 0 {
				iin |= IINParameterError
			}
			statics = append(statics, ch...)
		case h.Group == 70 && h.Var >= 4 && h.Var <= 7 && a.cfg.Files != nil:
			// A poll for file event objects (5.3.3).
			var evs []Event
			for _, e := range a.cfg.Events.Pending(map[int]bool{1: true, 2: true, 3: true}, 0) {
				if e.Group == 70 && (h.Var == e.Var || h.Var == 0) {
					evs = append(evs, e)
				}
			}
			if limit > 0 && len(evs) > limit {
				evs = evs[:limit]
			}
			takeEvents(evs)
		case h.Group == 88:
			var evs []Event
			for _, e := range a.cfg.Events.Pending(map[int]bool{1: true, 2: true, 3: true}, 0) {
				if e.Group == 88 {
					evs = append(evs, e)
				}
			}
			if limit > 0 && len(evs) > limit {
				evs = evs[:limit]
			}
			takeEvents(evs)
		default:
			typ := PointTypeOf(h.Group)
			if typ == "" || (typ == "security-statistic" && a.cfg.Auth == nil) {
				iin |= IINObjectUnknown
				continue
			}
			g := pointGroups[typ]
			if h.Group == g[1] {
				// Events of a type, whatever their class (EX 4-12).
				var evs []Event
				for _, e := range a.cfg.Events.Pending(map[int]bool{1: true, 2: true, 3: true}, 0) {
					if e.Group == g[1] && (h.Var == 0 || h.Var == e.Var) {
						evs = append(evs, e)
					}
				}
				if limit > 0 && len(evs) > limit {
					evs = evs[:limit]
				}
				takeEvents(evs)
				continue
			}
			if (h.Var != 0 && !Known(h.Group, h.Var) && typ != "octet-string") || (typ == "time-and-interval" && h.Var != 0 && h.Var != 4) ||
				typ == "virtual-terminal" {
				iin |= IINObjectUnknown
				continue
			}
			filter, missing := a.indexFilter(h, b, typ)
			if missing {
				iin |= IINParameterError
			}
			statics = append(statics, a.staticChunks(typ, h.Var, filter, false)...)
		}
	}
	// Events go before static data (4.4.2.1 rule 5).
	return append(events, statics...), iin
}

// attributes answers a read of group 0.
func (a *Association) attributes(h Header) ([]chunk, IIN) {
	all := h.Qual == QAll && (h.Var == AttrAll || h.Var == 255) // "all" for the whole set or the list
	if !all && (h.Qual&0x0F > 2 || h.Start != 0 || h.Stop != 0) {
		return nil, IINParameterError
	}
	vars := make([]int, 0, len(a.cfg.Attributes))
	for v := range a.cfg.Attributes {
		vars = append(vars, int(v))
	}
	sort.Sort(sort.Reverse(sort.IntSlice(vars)))
	switch h.Var {
	case AttrAll:
		var out []chunk
		for _, v := range vars {
			out = append(out, chunk{data: AppendAttribute(nil, uint8(v), 0, a.cfg.Attributes[uint8(v)])})
		}
		return out, 0
	case 255:
		list := []byte{}
		for _, v := range vars {
			prop := byte(0)
			if a.cfg.Writable[uint8(v)] {
				prop = 1
			}
			list = append(list, byte(v), prop)
		}
		obj := AppendHeader(nil, 0, 255, Q8Index8, 1, 0)
		obj = append(obj, 0, AttrList, byte(len(list)))
		return []chunk{{data: append(obj, list...)}}, 0
	}
	v, ok := a.cfg.Attributes[h.Var]
	if !ok {
		return nil, IINObjectUnknown
	}
	return []chunk{{data: AppendAttribute(nil, h.Var, 0, v)}}, 0
}

func (a *Association) dataSetChunks(group uint8, ids []uint32, class0 bool) []chunk {
	var out []chunk
	if group == 85 {
		if ids == nil {
			ids = a.cfg.DB.PrototypeIDs()
		}
		for _, id := range ids {
			if p, ok := a.cfg.DB.Prototype(id); ok {
				b, _ := EncodeBlock(85, 1, QFreeFormat, []Point{{Raw: p.EncodePrototype()}})
				out = append(out, chunk{data: b})
			}
		}
		return out
	}
	if ids == nil {
		ids = a.cfg.DB.DataSetIDs()
	}
	for _, id := range ids {
		d, ok := a.cfg.DB.DataSet(id)
		if !ok {
			continue
		}
		var raw []byte
		switch group {
		case 86:
			raw = d.Desc.EncodeDescriptor()
		case 87:
			if (class0 && !d.Class0) || d.Chars&DSReadable == 0 || d.Values == nil {
				continue
			}
			raw = DataSet{ID: id, Time: d.Time, Values: d.Values}.Encode()
		}
		b, _ := EncodeBlock(group, 1, QFreeFormat, []Point{{Raw: raw}})
		out = append(out, chunk{data: b})
	}
	return out
}

// descriptorVariant answers g86v2 (characteristics) and g86v3 (point
// index attributes).
func (a *Association) descriptorVariant(v uint8, ids []uint32) []chunk {
	if ids == nil {
		ids = a.cfg.DB.DataSetIDs()
	}
	var out []chunk
	for _, id := range ids {
		d, ok := a.cfg.DB.DataSet(id)
		if !ok {
			continue
		}
		if v == 2 {
			obj := AppendHeader(nil, 86, 2, Q16StartStop, id, id)
			out = append(out, chunk{data: append(obj, d.Chars)})
			continue
		}
		b, _ := EncodeBlock(86, 3, QFreeFormat, []Point{{Raw: EncodePointRefs(id, d.Refs)}})
		out = append(out, chunk{data: b})
	}
	return out
}

// ---- WRITE ------------------------------------------------------------------

func (a *Association) write(ctx context.Context, objs []byte, in inbound) IIN {
	blocks, err := ParseObjects(objs, true)
	if err != nil {
		return IINParameterError
	}
	var iin IIN
	for _, b := range blocks {
		h := b.Header
		switch {
		case h.Group == 80 && h.Var == 1:
			for _, p := range b.Points {
				switch {
				case p.Index == 7 && p.Value == false:
					a.restart = false
				case p.Index == 4 && p.Value == false:
					a.needTime, a.timeAt = false, time.Now()
				default:
					iin |= IINParameterError
				}
			}
		case h.Group == 50 && (h.Var == 1 || h.Var == 3) && len(b.Points) == 1:
			t, _ := b.Points[0].Value.(time.Time)
			now := t
			if h.Var == 3 {
				if a.recordedAt.IsZero() {
					iin |= IINParameterError
					continue
				}
				now = t.Add(time.Since(a.recordedAt))
			}
			a.needTime, a.timeAt = false, time.Now()
			a.clockOffset = time.Until(now)
			a.cfg.Handler.TimeSet(now)
		case h.Group == 50 && h.Var == 4:
			iin |= a.writeTimeAndInterval(ctx, b)
		case h.Group == 112:
			iin |= a.writeVirtualTerminal(ctx, b)
		case h.Group == 34:
			for _, p := range b.Points {
				v, _ := p.Value.(float64)
				if !a.cfg.DB.SetDeadband(p.Index, v) {
					iin |= IINParameterError
				}
			}
		case h.Group == 0:
			for _, p := range b.Points {
				if p.Index != 0 || !a.cfg.Writable[h.Var] {
					iin |= IINParameterError
					continue
				}
				a.cfg.Attributes[h.Var] = p.Value
			}
		case h.Group == 86 && h.Var == 1, h.Group == 85 && h.Var == 1:
			for _, p := range b.Points {
				d, err := ParseDescriptor(p.Raw, h.Group == 85)
				if err != nil {
					iin |= IINParameterError
					continue
				}
				if h.Group == 85 {
					err = a.cfg.DB.WritePrototype(d)
				} else {
					err = a.cfg.DB.WriteDescriptor(d)
				}
				if err != nil {
					iin |= IINParameterError
				}
			}
		case h.Group == 87 && h.Var == 1:
			for _, p := range b.Points {
				ds, err := ParseDataSet(p.Raw)
				if err == nil {
					err = a.cfg.DB.WriteDataSet(ds)
				}
				if err != nil {
					a.cfg.Log.Warn("DNP3 data set write refused", "error", err)
					iin |= IINParameterError
					continue
				}
				a.cfg.Handler.DataSetWritten(ctx, ds)
			}
		default:
			iin |= IINObjectUnknown
		}
	}
	return iin
}

// ---- controls -----------------------------------------------------------------

func (a *Association) control(ctx context.Context, req Fragment, user uint16) ([]byte, IIN) {
	blocks, err := ParseObjects(req.Objects, true)
	if err != nil || len(blocks) == 0 {
		return nil, IINParameterError
	}
	n := 0
	for i, b := range blocks {
		switch {
		case b.Header.Group == 12 && b.Header.Var == 1, b.Header.Group == 41 && b.Header.Var >= 1 && b.Header.Var <= 4, b.Header.Group == 87 && b.Header.Var == 1:
			n += len(b.Points)
		case b.Header.Group == 12 && b.Header.Var == 2:
			// A pattern control block: one object, then one or more
			// pattern masks (4.4.4.2.2, A.8.2).
			if len(b.Points) != 1 || i+1 >= len(blocks) || !isMask(blocks[i+1]) {
				return nil, IINParameterError
			}
		case isMask(b):
			if i == 0 || !(blocks[i-1].Header.Group == 12 && (blocks[i-1].Header.Var == 2 || blocks[i-1].Header.Var == 3)) {
				return nil, IINParameterError
			}
			for _, p := range b.Points {
				if on, _ := p.Value.(bool); on {
					n++
				}
			}
		case b.Header.Group == 12 && b.Header.Var == 3:
			return nil, IINParameterError // masks are ranges (A.8.3)
		default:
			return nil, IINObjectUnknown
		}
	}
	var status uint8
	now := time.Now()
	switch req.Func {
	case FCSelect:
		a.sel = nil
	case FCOperate:
		sel := a.sel
		a.sel = nil
		switch {
		case sel == nil || !bytes.Equal(sel.objs, req.Objects) || req.Seq() != (sel.seq+1)&0x0F:
			status = 2 // NO_SELECT (4.4.4.3 rule 4)
		case now.Sub(sel.at) > a.cfg.SelectTimeout:
			status = 1 // TIMEOUT (rule 1)
		}
	}
	if status == 0 && n > a.cfg.MaxControls {
		status = 8 // TOO_MANY_OBJS
	}
	var echo []byte
	var iin IIN
	allOK := true
	for i, b := range blocks {
		if b.Header.Group == 12 && b.Header.Var == 2 {
			p := b.Points[0]
			var masks []Block
			for _, m := range blocks[i+1:] {
				if !isMask(m) {
					break
				}
				masks = append(masks, m)
			}
			p.Status = a.pattern(ctx, req.Func, p.CROB, masks, user, status)
			if p.Status == 4 {
				iin |= IINParameterError // an index beyond those configured (EX 4-18)
			}
			if p.Status != 0 {
				allOK = false
			}
			e, err := EncodeBlock(12, 2, b.Header.Qual, []Point{p})
			if err != nil {
				return nil, IINParameterError
			}
			echo = append(echo, e...)
			continue
		}
		if isMask(b) {
			e, err := EncodeBlock(12, 3, b.Header.Qual, b.Points)
			if err != nil {
				return nil, IINParameterError
			}
			echo = append(echo, e...)
			continue
		}
		pts := make([]Point, len(b.Points))
		for i, p := range b.Points {
			st := status
			if b.Header.Group == 87 {
				raw, s := a.dataSetControl(ctx, req.Func, p.Raw, user, st)
				p.Raw = raw
				if s != 0 {
					allOK = false
				}
				pts[i] = p
				continue
			}
			if st == 0 {
				v, _ := p.Value.(float64)
				st = a.cfg.Handler.Control(ctx, ControlRequest{Func: req.Func, Group: b.Header.Group, Var: b.Header.Var, Index: p.Index,
					CROB: p.CROB, Value: v, Select: req.Func == FCSelect, User: user})
			}
			if st != 0 {
				allOK = false
			}
			p.Status = st
			pts[i] = p
		}
		e, err := EncodeBlock(b.Header.Group, b.Header.Var, b.Header.Qual, pts)
		if err != nil {
			return nil, IINParameterError
		}
		echo = append(echo, e...)
	}
	if req.Func == FCSelect && allOK {
		a.sel = &selection{objs: append([]byte(nil), req.Objects...), seq: req.Seq(), at: now}
	}
	return echo, iin
}

// isMask reports whether b is a pattern mask (g12v3 with a start-stop
// range).
func isMask(b Block) bool {
	q := b.Header.Qual
	return b.Header.Group == 12 && b.Header.Var == 3 && (q == Q8StartStop || q == Q16StartStop || q == Q32StartStop)
}

// pattern runs a pattern control block on the points its masks select:
// every point is checked first (as a select) so that none operates when
// one is refused; then, unless the request is a SELECT, each operates
// with the block's code. It returns the block's status.
func (a *Association) pattern(ctx context.Context, fc byte, crob CROB, masks []Block, user uint16, status uint8) uint8 {
	if status != 0 {
		return status
	}
	var idx []uint32
	for _, m := range masks {
		for _, p := range m.Points {
			if on, _ := p.Value.(bool); on {
				idx = append(idx, p.Index)
			}
		}
	}
	if len(idx) == 0 {
		return 3 // FORMAT_ERROR: nothing selected
	}
	for _, i := range idx {
		if st := a.cfg.Handler.Control(ctx, ControlRequest{Func: fc, Group: 12, Var: 2, Index: i, CROB: crob, Select: true, User: user}); st != 0 {
			return st
		}
	}
	if fc == FCSelect {
		return 0
	}
	var first uint8
	for _, i := range idx {
		if st := a.cfg.Handler.Control(ctx, ControlRequest{Func: fc, Group: 12, Var: 2, Index: i, CROB: crob, User: user}); st != 0 && first == 0 {
			first = st
		}
	}
	return first
}

// dataSetControl runs the control groups of a g87 in a control request
// (5.4.11) and returns the echo with each CTLS set to its status.
func (a *Association) dataSetControl(ctx context.Context, fc byte, raw []byte, user uint16, status uint8) ([]byte, uint8) {
	ds, err := ParseDataSet(raw)
	if err != nil {
		return raw, 3
	}
	flat, err := a.cfg.DB.Flat(ds.ID)
	if err != nil || len(flat) != len(ds.Values) {
		return raw, 4 // NOT_SUPPORTED
	}
	vals := make([][]byte, len(ds.Values))
	copy(vals, ds.Values)
	var worst uint8
	for i := 0; i < len(flat); i++ {
		if flat[i].Code != DescCTLS {
			continue
		}
		st := CTLSStatus(vals[i])
		j := i + 1
		var c DataSetControl
		c.Func, c.Select, c.ID, c.User = fc, fc == FCSelect, ds.ID, user
		for ; j < len(flat) && flat[j].Code != DescCTLS; j++ {
			if flat[j].Code == DescCTLV {
				v, _ := DataSetValue(flat[j].Type, vals[j])
				c.Names = append(c.Names, flat[j].Name())
				c.Values = append(c.Values, v)
			}
		}
		if st == 126 { // NON_PARTICIPATING
			i = j - 1
			continue
		}
		if status != 0 {
			st = status
		} else {
			st = a.cfg.Handler.DataSetControl(ctx, c)
		}
		vals[i] = []byte{st}
		if st != 0 {
			worst = st
		}
		i = j - 1
	}
	ds.Values = vals
	return ds.Encode(), worst
}

// ---- freezes, assign class ----------------------------------------------------

func (a *Association) freeze(ctx context.Context, req Fragment) IIN {
	clear := req.Func == FCFreezeClear || req.Func == FCFreezeClearNR
	atTime := req.Func == FCFreezeAtTime || req.Func == FCFreezeAtTimeNR
	var blocks []Block
	var err error
	if !atTime {
		blocks, err = ParseObjects(req.Objects, false)
		if err != nil || len(blocks) == 0 {
			return IINParameterError
		}
	}
	var sched *Point
	if atTime {
		full, err := ParseObjects(req.Objects, true)
		if err != nil || len(full) < 2 || full[0].Header.Group != 50 || full[0].Header.Var != 2 || len(full[0].Points) != 1 {
			return IINParameterError
		}
		sched = &full[0].Points[0]
		blocks = full[1:]
	}
	for _, b := range blocks {
		if b.Header.Group != 20 && b.Header.Group != 30 {
			return IINObjectUnknown
		}
	}
	run := func() {
		for _, b := range blocks {
			var idx []uint32
			if b.Header.Qual != QAll {
				for i := b.Header.Start; i <= b.Header.Stop; i++ {
					idx = append(idx, i)
				}
			}
			if b.Header.Group == 20 {
				a.cfg.DB.Freeze(ctx, idx, clear, time.Now())
			} else {
				for _, p := range a.cfg.DB.Points("analog") {
					if idx == nil || containsIdx(idx, p.Index) {
						if _, ok := a.cfg.DB.Point("frozen-analog", p.Index); ok {
							_, _ = a.cfg.DB.Update(ctx, "frozen-analog", p.Index, p.Value, nil, p.Flags, time.Now())
						}
					}
				}
			}
		}
	}
	if !atTime {
		run()
		return 0
	}
	// Table 4-11: time and interval decide once, at a time, or periodic.
	t, _ := sched.Value.(time.Time)
	iv := time.Duration(sched.Interval) * time.Millisecond
	for _, s := range a.schedules {
		close(s.stop)
	}
	a.schedules = nil
	if t.UnixMilli() == 0xFFFFFFFFFFFF {
		return 0 // all ones cancels
	}
	fs := &freezeSchedule{stop: make(chan struct{}), headers: blocks, clear: clear}
	a.schedules = append(a.schedules, fs)
	go func() {
		first := t
		switch {
		case t.UnixMilli() == 0 && iv == 0:
			run()
			return
		case t.UnixMilli() == 0:
			h := time.Now().Truncate(time.Hour)
			first = h
			for !first.After(time.Now()) {
				first = first.Add(iv)
			}
		case iv > 0:
			for !first.After(time.Now()) {
				first = first.Add(iv)
			}
		}
		timer := time.NewTimer(time.Until(first))
		defer timer.Stop()
		for {
			select {
			case <-fs.stop:
				return
			case <-ctx.Done():
				return
			case <-timer.C:
				run()
				if iv == 0 {
					return
				}
				timer.Reset(iv)
			}
		}
	}()
	return 0
}

// assign handles ASSIGN_CLASS (4.4.14): sets of a group 60 header and the
// headers of the points whose events go to that class.
func (a *Association) assign(objs []byte) IIN {
	blocks, err := parseRequestHeaders(objs)
	if err != nil || len(blocks) == 0 || blocks[0].Header.Group != 60 {
		return IINParameterError
	}
	class := 0
	var iin IIN
	for _, b := range blocks {
		h := b.Header
		if h.Group == 60 {
			if h.Var < 1 || h.Var > 4 || h.Qual != QAll {
				return IINParameterError
			}
			class = int(h.Var) - 1
			continue
		}
		if (h.Group == 120 || h.Group == 121 || h.Group == 122) && class == 0 {
			return IINNoFuncCodeSupport // Table 4-12 note a
		}
		if h.Group == 86 {
			for _, id := range a.cfg.DB.DataSetIDs() {
				if h.Qual == QAll || (id >= h.Start && id <= h.Stop) {
					a.cfg.DB.mu.Lock()
					a.cfg.DB.sets[id].Class = class
					a.cfg.DB.mu.Unlock()
				}
			}
			continue
		}
		typ := PointTypeOf(h.Group)
		if typ == "" || h.Group != pointGroups[typ][0] {
			if h.Group == 12 || h.Group == 41 {
				continue // command events are not generated
			}
			iin |= IINObjectUnknown
			continue
		}
		var idx []uint32
		switch {
		case h.Qual == QAll:
		case h.Qual&0x0F <= 2:
			for i := h.Start; i <= h.Stop; i++ {
				idx = append(idx, i)
			}
		default:
			for _, p := range b.Points {
				idx = append(idx, p.Index)
			}
		}
		if a.cfg.DB.Assign(typ, idx, class) {
			iin |= IINParameterError
		}
	}
	return iin
}

// String names the association for logs.
func (a *Association) String() string {
	return fmt.Sprintf("outstation %d / master %d", a.cfg.Address, a.cfg.Master)
}
