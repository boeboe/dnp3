package dnp3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// The outstation's point database and event buffers (IEEE 1815-2012
// 4.1.5, 4.1.6, 5.1.3, 5.1.4): static values per point type and index,
// each point assigned to class 0 (static data reported in integrity
// polls) and to an event class 1 to 3 (or none); a value change beyond
// the point's deadband creates an event for every association. Events
// stay buffered until a confirmation shows the master received them.

// Point types an outstation serves: the static group and the event
// group.
// PointGroup is the static and event group of a point type ("binary",
// "analog", ...; the keys of the outstation database's point types).
func PointGroup(typ string) ([2]uint8, bool) {
	g, ok := pointGroups[typ]
	return g, ok
}

var pointGroups = map[string][2]uint8{
	"binary": {1, 2}, "double": {3, 4}, "binary-output": {10, 11}, "counter": {20, 22}, "frozen-counter": {21, 23},
	"analog": {30, 32}, "frozen-analog": {31, 33}, "analog-output": {40, 42}, "octet-string": {110, 111},
	"security-statistic": {121, 122},
	"time-and-interval":  {50, 0},    // g50v4, no events (timeinterval.go)
	"virtual-terminal":   {112, 113}, // ports (vterm.go): g112 written, g113 events

}

// PointTypeOf is the point type of a static or event group.
func PointTypeOf(group uint8) string {
	for t, g := range pointGroups {
		if g[0] == group || (g[1] != 0 && g[1] == group) {
			return t
		}
	}
	return ""
}

// Default variations for static and event objects per point type.
var defaultVars = map[string][2]uint8{
	"binary": {2, 2}, "double": {2, 2}, "binary-output": {2, 2}, "counter": {1, 5}, "frozen-counter": {1, 5},
	"analog": {5, 7}, "frozen-analog": {7, 7}, "analog-output": {3, 7}, "security-statistic": {1, 2},
	"time-and-interval": {4, 0},
}

// DBPoint is one point of the outstation database.
type DBPoint struct {
	Type      string
	Index     uint32
	Value     float64
	Raw       []byte // octet strings
	Flags     uint8
	Time      time.Time
	Class0    bool    // reported in class 0 polls
	Class     int     // event class 1 to 3, 0: no events
	StaticVar uint8   // 0: the type's default
	EventVar  uint8   // 0: the type's default
	Deadband  float64 // analogs, counters: an event needs a change larger than this
	Frozen    float64 // counters: the value at the last freeze
	// Units is the interval's units code of a time-and-interval point
	// (whose Time is its start and Value its interval count).
	Units    uint8
	known    bool
	reported float64 // value of the last event (for deadbands)
}

// Event is one buffered event.
type Event struct {
	ID    int64     `json:"id"`
	Class int       `json:"class"`
	Group uint8     `json:"g"`
	Var   uint8     `json:"v"`
	Index uint32    `json:"i"`
	Value float64   `json:"value"`
	Raw   []byte    `json:"raw,omitempty"`
	Flags uint8     `json:"flags"`
	Time  time.Time `json:"t"`
	Assoc uint16    `json:"assoc,omitempty"`
}

// EventStore keeps an association's events durably (an application backs
// it with its own queue or database); nil keeps them in memory only.
type EventStore interface {
	Add(ctx context.Context, payload []byte) (int64, error)
	Delete(ctx context.Context, ids ...int64) error
	ListPayloads(ctx context.Context) ([]int64, [][]byte, error)
}

// EventBuffer is an association's events per class, bounded (4.5.12).
type EventBuffer struct {
	mu       sync.Mutex
	events   []Event
	capacity map[int]int // per class; 0: 100
	overflow bool
	store    EventStore
	next     int64
	notify   func()
	// typeCap bounds the events of one point type (SetTypeCapacity);
	// dropOldest makes a full buffer lose its oldest event of the class
	// (or type) rather than the new one (SetDropOldest).
	typeCap    map[string]int
	dropOldest bool
}

// SetTypeCapacity bounds the buffered events of one point type ("binary",
// "analog", ...) besides the per-class capacity, as outstations that size
// their buffers per object type do; n <= 0 removes the bound.
func (b *EventBuffer) SetTypeCapacity(typ string, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.typeCap == nil {
		b.typeCap = map[string]int{}
	}
	if n <= 0 {
		delete(b.typeCap, typ)
		return
	}
	b.typeCap[typ] = n
}

// SetDropOldest chooses what a full buffer loses: with on, its oldest
// event of the same class (or point type) makes room for the new one; by
// default the new event is lost. Either way the overflow is reported
// (IIN2.3).
func (b *EventBuffer) SetDropOldest(on bool) {
	b.mu.Lock()
	b.dropOldest = on
	b.mu.Unlock()
}

// NewEventBuffer makes a buffer with per-class capacities (0: 100 each).
func NewEventBuffer(capacity map[int]int, store EventStore) *EventBuffer {
	return &EventBuffer{capacity: capacity, store: store}
}

func (b *EventBuffer) capOf(class int) int {
	if n := b.capacity[class]; n > 0 {
		return n
	}
	return 100
}

// Load restores the durable events.
func (b *EventBuffer) Load(ctx context.Context) error {
	if b.store == nil {
		return nil
	}
	ids, payloads, err := b.store.ListPayloads(ctx)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, p := range payloads {
		var e Event
		if json.Unmarshal(p, &e) != nil {
			continue
		}
		e.ID = ids[i]
		b.events = append(b.events, e)
	}
	return nil
}

// Add buffers an event; a full class loses the event and sets overflow.
func (b *EventBuffer) Add(ctx context.Context, e Event) {
	b.mu.Lock()
	typ := PointTypeOf(e.Group)
	n, nt, oldestClass, oldestType := 0, 0, -1, -1
	for i, x := range b.events {
		if x.Class == e.Class {
			n++
			if oldestClass < 0 {
				oldestClass = i
			}
		}
		if typ != "" && PointTypeOf(x.Group) == typ {
			nt++
			if oldestType < 0 {
				oldestType = i
			}
		}
	}
	tcap, typed := b.typeCap[typ]
	var dropped []int64
	switch {
	case n >= b.capOf(e.Class), typed && nt >= tcap:
		b.overflow = true
		if !b.dropOldest {
			b.mu.Unlock()
			return
		}
		i := oldestClass
		if typed && nt >= tcap {
			i = oldestType
		}
		if i >= 0 {
			if id := b.events[i].ID; id > 0 {
				dropped = append(dropped, id)
			}
			b.events = append(b.events[:i], b.events[i+1:]...)
		}
	}
	b.mu.Unlock()
	if len(dropped) > 0 && b.store != nil {
		_ = b.store.Delete(ctx, dropped...)
	}
	if b.store != nil {
		p, _ := json.Marshal(e)
		if id, err := b.store.Add(ctx, p); err == nil {
			e.ID = id
		}
	}
	b.mu.Lock()
	if e.ID == 0 {
		b.next--
		e.ID = b.next
	}
	b.events = append(b.events, e)
	n2 := b.notify
	b.mu.Unlock()
	if n2 != nil {
		n2()
	}
}

// Pending returns the buffered events of the classes, oldest first (at
// most limit per class when limit > 0).
func (b *EventBuffer) Pending(classes map[int]bool, limit int) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Event
	count := map[int]int{}
	for _, e := range b.events {
		if classes[e.Class] && (limit <= 0 || count[e.Class] < limit) {
			out = append(out, e)
			count[e.Class]++
		}
	}
	return out
}

// Classes reports which classes have events not in except.
func (b *EventBuffer) Classes(except map[int64]bool) map[int]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[int]bool{}
	for _, e := range b.events {
		if !except[e.ID] {
			out[e.Class] = true
		}
	}
	return out
}

// Overflow reports the overflow condition: set by a lost event, cleared
// once every class has room again.
func (b *EventBuffer) Overflow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.overflow {
		return false
	}
	count := map[int]int{}
	types := map[string]int{}
	for _, e := range b.events {
		count[e.Class]++
		types[PointTypeOf(e.Group)]++
	}
	for c := 1; c <= 3; c++ {
		if count[c] >= b.capOf(c) {
			return true
		}
	}
	for t, n := range b.typeCap {
		if types[t] >= n {
			return true
		}
	}
	b.overflow = false
	return false
}

// Remove drops confirmed events.
func (b *EventBuffer) Remove(ctx context.Context, ids []int64) {
	if len(ids) == 0 {
		return
	}
	drop := map[int64]bool{}
	var durable []int64
	for _, id := range ids {
		drop[id] = true
		if id > 0 {
			durable = append(durable, id)
		}
	}
	b.mu.Lock()
	keep := b.events[:0]
	for _, e := range b.events {
		if !drop[e.ID] {
			keep = append(keep, e)
		}
	}
	b.events = keep
	b.mu.Unlock()
	if b.store != nil {
		_ = b.store.Delete(ctx, durable...)
	}
}

// Len is the number of buffered events.
// Counts are the buffered events per class.
func (b *EventBuffer) Counts() map[int]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[int]int{}
	for _, e := range b.events {
		out[e.Class]++
	}
	return out
}

// Capacity is a class's buffer size.
func (b *EventBuffer) Capacity(class int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capOf(class)
}

// Len counts the buffered events of every class.
func (b *EventBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// PointDB is the outstation's database, shared by its associations.
type PointDB struct {
	mu      sync.Mutex
	points  map[string]map[uint32]*DBPoint
	buffers map[*EventBuffer]bool
	// Data sets (5.4): descriptors and prototypes by identifier, the
	// present values, and which were defined by the master.
	sets   map[uint32]*DataSetDef
	protos map[uint32]*Descriptor
}

// DataSetDef is one data set of the outstation.
type DataSetDef struct {
	Desc     Descriptor
	Chars    uint8 // DSReadable, DSWritable, DSStatic, DSEvent, DSByMaster
	Refs     []PointRef
	Class    int  // event class of its events (0: none)
	Class0   bool // present value included in class 0
	Values   [][]byte
	Time     time.Time
	Received bool // a value was written by the master
}

// NewPointDB makes an empty database.
func NewPointDB() *PointDB {
	return &PointDB{points: map[string]map[uint32]*DBPoint{}, buffers: map[*EventBuffer]bool{},
		sets: map[uint32]*DataSetDef{}, protos: map[uint32]*Descriptor{}}
}

// Define adds a point (its value unknown until the first Update).
func (db *PointDB) Define(p DBPoint) error {
	if _, ok := pointGroups[p.Type]; !ok {
		return fmt.Errorf("point type %q is not served", p.Type)
	}
	if p.Class < 0 || p.Class > 3 {
		return errors.New("an event class is 0 to 3")
	}
	if p.Type == "time-and-interval" && p.Class != 0 {
		return errors.New("time-and-interval points have no events (class 0)")
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.points[p.Type] == nil {
		db.points[p.Type] = map[uint32]*DBPoint{}
	}
	if db.points[p.Type][p.Index] != nil {
		return fmt.Errorf("%s %d is defined twice", p.Type, p.Index)
	}
	c := p
	c.Flags = 0x02 // RESTART until the first value (11.6)
	db.points[p.Type][p.Index] = &c
	return nil
}

// Attach registers an association's event buffer.
func (db *PointDB) Attach(b *EventBuffer) {
	db.mu.Lock()
	db.buffers[b] = true
	db.mu.Unlock()
}

// Detach removes an association's event buffer.
func (db *PointDB) Detach(b *EventBuffer) {
	db.mu.Lock()
	delete(db.buffers, b)
	db.mu.Unlock()
}

// Point returns a copy of a point.
func (db *PointDB) Point(typ string, index uint32) (DBPoint, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	p := db.points[typ][index]
	if p == nil {
		return DBPoint{}, false
	}
	return *p, true
}

// Points returns copies of the points of a type in index order.
func (db *PointDB) Points(typ string) []DBPoint {
	db.mu.Lock()
	defer db.mu.Unlock()
	var out []DBPoint
	for _, p := range db.points[typ] {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// Types lists the point types defined.
func (db *PointDB) Types() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	var out []string
	for t := range db.points {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Update sets a point's value, flags and time and creates an event when
// the point has an event class and the value (or flags) changed beyond
// its deadband. It reports whether an event was created.
func (db *PointDB) Update(ctx context.Context, typ string, index uint32, v float64, raw []byte, flags uint8, t time.Time) (bool, error) {
	return db.UpdateWith(ctx, typ, index, v, raw, flags, t, EventDetect)
}

// EventMode decides whether an update creates an event.
type EventMode int

// Event modes of UpdateWith.
const (
	// EventDetect creates an event when the value or flags changed beyond
	// the point's deadband (Update's behaviour).
	EventDetect EventMode = iota
	// EventForce creates an event whether or not anything changed (an
	// event passed on from another device, a momentary change already
	// over).
	EventForce
	// EventSuppress updates the static value without an event.
	EventSuppress
	// EventOnly creates an event and leaves the static value as it was
	// (a historical event reported late).
	EventOnly
)

// UpdateFlags changes only a point's flags (and time), keeping its value;
// an event follows when the flags changed (communication lost, say).
func (db *PointDB) UpdateFlags(ctx context.Context, typ string, index uint32, flags uint8, t time.Time) (bool, error) {
	p, ok := db.Point(typ, index)
	if !ok {
		return false, fmt.Errorf("%s %d is not defined", typ, index)
	}
	return db.UpdateWith(ctx, typ, index, p.Value, p.Raw, flags, t, EventDetect)
}

// UpdateWith is Update with an event mode.
func (db *PointDB) UpdateWith(ctx context.Context, typ string, index uint32, v float64, raw []byte, flags uint8, t time.Time, mode EventMode) (bool, error) {
	db.mu.Lock()
	p := db.points[typ][index]
	if p == nil {
		db.mu.Unlock()
		return false, fmt.Errorf("%s %d is not defined", typ, index)
	}
	if mode == EventOnly {
		ok := p.Class != 0
		db.mu.Unlock()
		if ok {
			db.emit(ctx, p, typ, index, v, raw, flags, t)
		}
		return ok, nil
	}
	changed := !p.known || p.Flags != flags
	switch {
	case typ == "virtual-terminal":
		changed = true // every output is an event, repeated or not
	case raw != nil:
		changed = changed || string(raw) != string(p.Raw)
	case typ == "analog" || typ == "analog-output" || typ == "frozen-analog",
		(typ == "counter" || typ == "frozen-counter") && p.Deadband > 0:
		changed = changed || math.Abs(v-p.reported) > p.Deadband || (p.Deadband == 0 && v != p.reported)
	default:
		changed = changed || v != p.Value
	}
	switch mode {
	case EventForce:
		changed = true
	case EventSuppress:
		if changed {
			p.reported = v
		}
		changed = false
	}
	p.Value, p.Raw, p.Flags, p.Time, p.known = v, raw, flags, t, true
	if !changed || p.Class == 0 {
		if changed {
			p.reported = v
		}
		db.mu.Unlock()
		return false, nil
	}
	p.reported = v
	db.mu.Unlock()
	db.emit(ctx, p, typ, index, v, raw, flags, t)
	return true, nil
}

// emit buffers the event of point p in every association.
func (db *PointDB) emit(ctx context.Context, p *DBPoint, typ string, index uint32, v float64, raw []byte, flags uint8, t time.Time) {
	db.mu.Lock()
	g := pointGroups[typ]
	ev := p.EventVar
	if ev == 0 {
		ev = defaultVars[typ][1]
	}
	if typ == "octet-string" || typ == "virtual-terminal" {
		ev = uint8(len(raw))
	}
	e := Event{Class: p.Class, Group: g[1], Var: ev, Index: index, Value: v, Raw: raw, Flags: flags, Time: t}
	var bufs []*EventBuffer
	for b := range db.buffers {
		bufs = append(bufs, b)
	}
	db.mu.Unlock()
	for _, b := range bufs {
		b.Add(ctx, e)
	}
}

// AddEvent buffers an event that is not a point change (a data set event,
// an authentication error) in every association.
func (db *PointDB) AddEvent(ctx context.Context, e Event) {
	db.mu.Lock()
	var bufs []*EventBuffer
	for b := range db.buffers {
		bufs = append(bufs, b)
	}
	db.mu.Unlock()
	for _, b := range bufs {
		b.Add(ctx, e)
	}
}

// Assign changes the event class of the points of a type (all when
// indexes is nil); class 0 stops their events (4.4.14).
func (db *PointDB) Assign(typ string, indexes []uint32, class int) (missing bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	pts := db.points[typ]
	if indexes == nil {
		for _, p := range pts {
			p.Class = class
		}
		return false
	}
	for _, i := range indexes {
		if p := pts[i]; p != nil {
			p.Class = class
		} else {
			missing = true
		}
	}
	return missing
}

// SetDeadband sets an analog point's deadband (g34 writes).
func (db *PointDB) SetDeadband(index uint32, v float64) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	p := db.points["analog"][index]
	if p == nil {
		return false
	}
	p.Deadband = v
	return true
}

// Freeze copies counters to frozen counters (clearing them with clear)
// and returns the frozen points changed.
func (db *PointDB) Freeze(ctx context.Context, indexes []uint32, clear bool, at time.Time) []uint32 {
	db.mu.Lock()
	var done []uint32
	for i, p := range db.points["counter"] {
		if indexes != nil && !containsIdx(indexes, i) {
			continue
		}
		p.Frozen = p.Value
		if clear {
			p.Value = 0
		}
		done = append(done, i)
	}
	db.mu.Unlock()
	sort.Slice(done, func(a, b int) bool { return done[a] < done[b] })
	for _, i := range done {
		p, _ := db.Point("counter", i)
		if _, ok := db.Point("frozen-counter", i); ok {
			_, _ = db.Update(ctx, "frozen-counter", i, p.Frozen, nil, p.Flags, at)
		}
	}
	return done
}

func containsIdx(list []uint32, i uint32) bool {
	for _, x := range list {
		if x == i {
			return true
		}
	}
	return false
}

// DefineDataSet adds an outstation-defined data set (identifiers are
// contiguous from 0, 5.4.2.8.1).
func (db *PointDB) DefineDataSet(d DataSetDef) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.sets[d.Desc.ID] != nil {
		return fmt.Errorf("data set %d is defined twice", d.Desc.ID)
	}
	if d.Chars&^dsCharsValid != 0 {
		return errors.New("unknown data set characteristics bits")
	}
	c := d
	db.sets[d.Desc.ID] = &c
	return nil
}

// DefinePrototype adds a data set prototype.
func (db *PointDB) DefinePrototype(p Descriptor) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.protos[p.ID] != nil {
		return fmt.Errorf("prototype %d is defined twice", p.ID)
	}
	c := p
	db.protos[p.ID] = &c
	return nil
}

func (db *PointDB) protoMap() map[[16]byte]Descriptor {
	out := map[[16]byte]Descriptor{}
	for _, p := range db.protos {
		out[p.UUID] = *p
	}
	return out
}

// DataSetIDs lists the data set identifiers in order.
func (db *PointDB) DataSetIDs() []uint32 {
	db.mu.Lock()
	defer db.mu.Unlock()
	var out []uint32
	for id := range db.sets {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PrototypeIDs lists the prototype identifiers in order.
func (db *PointDB) PrototypeIDs() []uint32 {
	db.mu.Lock()
	defer db.mu.Unlock()
	var out []uint32
	for id := range db.protos {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DataSet returns a copy of a data set definition.
func (db *PointDB) DataSet(id uint32) (DataSetDef, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	d := db.sets[id]
	if d == nil {
		return DataSetDef{}, false
	}
	return *d, true
}

// Prototype returns a copy of a prototype.
func (db *PointDB) Prototype(id uint32) (Descriptor, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	p := db.protos[id]
	if p == nil {
		return Descriptor{}, false
	}
	return *p, true
}

// Flat is a data set's data elements with prototypes resolved.
func (db *PointDB) Flat(id uint32) ([]DescElement, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	d := db.sets[id]
	if d == nil {
		return nil, fmt.Errorf("data set %d is not defined", id)
	}
	return d.Desc.Flatten(db.protoMap())
}

// WriteDescriptor stores a master-defined data set descriptor (5.4.2.6.2);
// an outstation-defined one cannot be replaced.
func (db *PointDB) WriteDescriptor(d Descriptor) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if old := db.sets[d.ID]; old != nil && old.Chars&DSByMaster == 0 {
		return fmt.Errorf("data set %d is defined by the outstation", d.ID)
	}
	db.sets[d.ID] = &DataSetDef{Desc: d, Chars: DSReadable | DSWritable | DSStatic | DSByMaster}
	return nil
}

// WritePrototype stores a master-defined prototype.
func (db *PointDB) WritePrototype(p Descriptor) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, o := range db.protos {
		if o.UUID == p.UUID && o.ID != p.ID {
			// A duplicate of an existing prototype under another ID is
			// accepted (5.4.2.7).
			break
		}
	}
	c := p
	db.protos[p.ID] = &c
	return nil
}

// checkValues checks values against a data set's flattened elements.
func checkValues(flat []DescElement, vals [][]byte) error {
	if len(vals) != len(flat) {
		return fmt.Errorf("the data set has %d values, its descriptor %d", len(vals), len(flat))
	}
	for i, e := range flat {
		if e.MaxLen != 0 && len(vals[i]) > int(e.MaxLen) {
			return fmt.Errorf("value %d is longer than its maximum %d", i+1, e.MaxLen)
		}
		if _, err := DataSetValue(e.Type, vals[i]); err != nil && e.Type != DSNone {
			return fmt.Errorf("value %d: %w", i+1, err)
		}
	}
	return nil
}

// WriteDataSet stores a data set written by the master: it must be
// writable and match its complete structure (5.4.2.7).
func (db *PointDB) WriteDataSet(ds DataSet) error {
	flat, err := db.Flat(ds.ID)
	if err != nil {
		return err
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	d := db.sets[ds.ID]
	if d.Chars&DSWritable == 0 {
		return fmt.Errorf("data set %d is not writable", ds.ID)
	}
	if err := checkValues(flat, ds.Values); err != nil {
		return err
	}
	d.Values, d.Time, d.Received = ds.Values, ds.Time, true
	return nil
}

// SetDataSet sets a data set's present value (and, with event, buffers a
// g88 event when the data set has an event class).
func (db *PointDB) SetDataSet(ctx context.Context, id uint32, vals [][]byte, t time.Time, event bool) error {
	flat, err := db.Flat(id)
	if err != nil {
		return err
	}
	if err := checkValues(flat, vals); err != nil {
		return err
	}
	db.mu.Lock()
	d := db.sets[id]
	d.Values, d.Time = vals, t
	class := d.Class
	db.mu.Unlock()
	if event && class > 0 {
		db.AddEvent(ctx, Event{Class: class, Group: 88, Var: 1, Index: id, Raw: DataSet{ID: id, Time: t, Values: vals}.Encode(), Time: t})
	}
	return nil
}
