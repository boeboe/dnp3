// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"context"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

func dbWith(t *testing.T, b *dnp3.EventBuffer, pts ...dnp3.DBPoint) *dnp3.PointDB {
	t.Helper()
	db := dnp3.NewPointDB()
	for _, p := range pts {
		if err := db.Define(p); err != nil {
			t.Fatal(err)
		}
	}
	db.Attach(b)
	return db
}

// Event modes: detect (Update), force, suppress and event-only.
// Covers: SIG-IPE-6900
func TestEventModes(t *testing.T) {
	ctx := context.Background()
	b := dnp3.NewEventBuffer(nil, nil)
	db := dbWith(t, b, dnp3.DBPoint{Type: "analog", Index: 0, Class0: true, Class: 2, Deadband: 5})
	now := time.Now()
	if ok, _ := db.Update(ctx, "analog", 0, 10, nil, 0x01, now); !ok {
		t.Fatal("first value made no event")
	}
	if ok, _ := db.Update(ctx, "analog", 0, 12, nil, 0x01, now); ok {
		t.Error("a change within the deadband made an event")
	}
	if ok, _ := db.UpdateWith(ctx, "analog", 0, 12, nil, 0x01, now, dnp3.EventForce); !ok {
		t.Error("a forced update made no event")
	}
	if ok, _ := db.UpdateWith(ctx, "analog", 0, 100, nil, 0x01, now, dnp3.EventSuppress); ok {
		t.Error("a suppressed update made an event")
	}
	if p, _ := db.Point("analog", 0); p.Value != 100 {
		t.Errorf("suppressed update left value %v", p.Value)
	}
	if ok, _ := db.UpdateWith(ctx, "analog", 0, 7, nil, 0x01, now.Add(-time.Hour), dnp3.EventOnly); !ok {
		t.Error("an event-only update made no event")
	}
	if p, _ := db.Point("analog", 0); p.Value != 100 {
		t.Errorf("an event-only update changed the static value to %v", p.Value)
	}
	evs := b.Pending(map[int]bool{2: true}, 0)
	if len(evs) != 3 || evs[2].Value != 7 {
		t.Errorf("events %+v", evs)
	}
	// Flags only: the value stays, the flag change is an event.
	if ok, err := db.UpdateFlags(ctx, "analog", 0, 0x04, now); err != nil || !ok {
		t.Errorf("flags update: %v %v", ok, err)
	}
	if p, _ := db.Point("analog", 0); p.Value != 100 || p.Flags != 0x04 {
		t.Errorf("after the flags update %+v", p)
	}
	if _, err := db.UpdateFlags(ctx, "analog", 9, 0, now); err == nil {
		t.Error("flags of an undefined point were updated")
	}
}

// Buffer sizes per point type, and dropping the oldest event on overflow.
// Covers: SIG-IPE-6900
func TestEventBufferPolicies(t *testing.T) {
	ctx := context.Background()
	b := dnp3.NewEventBuffer(map[int]int{1: 3}, nil)
	db := dbWith(t, b, dnp3.DBPoint{Type: "binary", Index: 0, Class: 1}, dnp3.DBPoint{Type: "analog", Index: 0, Class: 1})
	for i := range 5 {
		_, _ = db.UpdateWith(ctx, "binary", 0, float64(i%2), nil, 0x01, time.Now(), dnp3.EventForce)
	}
	evs := b.Pending(map[int]bool{1: true}, 0)
	if len(evs) != 3 || evs[0].Value != 0 || !b.Overflow() {
		t.Errorf("default policy keeps the first events: %+v, overflow %v", evs, b.Overflow())
	}

	b2 := dnp3.NewEventBuffer(nil, nil)
	b2.SetDropOldest(true)
	b2.SetTypeCapacity("binary", 2)
	db2 := dbWith(t, b2, dnp3.DBPoint{Type: "binary", Index: 0, Class: 1}, dnp3.DBPoint{Type: "analog", Index: 0, Class: 1})
	for i := range 4 {
		_, _ = db2.UpdateWith(ctx, "binary", 0, float64(i), nil, 0x01, time.Now(), dnp3.EventForce)
	}
	_, _ = db2.Update(ctx, "analog", 0, 5, nil, 0x01, time.Now())
	evs = b2.Pending(map[int]bool{1: true}, 0)
	if len(evs) != 3 || evs[0].Value != 2 || evs[1].Value != 3 || evs[2].Group != 32 {
		t.Errorf("drop-oldest with a binary bound of 2: %+v", evs)
	}
	if !b2.Overflow() {
		t.Error("no overflow reported")
	}
	b2.Remove(ctx, []int64{evs[0].ID})
	if b2.Overflow() {
		t.Error("overflow still reported with room again")
	}
}
