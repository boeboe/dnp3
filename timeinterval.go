// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3

import (
	"context"
	"fmt"
	"time"
)

// Time-and-interval points (group 50 variation 4): a start time, an
// interval count and its units, static only (no events). The outstation
// serves them in class 0 and to reads of g50v4 (or g50v0) by range,
// index or all, and the master may write them by index.

// Units of a time-and-interval point (the codes of g50v4).
const (
	UnitsNoRepeat     uint8 = 0
	UnitsMilliseconds uint8 = 1
	UnitsSeconds      uint8 = 2
	UnitsMinutes      uint8 = 3
	UnitsHours        uint8 = 4
	UnitsDays         uint8 = 5
	UnitsWeeks        uint8 = 6
	// Months on the same day of the month, the same weekday counted from
	// the start of the month, and the same weekday counted from its end.
	UnitsMonthsDay        uint8 = 7
	UnitsMonthsWeekday    uint8 = 8
	UnitsMonthsWeekdayEnd uint8 = 9
	UnitsSeasons          uint8 = 10
)

// TimeAndInterval is the value of a time-and-interval point.
type TimeAndInterval struct {
	Index    uint32
	Time     time.Time
	Interval uint32
	Units    uint8
}

// TimeAndIntervalHandler is implemented by a Handler that wants to know
// when the master wrote a time-and-interval point (the database already
// holds the new value).
type TimeAndIntervalHandler interface {
	TimeAndIntervalWritten(ctx context.Context, ti TimeAndInterval)
}

// SetTimeAndInterval sets a time-and-interval point (Index is ignored).
func (db *PointDB) SetTimeAndInterval(index uint32, ti TimeAndInterval) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	p := db.points["time-and-interval"][index]
	if p == nil {
		return fmt.Errorf("time-and-interval %d is not defined", index)
	}
	p.Time, p.Value, p.Units, p.Flags, p.known = ti.Time, float64(ti.Interval), ti.Units, 0x01, true
	return nil
}

// TimeAndInterval reads a time-and-interval point.
func (db *PointDB) TimeAndInterval(index uint32) (TimeAndInterval, bool) {
	p, ok := db.Point("time-and-interval", index)
	if !ok {
		return TimeAndInterval{}, false
	}
	return TimeAndInterval{Index: index, Time: p.Time, Interval: uint32(p.Value), Units: p.Units}, true
}

// writeTimeAndInterval takes a master's g50v4 objects.
func (a *Association) writeTimeAndInterval(ctx context.Context, b Block) IIN {
	var iin IIN
	for _, p := range b.Points {
		t, _ := p.Value.(time.Time)
		ti := TimeAndInterval{Index: p.Index, Time: t, Interval: p.Interval, Units: p.Units}
		if err := a.cfg.DB.SetTimeAndInterval(p.Index, ti); err != nil {
			iin |= IINParameterError
			continue
		}
		if h, ok := a.cfg.Handler.(TimeAndIntervalHandler); ok {
			h.TimeAndIntervalWritten(ctx, ti)
		}
	}
	return iin
}
