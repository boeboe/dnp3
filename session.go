// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// A polling session on a Master (RunSession): the start-up sequence,
// periodic integrity polls and class scans, polls for the classes the
// outstation flags, time synchronisation when it asks, and the start-up
// again after it restarts. The master stays request-level underneath:
// an application may send its own requests (controls, file transfer)
// while a session runs; they take turns.

// TimeSyncMode selects how a session sets the outstation's clock when
// the outstation asks for it (IIN1.4).
type TimeSyncMode int

const (
	TimeSyncNone   TimeSyncMode = iota
	TimeSyncNonLAN              // DELAY_MEASURE, then WRITE g50v1
	TimeSyncLAN                 // RECORD_CURRENT_TIME, then WRITE g50v3
)

// ClassScan polls event classes (1 to 3; 0 for static data) every Period.
type ClassScan struct {
	Classes []int
	Period  time.Duration
}

// SessionConfig configures RunSession.
type SessionConfig struct {
	// Unsolicited lists the event classes to enable for unsolicited
	// reporting at the end of the start-up; reporting is first disabled
	// for every class. Empty: unsolicited reporting is disabled and stays
	// so.
	Unsolicited []int
	// Integrity repeats the integrity poll (classes 1, 2, 3, 0); it also
	// runs at start-up and after an event buffer overflow (IIN2.3).
	// 0: no periodic integrity poll.
	Integrity time.Duration
	// Scans are periodic class scans.
	Scans []ClassScan
	// EventPoll polls the classes the outstation reports events for
	// (IIN1.1 to 1.3).
	EventPoll bool
	// TimeSync sets the outstation's clock when it asks.
	TimeSync TimeSyncMode
	// AssignClass, when set, are the objects of an ASSIGN_CLASS request
	// sent at start-up before the integrity poll.
	AssignClass []byte
	// RetryDelay is the pause after a failed task (default 5 s).
	RetryDelay time.Duration
	// OnData receives the response fragments of the session's polls
	// (unsolicited responses go to MasterConfig.OnUnsolicited).
	OnData func(Fragment)
	// OnTask reports each task run ("disable unsolicited", "clear
	// restart", "assign class", "integrity", "time sync", "enable
	// unsolicited", "class N scan", "event poll") and its error.
	OnTask func(name string, err error)
}

// SyncTime sets the outstation's clock by the non-LAN procedure
// (DELAY_MEASURE, then a WRITE of g50v1 corrected by half the round trip
// less the outstation's processing delay) or the LAN one
// (RECORD_CURRENT_TIME, then a WRITE of g50v3 with the time it was
// sent).
func (m *Master) SyncTime(ctx context.Context, lan bool) error {
	if lan {
		t0 := time.Now()
		if _, err := m.Request(ctx, FCRecordCurrentTime, nil); err != nil {
			return err
		}
		objs, err := EncodeBlock(50, 3, Q8Count, []Point{{Value: t0}})
		if err != nil {
			return err
		}
		_, err = m.Request(ctx, FCWrite, objs)
		return err
	}
	t0 := time.Now()
	frags, err := m.Request(ctx, FCDelayMeasure, nil)
	if err != nil {
		return err
	}
	rtt := time.Since(t0)
	var delay time.Duration
	found := false
	for _, f := range frags {
		bl, err := ParseObjects(f.Objects, true)
		if err != nil {
			return err
		}
		for _, b := range bl {
			if b.Header.Group == 52 && len(b.Points) == 1 {
				v, _ := b.Points[0].Value.(float64)
				unit := time.Millisecond
				if b.Header.Var == 1 {
					unit = time.Second
				}
				delay, found = time.Duration(v)*unit, true
			}
		}
	}
	if !found {
		return errors.New("the outstation answered DELAY_MEASURE without a time delay object (g52)")
	}
	objs, err := EncodeBlock(50, 1, Q8Count, []Point{{Value: time.Now().Add(max((rtt-delay)/2, 0))}})
	if err != nil {
		return err
	}
	_, err = m.Request(ctx, FCWrite, objs)
	return err
}

// RunSession polls the outstation as cfg says until ctx is done (it
// returns ctx's error) or the connection ends (it returns why).
func (m *Master) RunSession(ctx context.Context, cfg SessionConfig) error {
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = 5 * time.Second
	}
	s := &session{m: m, cfg: cfg, next: make([]time.Time, len(cfg.Scans))}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	startup := true
	var wait, nextIntegrity, lastOverflow time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.done:
			return m.Err()
		case <-tick.C:
		}
		now := time.Now()
		if now.Before(wait) {
			continue
		}
		iin := m.IIN()
		if iin&IINDeviceRestart != 0 {
			startup = true
		}
		var err error
		switch {
		case startup:
			if err = s.startup(ctx); err == nil {
				startup = false
				now = time.Now()
				nextIntegrity = now.Add(cfg.Integrity)
				for i, sc := range cfg.Scans {
					s.next[i] = now.Add(sc.Period)
				}
			}
		case iin&IINEventBufferOverflow != 0 && now.Sub(lastOverflow) > cfg.RetryDelay:
			lastOverflow = now
			err = s.poll(ctx, "integrity", 1, 2, 3, 0)
		case iin&IINNeedTime != 0 && cfg.TimeSync != TimeSyncNone:
			err = s.run("time sync", m.SyncTime(ctx, cfg.TimeSync == TimeSyncLAN))
		case cfg.Integrity > 0 && !now.Before(nextIntegrity):
			nextIntegrity = now.Add(cfg.Integrity)
			err = s.poll(ctx, "integrity", 1, 2, 3, 0)
		default:
			if i := s.due(now); i >= 0 {
				sc := cfg.Scans[i]
				s.next[i] = now.Add(sc.Period)
				err = s.poll(ctx, scanName(sc.Classes), sc.Classes...)
			} else if cfg.EventPoll && iin&IINClassEvents != 0 {
				var classes []int
				for c := 1; c <= 3; c++ {
					if iin&(IINClass1Events<<(c-1)) != 0 {
						classes = append(classes, c)
					}
				}
				err = s.poll(ctx, "event poll", classes...)
			}
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-m.done:
				return m.Err()
			default:
			}
			wait = time.Now().Add(cfg.RetryDelay)
		}
	}
}

type session struct {
	m    *Master
	cfg  SessionConfig
	next []time.Time
}

func scanName(classes []int) string {
	s := "class"
	for _, c := range classes {
		s += fmt.Sprintf(" %d", c)
	}
	return s + " scan"
}

func (s *session) due(now time.Time) int {
	for i, sc := range s.cfg.Scans {
		if sc.Period > 0 && !now.Before(s.next[i]) {
			return i
		}
	}
	return -1
}

func (s *session) run(name string, err error) error {
	if s.cfg.OnTask != nil {
		s.cfg.OnTask(name, err)
	}
	return err
}

func (s *session) poll(ctx context.Context, name string, classes ...int) error {
	frags, err := s.m.Request(ctx, FCRead, ClassRequest(classes...))
	if s.cfg.OnData != nil {
		for _, f := range frags {
			s.cfg.OnData(f)
		}
	}
	return s.run(name, err)
}

func (s *session) startup(ctx context.Context) error {
	m := s.m
	if _, err := m.Request(ctx, FCDisableUnsolicited, ClassRequest(1, 2, 3)); s.run("disable unsolicited", err) != nil {
		return err
	}
	if m.IIN()&IINDeviceRestart != 0 {
		objs, _ := EncodeBlock(80, 1, Q8StartStop, []Point{{Index: 7, Value: false}})
		if _, err := m.Request(ctx, FCWrite, objs); s.run("clear restart", err) != nil {
			return err
		}
	}
	if s.cfg.AssignClass != nil {
		if _, err := m.Request(ctx, FCAssignClass, s.cfg.AssignClass); s.run("assign class", err) != nil {
			return err
		}
	}
	if err := s.poll(ctx, "integrity", 1, 2, 3, 0); err != nil {
		return err
	}
	if m.IIN()&IINNeedTime != 0 && s.cfg.TimeSync != TimeSyncNone {
		if err := s.run("time sync", m.SyncTime(ctx, s.cfg.TimeSync == TimeSyncLAN)); err != nil {
			return err
		}
	}
	if len(s.cfg.Unsolicited) > 0 {
		if _, err := m.Request(ctx, FCEnableUnsolicited, ClassRequest(s.cfg.Unsolicited...)); s.run("enable unsolicited", err) != nil {
			return err
		}
	}
	return nil
}
