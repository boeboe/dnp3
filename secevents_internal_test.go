package dnp3

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// statusMaster renders an association's status as the status container
// carries it (JSON) and decodes it back.
func statusMaster(t *testing.T, a *Association) map[string]any {
	t.Helper()
	b, err := json.Marshal(a.Status())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A broadcast refused under Secure Authentication shows in the
// association's status: in securityEvents (newest first, the detail
// written to the security log, never key material) and in the
// broadcastRefused count since start; it is still recorded to the
// security log.
//
// Covers: SIG-IPE-2747
func TestStatusShowsRefusedBroadcast(t *testing.T) {
	rec := useRecorder(t)
	a, _, _, _ := bcOutstation(t, true, nil)
	st := statusMaster(t, a)
	if st["broadcastRefused"] != float64(0) {
		t.Fatalf("broadcastRefused at start %v", st["broadcastRefused"])
	}
	if evs, ok := st["securityEvents"].([]any); !ok || len(evs) != 0 {
		t.Fatalf("securityEvents at start %v", st["securityEvents"])
	}
	deliverBroadcast(a, AddrBroadcastNoConfirm, Fragment{Control: AppFIR | AppFIN, Func: FCDirectOperateNR, Objects: latchObjects(t)}.Encode())
	deliverBroadcast(a, AddrBroadcastNoConfirm, Fragment{Control: AppFIR | AppFIN | 1, Func: FCColdRestart}.Encode())
	waitFor(t, "two refusals", func() bool { return len(rec.events(SecEventBroadcastRefused)) >= 2 })
	st = statusMaster(t, a)
	if st["broadcastRefused"] != float64(2) {
		t.Errorf("broadcastRefused %v, want 2", st["broadcastRefused"])
	}
	evs, _ := st["securityEvents"].([]any)
	if len(evs) != 2 {
		t.Fatalf("securityEvents %v", st["securityEvents"])
	}
	newest := evs[0].(map[string]any)
	oldest := evs[1].(map[string]any)
	if newest["event"] != SecEventBroadcastRefused || oldest["event"] != SecEventBroadcastRefused {
		t.Errorf("events %v", evs)
	}
	nd := newest["detail"].(map[string]any)
	od := oldest["detail"].(map[string]any)
	if nd["functionCode"] != fmt.Sprint(FCColdRestart) || od["functionCode"] != fmt.Sprint(FCDirectOperateNR) {
		t.Errorf("not newest first: %v then %v", nd, od)
	}
	if od["destination"] != "0xFFFD" || od["reason"] == "" || od["function"] != FuncName(FCDirectOperateNR) {
		t.Errorf("detail %v", od)
	}
	logged := rec.events(SecEventBroadcastRefused)[0].Detail
	for k, v := range logged {
		if od[k] != v {
			t.Errorf("detail %s = %v, security log %q", k, od[k], v)
		}
	}
	if _, err := time.Parse(time.RFC3339, oldest["at"].(string)); err != nil {
		t.Errorf("at %v: %v", oldest["at"], err)
	}
	if b, _ := json.Marshal(st["securityEvents"]); strings.Contains(strings.ToLower(string(b)), bcKey) {
		t.Error("key material in the status")
	}
}

// The association keeps its 20 most recent security events for the
// status (older ones remain only in the security log), while the
// broadcastRefused count keeps counting.
//
// Covers: SIG-IPE-2748
func TestStatusSecurityEventsKeepTwenty(t *testing.T) {
	useRecorder(t)
	a, _, oa, _ := bcOutstation(t, true, nil)
	ctx := context.Background()
	for i := range 25 {
		oa.gateBroadcast(ctx, Fragment{Control: AppFIR | AppFIN | byte(i)&0x0F, Func: FCAuthRequestNoAck}, AddrBroadcastNoConfirm)
	}
	st := statusMaster(t, a)
	if st["broadcastRefused"] != float64(25) {
		t.Errorf("broadcastRefused %v, want 25", st["broadcastRefused"])
	}
	evs, _ := st["securityEvents"].([]any)
	if len(evs) != secEventsKept || secEventsKept != 20 {
		t.Fatalf("%d security events kept, want 20", len(evs))
	}
	var prev time.Time
	for i, e := range evs {
		at, err := time.Parse(time.RFC3339, e.(map[string]any)["at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && at.After(prev) {
			t.Error("security events not newest first")
		}
		prev = at
	}
	kept, _ := oa.RecentSecurityEvents()
	if len(kept) != 20 {
		t.Fatalf("%d kept", len(kept))
	}
}

// The status's sa entry gives the Secure Authentication version (5), the
// association's exchange state (idle, or wait-for-reply while a
// challenge is unanswered) and when the session keys last changed.
//
// Covers: SIG-IPE-2749
func TestStatusSAState(t *testing.T) {
	useRecorder(t)
	ctx := context.Background()
	a, _, oa, url := bcOutstation(t, true, nil)
	sa := statusMaster(t, a)["sa"].(map[string]any)
	if sa["state"] != "idle" || sa["version"] != float64(5) || sa["sessionKeysAt"] != nil {
		t.Fatalf("sa at start %v", sa)
	}
	auth, err := NewAuth(&AuthConfig{UpdateKey: mustKey(bcKey), MAC: MACSHA256Trunc16, User: 1})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Dial(ctx, MasterConfig{URL: url, MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	before := time.Now().Add(-time.Second)
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	sa = statusMaster(t, a)["sa"].(map[string]any)
	at, err := time.Parse(time.RFC3339, fmt.Sprint(sa["sessionKeysAt"]))
	if err != nil || at.Before(before.Truncate(time.Second)) {
		t.Errorf("sessionKeysAt %v (%v)", sa["sessionKeysAt"], err)
	}
	w, _ := EncodeBlock(80, 1, Q8StartStop, []Point{{Index: 7, Value: false}})
	req := Fragment{Control: AppFIR | AppFIN, Func: FCWrite, Objects: w}
	if _, _, reply := oa.gate(ctx, req, req.Encode()); reply == nil {
		t.Fatal("not challenged")
	}
	if s := statusMaster(t, a)["sa"].(map[string]any)["state"]; s != "wait-for-reply" {
		t.Errorf("state %v while challenged, want wait-for-reply", s)
	}
	time.Sleep(150 * time.Millisecond) // ReplyTimeout 100 ms
	if s := statusMaster(t, a)["sa"].(map[string]any)["state"]; s != "idle" {
		t.Errorf("state %v after the reply timeout, want idle", s)
	}
}
