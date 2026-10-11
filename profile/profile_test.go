// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package profile_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3/profile"
)

func demoDB(t *testing.T) *dnp3.PointDB {
	t.Helper()
	db := dnp3.NewPointDB()
	for _, p := range []dnp3.DBPoint{
		{Type: "binary", Index: 0, Class0: true, Class: 1},
		{Type: "binary", Index: 1, Class0: true, Class: 0, StaticVar: 1},
		{Type: "analog", Index: 0, Class0: true, Class: 2, Deadband: 0.5, StaticVar: 5, EventVar: 7},
		{Type: "counter", Index: 3, Class0: true, Class: 3},
		{Type: "frozen-counter", Index: 3, Class0: true, Class: 3},
		{Type: "analog-output", Index: 2, Class0: true},
	} {
		if err := db.Define(p); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// The data points list written from a PointDB, read back and turned into
// an equal PointDB.
// Covers: SIG-IPE-6902
func TestWriteReadDefine(t *testing.T) {
	db := demoDB(t)
	dev := profile.Device{Vendor: "Example", Name: "Feeder RTU", Address: 10, Masters: []uint16{1, 2},
		Outstation: dnp3.OutstationConfig{Unsolicited: true, SelectTimeout: 5 * time.Second, NeedTime: 30 * time.Minute},
		Info: map[string]map[uint32]profile.PointInfo{"analog": {0: {Name: "Feeder voltage", ScaleFactor: 0.1, Units: "kV"}},
			"binary": {0: {Name: "Breaker", State0: "open", State1: "closed"}}}}
	var b bytes.Buffer
	if err := profile.New(dev, db).Write(&b); err != nil {
		t.Fatal(err)
	}
	doc := b.String()
	for _, want := range []string{"<DNP3DeviceProfileDocument", `schemaVersion="2.11.00"`, "<dataPointsList>", "<analogInputPoints>",
		"<changeEventClass>2</changeEventClass>", "<units>kV</units>", "<frozenCounterExists>true</frozenCounterExists>",
		"<dataLinkAddress>", "<unsolicitedResponseSupport>"} {
		if !strings.Contains(doc, want) {
			t.Errorf("document lacks %s:\n%s", want, doc)
		}
	}
	back, err := profile.Read(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if back.Device.Configuration.Link.Address != 10 || back.Device.Configuration.Application.SelectTimeoutMS != 5000 ||
		!back.Device.Configuration.Outstation.Unsolicited || len(back.Device.Configuration.Link.MasterAddrList) != 2 {
		t.Errorf("configuration read back %+v", back.Device.Configuration)
	}
	db2 := dnp3.NewPointDB()
	info, err := back.Define(db2)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"binary", "analog", "counter", "frozen-counter", "analog-output"} {
		a, c := db.Points(typ), db2.Points(typ)
		if !reflect.DeepEqual(a, c) {
			t.Errorf("%s: defined %+v, want %+v", typ, c, a)
		}
	}
	if info["analog"][0].Units != "kV" || info["binary"][0].State1 != "closed" {
		t.Errorf("point information %+v", info)
	}
	bad := strings.Replace(doc, "<changeEventClass>2</changeEventClass>", "<changeEventClass>9</changeEventClass>", 1)
	d3, err := profile.Read(strings.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d3.Define(dnp3.NewPointDB()); err == nil {
		t.Error("event class 9 was accepted")
	}
}
