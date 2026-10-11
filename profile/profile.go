// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package profile writes and reads a DNP3 device profile document in XML
// (IEEE 1815-2012 clause 14 and the DNP Users Group's XML device profile):
// the device's identity and communication settings and, from an
// outstation's PointDB, its data points list (index, name, default
// static and event variations, event class, class 0 membership, deadband,
// scaling and units per point). Read takes such a document back, and
// Document.Define builds a PointDB from it, so a profile can configure an
// outstation as well as describe one.
//
// Element names follow the data points list and configuration parts of
// the XML device profile schema as we read version 2.x of it; documents
// are not validated against the schema, which the DNP Users Group
// publishes to its members. Unknown elements are ignored on reading.
package profile

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"

	"github.com/cB-Sigma/dnp3"
)

// SchemaVersion is the schema version the documents name.
const SchemaVersion = "2.11.00"

// Document is a device profile document.
type Document struct {
	XMLName       xml.Name        `xml:"DNP3DeviceProfileDocument"`
	SchemaVersion string          `xml:"schemaVersion,attr"`
	Header        DocumentHeader  `xml:"documentHeader"`
	Device        ReferenceDevice `xml:"ReferenceDevice"`
}

// DocumentHeader names the document.
type DocumentHeader struct {
	Name        string `xml:"documentName"`
	Description string `xml:"documentDescription,omitempty"`
}

// ReferenceDevice is the device the profile describes.
type ReferenceDevice struct {
	Configuration Configuration `xml:"configuration"`
	Points        DataPoints    `xml:"dataPointsList"`
}

// Configuration holds the device and communication settings (parts 1.1
// to 1.10 of the template, the items this package fills).
type Configuration struct {
	Device      DeviceConfig      `xml:"deviceConfig"`
	Link        LinkConfig        `xml:"linkLayer"`
	Application ApplicationConfig `xml:"applicationLayer"`
	Outstation  OutstationConfig  `xml:"outstationConfig"`
}

// DeviceConfig is the device's identity.
type DeviceConfig struct {
	Function        string `xml:"deviceFunction>currentValue"` // "Master" or "Outstation"
	Vendor          string `xml:"vendorName>currentValue"`
	Name            string `xml:"deviceName>currentValue"`
	HardwareVersion string `xml:"hardwareVersion>currentValue,omitempty"`
	SoftwareVersion string `xml:"softwareVersion>currentValue,omitempty"`
	Level           int    `xml:"dnpLevelSupported>currentValue,omitempty"`
}

// LinkConfig is the data link layer's settings.
type LinkConfig struct {
	Address        uint16 `xml:"dataLinkAddress>currentValue"`
	SelfAddress    bool   `xml:"selfAddressSupport>currentValue"`
	LinkConfirm    string `xml:"sendsConfirmedUserDataFrames>currentValue"` // "Never", "Always", "Sometimes"
	MasterAddrList []int  `xml:"validMasterAddresses>currentValue>address,omitempty"`
}

// ApplicationConfig is the application layer's settings.
type ApplicationConfig struct {
	MaxTxFragment     int `xml:"maxTransmittedFragmentSize>currentValue"`
	MaxRxFragment     int `xml:"maxReceivedFragmentSize>currentValue,omitempty"`
	ConfirmTimeoutMS  int `xml:"applicationLayerConfirmTimeout>currentValue,omitempty"`
	SelectTimeoutMS   int `xml:"selectTimeout>currentValue,omitempty"`
	MaxControlObjects int `xml:"maxControlsPerRequest>currentValue,omitempty"`
}

// OutstationConfig is the outstation's reporting settings.
type OutstationConfig struct {
	Unsolicited     bool `xml:"unsolicitedResponseSupport>currentValue"`
	UnsolRetries    int  `xml:"unsolicitedRetries>currentValue,omitempty"`
	NeedTimeSeconds int  `xml:"timeSyncRequiredInterval>currentValue,omitempty"`
}

// DataPoints is the data points list, by point type.
type DataPoints struct {
	Binary       []DataPoint `xml:"binaryInputPoints>dataPoint,omitempty"`
	Double       []DataPoint `xml:"doubleBitInputPoints>dataPoint,omitempty"`
	BinaryOutput []DataPoint `xml:"binaryOutputPoints>dataPoint,omitempty"`
	Counter      []DataPoint `xml:"counterPoints>dataPoint,omitempty"`
	Analog       []DataPoint `xml:"analogInputPoints>dataPoint,omitempty"`
	AnalogOutput []DataPoint `xml:"analogOutputPoints>dataPoint,omitempty"`
	OctetString  []DataPoint `xml:"octetStringPoints>dataPoint,omitempty"`
}

// DataPoint is one point of the list.
type DataPoint struct {
	Index         uint32  `xml:"index"`
	Name          string  `xml:"name,omitempty"`
	StaticVar     uint8   `xml:"defaultStaticVariation,omitempty"`
	EventVar      uint8   `xml:"defaultEventVariation,omitempty"`
	Class         string  `xml:"changeEventClass"` // "1", "2", "3" or "none"
	Class0        bool    `xml:"includedInClass0response"`
	Deadband      float64 `xml:"deadband,omitempty"`
	ScaleFactor   float64 `xml:"scaleFactor,omitempty"`
	ScaleOffset   float64 `xml:"scaleOffset,omitempty"`
	Units         string  `xml:"units,omitempty"`
	FrozenCounter bool    `xml:"frozenCounterExists,omitempty"`
	State0        string  `xml:"nameState0,omitempty"`
	State1        string  `xml:"nameState1,omitempty"`
}

// PointInfo is what a PointDB does not hold about a point: its name,
// scaling and units, and the names of a binary's states.
type PointInfo struct {
	Name           string
	ScaleFactor    float64
	ScaleOffset    float64
	Units          string
	State0, State1 string
}

// Device is the input of New: the identity and settings the document
// records besides the points.
type Device struct {
	Function        string // "Outstation" (default) or "Master"
	Vendor, Name    string
	HardwareVersion string
	SoftwareVersion string
	Level           int
	Address         uint16
	SelfAddress     bool
	Masters         []uint16
	Outstation      dnp3.OutstationConfig // its sizes, timeouts and reporting are recorded
	// Info names points, by type and index.
	Info map[string]map[uint32]PointInfo
}

var listOf = map[string]func(*DataPoints) *[]DataPoint{
	"binary":        func(d *DataPoints) *[]DataPoint { return &d.Binary },
	"double":        func(d *DataPoints) *[]DataPoint { return &d.Double },
	"binary-output": func(d *DataPoints) *[]DataPoint { return &d.BinaryOutput },
	"counter":       func(d *DataPoints) *[]DataPoint { return &d.Counter },
	"analog":        func(d *DataPoints) *[]DataPoint { return &d.Analog },
	"analog-output": func(d *DataPoints) *[]DataPoint { return &d.AnalogOutput },
	"octet-string":  func(d *DataPoints) *[]DataPoint { return &d.OctetString },
}

// Types are the point types a data points list holds, in document order.
var Types = []string{"binary", "double", "binary-output", "counter", "analog", "analog-output", "octet-string"}

// New makes the document of an outstation with database db.
func New(dev Device, db *dnp3.PointDB) *Document {
	fn := dev.Function
	if fn == "" {
		fn = "Outstation"
	}
	oc := dev.Outstation
	d := &Document{SchemaVersion: SchemaVersion,
		Header: DocumentHeader{Name: dev.Name + " device profile", Description: "generated from the outstation's point database"}}
	c := &d.Device.Configuration
	c.Device = DeviceConfig{Function: fn, Vendor: dev.Vendor, Name: dev.Name, HardwareVersion: dev.HardwareVersion,
		SoftwareVersion: dev.SoftwareVersion, Level: dev.Level}
	c.Link = LinkConfig{Address: dev.Address, SelfAddress: dev.SelfAddress, LinkConfirm: "Never"}
	for _, m := range dev.Masters {
		c.Link.MasterAddrList = append(c.Link.MasterAddrList, int(m))
	}
	c.Application = ApplicationConfig{MaxTxFragment: or(oc.MaxFragment, 2048), MaxRxFragment: 2048,
		ConfirmTimeoutMS: int(oc.ConfirmTimeout.Milliseconds()), SelectTimeoutMS: int(oc.SelectTimeout.Milliseconds()),
		MaxControlObjects: or(oc.MaxControls, 16)}
	c.Outstation = OutstationConfig{Unsolicited: oc.Unsolicited, UnsolRetries: oc.UnsolRetries, NeedTimeSeconds: int(oc.NeedTime.Seconds())}
	frozen := map[uint32]bool{}
	if db != nil {
		for _, p := range db.Points("frozen-counter") {
			frozen[p.Index] = true
		}
		for _, typ := range Types {
			list := listOf[typ](&d.Device.Points)
			for _, p := range db.Points(typ) {
				info := dev.Info[typ][p.Index]
				class := "none"
				if p.Class > 0 {
					class = fmt.Sprint(p.Class)
				}
				*list = append(*list, DataPoint{Index: p.Index, Name: info.Name, StaticVar: p.StaticVar, EventVar: p.EventVar,
					Class: class, Class0: p.Class0, Deadband: p.Deadband, ScaleFactor: info.ScaleFactor, ScaleOffset: info.ScaleOffset,
					Units: info.Units, FrozenCounter: typ == "counter" && frozen[p.Index], State0: info.State0, State1: info.State1})
			}
		}
	}
	return d
}

func or(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// Write writes the document as indented XML with its declaration.
func (d *Document) Write(w io.Writer) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	e := xml.NewEncoder(w)
	e.Indent("", "  ")
	if err := e.Encode(d); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// Read reads a document.
func Read(r io.Reader) (*Document, error) {
	var d Document
	if err := xml.NewDecoder(r).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Points returns the list of a point type ("binary", "analog", ...),
// sorted by index.
func (d *Document) Points(typ string) []DataPoint {
	f, ok := listOf[typ]
	if !ok {
		return nil
	}
	out := append([]DataPoint(nil), *f(&d.Device.Points)...)
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// Define adds the document's points to db (counters with a frozen
// counter get the frozen counter point too) and returns their names and
// scaling by type and index.
func (d *Document) Define(db *dnp3.PointDB) (map[string]map[uint32]PointInfo, error) {
	info := map[string]map[uint32]PointInfo{}
	for _, typ := range Types {
		for _, p := range d.Points(typ) {
			class := 0
			switch p.Class {
			case "1", "2", "3":
				class = int(p.Class[0] - '0')
			case "", "none":
			default:
				return nil, fmt.Errorf("%s %d: event class %q is not 1, 2, 3 or none", typ, p.Index, p.Class)
			}
			if err := db.Define(dnp3.DBPoint{Type: typ, Index: p.Index, Class0: p.Class0, Class: class, StaticVar: p.StaticVar,
				EventVar: p.EventVar, Deadband: p.Deadband}); err != nil {
				return nil, err
			}
			if typ == "counter" && p.FrozenCounter {
				if err := db.Define(dnp3.DBPoint{Type: "frozen-counter", Index: p.Index, Class0: p.Class0, Class: class}); err != nil {
					return nil, err
				}
			}
			if info[typ] == nil {
				info[typ] = map[uint32]PointInfo{}
			}
			info[typ][p.Index] = PointInfo{Name: p.Name, ScaleFactor: p.ScaleFactor, ScaleOffset: p.ScaleOffset, Units: p.Units,
				State0: p.State0, State1: p.State1}
		}
	}
	return info, nil
}
