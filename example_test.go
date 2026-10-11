// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// exampleHandler is an outstation application that accepts every control
// and supports nothing else.
type exampleHandler struct{}

func (exampleHandler) Control(context.Context, dnp3.ControlRequest) uint8        { return 0 }
func (exampleHandler) DataSetControl(context.Context, dnp3.DataSetControl) uint8 { return 4 }
func (exampleHandler) Restart(context.Context, bool) time.Duration               { return 0 }
func (exampleHandler) Activate(context.Context, [][]byte) dnp3.ActivateStatus {
	return dnp3.ActivateStatus{}
}
func (exampleHandler) Application(context.Context, byte, [][]byte) dnp3.IIN {
	return dnp3.IINNoFuncCodeSupport
}
func (exampleHandler) TimeSet(time.Time)                            {}
func (exampleHandler) DataSetWritten(context.Context, dnp3.DataSet) {}

// An outstation: a point database, one association per master, served
// over TCP; a change becomes a class 1 event.
func ExampleNewAssociation() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := dnp3.NewPointDB()
	_ = db.Define(dnp3.DBPoint{Type: "binary", Index: 0, Class0: true, Class: 1})
	_, _ = db.Update(ctx, "binary", 0, 0, nil, 0x01, time.Now())

	a := dnp3.NewAssociation(dnp3.OutstationConfig{Address: 10, Master: 1, DB: db, Handler: exampleHandler{}})
	n := &dnp3.OutstationNet{}
	n.Add(a)
	go a.Run(ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go n.ServeStream(ctx, c)
		}
	}()

	m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: "tcp://" + ln.Addr().String(), MasterAddress: 1, OutstationAddress: 10, Timeout: 2 * time.Second})
	if err != nil {
		panic(err)
	}
	defer m.Close()
	_, _ = db.Update(ctx, "binary", 0, 1, nil, 0x01, time.Now())
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
	if err != nil {
		panic(err)
	}
	blocks, _ := dnp3.ParseObjects(frags[0].Objects, true)
	p := blocks[0].Points[0]
	fmt.Printf("event g%dv%d index %d: %v\n", p.Group, p.Var, p.Index, p.Value)
	// Output:
	// event g2v2 index 0: true
}

// Encoding an object block and reading it back.
func ExampleEncodeBlock() {
	b, _ := dnp3.EncodeBlock(30, 2, dnp3.Q8StartStop, []dnp3.Point{{Index: 3, Value: 1234.0, Flags: 0x01}})
	fmt.Printf("% X\n", b)
	blocks, _ := dnp3.ParseObjects(b, true)
	fmt.Println(blocks[0].Points[0].Value)
	// Output:
	// 1E 02 00 03 03 01 D2 04
	// 1234
}
