package dnp3

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// Covers: SIG-IPE-1620
func TestSerialMasterAndOutstation(t *testing.T) {
	a, b := net.Pipe()
	var gotDev string
	var gotBaud int
	var gotParity string
	orig := OpenSerial
	OpenSerial = func(dev string, baud int, parity string) (io.ReadWriteCloser, error) {
		gotDev, gotBaud, gotParity = dev, baud, parity
		return a, nil
	}
	defer func() { OpenSerial = orig }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := NewPointDB()
	_ = db.Define(DBPoint{Type: "analog", Index: 3, Class0: true})
	_, _ = db.Update(ctx, "analog", 3, 12.5, nil, 1, time.Now())
	assoc := NewAssociation(OutstationConfig{Address: 10, Master: 1, DB: db, Handler: nopHandler{}})
	go assoc.Run(ctx)
	n := &OutstationNet{}
	n.Add(assoc)
	go n.ServeStream(ctx, b)
	m, err := Dial(ctx, MasterConfig{URL: "serial:///dev/ttyUSB0?baud=19200&parity=e", MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if gotDev != "/dev/ttyUSB0" || gotBaud != 19200 || gotParity != "E" {
		t.Fatalf("opened %s %d %s", gotDev, gotBaud, gotParity)
	}
	frags, err := m.Request(ctx, FCRead, ClassRequest(0))
	if err != nil {
		t.Fatal(err)
	}
	bl, _ := ParseObjects(frags[0].Objects, true)
	if bl[0].Points[0].Value != 12.5 || bl[0].Points[0].Index != 3 {
		t.Fatalf("%+v", bl)
	}
	for _, bad := range []string{"serial:///dev/x?baud=7", "serial:///dev/x?parity=Q"} {
		if _, err := Dial(ctx, MasterConfig{URL: bad, Timeout: time.Second}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

type nopHandler struct{}

func (nopHandler) Control(context.Context, ControlRequest) uint8        { return 0 }
func (nopHandler) DataSetControl(context.Context, DataSetControl) uint8 { return 0 }
func (nopHandler) Restart(context.Context, bool) time.Duration          { return 0 }
func (nopHandler) Activate(context.Context, [][]byte) ActivateStatus    { return ActivateStatus{} }
func (nopHandler) Application(context.Context, byte, [][]byte) IIN      { return 0 }
func (nopHandler) TimeSet(time.Time)                                    {}
func (nopHandler) DataSetWritten(context.Context, DataSet)              {}
