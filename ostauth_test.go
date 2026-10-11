package dnp3_test

import (
	"context" //nolint:staticcheck // update key change methods 67 to 71
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

func saOutstation(t *testing.T, mal uint8, tune func(*dnp3.OutstationAuthConfig)) *testOutstation {
	t.Helper()
	c := dnp3.OutstationAuthConfig{MAL: mal, Users: []dnp3.OutstationUser{{Number: 1, Name: "Common", UpdateKey: mustHex(t, updateKeyHex), Role: dnp3.RoleSingleUser}}, Name: "rtu-9"}
	if tune != nil {
		tune(&c)
	}
	oa, err := dnp3.NewOutstationAuth(c)
	if err != nil {
		t.Fatal(err)
	}
	return startOutstation(t, func(cfg *dnp3.OutstationConfig) { cfg.Auth = oa })
}

func saMaster(t *testing.T, o *testOutstation, mac string, aggressive, challengeResp bool) *dnp3.Master {
	t.Helper()
	a, err := dnp3.NewAuth(&dnp3.AuthConfig{User: 1, UpdateKey: hexKey(updateKeyHex), MAC: dnp3.MACByName(mac), AggressiveMode: aggressive, ChallengeResponses: challengeResp, KeyChangeCount: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return o.master(t, a, nil)
}

// Covers: SIG-IPE-1610, SIG-IPE-1598, SIG-IPE-1613
func TestOutstationSecureAuthentication(t *testing.T) {
	for _, mal := range []struct {
		name string
		code uint8
	}{{"hmac-sha256-16", dnp3.MACSHA256Trunc16}, {"hmac-sha1-10", dnp3.MACSHA1Trunc10}, {"aes-gmac", dnp3.MACAESGMAC}} {
		t.Run(mal.name, func(t *testing.T) {
			o := saOutstation(t, mal.code, func(c *dnp3.OutstationAuthConfig) { c.ChallengeConfirms = true })
			m := saMaster(t, o, mal.name, true, true)
			ctx := context.Background()
			// A critical request before any key change: error 1.
			var ae *dnp3.AuthError
			if _, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0)); !errors.As(err, &ae) || ae.Code != dnp3.AuthErrAuthFailed {
				t.Fatalf("before keys: %v", err)
			}
			if err := m.ChangeSessionKeys(ctx); err != nil {
				t.Fatal(err)
			}
			// Challenge and reply, then aggressive mode.
			for i := range 3 {
				if _, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0)); err != nil {
					t.Fatalf("operate %d: %v", i, err)
				}
			}
			o.h.mu.Lock()
			if len(o.h.controls) != 3 || o.h.controls[2].User != 1 {
				t.Fatalf("controls %+v", o.h.controls)
			}
			o.h.mu.Unlock()
			// A second key change: the key status carries a MAC the master
			// checks with the last monitoring key.
			if err := m.ChangeSessionKeys(ctx); err != nil {
				t.Fatalf("second key change: %v", err)
			}
			// Events: the response ends with a challenge; the master
			// confirms in aggressive mode and the master challenges the
			// response (challengeResponses) before using it.
			_, _ = o.db.Update(ctx, "binary", 0, 0, nil, 1, time.Now())
			frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
			if err != nil || len(frags) == 0 {
				t.Fatalf("event poll: %v", err)
			}
			if pointsOf(t, frags)[[2]uint32{2, 0}].Value != false {
				t.Fatalf("event %+v", pointsOf(t, frags))
			}
			waitEvents(t, o, 0)
			st := o.assoc
			_ = st
			// Security statistics are in class 0 (Table 5-1) and readable.
			frags, _ = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 121, 0, dnp3.QAll, 0, 0))
			p := pointsOf(t, frags)[[2]uint32{121, dnp3.StatSessionKeyChanges}]
			if p.Value != 2.0 {
				t.Fatalf("statistic %+v", pointsOf(t, frags))
			}
		})
	}
}

func waitEvents(t *testing.T, o *testOutstation, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if o.assoc.Status()["events"] == n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("events %v, want %d", o.assoc.Status()["events"], n)
}

// Covers: SIG-IPE-1611
func TestOutstationUpdateKeyChange(t *testing.T) {
	authKey := make([]byte, 32)
	_, _ = rand.Read(authKey)
	for _, method := range []uint8{dnp3.KeyChangeAES256SHA256, dnp3.KeyChangeAES256GMAC} {
		saved := map[string]dnp3.OutstationUser{}
		o := saOutstation(t, dnp3.MACSHA256Trunc16, func(c *dnp3.OutstationAuthConfig) {
			c.AuthorityKey = authKey
			c.UserChanged = func(u dnp3.OutstationUser) { saved[u.Name] = u }
		})
		m := saMaster(t, o, "hmac-sha256-16", false, false)
		ctx := context.Background()
		if err := m.ChangeSessionKeys(ctx); err != nil {
			t.Fatal(err)
		}
		c := dnp3.UpdateKeyChange{Authority: dnp3.SymmetricAuthority{KeyChangeMethod: method, Key: authKey, MasterAddress: 1},
			UserName: "alice", Role: dnp3.RoleOperator, Expiry: 30, SCS: 1, Outstation: "rtu-9"}
		if err := m.ChangeUpdateKey(ctx, c); err != nil {
			t.Fatalf("method %d: %v", method, err)
		}
		if u := saved["alice"]; len(u.UpdateKey) != 32 || u.Role != dnp3.RoleOperator || u.Expires.IsZero() {
			t.Fatalf("saved %+v", u)
		}
		if _, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0)); err != nil {
			t.Fatalf("alice operates: %v", err)
		}
		// A replayed status change (same SCS): refused.
		var ae *dnp3.AuthError
		c.Role = dnp3.RoleViewer
		if err := m.ChangeUpdateKey(ctx, c); !errors.As(err, &ae) || ae.Code != dnp3.AuthErrInvalidCertData {
			t.Fatalf("replay: %v", err)
		}
		// Delete: the user and its keys go.
		c.SCS, c.Operation = 5, dnp3.UserDelete
		if err := m.ChangeUpdateKey(ctx, c); err != nil {
			t.Fatal(err)
		}
		if u := saved["alice"]; u.UpdateKey != nil {
			t.Fatal("deleted user kept its key")
		}
	}
}

// Covers: SIG-IPE-1598
func TestAESGMAC(t *testing.T) {
	// NIST SP 800-38D GCM test case 1 style check through the standard
	// library, plus our IV layout (Table 7-20, F-592).
	iv := dnp3.GMACIV(0x1234, 0x0005, 0x01020304, 0x0A0B0C0D)
	if len(iv) != 12 || iv[0] != 0x34 || iv[1] != 0x12 || iv[2] != 5 || iv[4] != 4 || iv[8] != 0x0D {
		t.Fatalf("iv % X", iv)
	}
	k := make([]byte, 16)
	tag, err := dnp3.GMAC(k, make([]byte, 12))
	// GCM with zero key, zero IV and no data: 58E2FCCEFA7E3061367F1D57A4E7455A.
	if err != nil || len(tag) != 12 || tag[0] != 0x58 || tag[11] != 0x57 {
		t.Fatalf("tag % X %v", tag, err)
	}
	if _, err := dnp3.MAC(dnp3.MACAESGMAC, k, []byte("x")); err == nil {
		t.Fatal("AES-GMAC without an IV")
	}
	if m, err := dnp3.MACIV(dnp3.MACAESGMAC, k, iv, []byte("x")); err != nil || len(m) != 12 {
		t.Fatal(err)
	}
}
