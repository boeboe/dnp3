// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // asymmetric key change methods
	"crypto/rand"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3/authority"
)

// The update key authority as a service: the master changes a user's
// update key through it without holding the authority key; the register
// refuses a role it does not give, an unknown user, another master's
// outstation, a replayed sequence number and a wrong token.
// Covers: SIG-IPE-6903
func TestAuthorityService(t *testing.T) {
	authKey := make([]byte, 32)
	_, _ = rand.Read(authKey)
	srv := &authority.Server{Method: dnp3.KeyChangeAES256SHA256, Key: authKey}
	srv.AddUser(authority.User{Name: "alice", Role: dnp3.RoleOperator, MaxExpiry: 90})
	srv.AddMaster(authority.Master{Name: "scada", Token: "t-1", Address: 1, Outstations: []string{"rtu-9"}})
	hs := httptest.NewServer(srv)
	defer hs.Close()

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
	cl := &authority.Client{URL: hs.URL, Token: "t-1", Outstation: "rtu-9"}
	method, _, next, err := cl.Fetch()
	if err != nil || method != dnp3.KeyChangeAES256SHA256 || next != 1 {
		t.Fatalf("fetch: %d %d %v", method, next, err)
	}
	c := dnp3.UpdateKeyChange{Authority: cl, UserName: "alice", Role: dnp3.RoleOperator, Expiry: 30, SCS: next, Outstation: "rtu-9"}
	if err := m.ChangeUpdateKey(ctx, c); err != nil {
		t.Fatal(err)
	}
	if u := saved["alice"]; len(u.UpdateKey) != 32 || u.Role != dnp3.RoleOperator {
		t.Fatalf("saved %+v", u)
	}
	if _, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0)); err != nil {
		t.Fatalf("alice operates: %v", err)
	}
	refused := func(name string, c dnp3.UpdateKeyChange, want string) {
		t.Helper()
		if err := m.ChangeUpdateKey(ctx, c); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c.SCS = 2
	c.Role = dnp3.RoleSecAdm
	refused("another role", c, "role")
	c.Role, c.Expiry = dnp3.RoleOperator, 365
	refused("a longer expiry", c, "expiry")
	c.Expiry, c.UserName = 30, "mallory"
	refused("an unknown user", c, "not registered")
	c.UserName, c.SCS = "alice", 1
	refused("a replayed sequence number", c, "sequence")
	other := &authority.Client{URL: hs.URL, Token: "t-1", Outstation: "rtu-1", KeyChangeMethod: method}
	c.Authority, c.SCS = other, 2
	refused("another outstation", c, "may not manage")
	bad := &authority.Client{URL: hs.URL, Token: "wrong", Outstation: "rtu-9", KeyChangeMethod: method}
	c.Authority = bad
	refused("a wrong token", c, "unknown master")
	var n int
	for _, r := range srv.Log() {
		if r.Err != "" {
			n++
		}
	}
	if n < 5 {
		t.Errorf("%d refusals in the authority's log", n)
	}
}

// Asymmetric methods: the authority issues a g120v8 certificate the
// outstation's verifier accepts against the authority certificate, and
// signs status changes with its DSA key.
// Covers: SIG-IPE-6903
func TestAuthorityCertificates(t *testing.T) {
	var key dsa.PrivateKey
	if err := dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L2048N256); err != nil {
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(&key, rand.Reader); err != nil {
		t.Fatal(err)
	}
	srv := &authority.Server{Method: dnp3.KeyChangeRSA2048SHA256, DSA: &key, Name: "authority"}
	srv.AddUser(authority.User{Name: "bob", Role: dnp3.RoleEngineer})
	srv.AddMaster(authority.Master{Name: "scada", Token: "t-2", Address: 1})
	hs := httptest.NewServer(srv)
	defer hs.Close()
	cl := &authority.Client{URL: hs.URL, Token: "t-2", Outstation: "rtu-9"}
	_, acert, _, err := cl.Fetch()
	if err != nil || len(acert) == 0 {
		t.Fatalf("authority certificate: %v", err)
	}
	var ukey dsa.PrivateKey
	ukey.Parameters = key.Parameters
	if err := dsa.GenerateKey(&ukey, rand.Reader); err != nil {
		t.Fatal(err)
	}
	spki, err := dnp3.MarshalDSAPublicKey(&ukey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := cl.Certificate("bob", spki, 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Certificate("eve", spki, 30); err == nil {
		t.Error("a certificate for an unregistered user was issued")
	}
	u := dnp3.UserStatus{Method: dnp3.KeyChangeRSA2048SHA256, Operation: 1, SCS: 1, Role: dnp3.RoleEngineer, Expiry: 10, Name: "bob", PublicKey: spki}
	sig, err := cl.Certify(u)
	if err != nil {
		t.Fatal(err)
	}
	if !dnp3.DSAVerify(dnp3.KeyChangeRSA2048SHA256, &key.PublicKey, u.StatusInfo(), sig) {
		t.Error("the status change signature does not verify with the authority key")
	}
	uc, err := dnp3.ParseUserCertificate(dnp3.UserCertificate{Method: dnp3.KeyChangeRSA2048SHA256, Type: 1, Cert: der}.Encode())
	if err != nil || len(uc.Cert) != len(der) {
		t.Errorf("the issued certificate does not travel as a g120v8: %v", err)
	}
}
