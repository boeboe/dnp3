// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package authority is a reference implementation of the update key
// authority of DNP3 Secure Authentication (IEEE 1815-2012 7.5.4): the
// party that decides which users exist at which outstation with which
// role, certifies the user status changes a master forwards, encrypts new
// update keys for the symmetric methods (3 to 5), and signs status changes
// and issues g120v8 user certificates with its DSA key for the asymmetric
// methods (67 to 69).
//
// The standard leaves the protocol between master and authority open.
// This package defines a small one of its own, JSON over HTTP(S) with a
// bearer token per master: Server is an http.Handler, and Client is the
// master's dnp3.Authority backed by it. The point of the split is that the
// master never holds the authority key: the authority checks each request
// against its user register and refuses what the register does not allow.
//
//	POST /v1/certify      {outstation, status}        -> {certData}
//	POST /v1/update-key   {outstation, user, key, challenge} -> {encrypted}
//	POST /v1/certificate  {user, publicKey, days}     -> {certificate}
//	GET  /v1/authority                                -> {method, certificate}
package authority

import (
	"bytes"
	"context"
	"crypto/dsa" //nolint:staticcheck // the asymmetric key change methods use DSA
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// User is one entry of the authority's register.
type User struct {
	Name string
	Role uint16
	// MaxExpiry bounds the expiry (days) a status change may give (0: no
	// bound).
	MaxExpiry uint16
	// Outstations are the outstation names the user may be added to (nil:
	// any).
	Outstations []string
	// Deleted users may only be deleted at outstations.
	Deleted bool
}

// Master is a master allowed to use the authority.
type Master struct {
	Name  string
	Token string
	// Address is the master's DNP3 address (the AES-GMAC IV of method 5).
	Address uint16
	// Outstations the master may manage (nil: any).
	Outstations []string
}

// Server is the authority.
type Server struct {
	// Method is the key change method (3, 4, 5 symmetric; 67 to 69
	// asymmetric).
	Method uint8
	// Key is the authority certification key shared with the outstations
	// (symmetric methods).
	Key []byte
	// DSA is the authority's private key (asymmetric methods), Name its
	// name in the certificates it issues.
	DSA  *dsa.PrivateKey
	Name string
	// Now is the clock for certificates (nil: time.Now).
	Now func() time.Time

	mu      sync.Mutex
	users   map[string]User
	masters map[string]Master
	scs     map[string]uint32 // last status change sequence number per outstation
	log     []Record
}

// Record is one decision of the authority (its audit trail).
type Record struct {
	Time       time.Time
	Master     string
	Outstation string
	User       string
	Action     string
	Err        string
}

// AddUser registers or replaces a user.
func (s *Server) AddUser(u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users == nil {
		s.users = map[string]User{}
	}
	s.users[u.Name] = u
}

// AddMaster allows a master.
func (s *Server) AddMaster(m Master) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.masters == nil {
		s.masters = map[string]Master{}
	}
	s.masters[m.Name] = m
}

// Log returns the authority's decisions so far.
func (s *Server) Log() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.log...)
}

func (s *Server) record(r Record, err error) {
	r.Time = time.Now()
	if err != nil {
		r.Err = err.Error()
	}
	s.mu.Lock()
	s.log = append(s.log, r)
	s.mu.Unlock()
}

// Errors of the authority (also the HTTP answer's text).
var (
	ErrUnauthorised = errors.New("unknown master or token")
	ErrNotAllowed   = errors.New("the register does not allow this")
	ErrReplay       = errors.New("the status change sequence number is not above the last one for this outstation")
)

func (s *Server) master(r *http.Request) (Master, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return Master{}, ErrUnauthorised
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.masters {
		if subtle.ConstantTimeCompare([]byte(m.Token), []byte(tok)) == 1 {
			return m, nil
		}
	}
	return Master{}, ErrUnauthorised
}

func allowed(list []string, name string) bool { return list == nil || slices.Contains(list, name) }

// Certify checks a status change of master m for outstation ostn against
// the register and returns its certification data.
func (s *Server) Certify(m Master, ostn string, u dnp3.UserStatus) ([]byte, error) {
	if !allowed(m.Outstations, ostn) {
		return nil, fmt.Errorf("%w: master %s may not manage %s", ErrNotAllowed, m.Name, ostn)
	}
	if u.Method != s.Method {
		return nil, fmt.Errorf("%w: method %d, the authority uses %d", ErrNotAllowed, u.Method, s.Method)
	}
	s.mu.Lock()
	reg, ok := s.users[u.Name]
	last, seen := s.scs[ostn]
	s.mu.Unlock()
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: %s is not registered", ErrNotAllowed, u.Name)
	case u.Operation != dnp3.UserDelete && reg.Deleted:
		return nil, fmt.Errorf("%w: %s is deleted", ErrNotAllowed, u.Name)
	case u.Operation != dnp3.UserDelete && u.Role != reg.Role:
		return nil, fmt.Errorf("%w: %s has role %d, not %d", ErrNotAllowed, u.Name, reg.Role, u.Role)
	case u.Operation != dnp3.UserDelete && reg.MaxExpiry > 0 && (u.Expiry == 0 || u.Expiry > reg.MaxExpiry):
		return nil, fmt.Errorf("%w: expiry %d days beyond %d", ErrNotAllowed, u.Expiry, reg.MaxExpiry)
	case u.Operation != dnp3.UserDelete && !allowed(reg.Outstations, ostn):
		return nil, fmt.Errorf("%w: %s may not be at %s", ErrNotAllowed, u.Name, ostn)
	case seen && u.SCS <= last:
		return nil, ErrReplay
	}
	var cert []byte
	var err error
	if dnp3.Symmetric(s.Method) {
		cert, err = dnp3.SymmetricAuthority{KeyChangeMethod: s.Method, Key: s.Key, MasterAddress: m.Address}.Certify(u)
	} else {
		if s.DSA == nil {
			return nil, errors.New("the authority has no DSA key")
		}
		cert, err = dnp3.AsymmetricAuthority{KeyChangeMethod: s.Method, Key: s.DSA}.Certify(u)
	}
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.scs == nil {
		s.scs = map[string]uint32{}
	}
	s.scs[ostn] = u.SCS
	s.mu.Unlock()
	return cert, nil
}

// NextSCS is the next status change sequence number for an outstation
// (the authority keeps the count; masters ask for it).
func (s *Server) NextSCS(ostn string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scs[ostn] + 1
}

// EncryptUpdateKey wraps a new update key of a registered user for the
// outstation (symmetric methods).
func (s *Server) EncryptUpdateKey(m Master, ostn, user string, key, challenge []byte) ([]byte, error) {
	if !dnp3.Symmetric(s.Method) {
		return nil, errors.New("the asymmetric methods encrypt with the outstation's public key")
	}
	if !allowed(m.Outstations, ostn) {
		return nil, fmt.Errorf("%w: master %s may not manage %s", ErrNotAllowed, m.Name, ostn)
	}
	s.mu.Lock()
	reg, ok := s.users[user]
	s.mu.Unlock()
	if !ok || reg.Deleted || !allowed(reg.Outstations, ostn) {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, user)
	}
	return dnp3.SymmetricAuthority{KeyChangeMethod: s.Method, Key: s.Key, MasterAddress: m.Address}.EncryptUpdateKey(user, key, challenge)
}

// Certificate issues a g120v8 ID certificate for a registered user with
// its register role (asymmetric methods).
func (s *Server) Certificate(user string, spki []byte, days int) ([]byte, error) {
	if s.DSA == nil {
		return nil, errors.New("the authority has no DSA key")
	}
	s.mu.Lock()
	reg, ok := s.users[user]
	s.mu.Unlock()
	if !ok || reg.Deleted {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, user)
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	t := now()
	if days <= 0 {
		days = 365
	}
	aor := "*"
	if len(reg.Outstations) == 1 {
		aor = reg.Outstations[0]
	}
	return dnp3.IssueDSAUserCertificate(s.Method, s.DSA, s.Name, user, spki,
		[]dnp3.UserRoleInfo{{Roles: []int{int(reg.Role)}, AOR: aor}}, t.Add(-time.Minute), t.AddDate(0, 0, days))
}

// AuthorityCertificate is the authority's own certificate (asymmetric
// methods), for the outstations' trust.
func (s *Server) AuthorityCertificate() ([]byte, error) {
	if s.DSA == nil {
		return nil, nil
	}
	t := time.Now()
	return dnp3.SelfSignedDSAAuthority(s.DSA, s.Name, t.Add(-time.Hour), t.AddDate(10, 0, 0))
}

type certifyReq struct {
	Outstation string          `json:"outstation"`
	Status     dnp3.UserStatus `json:"status"`
}

type keyReq struct {
	Outstation string `json:"outstation"`
	User       string `json:"user"`
	Key        []byte `json:"key"`
	Challenge  []byte `json:"challenge"`
}

type certReq struct {
	User      string `json:"user"`
	PublicKey []byte `json:"publicKey"`
	Days      int    `json:"days"`
}

type answer struct {
	CertData    []byte `json:"certData,omitempty"`
	Encrypted   []byte `json:"encrypted,omitempty"`
	Certificate []byte `json:"certificate,omitempty"`
	Method      uint8  `json:"method,omitempty"`
	NextSCS     uint32 `json:"nextSCS,omitempty"`
	Error       string `json:"error,omitempty"`
}

// ServeHTTP answers the authority protocol.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, err := s.master(r)
	if err != nil {
		reply(w, http.StatusUnauthorized, answer{Error: err.Error()})
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/authority":
		c, err := s.AuthorityCertificate()
		if err != nil {
			reply(w, http.StatusInternalServerError, answer{Error: err.Error()})
			return
		}
		reply(w, http.StatusOK, answer{Method: s.Method, Certificate: c, NextSCS: s.NextSCS(r.URL.Query().Get("outstation"))})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/certify":
		var q certifyReq
		if err := dec.Decode(&q); err != nil {
			reply(w, http.StatusBadRequest, answer{Error: err.Error()})
			return
		}
		c, err := s.Certify(m, q.Outstation, q.Status)
		s.record(Record{Master: m.Name, Outstation: q.Outstation, User: q.Status.Name, Action: "certify"}, err)
		if err != nil {
			reply(w, http.StatusForbidden, answer{Error: err.Error()})
			return
		}
		reply(w, http.StatusOK, answer{CertData: c})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/update-key":
		var q keyReq
		if err := dec.Decode(&q); err != nil {
			reply(w, http.StatusBadRequest, answer{Error: err.Error()})
			return
		}
		e, err := s.EncryptUpdateKey(m, q.Outstation, q.User, q.Key, q.Challenge)
		s.record(Record{Master: m.Name, Outstation: q.Outstation, User: q.User, Action: "update-key"}, err)
		if err != nil {
			reply(w, http.StatusForbidden, answer{Error: err.Error()})
			return
		}
		reply(w, http.StatusOK, answer{Encrypted: e})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/certificate":
		var q certReq
		if err := dec.Decode(&q); err != nil {
			reply(w, http.StatusBadRequest, answer{Error: err.Error()})
			return
		}
		c, err := s.Certificate(q.User, q.PublicKey, q.Days)
		s.record(Record{Master: m.Name, User: q.User, Action: "certificate"}, err)
		if err != nil {
			reply(w, http.StatusForbidden, answer{Error: err.Error()})
			return
		}
		reply(w, http.StatusOK, answer{Certificate: c})
	default:
		reply(w, http.StatusNotFound, answer{Error: "unknown request"})
	}
}

func reply(w http.ResponseWriter, code int, a answer) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(a)
}

// Client is a master's dnp3.Authority backed by a Server over HTTP(S).
type Client struct {
	URL   string // the server's base URL
	Token string
	// Outstation is the outstation the key changes are for.
	Outstation string
	// KeyChangeMethod is the authority's method (Fetch fills it).
	KeyChangeMethod uint8
	HTTP            *http.Client // nil: http.DefaultClient
	// Timeout bounds each request (zero: 10 s).
	Timeout time.Duration
}

var _ dnp3.Authority = (*Client)(nil)

func (c *Client) do(method, path string, in any) (answer, error) {
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return answer{}, err
		}
	}
	to := c.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.URL, "/")+path, &body)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	var a answer
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return answer{}, fmt.Errorf("authority answered %s: %w", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK {
		return a, fmt.Errorf("authority refused (%s): %s", resp.Status, a.Error)
	}
	return a, nil
}

// Fetch asks the authority for its method, certificate and the next
// status change sequence number for the client's outstation.
func (c *Client) Fetch() (method uint8, cert []byte, nextSCS uint32, err error) {
	a, err := c.do(http.MethodGet, "/v1/authority?outstation="+c.Outstation, nil)
	if err != nil {
		return 0, nil, 0, err
	}
	c.KeyChangeMethod = a.Method
	return a.Method, a.Certificate, a.NextSCS, nil
}

// Method is the key change method.
func (c *Client) Method() uint8 { return c.KeyChangeMethod }

// Certify asks the authority to certify a status change.
func (c *Client) Certify(u dnp3.UserStatus) ([]byte, error) {
	a, err := c.do(http.MethodPost, "/v1/certify", certifyReq{Outstation: c.Outstation, Status: u})
	return a.CertData, err
}

// EncryptUpdateKey asks the authority to encrypt a new update key.
func (c *Client) EncryptUpdateKey(name string, key, ostnChallenge []byte) ([]byte, error) {
	a, err := c.do(http.MethodPost, "/v1/update-key", keyReq{Outstation: c.Outstation, User: name, Key: key, Challenge: ostnChallenge})
	return a.Encrypted, err
}

// Certificate asks the authority for a g120v8 user certificate.
func (c *Client) Certificate(user string, spki []byte, days int) ([]byte, error) {
	a, err := c.do(http.MethodPost, "/v1/certificate", certReq{User: user, PublicKey: spki, Days: days})
	return a.Certificate, err
}
