package dnp3

import (
	"bytes"
	"testing"
)

// Covers: SIG-IPE-2672
func TestSecureAuthenticationProfileLimits(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 16)
	oa, err := NewOutstationAuth(OutstationAuthConfig{Users: []OutstationUser{{Number: UserDefault, UpdateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	// 1.12.20: the outstation's challenge data (key status) is 4 octets.
	oa.mu.Lock()
	ks, err := ParseKeyStatus(oa.keyStatus(oa.users[UserDefault]))
	oa.mu.Unlock()
	if err != nil || len(ks.Challenge) != 4 {
		t.Fatalf("key status challenge: %v %d", err, len(ks.Challenge))
	}
	// 1.12.21: error messages stop after 2 by default; the g122
	// thresholds are those of Table 7-6.
	if oa.cfg.MaxErrors != 2 || oa.cfg.MaxKeyStatus != 5 {
		t.Errorf("limits %d %d", oa.cfg.MaxErrors, oa.cfg.MaxKeyStatus)
	}
	want := [NumSecurityStatistics]uint32{3, 5, 5, 3, 3, 100, 100, 100, 100, 10, 2, 10, 100, 10, 5, 1, 1, 3}
	if statThresholds != want {
		t.Errorf("thresholds %v", statThresholds)
	}
	// The master's challenges of responses carry 16 octets.
	a, err := NewAuth(&AuthConfig{User: UserDefault, UpdateKey: mustKey("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"), ChallengeResponses: true})
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseFragment(a.challengeResponse(3))
	if err != nil {
		t.Fatal(err)
	}
	v, d, err := ParseAuthObject(f.Objects)
	if err != nil || v != AuthChallenge {
		t.Fatalf("challenge object %d %v", v, err)
	}
	c, err := ParseChallenge(d)
	if err != nil || len(c.Data) != 16 {
		t.Fatalf("master challenge: %v %d", err, len(c.Data))
	}
}
