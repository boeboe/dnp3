package dnp3

import (
	"context"
	"sync/atomic"

	"github.com/cB-Sigma/iotsec"
)

// Security events of Secure Authentication that go to the application's
// security log (through SetAuditor) as well as the slog log: refused
// broadcasts, and the statistic limits of Table 7-6 when they act
// (7.5.2.2; IEEE 1815-2012 7.7.1 asks that dropping a connection be
// logged). No key material is ever included.
const (
	SecEventBroadcastRefused     = "dnp3_broadcast_refused"
	SecEventMaxAuthFailures      = "dnp3_max_authentication_failures"
	SecEventMaxReplyTimeouts     = "dnp3_max_reply_timeouts"
	SecEventMaxAuthRekeys        = "dnp3_max_authentication_rekeys"
	SecEventMaxRekeysDueRestarts = "dnp3_max_rekeys_due_to_restarts"
	SecEventMaxErrorMessages     = "dnp3_max_error_messages_sent"
)

type recorderBox struct{ r iotsec.Auditor }

var recorder atomic.Pointer[recorderBox]

// SetAuditor sets where Secure Authentication security events are
// recorded for the whole process (an application's security log); nil
// stops recording.
func SetAuditor(r iotsec.Auditor) {
	if r == nil {
		recorder.Store(nil)
		return
	}
	recorder.Store(&recorderBox{r})
}

// recordSecurity writes one security event, when a recorder is set.
func recordSecurity(tenant, subject, event string, detail map[string]string) {
	b := recorder.Load()
	if b == nil {
		return
	}
	b.r.RecordSecurity(context.Background(), iotsec.SecurityEvent{Tenant: tenant, Category: "communication", Event: event,
		Outcome: iotsec.OutcomeFailure, Actor: "system", Subject: subject, Method: "dnp3-sav5", Detail: detail})
}
