// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package dnp3 is DNP3 (IEEE Std 1815-2012) in pure Go: a master and an
// outstation over TCP (optionally TLS), UDP or a serial line, with their
// own data link, transport and application layers, the object library,
// and Secure Authentication version 5 on both sides.
//
// The layers:
//
//   - Data link (link.go, clause 9): frames with block CRCs, a parser that
//     resynchronises after noise, primary and secondary stations with
//     FCB/FCV state, confirmed and unconfirmed user data, link status.
//   - Transport (transport.go, clause 8): segmenting and reassembly.
//   - Application (app.go, objects.go, clauses 4 to 6 and 11, Annex A):
//     fragments, function codes, qualifiers, internal indications, and
//     object encoding and decoding (static, event, command, frozen,
//     octet string, file, data set, device attribute and security
//     objects).
//   - Master (master.go): Dial a MasterConfig, then Request, SelectOperate,
//     ChangeSessionKeys and ChangeUpdateKey; unsolicited responses are
//     confirmed and handed to OnUnsolicited.
//   - Outstation (outstation.go, outdb.go, outfile.go, outnet.go): a
//     PointDB with per-class event buffers (EventStore makes them
//     durable), an Association per master that answers polls, controls,
//     time synchronisation, freeze, file transfer, data sets and
//     unsolicited reporting through a Handler, and an OutstationNet that
//     routes frames from streams (TCP, TLS, serial) and UDP sockets.
//   - Secure Authentication v5 (auth.go, ostauth.go, updatekey.go,
//     gmac.go, usercert.go, clause 7): session keys, challenges and
//     replies, aggressive mode, the security statistics and their limits,
//     update key change (symmetric and asymmetric), and g120v8 user
//     certificates read through an IEC 62351-8 role authority.
//
// Security services come in through the small interfaces of
// github.com/cB-Sigma/iotsec:
// a TLS client or server profile (MasterConfig.TLS; the outstation's
// listener is the caller's), a Dialer, an Auditor for security events
// (SetAuditor) and a RoleAuthority for user certificates
// (OutstationAuthConfig.Roles). Each is optional.
//
// A simulated outstation for tests, with a command that serves it, is
// the separate module github.com/cB-Sigma/dnp3-sim.
package dnp3
