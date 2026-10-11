# dnp3

DNP3 (IEEE Std 1815-2012) master and outstation in pure Go, with Secure Authentication version 5.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/dnp3.svg)](https://pkg.go.dev/github.com/cB-Sigma/dnp3) [![test](https://github.com/cB-Sigma/dnp3/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/dnp3/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24.0-00ADD8.svg)](go.mod)

The module has its own data link, transport and application layers, the
object library, file transfer, data sets and device attributes, over
TCP, TLS, UDP (including a fixed reply port) and serial lines, with
several outstations on one link. Secure Authentication v5 works on both
sides, with update key changes and g120v8 user certificates. It is built
on the standard library and goburrow/serial, without cgo. It was written
for SigmaM2M, a oneM2M platform, where it serves the DNP3 master and
outstation integrations.

## Features

| Feature | Status |
|---|---|
| Data link layer: block CRCs, resynchronisation, FCB/FCV, link reset, test, confirmed and unconfirmed user data, link status, self-address | yes |
| Transport function: segments of 1 to 249 octets, repeats dropped | yes |
| Application layer: every function code and qualifier of Table 4-6, sequence numbers, confirmations, multi-fragment and unsolicited responses | yes |
| Objects: binary, double-bit, binary output, counters, frozen counters, analogs, frozen analogs, analog outputs, their events (absolute or relative time), command events, deadbands, BCD, octet strings, virtual terminal, device storage, security statistics | yes; device profile objects are carried as raw data |
| Device attributes (group 0, set 0) | yes; other sets no |
| Time synchronisation (LAN and non-LAN) | yes; the outstation never sets the host clock |
| Freeze, freeze-and-clear, freeze at time, assign class, restarts, application control, activate configuration | yes |
| Sequential file transfer (both sides, with file authentication) | yes; outstation answers are always immediate |
| Data sets (g85 to g88) | yes |
| Pattern control blocks | binary outputs (g12v3) only, as the standard defines |
| Channels: TCP, TLS, UDP (including a fixed reply port), serial lines; several outstations on one link (multi-drop) | yes |
| Secure Authentication v5: session keys, challenge/reply, aggressive mode, HMAC-SHA-1/SHA-256 and AES-GMAC, the 18 statistics and their limits | yes |
| Update key change: symmetric methods 3 to 5, asymmetric 67 to 71 with g120v8 user certificates | yes; the authority's own protocol is outside the standard and not built |
| Secure Authentication v6 | no |
| Broadcast | outstation: per function code, critical requests only in verified aggressive mode under SA; master: never sends |
| Device profile document (XML) | no (an application's own) |
| Time-and-interval points (g50v4): class 0, reads, master writes | yes |
| Deadbands on analogs, analog outputs, counters and frozen counters | yes |
| A polling session on the master (`RunSession`): start-up sequence, periodic integrity polls and class scans, polls on IIN1.1 to 1.3, LAN or non-LAN time synchronisation when asked, start-up again after a restart | yes; requests of the application's own (controls, files) take turns with it |
| A measurement model on the master (mapping points to names and units) | no: the application's |

Security services come in through
[iotsec](https://github.com/cB-Sigma/iotsec): a TLS client or server
profile, a dialer, an auditor for security events and an IEC 62351-8
role authority. Each is optional; without them the module uses the
standard library and refuses only what needs the missing service (user
certificates need a role authority).

## Choosing a DNP3 library

Compared from each project's source and documentation at the versions
named, in October 2026. "Tested" means run against this module in the
interop tests below. Check the projects themselves before relying on a
row.

| | this module | opendnp3 3.1.2 | stepfunc dnp3 1.7.0 | Go alternatives |
|---|---|---|---|---|
| Language | Go, no cgo | C++11 (Java and .NET bindings) | Rust (C, C++, Java, .NET bindings) | none found with a master or an outstation |
| Licence | Apache-2.0 | Apache-2.0 | non-commercial and non-production only; commercial licence for sale | |
| Maintained | yes | no release since 2022 | yes | |
| Master and outstation | both (tested against opendnp3) | both | both | |
| TCP, TLS, UDP, serial | all four, each tested against opendnp3 both ways | all four (TLS through OpenSSL) | all four (TLS through rustls) | |
| Secure Authentication v5 | yes, both sides (tested against opendnp3 2.1.0-RC5's experimental SAv5) | no (an experimental version, in tags 2.1.0-RC1 to RC5, was moved out in RC6) | no | |
| File transfer | both sides | no (group 70 is only named) | master: read and write files, directories | |
| Device attributes (group 0) | yes | no | yes | |
| Data sets (groups 85 to 88) | yes | no | no | |
| Virtual terminal (groups 112, 113) | yes: codec, outstation ports | no (objects named only) | no | |
| Time-and-interval points (g50v4) | yes (tested against opendnp3) | yes | not checked | |
| Master scheduling (periodic scans, start-up sequence, automatic time sync) | yes (`RunSession`; tested against opendnp3) | yes | yes | |
| Event database with per-point configuration | yes (`PointDB`) | yes | yes | |
| Simulated outstation for tests | yes ([dnp3-sim](https://github.com/cB-Sigma/dnp3-sim)), with two vendor presets | demo programs | example programs | |

Pick this module for a Go program, for Secure Authentication v5, or for
file transfer, data sets and virtual terminal ports on both sides. Pick
stepfunc dnp3 when you can buy its commercial licence and want bindings
for several languages. Pick opendnp3 for a C++ or .NET code base that
already uses it and does not need Secure Authentication; it is no
longer released. A Go master or outstation other than this one
was not found (the Go DNP3 code that turns up in searches is scanner
plugins that send one link-status request).

## Install

```
go get github.com/cB-Sigma/dnp3@latest
```

Requires Go 1.24.0 or later.

## Quick start

```go
import "github.com/cB-Sigma/dnp3"

m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: "tcp://10.0.0.9:20000", MasterAddress: 1, OutstationAddress: 10})
frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0)) // integrity poll
for _, f := range frags {
	blocks, _ := dnp3.ParseObjects(f.Objects, true)
	// blocks[i].Points: group, variation, index, value, flags, time
}
latch, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
err = m.SelectOperate(ctx, latch, 5*time.Second, nil)
```

A polling session (start-up sequence, scans, time synchronisation) in
place of hand-made requests:

```go
go m.RunSession(ctx, dnp3.SessionConfig{Unsolicited: []int{1, 2, 3}, TimeSync: dnp3.TimeSyncLAN,
	Integrity: time.Hour, Scans: []dnp3.ClassScan{{Classes: []int{1}, Period: 5 * time.Second}},
	OnData: func(f dnp3.Fragment) { /* ParseObjects(f.Objects, true) */ }})
```

With Secure Authentication, and TLS from crypto/tls (or an IEC 62351-3
profile implementing `iotsec.TLSClient`):

```go
auth, _ := dnp3.NewAuth(&dnp3.AuthConfig{UpdateKey: updateKey, AggressiveMode: true})
m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: "tcp://rtu.example:19999", MasterAddress: 1, OutstationAddress: 10,
	Auth: auth, TLS: iotsec.StdTLS{Config: tlsConfig}})
err = m.ChangeSessionKeys(ctx)
```

The runnable examples are `ExampleNewAssociation` (an outstation polled
by the master) and `ExampleEncodeBlock`; dnp3-sim has a master against
the simulated outstation.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/dnp3

| Package | What it does |
|---|---|
| `dnp3` (module root) | Frames, segments and fragments; object encoding (`EncodeBlock`, `ParseObjects`); the master (`Dial`, `OpenChannel`, `Master.Request`, `SelectOperate`, `ChangeSessionKeys`, `ChangeUpdateKey`); the outstation (`PointDB`, `NewAssociation`, `OutstationNet`); Secure Authentication v5 (`NewAuth`, `NewOutstationAuth`); file transfer, data sets, device attributes |
| `interop` (nested module, tests only) | this module's master and outstation against opendnp3 3.1.2 and, for Secure Authentication v5, opendnp3 2.1.0-RC5, in Docker |

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments: these are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.
Code comments that cite `F-` numbers refer to SigmaM2M's register of
readings where the standard or a vendor profile leaves a choice open;
PROVENANCE.md explains them. The tests that drive the simulated
outstation are in [dnp3-sim](https://github.com/cB-Sigma/dnp3-sim), so
this module does not depend on its simulator.

`interop/` is a nested module with its own go.mod. It builds two
reference images in Docker and runs this module against them: opendnp3
3.1.2 with OpenSSL (TLS) and socat (`interop/peer`), and opendnp3
2.1.0-RC5, the last opendnp3 tag that carried its experimental Secure
Authentication v5 module, on Debian 9 with OpenSSL 1.0.2
(`interop/peer-sa`). The peer programs are ours; opendnp3 is built from
its own sources inside the containers. The tests are skipped unless
`SIGMA_DNP3_INTEROP=1` is set and Docker is running:

```
cd interop && SIGMA_DNP3_INTEROP=1 go test -race -v ./...
```

### Interop tested against

Run on 2026-10-11 on macOS with Docker Desktop; every item below passed.

opendnp3 3.1.2 (Apache-2.0), this module's master against opendnp3's
outstation:

| Area | What was checked |
|---|---|
| Channels | TCP; TLS 1.2 and TLS 1.3 with mutual certificates (crypto/tls against OpenSSL), and the connection refused when our certificate comes from a CA the outstation does not trust; UDP from a fixed local port; a serial line: this module opens a real pty whose bytes reach opendnp3's serial channel on its own pty through socat |
| Static data | integrity poll with g1v2, g3v2, g10v2, g20v1, g21v5, g30v5, g40v3, g50v4, g110 (every type, decoded and checked); an integrity poll split by opendnp3 into fragments of at most 249 octets, each confirmed |
| Events | g2v2, g2v3 and g4v3 after a common time of occurrence (g51), g4v2, g11v2, g22v1, g22v5, g23v5, g32v5, g32v7, g42v5, g42v7, g111; times within 5 s of the change; class polls return only their class; events cleared by our confirmation |
| Unsolicited | enabled and confirmed; with our first confirmation dropped by a proxy, opendnp3 repeats the response with the same sequence number, we confirm the repeat and the event is cleared |
| Functions | clear restart; non-LAN and LAN time synchronisation (to the millisecond, IIN1.4 cleared); immediate freeze, freeze and clear, freeze without response; cold and warm restart (g52v2 1500 ms, g52v1 3 s); assign class; WRITE of g50v4 |
| Controls | CROB select-before-operate, direct operate and pulse (count, on and off times); analog outputs g41v1, g41v2, g41v3 and g41v4; a CROB and an analog output in one select-before-operate |
| Link layer | confirmed user data (one link reset, FCB alternating, every frame acknowledged); REQUEST_LINK_STATUS both ways (our keep-alive answered, opendnp3's answered by us) |
| Polling session | `RunSession` start-up (disable unsolicited, clear restart, integrity, LAN or non-LAN time synchronisation, enable unsolicited), unsolicited events, a periodic class 3 scan |

opendnp3 3.1.2, opendnp3's master against this module's outstation:

| Area | What was checked |
|---|---|
| Channels | TCP; TLS 1.2 and 1.3 (OpenSSL client, our crypto/tls server requiring client certificates); UDP; a serial line on a real pty here |
| Start-up | opendnp3's sequence in non-LAN and LAN time-sync modes: disable unsolicited, our null unsolicited response confirmed, clear restart, integrity poll, time synchronisation, enable unsolicited |
| Data | static g1v2, g3v2, g10v2, g20v1, g21v1, g30v5, g40v3, g50v4, g110; unsolicited events g2v2, g4v2, g11v2, g22v5, g42v7, g111 with their times to the millisecond; frozen counters after IMMED_FREEZE, FREEZE_CLEAR and IMMED_FREEZE_NR, read back as g21 |
| Functions | WRITE of g50v4 and a range read of it; cold and warm restart; integrity and class polls |
| Controls | CROB select-before-operate, direct operate and pulse; analog outputs g41v1 to g41v4; a CROB and an analog output in one request; each reported SUCCESS by opendnp3 and seen by our handler with the values sent |
| Link layer and loss | opendnp3's REQUEST_LINK_STATUS keep-alive answered; with opendnp3's confirmation of our unsolicited response dropped, we repeat it with the same sequence number and the event is cleared once confirmed |

opendnp3 2.1.0-RC5 (Apache-2.0; its SAv5 module was marked experimental),
Secure Authentication v5:

| Direction | What was checked |
|---|---|
| Our master, opendnp3's outstation | session key status and session key change; challenges of critical requests answered with HMAC-SHA-256/16, HMAC-SHA-256/8, HMAC-SHA-1/10 and HMAC-SHA-1/8; AES-128 and AES-256 key wrap; direct operate and select-before-operate carried out after the challenge; every request challenged (the outstation's "authenticate everything" setting); a wrong update key refused with error 1 |
| opendnp3's master, our outstation | opendnp3's session key change, start-up and integrity poll; a CROB direct operate and an analog output challenged by us, answered by opendnp3 and carried out for user 1; MAC algorithms HMAC-SHA-256/16, HMAC-SHA-1/10, HMAC-SHA-256/8; AES-128 and AES-256 key wrap |
| Aggressive mode | opendnp3's outstation does not take aggressive mode: it challenges the request and then refuses its g120v3 object with IIN2.2. Our master falls back to challenges at once and the operation is carried out exactly once (tested). Aggressive mode itself is checked only against this module's own outstation |

Defects of the reference peers met on the way (not ours; recorded so
nobody chases them): opendnp3 3.1.2's master reads g52v1 (seconds) as
milliseconds when reporting a restart time; its UDP channel loses its
bound local port when the remote is given as a host name (asio's range
connect reopens the socket), so the peer programs resolve names first;
its master reports g111 octet string events with the event flag clear.

Not tested against an independent implementation:

- File transfer (group 70): opendnp3 only names the objects; stepfunc
  dnp3 (master only) was not run because of its licence.
- Data sets (groups 85 to 88), device attributes (group 0), virtual
  terminal ports: neither opendnp3 version implements them.
- Secure Authentication update key change (symmetric and asymmetric),
  g120v8 user certificates and aggressive mode: opendnp3 2.1.0-RC5 has
  a symmetric update key change on its master, not run here; only this
  module's own master and outstation exercise them.
- Real serial hardware (ptys and socat stand in), multi-drop serial
  lines with several outstations, IPv6.
- stepfunc dnp3 was not run: its licence allows only non-commercial,
  non-production use.
- In process: the simulated outstation and the vendor presets of
  dnp3-sim (same author, so not independent).

Defects of this module found by these tests and fixed in v0.2.0 are in
CHANGELOG.md.

## Related repositories

- [dnp3-sim](https://github.com/cB-Sigma/dnp3-sim): a simulated
  outstation with fault switches and two vendor presets, as a Go package
  and a command.
- [iotsec](https://github.com/cB-Sigma/iotsec): the security seams.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
