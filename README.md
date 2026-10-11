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
| A polling scheduler and a measurement model on the master | no: the master is request-level (`Request`, `SelectOperate`); scheduling and mapping are the application's |

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
| TCP, TLS, UDP, serial | all four | all four (TLS through OpenSSL) | all four (TLS through rustls) | |
| Secure Authentication v5 | yes, both sides | no (an experimental version was moved out in 2.1.0) | no | |
| File transfer | both sides | no | master: read and write files, directories | |
| Device attributes (group 0) | yes | no | yes | |
| Data sets (groups 85 to 88) | yes | no | no | |
| Master scheduling (periodic scans, start-up sequence, automatic time sync) | no, request-level | yes | yes | |
| Event database with per-point configuration | yes (`PointDB`) | yes | yes | |
| Simulated outstation for tests | yes ([dnp3-sim](https://github.com/cB-Sigma/dnp3-sim)), with two vendor presets | demo programs | example programs | |

Pick this module for a Go program, for Secure Authentication v5, or for
file transfer and data sets on both sides. Pick stepfunc dnp3 when you
can buy its commercial licence and want a maintained, scheduled master
with bindings for several languages. Pick opendnp3 for a C++ or .NET
code base that already uses it and does not need Secure Authentication;
it is no longer released. A Go master or outstation other than this one
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
| `interop` (nested module, tests only) | this module's master and outstation against opendnp3 in Docker |

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

`interop/` is a nested module with its own go.mod. It builds opendnp3
3.1.2 and two small programs on it (`interop/peer`) in a Debian
container and runs this module against them. It is skipped unless
`SIGMA_DNP3_INTEROP=1` is set and Docker is running:

```
cd interop && SIGMA_DNP3_INTEROP=1 go test -v ./...
```

### Interop tested against

opendnp3 3.1.2 (Apache-2.0), built from source in Docker, on
2026-10-11:

- This module's master against opendnp3's outstation (TCP): integrity
  poll (g1v2, g3v2, g10v2, g20v1, g21v1, g30v5, g40v1, g50v4, g110v1
  decoded), clearing the restart indication, non-LAN and LAN time
  synchronisation (the outstation's clock within 1 ms of the written
  time, IIN1.4 cleared), class 1, 2 and 3 polls returning only their
  class's events (g2v2, g32v5, g22v1), events cleared by our
  confirmation, unsolicited responses enabled and confirmed, CROB
  select-before-operate and direct operate, analog output (g41v3)
  select-before-operate. All passed.
- opendnp3's master against this module's outstation (TCP), in non-LAN
  and LAN time-sync modes: opendnp3's start-up sequence (disable
  unsolicited, our null unsolicited response confirmed, clear restart,
  integrity poll, time synchronisation, enable unsolicited), an
  unsolicited event confirmed by opendnp3, integrity and class polls,
  CROB select-before-operate and direct operate, analog output
  select-before-operate, each reported SUCCESS by opendnp3. All passed.
- Not tested against a reference: Secure Authentication v5 (opendnp3
  3.x and stepfunc dnp3 do not implement it), TLS, UDP, serial lines,
  file transfer, data sets. stepfunc dnp3 was not run: its licence
  allows only non-commercial, non-production use.
- In process: the simulated outstation and the vendor presets of
  dnp3-sim (same author, so not independent).

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
