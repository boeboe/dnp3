# Changelog

## v0.2.0 (2026-10-11)

Interop tests extended to TLS, UDP and serial lines, every object type
opendnp3 3.1.2 serves, freezes, restarts, the link layer, lost
confirmations, and Secure Authentication v5 against opendnp3 2.1.0-RC5
(see README.md, "Interop tested against"). The API only grew.

Added:

- `Master.RunSession` and `SessionConfig`: start-up sequence, periodic
  integrity polls and class scans, polls on IIN1.1 to 1.3, an integrity
  poll after an event buffer overflow, time synchronisation when asked,
  start-up again after a restart. `Master.SyncTime` runs the LAN or
  non-LAN procedure on its own.
- Time-and-interval points (g50v4): `PointDB.SetTimeAndInterval`,
  `PointDB.TimeAndInterval`, served in class 0 and to reads, written by
  the master (`TimeAndIntervalHandler`).
- Virtual terminal ports (g112, g113): `PointDB.VirtualTerminalOutput`,
  `VirtualTerminalHandler`.
- Deadbands on counters and frozen counters (`DBPoint.Deadband`).
- `OutstationConfig.UnsolOffline`.

Fixed:

- With `LinkConfirm`, the master's read loop waited for the sender to
  answer a frame (an unsolicited response to confirm, a link status
  request) while the sender held the link waiting for the acknowledgement
  the read loop had not read: every confirmed request timed out against
  opendnp3. Answers from the read loop now go out in order from their own
  goroutine.
- An outstation unsolicited series that ended unconfirmed (no retries
  left) left its events buffered until another event arrived; a new
  series now carries them after `UnsolOffline`.
- A time never set (or before 1970) was encoded as a wrapped 48-bit
  value; it is now 0.
- Closing a serial port while it was being read was a data race in
  goburrow/serial (found by `go test -race` on a pty); the port opened by
  `OpenSerial` now waits for the read in progress.
- A master in aggressive mode facing an outstation that refuses g120v3
  as an unknown or malformed object (opendnp3's experimental SAv5) failed
  every critical request; it now stops using aggressive mode with that
  outstation and sends the request again with a challenge.

## v0.1.0 (2026-10-11)

First release.
