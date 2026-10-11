# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go from IEEE Std 1815-2012
(DNP3), read in a licensed copy, and the RFCs and public documents in the
table. No code was ported or copied from another implementation. Codes,
octet layouts, bit positions, table orders and procedures are facts every
implementation must use; the code around them (Go types, goroutines and
channels, the point database, error handling) is our own design. No text
of the standard is reproduced; comments cite clause, table and annex
numbers in our own words.

The code came with SigmaM2M's baseline (2026-09-27) and was extended in
later SigmaM2M work (Release 4 on 2026-09-27; the IEC 62351-3 keepalive
on idle TLS links and the UDP reply-port fix on 2026-10-06). It became a
module of its own on 2026-10-06. On 2026-10-11 the simulated outstation,
its command and the tests that drive it moved to the separate module
dnp3-sim, so this module does not depend on its simulator, and the
opendnp3 interop tests (interop/) were added. Version 0.2.0 (2026-10-11)
added the polling session (session.go), time-and-interval points
(timeinterval.go), virtual terminal ports (vterm.go) and counter
deadbands, and fixed the defects the extended interop tests found
(CHANGELOG.md). Version 0.3.0 (2026-10-12) added the gateway (gateway/),
the device profile writer and reader (profile/), the update key
authority service (authority/) and the event modes, flags-only updates
and buffer policies of the point database, all written from the clauses
below; which database features to add was decided by comparing with the
features opendnp3 3.1.2's outstation database offers through its public
API (event modes, buffer sizes per type, overflow behaviour), not by
reading its implementation.

## Notes on open readings (F- numbers)

Where IEEE 1815-2012 leaves an encoding or a reading open, or a vendor
profile contradicts itself, the choice made was recorded in SigmaM2M's
register of findings, and code comments cite its numbers. Each is
explained here in our words:

| Note | Where | Choice |
|---|---|---|
| F-580 | session key change | the key change sequence number is carried in four octets, as in the key status object it must match |
| F-582 | file authentication | the authentication object's size is taken from its contents, not from the example's size prefix |
| F-585 to F-587 | update key change | certification data and confirmation MACs are the full HMAC output; DSA signatures are DER-encoded; the encrypted update key data is the user name, the key and the outstation's challenge data concatenated and zero-padded to a multiple of 8 octets for AES key wrap |
| F-592, F-593 | AES-GMAC | the IV fields go least significant octet first like every DNP3 integer; a user status change, made before the user has a number, uses user number 0 |
| F-601 | file transfer | an open for writing is answered with the announced file size, as the example shows |
| F-1464, F-1465 | Secure Authentication failures | the outstation, which never rekeys, drops the connection once its failure limit is passed; the master asks for new session keys after an error object from the outstation as well as after the failure limit |

The notes on the two vendor profiles (F-605 to F-608, F-1450 to F-1455)
are in dnp3-sim, which holds the presets.

## Sources

| Area (files) | Followed | Read for facts only (no code taken) |
|---|---|---|
| Data link layer (link.go) | IEEE 1815-2012 clause 9 (frame format, FCB/FCV, primary and secondary stations, link status, reserved and broadcast addresses, self-address 0xFFFC) and Annex E (CRC) | none |
| Transport function (transport.go) | clause 8 | none |
| Application layer, objects (app.go, objects.go, attributes.go, file.go, dataset.go, activate.go) | clauses 4 to 6 (function codes, qualifiers, IIN, procedures, file transfer, data sets, device attributes), clauses 11 and 12 and Annex A (object library) | none |
| Master (master.go, channel.go, udppeer.go) | clauses 4, 9 and 13 (TCP and UDP; the TCP keep-alive of 13.2.3.3.1); the UDP reply port follows the "destination UDP port for responses" item of the DNP Users Group device profile template | none |
| Outstation (outstation.go, outdb.go, outfile.go, outnet.go) | clauses 4 to 6, 9 and 13 | none |
| Secure Authentication v5 (auth.go, ostauth.go, updatekey.go, gmac.go, events.go) | clause 7 and Annex A.45 to A.47; RFC 3394 (AES key wrap); RFC 2104 (HMAC); NIST SP 800-38D (GCM, for AES-GMAC) | none |
| User certificates (usercert.go) | IEEE 1815-2012 A.45.8 (g120v8); IEC 62351-8 for the IECUserRoles extension OIDs (the token itself is read by the caller's iotsec.RoleAuthority) | none |
| Serial lines (channel.go) | none (URL parameters are our own) | github.com/goburrow/serial is a dependency, not a source |
| Polling session (session.go), time-and-interval points (timeinterval.go), virtual terminal ports (vterm.go) | IEEE 1815-2012 clauses 4 and 5 (start-up, class polls, time synchronisation procedures), Annex A (g50v4, g112, g113) | none; the session's task order matches what opendnp3's master does at start-up, observed as a peer, not read from its code |
| Gateway (gateway/) | clauses 4 and 11 (control procedures, the 4.4.4.3 rule that an operate follows its select directly, status codes; the ONLINE, RESTART and COMM_LOST flags). A data concentrator's behaviour is no standard's; the mapping, the passing of events and controls and the offline marking are our design | none |
| Device profile (profile/) | IEEE 1815-2012 clause 14 (device profile) and the DNP Users Group's XML device profile, as far as its data points list and configuration items go; element names as we read the published schema 2.x; documents are not validated against it | SigmaM2M's own profile writer is a separate, template-shaped document of the IPE, not this one |
| Update key authority (authority/) | clause 7.5.4 and Annex A.45 (what the authority certifies and encrypts, the status change sequence number); the master–authority protocol is not standardised, and the HTTP/JSON one here is our own | none |
| Interop peers (interop/peer, interop/peer-sa) | the public C++ APIs and example programs of opendnp3 3.1.2 and opendnp3 2.1.0-RC5 (its secauth examples), read to write our peer programs | the peer programs are ours; opendnp3 and standalone asio 1.10.8 are built from their own sources in the test containers; a few opendnp3 source files were read only to explain behaviour seen in the tests (UDPClient.cpp, RestartOperationTask.cpp, OutstationContext.cpp) |

## Other DNP3 implementations

Open implementations of DNP3 include opendnp3 (C++, Apache-2.0), the Rust
`dnp3` crate of Step Function I/O (source available under a
non-commercial, non-production licence) and pydnp3 (Python bindings of
opendnp3). None of them was read for the library code. On 2026-10-06 I
searched the module for their characteristic identifiers (for example
APDUHeader, IINField, LinkLayerParser, TransportRx, OContext, MContext,
GroupVariation, ControlRelayOutputBlock, EventBufferConfig) and for
porting or attribution comments, and found none. The CRC table is
computed from the polynomial at start-up, as the standard describes it.
The owner decided on 2026-10-06 that no line-by-line comparison with
those projects is needed; these notes are the record.

On 2026-10-11 opendnp3 3.1.2 was used as an independent test peer
(interop/): its public headers and examples were read to write the peer
programs, after the library code existed. The Step Function I/O crate
was not built or run, because its licence restricts use to
non-commercial, non-production purposes; its public README and change
log were read for the comparison in README.md.

For Secure Authentication v5 an open peer was looked for: pydnp3 wraps
opendnp3 3.x and has none; opendnp3's history shows an experimental
SAv5 module in tags 2.1.0-RC1 to 2.1.0-RC5 (Apache-2.0), moved to a
"secauth" branch in RC6 that is no longer published. RC5 was built and
used as the SAv5 peer (interop/peer-sa) after the library code existed.

## Test vectors and where they come from

| Test | Source |
|---|---|
| ieee1815_test.go, codec_test.go | the octet examples of IEEE 1815-2012 that each test names (clause 4 function code examples, the 9.2.4.3 frame, the Annex E CRC table entries, the clause 8 segmenting example, read and write examples); codec_test's reference CRC is an independent bit-by-bit implementation |
| outfile_test.go, outstation_test.go | the file transfer examples and the data set examples (5.4.12, 5.4.13) of IEEE 1815-2012 |
| gaps_test.go (TestDNP3AuthPrimitives) | RFC 3394 section 4 (4.1, 4.3, 4.6), RFC 4231 test case 2, RFC 2202 test case 2 |
| ostauth_test.go (TestAESGMAC) | the AES-GCM tag of an all-zero key and IV with no data (NIST SP 800-38D test case 1), computed through Go's crypto/cipher |
| interop/ | opendnp3 3.1.2 as master and outstation (TCP, TLS, UDP, serial), and on both sides of the gateway (roles_test.go); opendnp3 2.1.0-RC5 as SAv5 master and outstation |
| v030_test.go, authority_test.go, gateway/, profile/ | this module's master and outstation against each other and the authority service in memory, with expectations from the clauses named above |
| v020_test.go, session_test.go | this module's master and outstation, and hand-built frames (rawMaster, the fake outstation of TestLinkConfirmWhileFramesArrive) reproducing what opendnp3 sent in the interop tests |
| every other test and example_test.go | the master and the outstation of this module against each other, written from the same standard; not a real device |

All keys, passwords, certificates and addresses in the tests are made-up
demo values.
