#!/bin/sh
# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# udp.sh runs the reference outstation on a UDP channel with fixed ports
# (it receives on 20000 and sends every datagram to 127.0.0.1:20001), and
# socat relays between those ports and the test's master, which reaches
# the container through its published UDP port 21000.
#
#   udp.sh [key=value...]
set -e
socat UDP4-LISTEN:21000,reuseaddr UDP4:127.0.0.1:20000,sourceport=20001 &
exec dnp3-outstation udp 20000 127.0.0.1 20001 "$@"
