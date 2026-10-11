#!/bin/sh
# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# serial.sh puts a peer's serial channel on a pty that socat bridges to TCP
# port 2410, in place of a serial line and a serial-to-IP converter; the
# test bridges its own pty to that port.
#
#   serial.sh outstation|master <baud> [key=value...]
set -e
role=$1
baud=$2
shift 2
socat pty,link=/tmp/tty0,raw,echo=0 tcp-listen:2410,reuseaddr &
while [ ! -e /tmp/tty0 ]; do sleep 0.05; done
exec "dnp3-$role" serial /tmp/tty0 "$baud" "$@"
