# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Reference DNP3 peers for the interop tests: opendnp3 3.1.2 (Apache-2.0,
# github.com/dnp3/opendnp3) built from source with TLS (OpenSSL), with the
# small master and outstation programs of this directory linked against
# it. socat puts a serial channel on a pty bridged to TCP.
#
#   docker build -t sigma-dnp3-interop:opendnp3-3.1.2 .

FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends g++ cmake make git ca-certificates libssl-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 3.1.2 https://github.com/dnp3/opendnp3 /src/opendnp3
RUN cmake -S /src/opendnp3 -B /build -DCMAKE_BUILD_TYPE=Release -DDNP3_STATIC_LIBS=ON -DDNP3_TLS=ON \
 && cmake --build /build -j4 \
 && cmake --install /build
COPY outstation.cpp master.cpp common.h /peer/
RUN g++ -O2 -std=c++14 -o /usr/local/bin/dnp3-outstation /peer/outstation.cpp -lopendnp3 -lssl -lcrypto -lpthread \
 && g++ -O2 -std=c++14 -o /usr/local/bin/dnp3-master /peer/master.cpp -lopendnp3 -lssl -lcrypto -lpthread

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/dnp3-outstation /usr/local/bin/dnp3-master /usr/local/bin/
COPY serial.sh udp.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/serial.sh /usr/local/bin/udp.sh
