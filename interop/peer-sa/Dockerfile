# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Secure Authentication v5 reference peers for the interop tests:
# opendnp3 2.1.0-RC5 (Apache-2.0, github.com/dnp3/opendnp3), the last tag
# that carried its experimental SAv5 module (moved out in 2.1.0-RC6), built
# from source against OpenSSL 1.0.2, which its crypto wrapper was written
# for, on Debian 9 with standalone asio 1.10.8 (Boost Software License).
# The library sources are compiled directly (the release's CMake files
# need a newer CMake than Debian 9 can install beside OpenSSL 1.0); sa.cpp
# of this directory is linked against them.
#
#   docker build -t sigma-dnp3-interop:opendnp3-2.1.0-rc5-sa .

FROM debian:bookworm-slim AS source
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 2.1.0-RC5 https://github.com/dnp3/opendnp3 /src/opendnp3 \
 && git clone --depth 1 --branch asio-1-10-8 https://github.com/chriskohlhoff/asio /src/asio

FROM debian:stretch AS build
RUN echo "deb http://archive.debian.org/debian stretch main" > /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends g++ libssl1.0-dev \
 && rm -rf /var/lib/apt/lists/*
COPY --from=source /src/opendnp3 /src/opendnp3
COPY --from=source /src/asio/asio/include /src/asio
WORKDIR /src/opendnp3
RUN mkdir /obj \
 && find cpp/libs/src/openpal cpp/libs/src/opendnp3 cpp/libs/src/asiodnp3 cpp/libs/src/secauth cpp/libs/src/osslcrypto -name '*.cpp' > /srcs \
 && find cpp/libs/src/asiopal -maxdepth 1 -name '*.cpp' >> /srcs \
 && xargs -P 4 -I SRC sh -c 'g++ -O1 -std=c++11 -DASIO_STANDALONE -DOPENDNP3_USE_SECAUTH -I/src/asio -Icpp/libs/src -Icpp/libs/include -c SRC -o /obj/$(echo SRC | tr / _).o' < /srcs \
 && ar rcs /usr/local/lib/libdnp3sa.a /obj/*.o
COPY sa.cpp /peer/
RUN g++ -O1 -std=c++11 -DASIO_STANDALONE -DOPENDNP3_USE_SECAUTH -I/src/asio -Icpp/libs/include -o /usr/local/bin/dnp3-sa /peer/sa.cpp \
    /usr/local/lib/libdnp3sa.a -lssl -lcrypto -lpthread
