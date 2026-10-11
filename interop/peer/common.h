// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0
//
// Shared parts of the reference peers: output lines and channels.
//
// A channel is named on the command line, followed by key=value options:
//
//   tcp <port>                          outstation: listen on 0.0.0.0:<port>
//   tcp <host> <port>                   master: connect
//   tls <port> | tls <host> <port>      the same over TLS (/certs/ca.pem,
//                                       /certs/peer.pem, /certs/peer.key);
//                                       option tls=1.2 or tls=1.3 limits the
//                                       version
//   udp <local port> <host> <port>      datagrams from and to fixed ports
//   serial <device> <baud>              8N1, no flow control

#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/IChannelListener.h>
#include <opendnp3/gen/ChannelState.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

using namespace opendnp3;

static std::mutex out;

static void say(const std::string& s)
{
    std::lock_guard<std::mutex> l(out);
    std::cout << "PEER " << s << std::endl;
}

class ChannelEvents final : public IChannelListener
{
public:
    void OnStateChange(ChannelState state) override
    {
        say(std::string("CHANNEL ") + ChannelStateSpec::to_string(state));
    }
};

static std::map<std::string, std::string> options;

static std::string option(const std::string& key, const std::string& def)
{
    auto it = options.find(key);
    return it == options.end() ? def : it->second;
}

static std::string hex(const uint8_t* data, std::size_t n)
{
    std::ostringstream s;
    for (std::size_t i = 0; i < n; i++)
        s << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    return s.str();
}

// numeric is the first IPv4 address of a host name (the name itself when
// it does not resolve).
static std::string numeric(const std::string& host)
{
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr)
        return host;
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return buf;
}

static TLSConfig tlsConfig()
{
    const auto v = option("tls", "");
    return TLSConfig("/certs/ca.pem", "/certs/peer.pem", "/certs/peer.key", false, false, v != "1.3", v != "1.2");
}

// channel opens the channel named by argv[first...] and reads the key=value
// options after it.
static std::shared_ptr<IChannel> channel(DNP3Manager& m, bool master, int argc, char* argv[], int first)
{
    std::vector<std::string> a;
    for (int i = first; i < argc; i++)
    {
        std::string s = argv[i];
        auto eq = s.find('=');
        if (eq != std::string::npos)
            options[s.substr(0, eq)] = s.substr(eq + 1);
        else
            a.push_back(s);
    }
    if (a.empty())
        throw std::runtime_error("no channel");
    const auto levels = levels::NORMAL | levels::ALL_APP_COMMS;
    const auto listener = std::make_shared<ChannelEvents>();
    const auto& kind = a[0];
    if ((kind == "tcp" || kind == "tls") && !master && a.size() >= 2)
    {
        IPEndpoint ep("0.0.0.0", static_cast<uint16_t>(std::atoi(a[1].c_str())));
        if (kind == "tls")
            return m.AddTLSServer("server", levels, ServerAcceptMode::CloseExisting, ep, tlsConfig(), listener);
        return m.AddTCPServer("server", levels, ServerAcceptMode::CloseExisting, ep, listener);
    }
    if ((kind == "tcp" || kind == "tls") && master && a.size() >= 3)
    {
        std::vector<IPEndpoint> hosts{IPEndpoint(a[1], static_cast<uint16_t>(std::atoi(a[2].c_str())))};
        if (kind == "tls")
            return m.AddTLSClient("client", levels, ChannelRetry::Default(), hosts, "0.0.0.0", tlsConfig(), listener);
        return m.AddTCPClient("client", levels, ChannelRetry::Default(), hosts, "0.0.0.0", listener);
    }
    if (kind == "udp" && a.size() >= 4)
    {
        // opendnp3 3.1.2 resolves a host name with asio's range connect,
        // which reopens the socket and loses its bound local port; give it
        // an address.
        return m.AddUDPChannel("udp", levels, ChannelRetry::Default(),
                               IPEndpoint("0.0.0.0", static_cast<uint16_t>(std::atoi(a[1].c_str()))),
                               IPEndpoint(numeric(a[2]), static_cast<uint16_t>(std::atoi(a[3].c_str()))), listener);
    }
    if (kind == "serial" && a.size() >= 3)
    {
        SerialSettings s;
        s.deviceName = a[1];
        s.baud = std::atoi(a[2].c_str());
        s.dataBits = 8;
        s.stopBits = StopBits::One;
        s.parity = Parity::None;
        s.flowType = FlowControl::None;
        return m.AddSerial("serial", levels, ChannelRetry::Default(), s, listener);
    }
    throw std::runtime_error("bad channel arguments");
}
