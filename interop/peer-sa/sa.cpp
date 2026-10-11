// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0
//
// Secure Authentication v5 reference peers on opendnp3 2.1.0-RC5
// (Apache-2.0), the last opendnp3 tag that carried its experimental SAv5
// module, for the interop tests:
//
//   dnp3-sa outstation [key=value...]           listens on 0.0.0.0:20000
//   dnp3-sa master <host> <port> [key=value...]
//
// Outstation 10, master 1, the default user (1) with an update key of 16
// (key=128) or 32 (key=256) octets all equal to keybyte (hex, default 5a).
// Options: mac=sha1-8|sha1-10|sha256-8|sha256-16 (default sha256-16),
// challenge=all|critical (outstation: what it challenges; default
// critical).
//
// Results are printed on lines starting with "PEER ". Commands on
// standard input:
//
//   outstation: bin <index> <0|1> | ana <index> <value> | quit
//   master:     integrity | class1 | do <index> | sbo <index>
//               | ao <index> <value> | quit

#include <asiodnp3/ConsoleLogger.h>
#include <asiodnp3/DNP3Manager.h>
#include <asiodnp3/MeasUpdate.h>
#include <asiopal/UTCTimeSource.h>
#include <opendnp3/LogLevels.h>
#include <opendnp3/app/ControlRelayOutputBlock.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>
#include <osslcrypto/CryptoProvider.h>
#include <secauth/outstation/IOutstationApplicationSA.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <cstdlib>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>

using namespace openpal;
using namespace asiopal;
using namespace asiodnp3;
using namespace opendnp3;
using namespace secauth;

static std::mutex out;

static void say(const std::string& s)
{
    std::lock_guard<std::mutex> l(out);
    std::cout << "PEER " << s << std::endl;
}

static std::map<std::string, std::string> options;

static std::string option(const std::string& key, const std::string& def)
{
    auto it = options.find(key);
    return it == options.end() ? def : it->second;
}

static UpdateKey updateKey()
{
    const auto b = static_cast<uint8_t>(std::strtoul(option("keybyte", "5a").c_str(), nullptr, 16));
    return UpdateKey(b, option("key", "128") == "256" ? KeyWrapAlgorithm::AES_256 : KeyWrapAlgorithm::AES_128);
}

static HMACMode macMode()
{
    const auto m = option("mac", "sha256-16");
    if (m == "sha1-8")
        return HMACMode::SHA1_TRUNC_8;
    if (m == "sha1-10")
        return HMACMode::SHA1_TRUNC_10;
    if (m == "sha256-8")
        return HMACMode::SHA256_TRUNC_8;
    return HMACMode::SHA256_TRUNC_16;
}

class SOE final : public ISOEHandler
{
    template<class T> void print(const char* kind, const ICollection<Indexed<T>>& values)
    {
        values.ForeachItem([&](const Indexed<T>& v) {
            std::ostringstream s;
            s << "VAL " << kind << " " << v.index << " " << static_cast<double>(v.value.value);
            say(s.str());
        });
    }

public:
    void Start() override {}
    void End() override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<Binary>>& v) override
    {
        print("binary", v);
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<DoubleBitBinary>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<Analog>>& v) override
    {
        print("analog", v);
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<Counter>>& v) override
    {
        print("counter", v);
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<FrozenCounter>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryOutputStatus>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogOutputStatus>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<OctetString>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<TimeAndInterval>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<SecurityStat>>& v) override
    {
        v.ForeachItem([&](const Indexed<SecurityStat>& s) {
            say("VAL secstat " + std::to_string(s.index) + " " + std::to_string(s.value.value.count));
        });
    }
};

class MasterApp final : public IMasterApplicationSA
{
public:
    UTCTimestamp Now() override
    {
        return UTCTimeSource::Instance().Now();
    }
    void OnTaskComplete(const TaskInfo& info) override
    {
        say(std::string("TASK ") + MasterTaskTypeToString(info.type) + " " + TaskCompletionToString(info.result));
    }
    void PersistNewUpdateKey(const std::string&, opendnp3::User, const UpdateKey&) override {}
};

class OutstationApp final : public IOutstationApplicationSA
{
public:
    UTCTimestamp Now() override
    {
        return UTCTimeSource::Instance().Now();
    }
};

class Commands final : public SimpleCommandHandler
{
public:
    Commands() : SimpleCommandHandler(CommandStatus::SUCCESS) {}

protected:
    void DoSelect(const ControlRelayOutputBlock& c, uint16_t index) override
    {
        say("SELECT crob " + std::to_string(index) + " " + std::to_string(static_cast<int>(c.rawCode)));
    }
    void DoOperate(const ControlRelayOutputBlock& c, uint16_t index, OperateType) override
    {
        say("OPERATE crob " + std::to_string(index) + " " + std::to_string(static_cast<int>(c.rawCode)));
    }
    void DoOperate(const AnalogOutputFloat32& c, uint16_t index, OperateType) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputInt32& c, uint16_t index, OperateType) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputInt16& c, uint16_t index, OperateType) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
};

static CommandCallbackT result(const std::string& name)
{
    return [name](const ICommandTaskResult& r) {
        std::ostringstream s;
        s << "CMD " << name << " " << TaskCompletionToString(r.summary);
        r.ForeachItem([&](const CommandPointResult& p) {
            s << " " << p.index << ":" << CommandPointStateToString(p.state) << ":" << CommandStatusToString(p.status);
        });
        say(s.str());
    };
}

static int runOutstation(DNP3Manager& manager)
{
    auto ch = manager.AddTCPServer("server", levels::NORMAL | levels::ALL_APP_COMMS, ChannelRetry::Default(), "0.0.0.0",
                                   20000);
    OutstationAuthStackConfig config;
    config.dbTemplate = DatabaseTemplate::AllTypes(10);
    config.outstation.eventBufferConfig = EventBufferConfig::AllTypes(20);
    config.outstation.params.allowUnsolicited = false;
    config.link.LocalAddr = 10;
    config.link.RemoteAddr = 1;
    config.link.KeepAliveTimeout = TimeDuration::Max();
    config.auth.hmacMode = macMode();
    config.auth.functions =
        option("challenge", "critical") == "all" ? CriticalFunctions::AuthEverything() : CriticalFunctions::AuthOptional();
    static OutstationApp app;
    static Commands commands;
    auto o = ch->AddOutstationSA("outstation", commands, app, config);
    o->ConfigureUser(OutstationUserInfo(User::Default(), "default", Permissions::AllowAll(), updateKey()));
    {
        MeasUpdate u(o);
        u.Update(Binary(true), 0);
        u.Update(Analog(230.5), 0);
    }
    o->Enable();
    say("READY");
    std::string line;
    while (std::getline(std::cin, line))
    {
        std::istringstream in(line);
        std::string what;
        unsigned index = 0;
        double value = 0;
        in >> what >> index >> value;
        if (what == "quit")
            break;
        MeasUpdate u(o);
        if (what == "bin")
            u.Update(Binary(value != 0), static_cast<uint16_t>(index));
        else if (what == "ana")
            u.Update(Analog(value), static_cast<uint16_t>(index));
        else
            continue;
        say("APPLIED " + what + " " + std::to_string(index));
    }
    return 0;
}

// numeric is the first IPv4 address of a host name: this opendnp3 takes
// addresses only.
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

static int runMaster(DNP3Manager& manager, const std::string& host, uint16_t port)
{
    auto ch = manager.AddTCPClient("client", levels::NORMAL | levels::ALL_APP_COMMS, ChannelRetry::Default(),
                                   numeric(host), "0.0.0.0", port);
    MasterAuthStackConfig config;
    config.master.responseTimeout = TimeDuration::Seconds(3);
    config.master.disableUnsolOnStartup = true;
    config.link.LocalAddr = 1;
    config.link.RemoteAddr = 10;
    config.auth.hmacMode = macMode();
    static SOE soe;
    static MasterApp app;
    auto m = ch->AddMasterSA("master", soe, app, config);
    m->AddUser(User::Default(), updateKey());
    m->Enable();
    say("READY");
    std::string line;
    while (std::getline(std::cin, line))
    {
        std::istringstream in(line);
        std::string what;
        unsigned index = 0;
        double value = 0;
        in >> what >> index >> value;
        const auto idx = static_cast<uint16_t>(index);
        if (what == "quit")
            break;
        else if (what == "integrity")
            m->ScanClasses(ClassField::AllClasses());
        else if (what == "class1")
            m->ScanClasses(ClassField(ClassField::CLASS_1));
        else if (what == "do" || what == "sbo")
        {
            CommandSet set;
            set.StartHeader<ControlRelayOutputBlock>().Add(ControlRelayOutputBlock(ControlCode::LATCH_ON), idx);
            if (what == "do")
                m->DirectOperate(std::move(set), result(what));
            else
                m->SelectAndOperate(std::move(set), result(what));
        }
        else if (what == "ao")
        {
            CommandSet set;
            set.StartHeader<AnalogOutputFloat32>().Add(AnalogOutputFloat32(static_cast<float>(value)), idx);
            m->DirectOperate(std::move(set), result(what));
        }
        else
            say("UNKNOWN " + what);
    }
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "usage: dnp3-sa outstation [k=v...] | dnp3-sa master <host> <port> [k=v...]" << std::endl;
        return 2;
    }
    std::string mode = argv[1];
    int first = mode == "master" ? 4 : 2;
    for (int i = first; i < argc; i++)
    {
        std::string s = argv[i];
        auto eq = s.find('=');
        if (eq != std::string::npos)
            options[s.substr(0, eq)] = s.substr(eq + 1);
    }
    osslcrypto::CryptoProvider crypto;
    DNP3Manager manager(1, &crypto);
    manager.AddLogSubscriber(ConsoleLogger::Instance());
    if (mode == "outstation")
        return runOutstation(manager);
    if (mode == "master" && argc >= 4)
        return runMaster(manager, argv[2], static_cast<uint16_t>(std::atoi(argv[3])));
    return 2;
}
