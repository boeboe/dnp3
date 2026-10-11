// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0
//
// A reference master on opendnp3 (Apache-2.0) for the interop tests:
//
//   dnp3-master <host> <port> <none|lan|nonlan>
//
// It connects as master 1 to outstation 10, runs opendnp3's start-up
// sequence (disable unsolicited, integrity poll, enable unsolicited, time
// synchronisation when the outstation asks for it in the given mode), and
// then carries out commands read from standard input:
//
//   integrity | class1 | class2 | class3 | sbo <index> | do <index>
//   | aosbo <index> <value> | aodo <index> <value> | quit
//
// Every value received and every result is printed on a line starting
// with "PEER ".

#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/ISOEHandler.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

using namespace opendnp3;

static std::mutex out;

static void say(const std::string& s)
{
    std::lock_guard<std::mutex> l(out);
    std::cout << "PEER " << s << std::endl;
}

class SOE final : public ISOEHandler
{
    template<class T> void print(const char* kind, const HeaderInfo& info, const ICollection<Indexed<T>>& values)
    {
        values.ForeachItem([&](const Indexed<T>& v) {
            std::ostringstream s;
            s << "VAL " << kind << " " << v.index << " " << static_cast<double>(v.value.value) << " flags="
              << static_cast<int>(v.value.flags.value) << " gv=" << GroupVariationSpec::to_string(info.gv)
              << " event=" << (info.isEventVariation ? 1 : 0) << " unsol=" << (unsol ? 1 : 0);
            say(s.str());
        });
    }

    bool unsol = false;

public:
    void BeginFragment(const ResponseInfo& info) override
    {
        unsol = info.unsolicited;
        say(std::string("FRAGMENT unsol=") + (info.unsolicited ? "1" : "0"));
    }
    void EndFragment(const ResponseInfo&) override {}

    void Process(const HeaderInfo& i, const ICollection<Indexed<Binary>>& v) override
    {
        print("binary", i, v);
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<DoubleBitBinary>>& v) override
    {
        v.ForeachItem([&](const Indexed<DoubleBitBinary>& p) {
            say("VAL doublebit " + std::to_string(p.index) + " " + std::to_string(static_cast<int>(p.value.value)));
        });
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<Analog>>& v) override
    {
        print("analog", i, v);
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<Counter>>& v) override
    {
        print("counter", i, v);
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<FrozenCounter>>& v) override
    {
        print("frozencounter", i, v);
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<BinaryOutputStatus>>& v) override
    {
        print("bostatus", i, v);
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<AnalogOutputStatus>>& v) override
    {
        print("aostatus", i, v);
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<OctetString>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<TimeAndInterval>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<DNPTime>&) override {}
};

class Done final : public ITaskCallback
{
    std::string name;

public:
    explicit Done(std::string n) : name(std::move(n)) {}
    void OnStart() override {}
    void OnComplete(TaskCompletion r) override
    {
        say("DONE " + name + " " + TaskCompletionSpec::to_string(r));
    }
    void OnDestroyed() override {}
};

class App final : public IMasterApplication
{
public:
    UTCTimestamp Now() override
    {
        return UTCTimestamp(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      std::chrono::system_clock::now().time_since_epoch())
                                                      .count()));
    }

    void OnReceiveIIN(const IINField& iin) override
    {
        if (iin.IsSet(IINBit::NEED_TIME))
            say("IIN need-time");
    }
    void OnTaskComplete(const TaskInfo& info) override
    {
        say(std::string("TASK ") + MasterTaskTypeSpec::to_string(info.type) + " "
            + TaskCompletionSpec::to_string(info.result));
    }
};

static CommandResultCallbackT commandResult(const std::string& name)
{
    return [name](const ICommandTaskResult& r) {
        std::ostringstream s;
        s << "CMD " << name << " " << TaskCompletionSpec::to_string(r.summary);
        r.ForeachItem([&](const CommandPointResult& p) {
            s << " " << p.index << ":" << CommandPointStateSpec::to_string(p.state) << ":"
              << CommandStatusSpec::to_string(p.status);
        });
        say(s.str());
    };
}

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        std::cerr << "usage: dnp3-master <host> <port> <none|lan|nonlan>" << std::endl;
        return 2;
    }
    const std::string mode = argv[3];

    DNP3Manager manager(1, ConsoleLogger::Create());
    auto channel = manager.AddTCPClient("client", levels::NORMAL | levels::ALL_APP_COMMS, ChannelRetry::Default(),
                                        {IPEndpoint(argv[1], static_cast<uint16_t>(std::atoi(argv[2])))}, "0.0.0.0",
                                        PrintingChannelListener::Create());

    MasterStackConfig config;
    config.master.responseTimeout = TimeDuration::Seconds(3);
    config.master.disableUnsolOnStartup = true;
    config.master.unsolClassMask = ClassField::AllEventClasses();
    config.master.startupIntegrityClassMask = ClassField::AllClasses();
    if (mode == "lan")
        config.master.timeSyncMode = TimeSyncMode::LAN;
    else if (mode == "nonlan")
        config.master.timeSyncMode = TimeSyncMode::NonLAN;
    config.link.LocalAddr = 1;
    config.link.RemoteAddr = 10;

    auto soe = std::make_shared<SOE>();
    auto master = channel->AddMaster("master", soe, std::make_shared<App>(), config);
    master->Enable();
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
            master->ScanClasses(ClassField::AllClasses(), soe, TaskConfig::With(std::make_shared<Done>(what)));
        else if (what == "class1")
            master->ScanClasses(ClassField(ClassField::CLASS_1), soe, TaskConfig::With(std::make_shared<Done>(what)));
        else if (what == "class2")
            master->ScanClasses(ClassField(ClassField::CLASS_2), soe, TaskConfig::With(std::make_shared<Done>(what)));
        else if (what == "class3")
            master->ScanClasses(ClassField(ClassField::CLASS_3), soe, TaskConfig::With(std::make_shared<Done>(what)));
        else if (what == "sbo")
            master->SelectAndOperate(ControlRelayOutputBlock(OperationType::LATCH_ON), idx, commandResult(what));
        else if (what == "do")
            master->DirectOperate(ControlRelayOutputBlock(OperationType::LATCH_OFF), idx, commandResult(what));
        else if (what == "aosbo")
            master->SelectAndOperate(AnalogOutputFloat32(static_cast<float>(value)), idx, commandResult(what));
        else if (what == "aodo")
            master->DirectOperate(AnalogOutputFloat32(static_cast<float>(value)), idx, commandResult(what));
        else
            say("UNKNOWN " + what);
    }
    return 0;
}
