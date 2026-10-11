// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0
//
// A reference master on opendnp3 (Apache-2.0) for the interop tests:
//
//   dnp3-master <host> <port> <none|lan|nonlan>          (TCP, as before)
//   dnp3-master <channel> [key=value...]                 (see common.h)
//
// Options: mode=none|lan|nonlan (time synchronisation), keepalive=<ms>
// (link status requests when idle). It is master 1 of outstation 10 and
// runs opendnp3's start-up sequence (disable unsolicited, integrity poll,
// enable unsolicited, time synchronisation when asked for), then carries
// out commands read from standard input:
//
//   integrity | class1 | class2 | class3
//   sbo <index> | do <index> | pulse <index> <count> <on ms> <off ms>
//   aosbo <index> <value> | aodo <index> <value>          (g41v3)
//   ao16 <index> <value> | ao32 <index> <value> | aodbl <index> <value>
//   multi                    CROB 0 latch on and g41v3 1 = 12.5 in one request
//   freeze | freezeclear | freezenr                       (all counters)
//   read <group> <variation>                              (all objects)
//   range <group> <variation> <start> <stop>
//   writeti <index> <ms> <interval> <units>
//   cold | warm | quit
//
// Every value received and every result is printed on a line starting
// with "PEER ".

#include "common.h"

#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/ISOEHandler.h>

#include <chrono>

class SOE final : public ISOEHandler
{
    bool unsol = false;

    std::string suffix(const HeaderInfo& info, uint64_t t)
    {
        std::ostringstream s;
        s << " gv=" << GroupVariationSpec::to_string(info.gv) << " event=" << (info.isEventVariation ? 1 : 0)
          << " unsol=" << (unsol ? 1 : 0) << " time=" << t;
        return s.str();
    }

    template<class T> void print(const char* kind, const HeaderInfo& info, const ICollection<Indexed<T>>& values)
    {
        values.ForeachItem([&](const Indexed<T>& v) {
            std::ostringstream s;
            s << "VAL " << kind << " " << v.index << " " << static_cast<double>(v.value.value)
              << " flags=" << static_cast<int>(v.value.flags.value) << suffix(info, v.value.time.value);
            say(s.str());
        });
    }

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
            std::ostringstream s;
            s << "VAL doublebit " << p.index << " " << static_cast<int>(p.value.value)
              << " flags=" << static_cast<int>(p.value.flags.value) << suffix(i, p.value.time.value);
            say(s.str());
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
    void Process(const HeaderInfo& i, const ICollection<Indexed<OctetString>>& v) override
    {
        v.ForeachItem([&](const Indexed<OctetString>& p) {
            auto b = p.value.ToBuffer();
            say("VAL octets " + std::to_string(p.index) + " " + hex(b.data, b.length) + suffix(i, 0));
        });
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<TimeAndInterval>>& v) override
    {
        v.ForeachItem([&](const Indexed<TimeAndInterval>& p) {
            say("VAL ti " + std::to_string(p.index) + " " + std::to_string(p.value.time.value) + " "
                + std::to_string(p.value.interval) + " " + std::to_string(p.value.units) + suffix(i, 0));
        });
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<BinaryCommandEvent>>& v) override
    {
        v.ForeachItem([&](const Indexed<BinaryCommandEvent>& p) {
            say("VAL bocmd " + std::to_string(p.index) + " " + std::to_string(p.value.value ? 1 : 0) + " status="
                + std::to_string(static_cast<int>(p.value.status)) + suffix(i, p.value.time.value));
        });
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<AnalogCommandEvent>>& v) override
    {
        v.ForeachItem([&](const Indexed<AnalogCommandEvent>& p) {
            say("VAL aocmd " + std::to_string(p.index) + " " + std::to_string(p.value.value) + " status="
                + std::to_string(static_cast<int>(p.value.status)) + suffix(i, p.value.time.value));
        });
    }
    void Process(const HeaderInfo& i, const ICollection<DNPTime>& v) override
    {
        v.ForeachItem([&](const DNPTime& t) { say("VAL time " + std::to_string(t.value) + suffix(i, t.value)); });
    }
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
        if (iin.IsSet(IINBit::EVENT_BUFFER_OVERFLOW))
            say("IIN overflow");
    }
    void OnTaskComplete(const TaskInfo& info) override
    {
        say(std::string("TASK ") + MasterTaskTypeSpec::to_string(info.type) + " "
            + TaskCompletionSpec::to_string(info.result));
    }
    void OnKeepAliveInitiated() override
    {
        say("KEEPALIVE sent");
    }
    void OnKeepAliveSuccess() override
    {
        say("KEEPALIVE ok");
    }
    void OnKeepAliveFailure() override
    {
        say("KEEPALIVE failed");
    }
    void OnStateChange(LinkStatus value) override
    {
        say(std::string("LINK ") + LinkStatusSpec::to_string(value));
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
    if (argc < 3)
    {
        std::cerr << "usage: dnp3-master <host> <port> <mode> | dnp3-master <channel> [key=value...]" << std::endl;
        return 2;
    }
    DNP3Manager manager(1, ConsoleLogger::Create());
    std::shared_ptr<IChannel> ch;
    const std::string first = argv[1];
    if (first == "tcp" || first == "tls" || first == "udp" || first == "serial")
    {
        ch = channel(manager, true, argc, argv, 1);
    }
    else
    {
        char kind[] = "tcp";
        char* args[] = {argv[0], kind, argv[1], argv[2]};
        ch = channel(manager, true, 4, args, 1);
        if (argc >= 4)
            options["mode"] = argv[3];
    }
    const std::string mode = option("mode", "none");

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
    const int ka = std::atoi(option("keepalive", "0").c_str());
    config.link.KeepAliveTimeout = ka > 0 ? TimeDuration::Milliseconds(ka) : TimeDuration::Max();

    auto soe = std::make_shared<SOE>();
    auto master = ch->AddMaster("master", soe, std::make_shared<App>(), config);
    master->Enable();
    say("READY");

    std::string line;
    while (std::getline(std::cin, line))
    {
        std::istringstream in(line);
        std::string what;
        in >> what;
        if (what == "quit")
            break;
        const auto done = TaskConfig::With(std::make_shared<Done>(what));
        if (what == "integrity")
            master->ScanClasses(ClassField::AllClasses(), soe, done);
        else if (what == "class1")
            master->ScanClasses(ClassField(ClassField::CLASS_1), soe, done);
        else if (what == "class2")
            master->ScanClasses(ClassField(ClassField::CLASS_2), soe, done);
        else if (what == "class3")
            master->ScanClasses(ClassField(ClassField::CLASS_3), soe, done);
        else if (what == "read" || what == "range")
        {
            unsigned g = 0, v = 0, start = 0, stop = 0;
            in >> g >> v >> start >> stop;
            const GroupVariationID id(static_cast<uint8_t>(g), static_cast<uint8_t>(v));
            if (what == "read")
                master->ScanAllObjects(id, soe, done);
            else
                master->ScanRange(id, static_cast<uint16_t>(start), static_cast<uint16_t>(stop), soe, done);
        }
        else if (what == "freeze")
            master->PerformFunction(what, FunctionCode::IMMED_FREEZE, {Header::AllObjects(20, 0)}, done);
        else if (what == "freezeclear")
            master->PerformFunction(what, FunctionCode::FREEZE_CLEAR, {Header::AllObjects(20, 0)}, done);
        else if (what == "freezenr")
            master->PerformFunction(what, FunctionCode::IMMED_FREEZE_NR, {Header::AllObjects(20, 0)}, done);
        else if (what == "writeti")
        {
            unsigned index = 0, interval = 0, units = 0;
            unsigned long long ms = 0;
            in >> index >> ms >> interval >> units;
            master->Write(TimeAndInterval(DNPTime(ms), interval, static_cast<uint8_t>(units)),
                          static_cast<uint16_t>(index), done);
        }
        else if (what == "cold" || what == "warm")
        {
            master->Restart(what == "cold" ? RestartType::COLD : RestartType::WARM,
                            [what](const RestartOperationResult& r) {
                                say("RESTART " + what + " " + TaskCompletionSpec::to_string(r.summary) + " "
                                    + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                         r.restartTime.value)
                                                         .count()));
                            });
        }
        else if (what == "multi")
        {
            CommandSet set;
            set.Add<ControlRelayOutputBlock>({WithIndex(ControlRelayOutputBlock(OperationType::LATCH_ON), 0)});
            set.Add<AnalogOutputFloat32>({WithIndex(AnalogOutputFloat32(12.5f), 1)});
            master->SelectAndOperate(std::move(set), commandResult(what));
        }
        else
        {
            unsigned index = 0;
            in >> index;
            const auto idx = static_cast<uint16_t>(index);
            if (what == "sbo")
                master->SelectAndOperate(ControlRelayOutputBlock(OperationType::LATCH_ON), idx, commandResult(what));
            else if (what == "do")
                master->DirectOperate(ControlRelayOutputBlock(OperationType::LATCH_OFF), idx, commandResult(what));
            else if (what == "pulse")
            {
                unsigned count = 1, on = 100, off = 100;
                in >> count >> on >> off;
                master->DirectOperate(ControlRelayOutputBlock(OperationType::PULSE_ON, TripCloseCode::NUL,
                                                              false, static_cast<uint8_t>(count), on, off),
                                      idx, commandResult(what));
            }
            else
            {
                double value = 0;
                in >> value;
                if (what == "aosbo")
                    master->SelectAndOperate(AnalogOutputFloat32(static_cast<float>(value)), idx, commandResult(what));
                else if (what == "aodo")
                    master->DirectOperate(AnalogOutputFloat32(static_cast<float>(value)), idx, commandResult(what));
                else if (what == "ao16")
                    master->DirectOperate(AnalogOutputInt16(static_cast<int16_t>(value)), idx, commandResult(what));
                else if (what == "ao32")
                    master->DirectOperate(AnalogOutputInt32(static_cast<int32_t>(value)), idx, commandResult(what));
                else if (what == "aodbl")
                    master->DirectOperate(AnalogOutputDouble64(value), idx, commandResult(what));
                else
                    say("UNKNOWN " + what);
            }
        }
    }
    return 0;
}
