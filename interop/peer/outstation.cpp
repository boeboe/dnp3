// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0
//
// A reference outstation on opendnp3 (Apache-2.0) for the interop tests:
//
//   dnp3-outstation [<channel> [key=value...]]     (default: tcp 20000)
//
// It is outstation 10 for master 1 (see common.h for channels). Options:
// unsolto=<ms> (unsolicited confirmation timeout), keepalive=<ms> (link
// status requests when idle), maxtx=<octets> (largest fragment sent).
//
// Points 0 to 9 of every type. Binary inputs, double-bit inputs and binary
// output status are class 1; analogs and analog output status class 2;
// counters, frozen counters and octet strings class 3. Index 3 of each
// type with events uses an event variation with time (binary input: g2v3,
// relative to a common time of occurrence).
//
// What the master does is printed on lines starting with "PEER ". Updates
// come on standard input:
//
//   bin|dbl|ana|cnt|bo|ao <index> <value>   change a point (an event)
//   freeze <index> <clear 0|1>              freeze a counter locally
//   oct <index> <hex>                       octet string
//   ti <index> <ms> <interval> <units>      time and interval (g50v4)
//   quit

#include "common.h"

#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>
#include <opendnp3/outstation/UpdateBuilder.h>

#include <atomic>

class App final : public DefaultOutstationApplication
{
public:
    std::atomic<bool> needTime{true};

    bool SupportsWriteAbsoluteTime() override
    {
        return true;
    }

    bool WriteAbsoluteTime(const UTCTimestamp& t) override
    {
        needTime = false;
        say("TIME " + std::to_string(t.msSinceEpoch));
        return true;
    }

    bool SupportsWriteTimeAndInterval() override
    {
        return true;
    }

    bool WriteTimeAndInterval(const ICollection<Indexed<TimeAndInterval>>& values) override
    {
        values.ForeachItem([](const Indexed<TimeAndInterval>& v) {
            say("WRITE ti " + std::to_string(v.index) + " " + std::to_string(v.value.time.value) + " "
                + std::to_string(v.value.interval) + " " + std::to_string(v.value.units));
        });
        return true;
    }

    ApplicationIIN GetApplicationIIN() const override
    {
        ApplicationIIN iin;
        iin.needTime = needTime;
        return iin;
    }

    bool SupportsAssignClass() override
    {
        return true;
    }

    void RecordClassAssignment(AssignClassType type, PointClass clazz, uint16_t start, uint16_t stop) override
    {
        say("ASSIGN " + std::to_string(static_cast<int>(type)) + " " + std::to_string(static_cast<int>(clazz)) + " "
            + std::to_string(start) + " " + std::to_string(stop));
    }

    RestartMode ColdRestartSupport() const override
    {
        return RestartMode::SUPPORTED_DELAY_FINE;
    }

    RestartMode WarmRestartSupport() const override
    {
        return RestartMode::SUPPORTED_DELAY_COARSE;
    }

    uint16_t ColdRestart() override
    {
        say("RESTART cold");
        return 1500;
    }

    uint16_t WarmRestart() override
    {
        say("RESTART warm");
        return 3;
    }

    void OnConfirmProcessed(bool unsol, uint32_t c1, uint32_t c2, uint32_t c3) override
    {
        say("CONFIRM unsol=" + std::to_string(unsol ? 1 : 0) + " left=" + std::to_string(c1) + "," + std::to_string(c2)
            + "," + std::to_string(c3));
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

class Commands final : public SimpleCommandHandler
{
public:
    Commands() : SimpleCommandHandler(CommandStatus::SUCCESS) {}

protected:
    void DoSelect(const ControlRelayOutputBlock& c, uint16_t index) override
    {
        say("SELECT crob " + std::to_string(index) + " " + std::to_string(static_cast<int>(c.rawCode)));
    }
    void DoOperate(const ControlRelayOutputBlock& c, uint16_t index, OperateType op) override
    {
        say("OPERATE crob " + std::to_string(index) + " " + std::to_string(static_cast<int>(c.rawCode)) + " "
            + OperateTypeSpec::to_string(op) + " count=" + std::to_string(c.count) + " on=" + std::to_string(c.onTimeMS)
            + " off=" + std::to_string(c.offTimeMS));
    }
    void DoSelect(const AnalogOutputFloat32& c, uint16_t index) override
    {
        say("SELECT ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputFloat32& c, uint16_t index, OperateType op) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value) + " " + OperateTypeSpec::to_string(op)
            + " g41v3");
    }
    void DoSelect(const AnalogOutputDouble64& c, uint16_t index) override
    {
        say("SELECT ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputDouble64& c, uint16_t index, OperateType op) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value) + " " + OperateTypeSpec::to_string(op)
            + " g41v4");
    }
    void DoSelect(const AnalogOutputInt16& c, uint16_t index) override
    {
        say("SELECT ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputInt16& c, uint16_t index, OperateType op) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value) + " " + OperateTypeSpec::to_string(op)
            + " g41v2");
    }
    void DoSelect(const AnalogOutputInt32& c, uint16_t index) override
    {
        say("SELECT ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputInt32& c, uint16_t index, OperateType op) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value) + " " + OperateTypeSpec::to_string(op)
            + " g41v1");
    }
};

static std::vector<uint8_t> unhex(const std::string& s)
{
    std::vector<uint8_t> b;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2)
        b.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return b;
}

int main(int argc, char* argv[])
{
    DNP3Manager manager(1, ConsoleLogger::Create());
    char defPort[] = "20000";
    char defKind[] = "tcp";
    char* defArgs[] = {argv[0], defKind, defPort};
    auto ch = argc >= 2 ? channel(manager, false, argc, argv, 1) : channel(manager, false, 3, defArgs, 1);

    DatabaseConfig db(10);
    for (auto& p : db.binary_input)
    {
        p.second.clazz = PointClass::Class1;
        p.second.svariation = StaticBinaryVariation::Group1Var2;
        p.second.evariation = p.first == 3 ? EventBinaryVariation::Group2Var3 : EventBinaryVariation::Group2Var2;
    }
    for (auto& p : db.double_binary)
    {
        p.second.clazz = PointClass::Class1;
        p.second.svariation = StaticDoubleBinaryVariation::Group3Var2;
        p.second.evariation = p.first == 3 ? EventDoubleBinaryVariation::Group4Var3 : EventDoubleBinaryVariation::Group4Var2;
    }
    for (auto& p : db.analog_input)
    {
        p.second.clazz = PointClass::Class2;
        p.second.svariation = StaticAnalogVariation::Group30Var5;
        p.second.evariation = p.first == 3 ? EventAnalogVariation::Group32Var7 : EventAnalogVariation::Group32Var5;
    }
    for (auto& p : db.counter)
    {
        p.second.clazz = PointClass::Class3;
        p.second.svariation = StaticCounterVariation::Group20Var1;
        p.second.evariation = p.first == 3 ? EventCounterVariation::Group22Var5 : EventCounterVariation::Group22Var1;
    }
    for (auto& p : db.frozen_counter)
    {
        p.second.clazz = PointClass::Class3;
        p.second.svariation = StaticFrozenCounterVariation::Group21Var5;
        p.second.evariation = EventFrozenCounterVariation::Group23Var5;
    }
    for (auto& p : db.binary_output_status)
    {
        p.second.clazz = PointClass::Class1;
        p.second.svariation = StaticBinaryOutputStatusVariation::Group10Var2;
        p.second.evariation = EventBinaryOutputStatusVariation::Group11Var2;
    }
    for (auto& p : db.analog_output_status)
    {
        p.second.clazz = PointClass::Class2;
        p.second.svariation = StaticAnalogOutputStatusVariation::Group40Var3;
        p.second.evariation = p.first == 3 ? EventAnalogOutputStatusVariation::Group42Var7
                                           : EventAnalogOutputStatusVariation::Group42Var5;
    }
    for (auto& p : db.octet_string)
    {
        p.second.clazz = PointClass::Class3;
    }

    OutstationStackConfig config(db);
    config.outstation.eventBufferConfig = EventBufferConfig::AllTypes(100);
    config.outstation.params.allowUnsolicited = true;
    config.outstation.params.unsolConfirmTimeout = TimeDuration::Milliseconds(std::atoi(option("unsolto", "5000").c_str()));
    config.outstation.params.maxTxFragSize = static_cast<uint32_t>(std::atoi(option("maxtx", "2048").c_str()));
    config.link.LocalAddr = 10;
    config.link.RemoteAddr = 1;
    const int ka = std::atoi(option("keepalive", "0").c_str());
    config.link.KeepAliveTimeout = ka > 0 ? TimeDuration::Milliseconds(ka) : TimeDuration::Max();

    auto app = std::make_shared<App>();
    auto outstation = ch->AddOutstation("outstation", std::make_shared<Commands>(), app, config);

    {
        UpdateBuilder b;
        b.Update(Binary(true, Flags(0x01), app->Now()), 0, EventMode::Suppress);
        b.Update(DoubleBitBinary(DoubleBit::DETERMINED_ON, Flags(0x01), app->Now()), 0, EventMode::Suppress);
        b.Update(Analog(230.5, Flags(0x01)), 0, EventMode::Suppress);
        b.Update(Counter(42, Flags(0x01)), 0, EventMode::Suppress);
        b.Update(BinaryOutputStatus(true, Flags(0x01)), 0, EventMode::Suppress);
        b.Update(AnalogOutputStatus(7.25, Flags(0x01)), 0, EventMode::Suppress);
        const uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};
        b.Update(OctetString(Buffer(hello, sizeof(hello))), 0, EventMode::Suppress);
        b.Update(TimeAndInterval(DNPTime(1700000000000ULL), 15, IntervalUnits::Minutes), 0);
        outstation->Apply(b.Build());
    }
    outstation->Enable();
    say("READY");

    std::string line;
    while (std::getline(std::cin, line))
    {
        std::istringstream in(line);
        std::string what;
        unsigned index = 0;
        in >> what >> index;
        if (what == "quit")
            break;
        const auto idx = static_cast<uint16_t>(index);
        UpdateBuilder b;
        if (what == "oct")
        {
            std::string h;
            in >> h;
            auto bytes = unhex(h);
            b.Update(OctetString(Buffer(bytes.data(), bytes.size())), idx);
        }
        else if (what == "ti")
        {
            unsigned long long ms = 0;
            unsigned interval = 0, units = 0;
            in >> ms >> interval >> units;
            b.Update(TimeAndInterval(DNPTime(ms), interval, static_cast<uint8_t>(units)), idx);
        }
        else if (what == "freeze")
        {
            int clear = 0;
            in >> clear;
            b.FreezeCounter(idx, clear != 0);
        }
        else
        {
            double value = 0;
            in >> value;
            if (what == "bin")
                b.Update(Binary(value != 0, Flags(0x01), app->Now()), idx);
            else if (what == "dbl")
                b.Update(DoubleBitBinary(static_cast<DoubleBit>(static_cast<int>(value)), Flags(0x01), app->Now()), idx);
            else if (what == "ana")
                b.Update(Analog(value, Flags(0x01), app->Now()), idx);
            else if (what == "cnt")
                b.Update(Counter(static_cast<uint32_t>(value), Flags(0x01), app->Now()), idx);
            else if (what == "bo")
                b.Update(BinaryOutputStatus(value != 0, Flags(0x01), app->Now()), idx);
            else if (what == "ao")
                b.Update(AnalogOutputStatus(value, Flags(0x01), app->Now()), idx);
            else
            {
                say("UNKNOWN " + what);
                continue;
            }
        }
        outstation->Apply(b.Build());
        say("APPLIED " + what + " " + std::to_string(index));
    }
    return 0;
}
