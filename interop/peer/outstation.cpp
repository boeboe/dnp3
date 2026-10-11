// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0
//
// A reference outstation on opendnp3 (Apache-2.0) for the interop tests:
// it listens on 0.0.0.0:20000 as outstation 10 for master 1, prints what
// the master does on lines starting with "PEER ", and reads updates from
// standard input ("bin <index> <0|1>", "ana <index> <value>",
// "cnt <index> <value>", "quit").

#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>
#include <opendnp3/outstation/UpdateBuilder.h>

#include <atomic>
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
            + OperateTypeSpec::to_string(op));
    }
    void DoSelect(const AnalogOutputFloat32& c, uint16_t index) override
    {
        say("SELECT ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputFloat32& c, uint16_t index, OperateType op) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value) + " "
            + OperateTypeSpec::to_string(op));
    }
    void DoSelect(const AnalogOutputInt16& c, uint16_t index) override
    {
        say("SELECT ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputInt16& c, uint16_t index, OperateType op) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value) + " "
            + OperateTypeSpec::to_string(op));
    }
    void DoSelect(const AnalogOutputInt32& c, uint16_t index) override
    {
        say("SELECT ao " + std::to_string(index) + " " + std::to_string(c.value));
    }
    void DoOperate(const AnalogOutputInt32& c, uint16_t index, OperateType op) override
    {
        say("OPERATE ao " + std::to_string(index) + " " + std::to_string(c.value) + " "
            + OperateTypeSpec::to_string(op));
    }
};

int main()
{
    DNP3Manager manager(1, ConsoleLogger::Create());
    auto channel = manager.AddTCPServer("server", levels::NORMAL | levels::ALL_APP_COMMS, ServerAcceptMode::CloseExisting,
                                        IPEndpoint("0.0.0.0", 20000), PrintingChannelListener::Create());

    DatabaseConfig db(10);
    for (auto& p : db.binary_input)
    {
        p.second.clazz = PointClass::Class1;
        p.second.svariation = StaticBinaryVariation::Group1Var2;
        p.second.evariation = EventBinaryVariation::Group2Var2;
    }
    for (auto& p : db.analog_input)
    {
        p.second.clazz = PointClass::Class2;
        p.second.svariation = StaticAnalogVariation::Group30Var5;
        p.second.evariation = EventAnalogVariation::Group32Var5;
    }
    for (auto& p : db.counter)
    {
        p.second.clazz = PointClass::Class3;
        p.second.svariation = StaticCounterVariation::Group20Var1;
        p.second.evariation = EventCounterVariation::Group22Var1;
    }

    OutstationStackConfig config(db);
    config.outstation.eventBufferConfig = EventBufferConfig::AllTypes(100);
    config.outstation.params.allowUnsolicited = true;
    config.link.LocalAddr = 10;
    config.link.RemoteAddr = 1;
    config.link.KeepAliveTimeout = TimeDuration::Max();

    auto app = std::make_shared<App>();
    auto outstation = channel->AddOutstation("outstation", std::make_shared<Commands>(), app, config);

    {
        UpdateBuilder b;
        b.Update(Binary(true, Flags(0x01), app->Now()), 0, EventMode::Suppress);
        b.Update(Analog(230.5, Flags(0x01)), 0, EventMode::Suppress);
        b.Update(Counter(42, Flags(0x01)), 0, EventMode::Suppress);
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
        double value = 0;
        in >> what >> index >> value;
        if (what == "quit")
            break;
        UpdateBuilder b;
        if (what == "bin")
            b.Update(Binary(value != 0, Flags(0x01), app->Now()), static_cast<uint16_t>(index));
        else if (what == "ana")
            b.Update(Analog(value, Flags(0x01), app->Now()), static_cast<uint16_t>(index));
        else if (what == "cnt")
            b.Update(Counter(static_cast<uint32_t>(value), Flags(0x01), app->Now()), static_cast<uint16_t>(index));
        else
            continue;
        outstation->Apply(b.Build());
        say("APPLIED " + what + " " + std::to_string(index));
    }
    return 0;
}
