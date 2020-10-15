// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef EVENT_FORMATTER_H
#define EVENT_FORMATTER_H

#include <vector>

#include "../common/telemetry.h"
#include "../common/event.h"
#include "../display/screen_configuration.h"
#include "../configuration/procmon_configuration.h"

class EventFormatter
{

protected:
    std::string syscall;
    ProcmonConfiguration* config;

    std::string CalculateDeltaTimestamp(uint64_t ebpfEventTimestamp);
    int FindSyscall(std::string& syscallName);
    std::string DecodeArguments(ITelemetry &event);

public:
    EventFormatter(){};
    virtual ~EventFormatter(){};

    void Initialize(const std::string &syscall, ProcmonConfiguration* config) { this->syscall = syscall; this->config = config; }

    std::string& GetSyscall() { return syscall; }

    virtual std::string GetTimestamp(ITelemetry &event);
    virtual std::string GetPID(ITelemetry &event);
    virtual std::string GetProcess(ITelemetry &event);
    virtual std::string GetOperation(ITelemetry &event);
    virtual std::string GetResult(ITelemetry &event);
    virtual std::string GetDuration(ITelemetry &event);
    virtual std::string GetDetails(ITelemetry &event);
};

#endif
