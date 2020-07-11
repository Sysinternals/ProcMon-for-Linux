// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include <ctime>

#include <getopt.h>
#include <time.h>

#include "../storage/mock_storage_engine.h"
#include "../storage/storage_engine.h"
#include "../storage/storage_proxy.h"
#include "../tracer/tracer_engine.h"
#include "../tracer/mock_tracer_engine.h"
#include "../tracer/ebpf/ebpf_tracer_engine.h"
#include "../common/event.h"
#include "../common/cli_utils.h"
#include "../logging/easylogging++.h"

#define DEFAULT_TIMESTAMP_LENGTH 25
#define DEFAULT_DATESTAMP_LENGTH 11

struct ProcmonArgs
{
    std::vector<pid_t> pids;
    std::vector<Event> events;
    StorageProxy::StorageEngineType storageEngineType;
    // Other args
};

// Should only be created once.  Pass around using
// a std::shared_ptr<ProcmonConfiguration>.
class ProcmonConfiguration : public ProcmonArgs
{
private:
    std::shared_ptr<IStorageEngine> _storageEngine;
    std::unique_ptr<ITracerEngine>  _tracerEngine;
    std::vector<struct SyscallSchema::SyscallSchema> syscallSchema;
    std::vector<std::string> pointerSyscalls;
    struct timespec startTime;
    std::string epocStartTime;
    std::string date;
    bool headless = false;
    std::string traceFilePath = "";
    std::string outputTraceFilePath = "";

    void HandlePidArgs(char *pidArgs);

    void HandleStorageArgs(char *storageArgs);

    void HandleEventArgs(char *eventArgs);

    void HandleFileArg(char * filepath);

    std::string ConvertEpocTime(time_t time);

public:
    // TODO: What does every configuration need to have
    // TODO: How do we map CLI args to fields here

    // Initializes the configuration handling args 
    // and creating necessary resources.
    ProcmonConfiguration(int argc, char *argv[]);

    // Getters & Setters
    const std::unique_ptr<ITracerEngine>& GetTracer() { return _tracerEngine; };
    std::shared_ptr<IStorageEngine> GetStorage() { return _storageEngine; };
    std::vector<struct SyscallSchema::SyscallSchema>& GetSchema() { return syscallSchema; }
    std::vector<std::string> getPointerSyscalls() { return pointerSyscalls; }
    uint64_t GetStartTime();
    void SetStartTime(uint64_t start);
    void SetEpocStartTime(std::string startTime) { epocStartTime = startTime; }
    std::string GetEpocStartTime() { return epocStartTime; }
    std::string GetStartDate() { return date; }
    bool GetHeadlessMode() { return headless; }
    std::string GetTraceFilePath() { return traceFilePath; }
    std::string GetOutputTraceFilePath() { return outputTraceFilePath; }
};