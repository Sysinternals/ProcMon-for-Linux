// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <BPF.h>
#include <map>
#include <memory>
#include <vector>
#include <thread>
#include <elf.h>

#include "syscall_schema.h"
#include "bpf_prog.h"
#include "raw_ebpf_event.h"
#include "../../common/cancellable_message_queue.h"
#include "../tracer_engine.h"
#include "../../common/event.h"
#include "../../storage/storage_engine.h"

#define MAX_PIDS           10

class EbpfTracerEngine : public ITracerEngine
{
private:
    ~EbpfTracerEngine();

    // The thread for polling the perf buffer
    // This thread will also be calling the
    // callback for every event
    std::thread PollingThread;

    // The thread for consuming the raw events
    std::thread ConsumerThread;

    // The queue for containing raw events
    // from eBPF to be processed into telemetry
    CancellableMessageQueue<SyscallEvent> EventQueue;

    // The handle for the BPF program
    std::unique_ptr<ebpf::BPF> BPF;

    std::vector<struct SyscallSchema::SyscallSchema> Schemas;

    std::map<int, void*> SymbolCacheMap;

    // use the same symbol settings as the defaults from bcc
    static bcc_symbol_option SymbolOption;

    void Poll();
    void Consume();

    StackTrace GetStackTraceForIPs(int pid, uint64_t *kernelIPs, uint64_t kernelCount, uint64_t *userIPs, uint64_t userCount);

    // Instance level callback
    void PerfCallback(void *rawMessage, int rawMessageSize);
    // static callback that passes the instance pointer in cbCookie
    static void PerfCallbackWrapper(void *cbCookie, void *rawMessage, int rawMessageSize);

    // Instance level callback
    void PerfLostCallback(uint64_t lost);
    // static callback that passes the instance pointer in cbCookie
    static void PerfLostCallbackWrapper(void *cbCookie, uint64_t lost);
public:
    EbpfTracerEngine(std::shared_ptr<IStorageEngine> storageEngine, std::vector<Event> targetEvents);

    void AddPids(std::vector<int> pidsToTrace) override;   

    void SetRunState(int runState) override;
};