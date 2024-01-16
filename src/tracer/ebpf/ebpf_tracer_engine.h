/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include <map>
#include <memory>
#include <vector>
#include <thread>
#include <elf.h>

#include "syscall_schema.h"
//#include "bpf_prog.h"
#include "kern/procmonEBPF_common.h"
#include "../../common/cancellable_message_queue.h"
#include "../tracer_engine.h"
#include "../../common/event.h"
#include "../../storage/storage_engine.h"

#define MAX_PIDS           10

#define STAT_MAX_ITEMS      10
#define CONFIG_ITEMS        1

#define KERN_4_17_5_1_OBJ       "procmonEBPFkern4.17-5.1.o"
#define KERN_5_2_OBJ            "procmonEBPFkern5.2.o"
#define KERN_5_3_5_5_OBJ        "procmonEBPFkern5.3-5.5.o"
#define KERN_5_6__OBJ           "procmonEBPFkern5.6-.o"
#define KERN_4_17_5_1_CORE_OBJ  "procmonEBPFkern4.17-5.1_core.o"
#define KERN_5_2_CORE_OBJ       "procmonEBPFkern5.2_core.o"
#define KERN_5_3_5_5_CORE_OBJ   "procmonEBPFkern5.3-5.5_core.o"
#define KERN_5_6__CORE_OBJ      "procmonEBPFkern5.6-_core.o"

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

    std::vector<struct SyscallSchema::SyscallSchema> Schemas;

    std::map<int, void*> SymbolCacheMap;

    // use the same symbol settings as the defaults from bcc
    //static bcc_symbol_option SymbolOption;

    void Poll();
    void Consume();

    StackTrace GetStackTraceForIPs(int pid, uint64_t *kernelIPs, uint64_t kernelCount, uint64_t *userIPs, uint64_t userCount);

    // Instance level callback
    void PerfCallback(void *rawMessage, int rawMessageSize);
    // static callback that passes the instance pointer in cbCookie
    static void PerfCallbackWrapper(void *cbCookie, int cpu, void *rawMessage, uint32_t rawMessageSize);

    // Instance level callback
    void PerfLostCallback(uint64_t lost);
    // static callback that passes the instance pointer in cbCookie
    static void PerfLostCallbackWrapper(void *cbCookie, int cpu, uint64_t lost);
public:
    EbpfTracerEngine(std::shared_ptr<IStorageEngine> storageEngine, std::vector<Event> targetEvents);
    void Initialize() override;

    void AddPids(std::vector<int> pidsToTrace) override;

    void SetRunState(int runState) override;
};