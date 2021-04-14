// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ebpf_tracer_engine.h"
#include "../../logging/easylogging++.h"
#include <iostream>

#define STAT_MAX_ITEMS      10
#define CONFIG_ITEMS        1


bcc_symbol_option EbpfTracerEngine::SymbolOption = {.use_debug_file = 1,
                                                    .check_debug_file_crc = 1,
						    .lazy_symbolize = 1,
                                                    .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)};

EbpfTracerEngine::EbpfTracerEngine(std::shared_ptr<IStorageEngine> storageEngine, std::vector<Event> targetEvents)
    : ITracerEngine(storageEngine, targetEvents), Schemas(SyscallSchema::Utils::CollectSyscallSchema())
{
    RunState = TRACER_RUNNING;

    // TODO: INIT THE BPF STUFF
    // Create all BPF maps early to be stored in external table storage.
    auto config_fd = bcc_create_map(BPF_MAP_TYPE_ARRAY, "config", sizeof(int), sizeof(uint64_t), CONFIG_ITEMS, 0);
    auto pid_fd = bcc_create_map(BPF_MAP_TYPE_ARRAY, "pids", sizeof(int), sizeof(uint64_t), MAX_PIDS, 0);
    auto runstate_fd = bcc_create_map(BPF_MAP_TYPE_ARRAY, "runstate", sizeof(int), sizeof(uint64_t), 1, 0);
    auto syscalls_fd = bcc_create_map(BPF_MAP_TYPE_HASH, "syscalls", sizeof(int), sizeof(SyscallSchema::SyscallSchema), 345, 0);
    if (config_fd < 0 || syscalls_fd < 0 || runstate_fd < 0 || pid_fd < 0) {}
        // TODO: Error
    
    // Create external table storage and populate it with BPF maps.
    std::unique_ptr<ebpf::TableStorage> tblstore = ebpf::createSharedTableStorage();

    ebpf::Path syscalls_path({"syscalls"});
    ebpf::Path pid_path({"pids"});    
    ebpf::Path config_path({"config"});
    ebpf::Path runstate_path({"runstate"});    

    ebpf::TableDesc runstate_desc("runstate", ebpf::FileDesc(runstate_fd), BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), 1, 0);
    ebpf::TableDesc config_desc("config", ebpf::FileDesc(config_fd), BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), CONFIG_ITEMS, 0);
    ebpf::TableDesc pid_desc("pids", ebpf::FileDesc(pid_fd), BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), MAX_PIDS, 0);    
    ebpf::TableDesc syscalls_desc("syscalls", ebpf::FileDesc(syscalls_fd), BPF_MAP_TYPE_HASH, sizeof(int), sizeof(SyscallSchema::SyscallSchema), 320, 0);

    tblstore->Insert(config_path, std::move(config_desc));
    tblstore->Insert(pid_path, std::move(pid_desc));    
    tblstore->Insert(syscalls_path, std::move(syscalls_desc));
    tblstore->Insert(runstate_path, std::move(runstate_desc));    

    // Initialize BPF object with prepared table storage.
    BPF = std::make_unique<ebpf::BPF>(0, tblstore.release());
    BPF->init(bpf_prog);
    BPF->get_array_table<uint64_t>("config").update_value(0, getpid());
    BPF->get_array_table<uint64_t>("runstate").update_value(0, RunState);             // Start procmon in a resumed state. We update this to suspended state if user chooses from TUI.
    auto schemaTable = BPF->get_hash_table<int, ::SyscallSchema::SyscallSchema>("syscalls");

    // Initialize pids map to -1
    for(int i=0; i<MAX_PIDS; i++)
    {
        BPF->get_array_table<uint64_t>("pids").update_value(i, -1);
    }
    
    for (auto event : targetEvents)
    {
        auto schemaItr = std::find_if(Schemas.begin(), Schemas.end(), [event](auto s) -> bool {return event.Name().compare(s.syscallName) == 0; });
        if(schemaItr != Schemas.end())
        {
            auto code = schemaTable.update_value(::SyscallSchema::Utils::GetSyscallNumberForName(event.Name()), std::move(*schemaItr.base()));
            if (code.code())
                std::cout << "ERROR" << std::endl;
        }
    }

    BPF->open_perf_buffer("events", &EbpfTracerEngine::PerfCallbackWrapper, &EbpfTracerEngine::PerfLostCallbackWrapper, (void*)this, 64);
    PollingThread = std::thread(&EbpfTracerEngine::Poll, this);
    ConsumerThread = std::thread(&EbpfTracerEngine::Consume, this);

    BPF->attach_tracepoint("raw_syscalls:sys_enter", sys_enter_bpf_prog_name);
    BPF->attach_tracepoint("raw_syscalls:sys_exit", sys_exit_bpf_prog_name);
}

void EbpfTracerEngine::SetRunState(int runState)
{
    RunState = runState; 
    BPF->get_array_table<uint64_t>("runstate").update_value(0, runState);
}

EbpfTracerEngine::~EbpfTracerEngine()
{
    EventQueue.cancel();
    PollingThread.join();
    ConsumerThread.join();
}

void EbpfTracerEngine::PerfCallbackWrapper(/* EbpfTracerEngine* */void *cbCookie, void *rawMessage, int rawMessageSize)
{
    static_cast<EbpfTracerEngine *>(cbCookie)->PerfCallback(rawMessage, rawMessageSize);
}

void EbpfTracerEngine::PerfCallback(void *rawMessage, int rawMessageSize)
{
    EventQueue.push(*static_cast<SyscallEvent*>(rawMessage));
}

void EbpfTracerEngine::PerfLostCallbackWrapper(void *cbCookie, uint64_t lost)
{
    static_cast<EbpfTracerEngine*>(cbCookie)->PerfLostCallback(lost);
}

void EbpfTracerEngine::PerfLostCallback(uint64_t lost)
{
    return;
}

void EbpfTracerEngine::Poll()
{
    while (!EventQueue.isCancelled())
    {
        if (BPF->poll_perf_buffer("events", 500) == -1)
        {
            // either we closed the perf buffer
            // or something else did -> get out
            break;
        }
    }

    // Any cleanup?
    return;
}

void EbpfTracerEngine::Consume()
{
    // blocking pop return optional<T>, evaluates to "true" if we get a value
    // "false" if we've been cancelled
    // auto stacks = BPF->get_stack_table("stack_traces");
    std::vector<ITelemetry> batch;
    size_t batchSize = 50;
    batch.reserve(batchSize);
    while (!EventQueue.isCancelled())
    {
        if(RunState == TRACER_STOP) break;
        
        auto event = EventQueue.pop();
        
        if (!event.has_value()) 
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
            
        if (batch.size() >= batchSize)
        {
            auto res = _storageEngine->StoreMany(batch);
            // Free memory used for the arguments
            for (ITelemetry& datam: batch)
            {
                free(datam.arguments);
                datam.arguments = NULL;
            }

            batch.clear();
        }

        std::string syscall = SyscallSchema::Utils::SyscallNumberToName[event->sysnum];
        ITelemetry tel;
        tel.pid = event->pid;
        tel.stackTrace = GetStackTraceForIPs(event->pid, event->kernelStack, event->kernelStackCount, event->userStack, event->userStackCount);
        tel.comm = std::string(event->comm);
        tel.processName = std::string(event->comm);
        tel.syscall = syscall;

        if((int64_t)event->ret < 0)
        {
            constexpr uint64_t sign_bits = ~uint64_t{} << 63;
            tel.result = (int)(-1 * (event->ret & sign_bits) + (event->ret & ~sign_bits));
        }
        else    tel.result = event->ret;

        tel.duration = event->duration_ns;
        tel.arguments = (unsigned char*) malloc(MAX_BUFFER);
        memset(tel.arguments, 0, MAX_BUFFER);
        memcpy(tel.arguments, event->buffer, MAX_BUFFER);
        tel.timestamp = event->timestamp;

        batch.push_back(tel);
    }

    return;
}

StackTrace EbpfTracerEngine::GetStackTraceForIPs(int pid, uint64_t *kernelIPs, uint64_t kernelCount, uint64_t *userIPs, uint64_t userCount)
{
    StackTrace result;
    if (pid < 0)
        pid = -1;

    if (SymbolCacheMap.find(-1) == SymbolCacheMap.end())
        SymbolCacheMap[-1] = bcc_symcache_new(pid, &SymbolOption);
    void *kcache = SymbolCacheMap[-1];
    if (SymbolCacheMap.find(pid) == SymbolCacheMap.end())
        SymbolCacheMap[pid] = bcc_symcache_new(pid, &SymbolOption);
    void *cache = SymbolCacheMap[pid];


    // loop over the IPs and get symbols
    bcc_symbol symbol;
    for (int i = 0; i < kernelCount; i++)
    {
        result.kernelIPs.push_back(kernelIPs[i]);
        if (bcc_symcache_resolve(kcache, kernelIPs[i], &symbol) != 0)
        {
            result.kernelSymbols.push_back("[UNKNOWN]");
        }
        else
        {
            result.kernelSymbols.push_back(symbol.demangle_name);
        }
    }

    for (int i = 0; i < userCount; i++)
    {
        result.userIPs.push_back(userIPs[i]);
        int ret = bcc_symcache_resolve(cache, userIPs[i], &symbol);

        if (ret != 0)
        {
            if (symbol.module != NULL)
            {
                std::stringstream ss;
                ss << symbol.module << "![UNKNOWN]"; 
                result.userSymbols.push_back(ss.str());
            }
            else
            {
                result.userSymbols.push_back("[UNKNOWN]");
            }
        }
        else
        {
            std::stringstream ss;
            ss << symbol.module << "!" << symbol.demangle_name;
            result.userSymbols.push_back(ss.str());
        }
    }

    return result;
}

void EbpfTracerEngine::AddPids(std::vector<int> pidsToTrace)
{
    for(int i=0; i<pidsToTrace.size(); i++)
    {
        BPF->get_array_table<uint64_t>("pids").update_value(i, pidsToTrace[i]);
    }
}

