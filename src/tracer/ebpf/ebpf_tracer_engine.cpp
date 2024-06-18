/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "ebpf_tracer_engine.h"
#include "../../logging/easylogging++.h"
#include <iostream>
#include <limits.h>

double g_bootSecSinceEpoch = 0;
int machineId = 0;

int     g_clkTck = 100;
size_t  g_pwEntrySize = 0;

std::vector<Event> events;
std::vector<struct SyscallSchema> schemas = Utils::CollectSyscallSchema();

const ebpfSyscallRTPprog        RTPenterProgs[] =
{
    {"genericRawEnter", EBPF_GENERIC_SYSCALL}
};

const ebpfSyscallRTPprog        RTPexitProgs[] =
{
    {"genericRawExit", EBPF_GENERIC_SYSCALL}
};

const ebpfTelemetryMapObject mapObjects[4] =
{
    {"configuration", 0, NULL, NULL},
    {"pids", 0, NULL, NULL},
    {"runstate", 0, NULL, NULL},
    {"syscalls", 0, NULL, NULL}
};

// this holds the FDs for the above maps.
// mapObjects above gets passed into sysinternalsEBPF config during telemetryStart.
// mapFds also gets passed into telemetryStart. mapFds gets populated during telemetryStart
// and can subsequently be used to access the maps.
int mapFds[sizeof(mapObjects) / sizeof(*mapObjects)];

//--------------------------------------------------------------------
//
// logHandler
//
// Handles logs from sysinternalsEBPF
//
//--------------------------------------------------------------------
void logHandler(const char *format, va_list args)
{
    vfprintf(stderr, format, args);
}

//--------------------------------------------------------------------
//
// telemetryReady
//
// Callback from loader library to indicate that it has started up.
//
//--------------------------------------------------------------------
void telemetryReady()
{
    // Set PID
    pid_t act_pid = getpid();
    int key = CONFIG_PID_KEY;
    telemetryMapUpdateElem(mapFds[CONFIG_INDEX], &key, &act_pid, MAP_UPDATE_CREATE_OR_OVERWRITE);

    // Set runstate
    int state = TRACER_RUNNING;
    key = RUNSTATE_KEY;
    telemetryMapUpdateElem(mapFds[RUNSTATE_INDEX], &key, &state, MAP_UPDATE_CREATE_OR_OVERWRITE);

    // Init the PIDs
    uint64_t init_pid = -1;
    for(int i=0; i<MAX_PIDS; i++)
    {
       telemetryMapUpdateElem(mapFds[PIDS_INDEX], &i, &init_pid, MAP_UPDATE_CREATE_OR_OVERWRITE);
    }

    // Set targeted syscalls
    for (auto event : events)
    {
        auto schemaItr = std::find_if(schemas.begin(), schemas.end(), [event](auto s) -> bool {return event.Name().compare(s.syscallName) == 0; });
        if(schemaItr != schemas.end())
        {
            std::string str = schemaItr->syscallName;
            char* charPtr = new char[str.size() + 1];
            std::strcpy(charPtr, str.c_str());

            int num = ::Utils::GetSyscallNumberForName(event.Name());
            telemetryMapUpdateElem(mapFds[SYSCALL_INDEX], &num, static_cast<void*>(&(*schemaItr)), MAP_UPDATE_CREATE_OR_OVERWRITE);
        }
    }
}

//--------------------------------------------------------------------
//
// configChange
//
// Called when config has changed.
//
//--------------------------------------------------------------------
void configChange()
{
}

//--------------------------------------------------------------------
//
// SetBootTime
//
// Sets the boot time.
//
//--------------------------------------------------------------------
void SetBootTime()
{
    FILE *fp = NULL;
    double uptimeF = 0.0;
    char machineIdStr[9];
    struct timeval tv;

    fp = fopen( "/proc/uptime", "r" );
    if (fp != NULL) {
        if(fscanf(fp, "%lf", &uptimeF) == EOF) {
            fclose(fp);
            return;
        }

        gettimeofday(&tv, NULL);

        g_bootSecSinceEpoch = (double)tv.tv_sec + ((double)tv.tv_usec / (1000 * 1000)) - uptimeF;
        fclose(fp);
    } else {
        g_bootSecSinceEpoch = 0.0;
    }

    g_clkTck = sysconf( _SC_CLK_TCK );
    // if error, set it to the default of 100
    if (g_clkTck <= 0) {
        g_clkTck = 100;
    }

    // get passwd entry size, or guess at 4K if not
    g_pwEntrySize = sysconf( _SC_GETPW_R_SIZE_MAX );
    if (g_pwEntrySize == (size_t)-1) {
        g_pwEntrySize = 4096;
    }

    // get the machineId
    machineId = 0;
    fp = fopen( "/etc/machine-id", "r" );
    if (fp != NULL) {
        if (fread( machineIdStr, 1, 8, fp ) == 8) {
            machineIdStr[8] = 0x00;
            machineId = strtol( machineIdStr, NULL, 16 );
        }
        fclose( fp );
    }
}


//--------------------------------------------------------------------
//
// Initialize
//
// Initializes the eBPF tracer engine.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::Initialize()
{
    PollingThread = std::thread(&EbpfTracerEngine::Poll, this);
    ConsumerThread = std::thread(&EbpfTracerEngine::Consume, this);
}


//--------------------------------------------------------------------
//
// EbpfTracerEngine
//
// Constructor for the eBPF tracer engine.
//
//--------------------------------------------------------------------
EbpfTracerEngine::EbpfTracerEngine(std::shared_ptr<IStorageEngine> storageEngine, std::vector<Event> targetEvents)
    : ITracerEngine(storageEngine, targetEvents), Schemas(Utils::CollectSyscallSchema())
{
    events = targetEvents;
/*    mapObjects[0] = {"config", 0, nullptr, nullptr};
    mapObjects[1] = {"pids", 0, nullptr, nullptr};
    mapObjects[2] = {"runstate", 0, nullptr, nullptr};
    mapObjects[3] = {"syscalls", 0, nullptr, nullptr};*/

/*    RunState = TRACER_RUNNING;

    // TODO: INIT THE BPF STUFF
    // Create all BPF maps early to be stored in external table storage.
    auto config_fd = bcc_create_map(BPF_MAP_TYPE_ARRAY, "config", sizeof(int), sizeof(uint64_t), CONFIG_ITEMS, 0);
    auto pid_fd = bcc_create_map(BPF_MAP_TYPE_ARRAY, "pids", sizeof(int), sizeof(uint64_t), MAX_PIDS, 0);
    auto runstate_fd = bcc_create_map(BPF_MAP_TYPE_ARRAY, "runstate", sizeof(int), sizeof(uint64_t), 1, 0);
    auto syscalls_fd = bcc_create_map(BPF_MAP_TYPE_HASH, "syscalls", sizeof(int), sizeof(SyscallSchema), 345, 0);
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
    ebpf::TableDesc syscalls_desc("syscalls", ebpf::FileDesc(syscalls_fd), BPF_MAP_TYPE_HASH, sizeof(int), sizeof(SyscallSchema), 320, 0);

    tblstore->Insert(config_path, std::move(config_desc));
    tblstore->Insert(pid_path, std::move(pid_desc));
    tblstore->Insert(syscalls_path, std::move(syscalls_desc));
    tblstore->Insert(runstate_path, std::move(runstate_desc));

    // Initialize BPF object with prepared table storage.
    BPF = std::make_unique<ebpf::BPF>(0, tblstore.release());
    BPF->init(bpf_prog);
    BPF->get_array_table<uint64_t>("config").update_value(0, getpid());
    BPF->get_array_table<uint64_t>("runstate").update_value(0, RunState);             // Start procmon in a resumed state. We update this to suspended state if user chooses from TUI.
    auto schemaTable = BPF->get_hash_table<int, ::SyscallSchema>("syscalls");

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
            auto code = schemaTable.update_value(::Utils::GetSyscallNumberForName(event.Name()), std::move(*schemaItr.base()));
            if (code.code())
                std::cout << "ERROR" << std::endl;
        }
    }

    BPF->open_perf_buffer("events", &EbpfTracerEngine::PerfCallbackWrapper, &EbpfTracerEngine::PerfLostCallbackWrapper, (void*)this, 64);
    PollingThread = std::thread(&EbpfTracerEngine::Poll, this);
    ConsumerThread = std::thread(&EbpfTracerEngine::Consume, this);

    BPF->attach_tracepoint("raw_syscalls:sys_enter", sys_enter_bpf_prog_name);
    BPF->attach_tracepoint("raw_syscalls:sys_exit", sys_exit_bpf_prog_name);
*/
}

//--------------------------------------------------------------------
//
// SetRunState
//
// Sets the run state of the tracer.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::SetRunState(int runState)
{
    RunState = runState;
    int key = RUNSTATE_KEY;
    telemetryMapUpdateElem(mapFds[RUNSTATE_INDEX], &key, &runState, MAP_UPDATE_CREATE_OR_OVERWRITE);
}

//--------------------------------------------------------------------
//
// ~EbpfTracerEngine
//
// Destructor for the eBPF tracer engine.
//
//--------------------------------------------------------------------
EbpfTracerEngine::~EbpfTracerEngine()
{
    EventQueue.cancel();
    PollingThread.join();
    ConsumerThread.join();
}

//--------------------------------------------------------------------
//
// PerfCallbackWrapper
//
// Wrapper for the PerfCallback function. Called when new events
// arrive in the perf buffer.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::PerfCallbackWrapper(/* EbpfTracerEngine* */void *cbCookie, int cpu, void* rawMessage, uint32_t rawMessageSize)
{
    static_cast<EbpfTracerEngine *>(cbCookie)->PerfCallback(rawMessage, rawMessageSize);
}

//--------------------------------------------------------------------
//
// PerfCallback
//
// Called when new events arrive in the perf buffer.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::PerfCallback(void *rawMessage, int rawMessageSize)
{
    EventQueue.push(*static_cast<SyscallEvent*>(rawMessage));
}

//--------------------------------------------------------------------
//
// PerfLostCallbackWrapper
//
// Lost events callback wrapper.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::PerfLostCallbackWrapper(void *cbCookie, int cpu, uint64_t lost)
{
    static_cast<EbpfTracerEngine*>(cbCookie)->PerfLostCallback(lost);
}

//--------------------------------------------------------------------
//
// PerfLostCallback
//
// Lost events callback.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::PerfLostCallback(uint64_t lost)
{
    return;
}

//--------------------------------------------------------------------
//
// Poll
//
// Polls the perf buffer for new events.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::Poll()
{
    bool btfEnabled = true;

    bool activeSyscalls[SYSCALL_ARRAY_SIZE];
    for(int i = 0; i < SYSCALL_ARRAY_SIZE; i++)
    {
        activeSyscalls[i] = false;
    }

    SetBootTime();

    const ebpfTelemetryObject   kernelObjs[] =
    {
        {
            KERN_4_17_5_1_OBJ, {4, 17}, {5, 2}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_2_OBJ, {5, 2}, {5, 3}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_3_5_5_OBJ, {5, 3}, {5, 6}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_6__OBJ, {5, 6}, {0, 0}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        }
    };

    ebpfTelemetryObject   kernelObjs_core[] =
    {
        {
            KERN_4_17_5_1_CORE_OBJ, {4, 17}, {5, 2}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_2_CORE_OBJ, {5, 2}, {5, 3}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_3_5_5_CORE_OBJ, {5, 3}, {5, 6}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_6__CORE_OBJ, {5, 6}, {0, 0}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        }
    };

    const char* defPaths[] = {"./", "./procmonEBPF", "/tmp/"};

    const ebpfTelemetryConfig procmonConfig = (ebpfTelemetryConfig)
    {
        g_bootSecSinceEpoch,
        false, // enable raw socket capture
        btfEnabled ? sizeof(kernelObjs_core) / sizeof(*kernelObjs_core) : sizeof(kernelObjs) / sizeof(*kernelObjs),
        btfEnabled ? kernelObjs_core : kernelObjs,
        sizeof(defPaths) / sizeof(*defPaths),
        defPaths,
        sizeof(mapObjects) / sizeof(*mapObjects),
        mapObjects,
        NULL,
        false
    };

    const char* const argv[] = {"procmon"};

    setLogCallback(logHandler);

    int ret = telemetryStart(&procmonConfig, PerfCallbackWrapper, PerfLostCallbackWrapper, telemetryReady, configChange, this, (const char **)argv, mapFds);

    return;
}

//--------------------------------------------------------------------
//
// Consume
//
// Consumes the events from the event queue
//
//--------------------------------------------------------------------
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

        if(RunState == TRACER_SUSPENDED)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

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

        std::string syscall = Utils::SyscallNumberToName[event->sysnum];
        ITelemetry tel;
        tel.pid = event->pid;
        //tel.stackTrace = GetStackTraceForIPs(event->pid, event->kernelStack, event->kernelStackCount, event->userStack, event->userStackCount);
        tel.comm = std::string(event->comm);
        tel.processName = std::string(event->comm);
        tel.syscall = syscall;

        if((int64_t)event->ret < 0)
        {
            constexpr uint64_t sign_bits = ~uint64_t{} << 63;
            tel.result = (int)(-1 * (event->ret & sign_bits) + (event->ret & ~sign_bits));
        }
        else
        {
            tel.result = event->ret;
        }

        tel.duration = event->duration_ns;
        tel.arguments = (unsigned char*) malloc(MAX_BUFFER);
        memset(tel.arguments, 0, MAX_BUFFER);
        memcpy(tel.arguments, event->buffer, MAX_BUFFER);
        tel.timestamp = event->timestamp;

        batch.push_back(tel);
    }

    //
    // Cancel the sysinternalsEBPF polling loop
    //
    telemetryCancel();

    return;
}

//--------------------------------------------------------------------
//
// GetStackTraceForIPs
//
// Gets callstack
//
//--------------------------------------------------------------------
StackTrace EbpfTracerEngine::GetStackTraceForIPs(int pid, uint64_t *kernelIPs, uint64_t kernelCount, uint64_t *userIPs, uint64_t userCount)
{
    StackTrace result;

/*    if (pid < 0)
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
    */

    return result;
}

//--------------------------------------------------------------------
//
// AddPids
//
// Sets the pids to trace
//
//--------------------------------------------------------------------
void EbpfTracerEngine::AddPids(std::vector<int> pidsToTrace)
{
    for(int i=0; i<pidsToTrace.size(); i++)
    {
        telemetryMapUpdateElem(mapFds[PIDS_INDEX], &i, &pidsToTrace[i], MAP_UPDATE_CREATE_OR_OVERWRITE);
    }
}

