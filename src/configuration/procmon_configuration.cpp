// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "procmon_configuration.h"

void ProcmonConfiguration::HandlePidArgs(char *pidArgs)
{
    std::stringstream pidStream(pidArgs);
    std::string pidString;
    while (getline(pidStream, pidString, ','))
    {
        pid_t pid;
        try
        {
            pid = std::stoi(pidString, nullptr, 10);
            pids.push_back(pid);
            if(pids.size()>MAX_PIDS)
            {
                std::cerr << "Max number of pids (" << MAX_PIDS << ")" << " exceeded" << '\n';
                CLIUtils::FastExit();
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << "ProcmonConfiguration::Invalid pid specified - " << e.what() << '\n';
            CLIUtils::FastExit();
        }
    }
}

void ProcmonConfiguration::HandleStorageArgs(char *storageArgs)
{
    if (StorageProxy::IsValidStorageEngineType(storageArgs))
    {
        storageEngineType = StorageProxy::GetStorageTypeForString(storageArgs);
        _storageEngine = std::shared_ptr<IStorageEngine>(StorageProxy::StorageFactory(storageEngineType));
    }
    else
    {
        std::cerr << "ProcmonConfiguration::\"" << storageArgs << "\" is not a valid storage engine" << std::endl;
        CLIUtils::FastExit();
    }
}

void ProcmonConfiguration::HandleEventArgs(char *eventArgs)
{
    std::stringstream eventStream(eventArgs);
    std::string eventString;
    while (getline(eventStream, eventString, ','))
    {
        events.emplace_back(eventString);
    }
}

void ProcmonConfiguration::HandleFileArg(char * filepath)
{
    std::ifstream testFilePath(filepath); 
    if (!testFilePath)
    {
        std::cerr << "The specified promcon trace file doesn't exist" << std::endl;
        CLIUtils::FastExit();
    }

    traceFilePath = std::string(filepath);
}

ProcmonConfiguration::ProcmonConfiguration(int argc, char *argv[])
{
    // get start time since EPOC for header
    epocStartTime = ConvertEpocTime(time(nullptr));

    // get start time of procmon
    if(clock_gettime(CLOCK_MONOTONIC, &startTime) == -1)
    {
        LOG(ERROR) << "Failed to get start time";
        exit(1);
    }

    LOG(INFO) << "Tv_sec " << startTime.tv_sec << " Tv_nsec " << startTime.tv_nsec;

    // setup default output trace file
    outputTraceFilePath = "procmon_" + date + "_" + epocStartTime + ".db";

    static struct option long_options[] =
    {
        { "pids",          required_argument, NULL, 'p' },
        { "storageEngine", required_argument, NULL, 's' },
        { "events",        required_argument, NULL, 'e' },
        { "collect",       optional_argument, NULL, 'c' },
        { "file",          required_argument, NULL, 'f' },
        { "help",          no_argument,       NULL, 'h' },
        { NULL,            0,                 NULL,  0  }
    };

    int c = 0;
    int option_index = 0;
    while (true)
    {
        if ((c = getopt_long(argc, argv, "hc:p:s:e:f:", long_options, &option_index)) == -1)
            break;
        
        switch (c)
        {
            case 0:
                // We've encountered an unknown long arg!!
                CLIUtils::DisplayUsage(true);
                break;
            case 'p':
                HandlePidArgs(optarg);
                break;

            case 's':
                HandleStorageArgs(optarg);
                break;

            case 'e':
                HandleEventArgs(optarg);
                break;

            case 'c':
            {
                if(strlen(optarg) > 0)
                {
                    outputTraceFilePath = std::string(optarg);
                }

                headless = true;
                break;
            }

            case 'f':
                HandleFileArg(optarg);
                break;

            default:
                // Invalid argument
                CLIUtils::DisplayUsage(true);
        }
    }

    LOG(INFO) << "Output trace file:" << outputTraceFilePath;

    // Get schema of all syscalls on system
    syscallSchema = ::SyscallSchema::Utils::CollectSyscallSchema();

    // if user has not specified any syscalls trace all events
    if(events.size() == 0)
    {
        for (auto i : ::SyscallSchema::Utils::SyscallNameToNumber)
        {
            events.push_back({i.first});
        }
    }
    else
    {
        for (auto event : events)
        {
            auto search = std::find_if(syscallSchema.begin(), syscallSchema.end(), [event](auto s) -> bool {return event.Name().compare(s.syscallName) == 0; });
        
            if (search == syscallSchema.end())
            {
                // Invalid syscall passed to procmon
                std::cerr << "ERROR: Invalid syscall " << event.Name() << std::endl << std::endl;

                CLIUtils::DisplayUsage(true);
            }
        }
    }

    if (_storageEngine == nullptr)
    {
        // Use default storage engine
        _storageEngine = std::shared_ptr<IStorageEngine>(StorageProxy::StorageFactory(StorageProxy::StorageEngineType::Sql));
    }

    // Initialize Storage Engine
    _storageEngine->Initialize(events);

    // Initialize Tracer
    _tracerEngine = std::unique_ptr<ITracerEngine>(new EbpfTracerEngine(_storageEngine, events));
    _tracerEngine->AddEvent(events);
    _tracerEngine->AddPids(pids);

    // List of all syscalls that contain pointer params
    pointerSyscalls = ::SyscallSchema::Utils::Linux64PointerSycalls;
}

uint64_t ProcmonConfiguration::GetStartTime()
{
    return startTime.tv_sec * 1000000000 + startTime.tv_nsec;
}

void ProcmonConfiguration::SetStartTime(uint64_t start)
{
    startTime.tv_sec = start / 1000000000;
    startTime.tv_nsec = start % 1000000000;
}

std::string ProcmonConfiguration::ConvertEpocTime(time_t time)
{
    char _buf[DEFAULT_TIMESTAMP_LENGTH];
    char _date_buf[DEFAULT_DATESTAMP_LENGTH];
    struct tm* _time;

    _time = localtime(&time);
    // prep datestamp
    strftime(_date_buf, DEFAULT_DATESTAMP_LENGTH, "%Y-%m-%d", _time);
    date = std::string(_date_buf);

    // prep timestamp
    strftime(_buf, DEFAULT_TIMESTAMP_LENGTH, "%T", _time);
    
    return std::string(_buf);
}