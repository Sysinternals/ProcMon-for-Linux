/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "procmon_configuration.h"

extern std::string debugTraceFile;

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

void ProcmonConfiguration::HandleLogArg(char * filepath)
{
    if(filepath)
    {
        debugTraceFilePath = std::string(filepath);
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

    LOG(DEBUG) << "Tv_sec " << startTime.tv_sec << " Tv_nsec " << startTime.tv_nsec;

    // setup default output trace file
    outputTraceFilePath = "procmon_" + date + "_" + epocStartTime + ".db";

    static struct option long_options[] =
    {
        { "pids",          required_argument, NULL, 'p' },
        { "storageEngine", required_argument, NULL, 's' },
        { "events",        required_argument, NULL, 'e' },
        { "collect",       optional_argument, NULL, 'c' },
        { "file",          required_argument, NULL, 'f' },
        { "log",           required_argument, NULL, 'l' },
        { "help",          no_argument,       NULL, 'h' },
        { NULL,            0,                 NULL,  0  }
    };

    int c = 0;
    int option_index = 0;
    while (true)
    {
        if ((c = getopt_long(argc, argv, "hc:p:s:e:f:l:", long_options, &option_index)) == -1)
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

            case 'l':
                HandleLogArg(optarg);
                break;

            default:
                // Invalid argument
                CLIUtils::DisplayUsage(true);
        }
    }

    LOG(DEBUG) << "Output trace file:" << outputTraceFilePath;

    // Get schema of all syscalls on system
    syscallSchema = Utils::CollectSyscallSchema();

    // if user has not specified any syscalls trace all events
    if(events.size() == 0)
    {
        for (auto i : syscalls)
        {
            events.push_back({i.name});
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
    _tracerEngine = std::unique_ptr<ITracerEngine>(new EbpfTracerEngine(_storageEngine, events, pids));
    _tracerEngine->Initialize();
    _tracerEngine->AddEvent(events);

    // List of all syscalls that contain pointer params
    pointerSyscalls = Utils::Linux64PointerSycalls;
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