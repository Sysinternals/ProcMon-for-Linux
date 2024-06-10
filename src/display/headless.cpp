/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "headless.h"
#include "../logging/easylogging++.h"

#include <version.h>
#include <csignal>
#include <iostream>
#include <thread>

namespace
{
    volatile std::sig_atomic_t signalStatus;
}

void sigintHandler(int sig)
{
    signalStatus = sig;
}

bool Headless::initialize(std::shared_ptr<ProcmonConfiguration> configPtr)
{
    config = configPtr;

    std::cout << "Procmon " << PROCMON_VERSION_MAJOR << "." << PROCMON_VERSION_MINOR << " - (C) 2020 Microsoft Corporation. Licensed under the MIT license." << std::endl;
    std::cout << "Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license." << std::endl;
    std::cout << "Mark Russinovich, Mario Hewardt, Javid Habibi, John Salem" << std::endl << std::endl;

    std::cout << "Press Ctrl-C to end monitoring without terminating the process." << std::endl << std::endl;

    std::cout << "PID Filter: ";
    if(config->pids.size() == 0)
    {
        std::cout << "All Pids" << std::endl;
    }
    else
    {
        std::cout << config->pids[0];

        for(int i = 1; i < config->pids.size(); i++)
        {
            std::cout << ", " << config->pids[i];
        }
        std::cout << std::endl;
    }

    std::cout << "Syscall Filter: ";
    if(config->events.size() == Utils::SyscallNameToNumber.size())
    {
        std::cout << "All Syscalls" << std::endl;
    }
    else
    {
        std::cout << config->events[0].Name();

        for(int i = 1; i < config->events.size(); i++)
        {
            std::cout << ", " << config->events[i].Name();
        }
        std::cout << std::endl;
    }

    return true;
}

void Headless::run()
{
    bool running = true;
    std::string size;

    // setup signal handler
    signal(SIGINT, sigintHandler);

    std::cout << "Events captured: ";

    while(running)
    {
        // check to see if user has hit ctrl + c
        if(signalStatus == SIGINT)
        {
            config->GetTracer()->SetRunState(TRACER_SUSPENDED);
            running = false;
            break;
        }

        // update terminal with events captured
        size = std::to_string(config->GetStorage()->Size());
        std::cout << size << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // print overwrite pervious value printed to screen
        std::cout << std::string(size.length(),'\b');
    }
    std::cout << std::endl << std::endl;
}

void Headless::shutdown()
{
    std::cout << "Writing events to " << config->GetOutputTraceFilePath() << std::endl;

    try
    {
        config->GetStorage()->Export(std::make_tuple(config->GetStartTime(), config->GetEpocStartTime()), config->GetOutputTraceFilePath());
    }
    catch(const std::runtime_error& e)
    {
        LOG(ERROR) << e.what();
        std::cerr << "Failed to write to tracefile " << config->GetOutputTraceFilePath() << std::endl;
        CLIUtils::FastExit();
    }


    std::cout << "Total events captured: " << config->GetStorage()->Size() << std::endl;

}