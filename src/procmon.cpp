/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <iostream>
#include <version.h>
#include <unistd.h>

#include "configuration/procmon_configuration.h"
#include "display/screen.h"
#include "display/headless.h"
#include "logging/easylogging++.h"
#include "installer.h"

INITIALIZE_EASYLOGGINGPP

//--------------------------------------------------------------------
//
// main
//
// Main entry point
//
//--------------------------------------------------------------------
int main(int argc, char *argv[])
{
    // Make sure user is running elevated
    if(geteuid() != 0)
    {
        std::cout << "Procmon requires elevated credentials. Please run with sudo.\n";
        exit(-1);
    }

    /*
    * Turn off cursor for shell. Note this has to be done before EBPF spins up.
    * This is due to a conflict that leads to the consumer thread dieing when the system
    * function is executed.
    */
    curs_set(0);

    // Configure logging
    el::Loggers::addFlag(el::LoggingFlag::HierarchicalLogging);
    el::Loggers::addFlag(el::LoggingFlag::AutoSpacing);
    el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
    el::Loggers::addFlag(el::LoggingFlag::HierarchicalLogging);
    el::Loggers::setLoggingLevel(el::Level::Error);

    // Extrace eBPF programs
    ExtractEBPFPrograms();

    // Program initialization: create global config from args
    auto config = std::make_shared<ProcmonConfiguration>(argc, argv);

    LOG(INFO) << "Tracing " << config->events.size() << " system calls";

    // Configure logging
    el::Configurations defaultConf;
    defaultConf.setToDefault();

    if(config->GetHeadlessMode())
    {
        if(config->GetTraceFilePath().compare("") != 0)
        {
            std::cerr << "Cannot open trace file in headless mode";
            CLIUtils::DisplayUsage(true);
        }

        Headless headlessDisplay;

        // init headless interface
        headlessDisplay.initialize(config);

        // run in headless mode
        headlessDisplay.run();

        // cleanup run
        headlessDisplay.shutdown();
    }
    else
    {
        Screen display;

        // initialize curses UI
        display.initScreen(config);

        // run display
        display.run();

        // shutdown curses UI
        display.shutdownScreen();
    }

    // re-enable cursor before exiting Procmon
    curs_set(1);

    config->GetTracer()->Cancel();
    DeleteEBPFPrograms();

    return 0;
}
