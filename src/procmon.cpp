// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <iostream>
#include <version.h>

#include "configuration/procmon_configuration.h"
#include "display/screen.h"
#include "display/headless.h"
#include "logging/easylogging++.h"

INITIALIZE_EASYLOGGINGPP

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

    return 0;
}
