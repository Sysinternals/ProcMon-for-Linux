// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "cli_utils.h"

namespace CLIUtils
{
    // An immediate exit with no cleanup/wind-down
    void FastExit()
    {
        // re-enable cursor before exiting Procmon
        system("setterm -cursor on");
        
        exit(-1);
    }

    // Prints usage string to terminal
    void DisplayUsage(bool shouldExit)
    {
        std::cout << "procmon [OPTIONS...]" << std::endl;
        std::cout << "   OPTIONS" << std::endl;
        std::cout << "      -h/--help                Prints this help screen" << std::endl;
        std::cout << "      -p/--pids                Comma separated list of process ids to monitor" << std::endl;
        std::cout << "      -e/--events              Comma separated list of system calls to monitor" << std::endl;
        std::cout << "      -c/--collect [FILEPATH]  Option to start Procmon in a headless mode" << std::endl;
        std::cout << "      -f/--file FILEPATH       Open a Procmon trace file" << std::endl;

        if (shouldExit)
            FastExit();
    }
}