/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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