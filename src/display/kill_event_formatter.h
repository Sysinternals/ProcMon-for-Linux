/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef KILL_EVENT_FORMATTER_H
#define KILL_EVENT_FORMATTER_H

#include <vector>

#include "../common/telemetry.h"
#include "../common/event.h"
#include "event_formatter.h"

class KillEventFormatter : public EventFormatter
{

protected:
    std::map<int, std::string> signalmap = {
        {0, "CHECKPERM"},
        {1, "SIGHUP"},
        {2, "SIGINT"},
        {3, "SIGQUIT"},
        {4, "SIGILL"},
        {5, "SIGTRAP"},
        {6, "SIGABRT"},
        {7, "SIGBUS"},
        {8, "SIGFPE"},
        {9, "SIGKILL"},
        {10, "SIGUSR1"},
        {11, "SIGSEGV"},
        {12, "SIGUSR2"},
        {13, "SIGPIPE"},
        {14, "SIGALRM"},
        {15, "SIGTERM"},
        {16, "SIGSTKFLT"},
        {17, "SIGCHLD"},
        {18, "SIGCONT"},
        {19, "SIGSTOP"},
        {20, "SIGTSTP"},
        {21, "SIGTTIN"},
        {22, "SIGTTOU"},
        {23, "SIGURG"},
        {24, "SIGXCPU"},
        {25, "SIGXFSZ"},
        {26, "SIGVTALRM"},
        {27, "SIGPROF"},
        {28, "SIGWINCH"},
        {29, "SIGIO"},
        {30, "SIGPWR"},
        {31, "SIGSYS"}
    };

public:
    KillEventFormatter() {};
    ~KillEventFormatter(){};

    std::string GetDetails(ITelemetry event);
    void Initialize(const std::string syscall, ProcmonConfiguration* config) { EventFormatter::Initialize(syscall, config); }
};

#endif