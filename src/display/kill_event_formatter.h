// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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