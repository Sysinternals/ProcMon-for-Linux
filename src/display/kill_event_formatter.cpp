// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


#include "kill_event_formatter.h"
#include "../logging/easylogging++.h"


std::string KillEventFormatter::GetDetails(ITelemetry event)
{ 
    std::string details; 
    long pid = 0;
    long signal = 0;

    // First get the PID
    int size = sizeof(long);
    memcpy(&pid, event.arguments, size);

    // Next, the signal #
    memcpy(&signal, event.arguments+sizeof(long), size);

    if(signal<signalmap.size())
    {
        std::string signalname = signalmap[signal];
        details = signalname + " sent to process ID " + std::to_string(pid);
    }
    else
    {
        details = "Signal " + std::to_string(signal) + " send to process ID " + std::to_string(pid);
    }

    return details; 
}


