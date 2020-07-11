// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef TELEMETRY_BASE_H
#define TELEMETRY_BASE_H

#include "stack_trace.h"
#include "string.h"

#define MAX_BUFFER      128

struct ITelemetry
{
    pid_t pid;
    StackTrace stackTrace;
    std::string comm;
    std::string processName;
    std::string syscall;
    int64_t result;
    uint64_t duration;
    unsigned char *arguments; 
    uint64_t timestamp;

    friend bool operator != (ITelemetry a, ITelemetry b)
    {
        if(a.pid != b.pid) return true;
        if(a.stackTrace.Serialize() != b.stackTrace.Serialize()) return true;
        if(a.comm != b.comm) return true;
        if(a.syscall != b.syscall) return true;
        if(a.result != b.result) return true;
        if(a.duration != b.duration) return true;
        if(strcmp((const char *)a.arguments, (const char *)b.arguments) != 0) return true;
        if(a.timestamp != b.timestamp) return true;

        return false;
    }
};

#endif // TELEMETRY_BASE_H