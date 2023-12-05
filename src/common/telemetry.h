/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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